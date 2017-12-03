'''
Script for interfacing with multiple remote *nix hosts
Functions for sudo and su
Written by: Carlo Viqueira
'''

import os
import paramiko
import base64
import logging
from logging import handlers
from Cryptodome.Cipher import AES
from Cryptodome import Random
import re
import csv
import cmd
import hashlib

input_hosts = './input/hosts.csv'
df_output = './output/df-results.csv'
log_file = './upgrade-logs/upgrade-log.txt'
conf_input = './input/upgrade-splunk.conf'
copy_file_from = './input/splunk-6.6.3-e21ee54bc796-linux-2.6-x86_64.rpm'
copy_file_to = '/tmp/aaa_splunkupgrade/software/splunk-6.6.3-e21ee54bc796-linux-2.6-x86_64.rpm'
host_keys = './input/host-keys.txt'
tail = '~'

class RunCommand(cmd.Cmd):
    prompt = 'ssh> '
    intro = '''
    \n\n\n\n
    Run commands in the prompt. 
    Type read to load the input_hosts file into a dictionary. 
    Type 'connect' to open the SSH sessions.
    Type 'df -h /desireddirectory' to run the command on the hosts and output to './output/df-results.csv'
    Type 'shell username' to get an interactive for the specified username (if no username specified defaults to splunk)
    '''
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.hosts = []
        self.connections = []
        self.channels = []
        self.count = 0

    def do_add_host(self, args):
        # Use Add hosts to add more to connect to
        if args:
            try:
                self.hosts.append(args.split(','))
            except Exception as err:
                logger.error(err)

    def do_connect(self, args):
        # Connect to all hosts in the hosts list
        for host in self.hosts:
            try:
                client = paramiko.SSHClient()
                try:
                    if not os.path.exists(host_keys):
                        with open(host_keys, 'w+') as create:
                            create.close()
                    client.load_host_keys(host_keys)
                except Exception as err:
                    logger.error(err)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect(host['hostname'],
                               username=host['username'],
                               password=decrypt_password(host['ePassword']))
                self.connections.append(client)
                self.count += 1
            except paramiko.AuthenticationException as err:
                err = host['hostname'] + ' ' + err
                logger.error(err)
            except paramiko.SSHException as err:
                print(err)
                add_host = input('Do you want to add the host to known hosts? y/n: ')
                if add_host == 'y':
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host['hostname'],
                                   username=host['username'],
                                   password=decrypt_password(host['ePassword']))
                    self.connections.append(client)
                    self.count += 1
                logger.error(err)
            except Exception as err:
                err = '{} {}'.format(host['hostname'], err)
                logger.error(err)

        self.prompt = 'ssh {} connected> '.format(self.count)

    def do_sftp_put(self, args, local_file=copy_file_from, remote_file=copy_file_to):
        for host, conn in zip(self.hosts, self.connections):
            try:
                ftp = conn.open_sftp()
                ftp.put(local_file, remote_file)
                print('Copied %s to %s on %s' % (local_file, remote_file, host['hostname']))
                ftp.close()
            except paramiko.SFTPError as err:
                err = host['hostname'] + ' ' + err
                logger.error(err)
            except Exception as err:
                err = '{} {}'.format(host['hostname'], err)
                logger.error(err)

    def do_sudo(self, command):
        for host, conn in zip(self.hosts, self.connections):
            try:
                if host['username'] != "root":
                    command = "sudo -S -p '' %s" % command
                    stdin, stdout, stderr = conn.exec_command(command)
                    stdin.write((decrypt_password(host['ePassword'])) + "\n")
                    stdin.flush()
                    for line in stdout.read().splitlines():
                        t_line = line.decode("utf-8")
                        print('host: %s %s' % (host['hostname'], t_line))
                    for line in stderr.read().splitlines():
                        t_line = line.decode("utf-8")
                        print('host: %s %s' % (host['hostname'], t_line))
                    print('host: %s return value: %s' % (host['hostname'], stdout.channel.recv_exit_status()))
            except Exception as err:
                err = '{} {}'.format(host['hostname'], err)
                logger.error(err)

    def do_run(self, command):
        # This is a general purpose function to run different commands in ssh
        data = []
        if command:
                for host, conn in zip(self.hosts, self.connections):
                    try:
                        stdin, stdout, stderr = conn.exec_command(command)
                        stdin.close()
                        for line in stdout.read().splitlines():
                            print('host: %s %s' % (host['hostname'], line.decode("utf-8")))
                            data.append([host['hostname'], line.decode("utf-8")])
                        for line in stderr.read().splitlines():
                            logger.error('host: %s Message: %s' % (host['hostname'], line.decode("utf-8")))
                            print('host: %s %s' % (host['hostname'], line.decode("utf-8")))
                    except Exception as err:
                        err = '{} {}'.format(host['hostname'], err)
                        logger.error(err)
        else:
            print("usage: run ")

    def do_shell(self, args):
        shell_input = ''
        user = 'splunk'
        if args:
            user = args
        for host, conn in zip(self.hosts, self.connections):
            try:
                channel = conn.invoke_shell()
                hostname = (re.sub('.itsc.hhs-itsc.local', '', host['hostname']))
                password = (decrypt_password(host['ePassword']))
                if host['username'] != 'root':
                    send_shell('sudo su - {}'.format(user), host['username'], hostname, channel, False, password)
                else:
                    send_shell('su - {}'.format(user), user, hostname, channel, False)
                send_shell('\n', user, hostname, channel, False)
                self.channels.append(channel)
            except Exception as err:
                err = '{} {}'.format(host['hostname'], err)
                logger.error(err)
                continue
        while shell_input != 'exit':
            shell_input = input('shell {}> '.format(self.count))
            for host, session in zip(self.hosts, self.channels):
                try:
                    hostname = re.sub('.itsc.hhs-itsc.local', '', host['hostname'])
                    send_shell(shell_input, user, hostname, session, True)
                except Exception as err:
                    err = '{} {}'.format(host['hostname'], err)
                    logger.error(err)
                    continue
        for channel in self.channels:
            channel.close()
        self.channels = []

    def do_read(self, args):
        try:
            file_hosts = read_csv(input_hosts)
            creds = get_creds()
            count = 0
            for f_host in file_hosts:
                for user in creds:
                    if f_host['username'] == user['username']:
                        ePassword = user['ePassword']
                f_host['ePassword'] = ePassword
                self.hosts.append(f_host)
                count += 1
        except Exception as err:
            logger.error(err)
        print('Read {} hosts from file.'.format(count))

    def do_df(self, args):
        data = []
        data.append('')
        command = 'df'
        if args:
            command = command + ' ' + args
        if command:
            for host, conn in zip(self.hosts, self.connections):
                try:
                    stdin, stdout, stderr = conn.exec_command(command)
                    stdin.close()
                    for line in stdout.read().splitlines():
                        t_line = line.decode("utf-8")
                        if t_line == 'Filesystem                        Size  Used Avail Use% Mounted on':
                            if not os.path.exists(df_output):
                                data[0] = ['Hostname', 'Filesystem', 'Size', 'Used', 'Avail', 'Use%', 'Mounted On']
                        else:
                            t_line = host['hostname'] + ',' + t_line
                            t_line = re.sub('\s+', ',', t_line)
                            data.append(t_line.split(','))
                    for line in stderr.read().splitlines():
                        logger.error('host: %s Message: %s' % (host['hostname'], line.decode("utf-8")))
                except Exception as err:
                    err = '{} {}'.format(host['hostname'], err)
                    logger.error(err)
            try:
                write_csv(df_output, data)
            except Exception as err:
                logger.error(err)
            print('Output written to %s.' % df_output)

    def do_close(self, args):
        for conn in self.connections:
            try:
                conn.close()
            except Exception as err:
                logger.error(err)
        print('Disconnected from SSH Sessions.')
        self.prompt = 'ssh> '

    def do_exit(self, args):
        for conn in self.connections:
            try:
                conn.close()
            except Exception as err:
                logger.error(err)
        print('Disconnected from SSH Sessions.')
        self.prompt = 'ssh> '
        return True


def write_csv(filename, results):
    if not os.path.exists(filename):
        config = open(filename, 'w+')
        config.close
    with open(filename, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for row in results:
            csv_writer.writerow(row)
    csvfile.close()


def read_csv(filename):
    results = []
    if not filename:
        filename = df_output
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            results.append(row)
    print('Read "%s"' % filename)
    return results

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-s[-1]]


def store_creds(filename=conf_input):
    num_creds = int(input('How many credential sets do you want to enter?: '))
    creds_list = [None] * num_creds
    for x in range(num_creds):
        username = input('Enter the username: ')
        password = input('Enter the password: ')
        ePassword = encrypt_password(password).decode('utf-8')
        creds_list[x] = [username, ePassword]
    with open(filename, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for cred in creds_list:
            csv_writer.writerow(cred)
    csvfile.close()


def decrypt_password(enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key_pass, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:])).decode('utf-8')


def encrypt_password(raw):
    raw = pad(raw).encode('utf-8')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key_pass, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def log_to_file():
    # This is what makes the logs for this script

    if not os.path.exists('./upgrade-logs'):
        os.mkdir('./upgrade-logs')
    logger = logging.getLogger(__name__)
    hdlr = handlers.RotatingFileHandler('./upgrade-logs/upgrade-log.txt',
                                        maxBytes=100000, backupCount=10, encoding='UTF-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    return logger


def get_creds():
    global conf_input
    fieldnames = ['username', 'ePassword']
    dicts_from_file = []
    with open(conf_input, 'r') as inf:
        reader = csv.reader(inf)
        for row in reader:
            dicts_from_file.append(dict(zip(fieldnames, row)))
    return dicts_from_file


def send_shell(command, username, host, conn, should_print, password=''):
    buff = ''
    global tail
    prompt = '[{}@{} {}]$ '.format(username, host, tail)
    prompt_command = '[{}@{} {}]$ {}'.format(username, host, tail, command)
    if password != '':
        conn.send(command + '\n')
        while not buff.endswith('password for {}: '.format(username)):
            resp = conn.recv(9999).decode('utf-8')
            buff += resp
        conn.send(password + '\n')
    else:
        try:
            if command != 'exit':
                if command.startswith('cd '):
                    in_path = command.lstrip('cd ')
                    split = os.path.split(in_path)
                    if split[0] == ('/' or '') and in_path != '..':
                        tail = split[1]
                    elif in_path == '..':
                        conn.send('pwd\n')
                        while not buff.endswith(prompt):
                            resp = conn.recv(9999).decode('utf-8')
                            buff += resp
                            if should_print:
                                for line in resp.splitlines():
                                    if line.startswith('/'):
                                        split = os.path.split(line)
                                        tail = os.path.basename(split[0])
                    else:
                        tail = '~'
                    prompt = '[{}@{} {}]$ '.format(username, host, tail)
                    prompt_command = '[{}@{} {}]$ {}'.format(username, host, tail, command)
        except Exception as err:
            err = '{}: {}'.format(host, err)
            logger.error(err)
        finally:
            conn.send(command + '\n')
            if command != 'exit':
                while not buff.endswith(prompt):
                    resp = conn.recv(9999).decode('utf-8')
                    buff += resp
                    if should_print:
                        for line in resp.splitlines():
                            if line != (prompt or prompt_command):
                                print('{}: {}'.format(host, line))

logger = log_to_file()
try:
    if not os.path.exists(conf_input):
        if not os.path.exists('./input'):
            os.makedirs('./input')
        config = open(conf_input, 'w+')
        config.close
        SECRET_KEY = input('Enter a passphrase to store the credentials: ')
        key_pass = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        store_creds()
        logger.info('Credentials stored with new Secret key.')
    else:
        SECRET_KEY = input('Enter the passphrase: ')
        key_pass = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        cred_set = get_creds()
        out_pass = decrypt_password(cred_set[0]['ePassword'])
        logger.info('Credentials Used.')
except Exception as err:
    logger.error(err)

try:
    if __name__ == '__main__':
        RunCommand().cmdloop()
    logger.info('Command Loop run.')
except Exception as err:
    logger.error(err)
