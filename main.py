import os
import paramiko
import base64
import logging
from logging import handlers
from Cryptodome.Cipher import AES
from Cryptodome import Random
import hashlib
import re
import csv
import cmd
import time

input_hosts = './input/hosts.csv'
df_output = './output/df-results.csv'
log_file = './upgrade-logs/upgrade-log.txt'
conf_input = './input/upgrade-splunk.conf'
copy_file_from = './input/splunk-6.6.3-e21ee54bc796-linux-2.6-x86_64.rpm'
copy_file_to = '/tmp/aaa_splunkupgrade/software/splunk-6.6.3-e21ee54bc796-linux-2.6-x86_64.rpm'
glob_flag = 0


class RunCommand(cmd.Cmd):
    prompt = 'ssh> '
    intro = '''
    Run commands in the prompt. 
    Type 'add_host servername,username' to add hosts to connect to. 
    Type 'connect' to open the SSH sessions.
    Type 'df -h /desireddirectory' to run the command on the hosts and output to './output/df-results.csv'
    Type 'shell username' to get an interactive for the specified username (if no username specified defaults to splunk)
    '''

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.hosts = []
        self.connections = []

    def do_add_host(self, args):
        # Use Add hosts to add more hosts to the input hosts file.
        if args:
            try:
                self.hosts.append(args.split(','))
            except os.error as err:
                logger.error(err)
        else:
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
            except os.error as err:
                logger.error(err)
            print('Read %s hosts from file.' % count)

    def do_connect(self, args):
        # Connect to all hosts in the hosts list
        count = 0
        for host in self.hosts:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(
                    paramiko.AutoAddPolicy())
                client.connect(host['hostname'],
                               username=host['username'],
                               password=decrypt_password(host['ePassword']))
                self.connections.append(client)
                count += 1
            except paramiko.AuthenticationException as err:
                err = host['hostname'] + ' ' + err
                logger.error(err)
        self.prompt = 'ssh %s connected> ' % count

    def do_sftp_put(self, args, local_file=copy_file_from, remote_file=copy_file_to):
        for host, conn in zip(self.hosts, self.connections):
            try:
                ftp = conn.open_sftp()
                ftp.put(local_file, remote_file)
                print('Copied %s to %s on %s' % (local_file, remote_file, host['hostname']))
                ftp.close()
            except(paramiko.SFTPError, os.error) as err:
                err = host['hostname'] + ' ' + err
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
            except os.error as err:
                err = host['hostname'] + ' ' + err
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
                except os.error as err:
                    err = host['hostname'] + ' ' + err
                    logger.error(err)
        else:
            print("usage: run ")

    def do_shell(self, args):
        channel_list = []
        shell_input = ''
        user = 'splunk'
        if args:
            user = args
        for host, conn in zip(self.hosts, self.connections):
            try:
                channel = conn.invoke_shell()
                hostname = (re.sub('.itsc.hhs-itsc.local', '', host['hostname']))
                password = (decrypt_password(host['ePassword']))
                send_shell('sudo su - {}'.format(user), host['username'], hostname, channel, False, password=password)
                send_shell('\n', user, hostname, channel, False)
                channel_list.append(channel)
            except os.error as err:
                err = host['hostname'] + ' ' + err
                logger.error(err)
        while shell_input != 'exit':
            shell_input = input('shell> ')
            for host, session in zip(self.hosts, channel_list):
                try:
                    hostname = re.sub('.itsc.hhs-itsc.local', '', host['hostname'])
                    send_shell(shell_input, user, hostname, session, True)
                except os.error as err:
                    err = host['hostname'] + ' ' + err
                    logger.error(err)

    def do_read(self, args):
        if args == './input/hosts.csv':
            in_hosts = read_csv(args)
            for host in in_hosts:
                self.hosts.append(host)
        read_csv(args)

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
                except os.error as err:
                    logger.error(err)
            try:
                write_csv(df_output, data)
            except os.error as err:
                logger.error(err)
            print('Output written to %s.' % df_output)

    def do_close(self, args):
        for conn in self.connections:
            try:
                conn.close()
            except os.error as err:
                logger.error(err)
        print('Disconnected from SSH Sessions.')
        self.prompt = 'ssh> '

    def do_exit(self, args):
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
    hdlr = handlers.RotatingFileHandler('./upgrade-logs/upgrade-log.txt', maxBytes=100000, backupCount=10,
                                        encoding='UTF-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    return logger


def get_creds():
    fieldnames = ['username', 'ePassword']
    dicts_from_file = []
    with open(conf_input, 'r') as inf:
        reader = csv.reader(inf)
        for row in reader:
            dicts_from_file.append(dict(zip(fieldnames, row)))
    return dicts_from_file


def send_shell(command, username, host, conn, should_print, password=''):
    buff = ''
    prompt = '[{}@{} {}]$ '.format(username, host, '~')
    prompt_command = '[{}@{} {}]$ {}'.format(username, host, '~', command)
    if password != '':
        conn.send(command + '\n')
        while not buff.endswith('password for {}: '.format(username)):
            resp = conn.recv(9999).decode('utf-8')
            buff += resp
        time.sleep(1)
        conn.send(password + '\n')
    else:
        conn.send(command + "\n")
        if command != 'exit':
            if command.startswith('cd '):
                in_path = command.lstrip('cd ')
                tail = os.path.basename(in_path)
                prompt = '[{}@{} {}]$ '.format(username, host, tail)
                prompt_command = '[{}@{} {}]$ {}'.format(username, host, tail, command)
                time.sleep(.001)
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
except os.error as err:
    logger.error(err)
try:
    if __name__ == '__main__':
        RunCommand().cmdloop()
    logger.info('Command Loop run.')
except os.error as err:
    logger.error(err)
