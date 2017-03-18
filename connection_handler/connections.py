__author__ = 'mkabajah'
import telnetlib
import time
import paramiko
import threading
from corelib.SetupInit import s_log

# known prompts
POSITRON_ROOT_PROMPT = "root#"
POSITRON_ADMIN_PROMPT = "admin#"


class BaseProtocol:

    def __init__(self, hostname=None, username=None, password=None, cmd=None, port=22, timeout=30):
        self._hostname = hostname
        self._username = username
        self._port = port
        self._password = password
        self._command = cmd
        self._timeout = timeout
        self._client = None


class SSH(BaseProtocol):

    def __init__(self, hostname, username, password, cmd='', port=22, timeout=30):
        super(SSH, self).__init__(hostname, username, password, cmd, port, timeout)
        self.shell = None
        self.shell_log = ''
        self.kill_shell = False
        self.exit_status = None

    def __del__(self):
        self.close()

    def close(self):
        self._client.close()

    def connect(self, retries=3):
        """
            open a connection to the given machine, the function set a channel for interactive shell.
            if it fail to open a connection the function will print an error to logger an then raise an exception
        """
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connection_success = False
        for _ in range(retries):
            try:
                self._client.connect(self._hostname, self._port, self._username, self._password, timeout=self._timeout)
                connection_success = True
                break
            except Exception as e:
                s_log.error(e)
                time.sleep(3)
                pass

        if not connection_success:
            s_log.warning("fail to connect to hostname: {0} username: {1} password: {2}".format(self._hostname, self._username, self._password))
            raise Exception

        s_log.info("connected to host: {0}".format(self._hostname))


    def exec_tail_log(self, cmd, name, thread_id, dict, map, prompt=POSITRON_ROOT_PROMPT, timeout = 10, enable_wait=True, verbose=False, logger=None):
        """
            this function send the command for the channel, and wait for prompt
        :param cmd: the text to send to the channel
        :param prompt: prompt to wait after sending the command. default value is root prompt
        :param timeout: timeout for the command to finish
        :param enable_wait: when true, the function will run in  blocking mode and wait for given prompt
                            when false, the function will run the command and return.
        :return: buffer: [interactive mode] the output of the command
                 stdin, stdout, stderr: [non interactive mode] channel standard output
        """
        _id = threading.get_ident()
        thread_id[_id] = True
        dict[name] = ''
        map[name] = _id
        shell = self._client.invoke_shell()
        shell.send(cmd + '\n')
        start_time = time.time()
        while timeout > time.time() - start_time or (timeout == -1 and thread_id[_id]):
            if shell.recv_ready():
                line = shell.recv(9999)
                if verbose and logger:
                    s_log.debug(line)
                dict[name] += line.decode("utf-8")
        return dict[name]


    def open_shell(self, verbose=False, timeout=-1):
        output = ''
        self.shell_log = ''
        self.shell = self._client.invoke_shell()
        start_time = time.time()
        while (timeout > time.time() - start_time or timeout == -1) and not self.kill_shell:
            if self.shell.recv_ready():
                line = self.shell.recv(9999)
                if verbose:
                    s_log.debug(line)
                self.shell_log += line.decode("utf-8")
        self.kill_shell = False

    def send_to_shell(self, cmd):
        self.shell.send(cmd + '\n')

    def exec_command(self, command, bufsize=-1, timeout=None, get_pty=False):
        stdin, stdout, stderr = self._client.exec_command(command, bufsize, timeout, get_pty)
        exit_status = stdout.channel.recv_exit_status()
        return stdin, stdout, stderr, exit_status

    def get_exit_code(self):
        self.exit_status = self.shell.recv_exit_status()

    def kill_connection(self, sleep_before=0):
        time.sleep(sleep_before)
        self._client.close()

    def printlines(self, channel_file):
        for output_line in channel_file.readlines():
            s_log.debug(output_line[:-1])


class Telnet(BaseProtocol):

    def connect(self):
        self._client = telnetlib.Telnet(self._hostname, self._port)
        self._client.write(b'\n')
        self._client.read_until(b'Username: ')
        self._client.write(self._username.encode('ascii') + b'\n')
        self._client.read_until(b'Password: ')
        self._client.write(self._password.encode('ascii') + b'\n')
        print('connected')
        time.sleep(2)
        return self._client.read_very_eager().decode('ascii').splitlines()[-1]

    def send_cmd(self, command=None, name=None):
        if command:
            cmd_to_run = command
        else:
            cmd_to_run = self._command
        self._client.write(cmd_to_run.encode('ascii') + b'\n')
        return self._client.read_until(name.encode('ascii')).decode('ascii')

    def kill_connection(self, sleep_before=0):
        time.sleep(sleep_before)
        self._client.close()

    def send_positron_enter(self):
        s_log.debug('TelNet Connection to machine: {0} Port: {1}'.format(self._hostname, self._port))
        self._client = telnetlib.Telnet(self._hostname, self._port)
        time.sleep(1)
        s_log.debug('Sending "Enter"')
        self._client.write('\r\n'.encode('ascii'))
        s_log.debug('Disconnecting')
        self._client.close()


def ssh_test():
    my_ssh = SSH("10.56.32.90", "root", "Lab@123")
    my_ssh.connect()
    threading.Thread(target=my_ssh.open_shell, args=(True, -1)).start()
    in_str = ''
    while not in_str == 'exit':
        in_str = input()
        my_ssh.send_to_shell(in_str)
    my_ssh.kill_shell = True
    my_ssh.kill_connection()


def ssh_cmd_full_output(ip="10.56.32.90", user="root", key="Lab@123", cmd='ls -la'):
    my_ssh = SSH(ip, user, key)
    my_ssh.connect()
    stdin, stdout, stderr, exit_status = my_ssh.exec_command(cmd)
    return stdin, stdout.readlines(), stderr.readlines(), exit_status


def telnet_test():
    my_telnet = Telnet(hostname='10.56.32.91', port=23, username='autobot', password='Auto8m3', timeout=10, cmd='')
    telnet_name = my_telnet.connect()
    output = my_telnet.send_cmd('ping 10.56.32.90', telnet_name)
    my_telnet.kill_connection()
    print(output)


def main():
    telnet = Telnet(hostname='10.0.10.110', port=6068)
    telnet.send_positron_enter()

if __name__ == '__main__':
    main()

