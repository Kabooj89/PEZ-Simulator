"""
@copyright:
        Copyright 2017 PointGrab, LTD.

        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.

@author:
        Mohammad Kabajah
@Contact:
        mohammadk@pointgrab.com
@date:
        June 29, 2017
@Purpose:
        Contains All Utils related to SSH connection
"""

import threading
import time
import paramiko
import logging
from utilities.logging_utils import log_func_details, logger
from utilities.connection_handler.connection import Connection

logging.getLogger("paramiko").setLevel(logging.WARNING)


class SSH(Connection):
    class_doc = '''
    *SSH: is class aimed to established ssh connection with main functionality:
        1- establish_connection (abstract method)
        2- terminate_connection (abstract method)
        3- exec_command
        4- exec_tail_log
        5- open_shell
        6- print_lines
        7- get_shell_log
        '''

    def __init__(self, hostname, username, password, port, timeout, retries):
        """
        initiate SSH class instance with params
        :param hostname: device ip or address
        :param username: username for connection
        :param password: password for connection
        :param port: ssh port in general 22
        :param timeout: timeout for trying connection before raise exception of timeout
        :param retries: number of connection tries before throw exception
        :type password: str
        :type username: str
        :type hostname: str
        :type port: int
        :type timeout: int
        :type retries: int
        """

        super().__init__(hostname=hostname, username=username, password=password,
                         port=port, timeout=timeout, retries=retries)
        self.shell = None
        self.shell_log = ''
        self.kill_shell = False
        self.exit_status = None

    def initiate_connection(self, verbose=True):
        """
        open a connection to the given machine, the function set a channel for interactive shell.
        if it fail to open a connection the function will print an error to logger an then raise an exception
        :param verbose <boolean> trace option
        :return: connection (self._client)
        """
        if verbose:
            logger.debug("[*] initiate the ssh connection... ")
            log_func_details(hostname=self.hostname, username=self.username, passwor=self.password,
                             port=self.port, timeout=self.timeout, verbose=verbose)
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connection_success = False
        for i in range(self.retries):
            try:
                logger.debug("retries #:{0}".format(i + 1))
                self._client.connect(hostname=self.hostname, port=self.port, username=self.username,
                                     password=self.password, timeout=self.timeout)
                connection_success = True
                break
            except Exception as e:
                logger.error(e)
                time.sleep(3)
                pass

        if not connection_success:
            logger.error("fail to connect to hostname: {0} username: {1} password: {2}".format(self.hostname,
                                                                                               self.username,
                                                                                               self.password))
            raise Exception

        logger.info("connected to host: {0}".format(self.hostname))

    def exec_tail_log(self, cmd, name, thread_id, dict, map, timeout=10,
                      enable_wait=True, verbose=True, logger=None):
        """
            this function send the command for the channel, and wait for prompt
        :param cmd: the text to send to the channel
        :param prompt: prompt to wait after sending the command. default value is gp prompt
        :param timeout: timeout for the command to finish
        :param enable_wait: when true, the function will run in  blocking mode and wait for given prompt
                            when false, the function will run the command and return.
        :return: buffer: [interactive mode] the output of the command
                 stdin, stdout, stderr: [non interactive mode] channel standard output
        """
        if verbose:
            log_func_details(cmd=cmd, name=name, thread_id=thread_id, dict=dict, map=map,
                             timeout=timeout, enable_wait=enable_wait, verbose=verbose, logger=logger)
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
                    logger.debug(line)
                dict[name] += line.decode("utf-8")
        return dict[name]

    def open_shell(self, verbose=True, timeout=-1):
        """
        Open shell
        :param verbose: boolean
        :param timeout: timeout in sec
        :return: None

        """
        output = ''
        self.shell_log = ''
        self.shell = self._client.invoke_shell()
        start_time = time.time()
        while (timeout > time.time() - start_time or timeout == -1) and not self.kill_shell:
            if self.shell.recv_ready():
                line = self.shell.recv(9999)
                if verbose:
                    logger.info(line.decode("utf-8"))
                self.shell_log += line.decode("utf-8")
        self.kill_shell = False

    def send_to_shell(self, cmd):
        self.shell.send(cmd + '\n')

    def exec_command(self, command, bufsize=-1, timeout=None, sudo_required=False,
                     get_pty=False, sudo_passwd='q1w2e3r4', verbose=True):
        """
        exec command via ssh
        :param command: <str>
        :param bufsize: <int>
        :param timeout: <int> second , None in None
        :param sudo: <boolean> if sudo needed
        :param get_pty: <boolean>
        :param sudo_passwd: <string> sudo password
        :param verbose <boolean>
        :return: stdin, stdout, stderr , exit_code
        """
        if verbose:
            log_func_details(command=command, bufsize=bufsize,
                             timeout=timeout, sudo=sudo_required, get_pty=get_pty,
                             sudo_passwd=sudo_passwd)
        if sudo_required or "sudo" in command.lower():
            logger.info("sudo command was detected,the password used for sudo is: {0}".format(sudo_passwd))
            command = "echo '{0}' | sudo -S {1}".format(sudo_passwd, command)
        stdin, stdout, stderr = self._client.exec_command(command, bufsize, timeout, get_pty)
        exit_status = stdout.channel.recv_exit_status()
        stdout = "".join(stdout.readlines())
        stderr = "".join(stderr.readlines())
        if verbose:
            logger.debug("stdout:{0}".format(stdout))
            logger.debug("stderr:{0}".format(stderr))
            logger.debug("exit_status: {0}".format(exit_status))
        return stdin, stdout, stderr, exit_status

    def get_exit_code(self):
        self.exit_status = self.shell.recv_exit_status()

    def terminate_connection(self, sleep_before=0, verbose=True):
        """
        close connection in case the connection still opened until end of the script
        :param sleep_before: in sec <int>
        :param verbose: Boolean - activate the trace
        :return: None
        :Raises: Exception in case cannot close connection
        """
        if verbose:
            log_func_details(sleep_before=sleep_before, verbose=verbose)
        time.sleep(sleep_before)
        try:
            if self._client is not None:
                if self._client.get_transport() is not None:
                    self._client.close()
                    logger.info("connection is closed successfully!")
                else:
                    logger.info("connection is closed!")
            else:
                logger.error(
                    "there is no open connection to close, you should did establish_connection before !!".format(
                        self._client))
                raise ValueError("no open connection to close!")
        except Exception as e:
            raise Exception("connection <{0}> cannot be closed: {1}".format(self._client, e))

    def print_lines(self, channel_file):
        for output_line in channel_file.readlines():
            logger.debug(output_line[:-1])

    def get_shell_log(self):
        return self.shell_log


#######################
# for testing purpose #
#######################

def ssh_cmd_full_output(ip="10.0.0.169", user="pg", key="q1w2e3r4", cmd='sudo ifconfig'):
    ssh_conn = SSH(hostname=ip, username=user, password=key, port=22, retries=1, timeout=30)
    ssh_conn.initiate_connection(verbose=True)
    stdin, stdout, stderr, exit_status = ssh_conn.exec_command(cmd)
    logger.info(exit_status)
    logger.info(stdout)
    ssh_conn.terminate_connection(verbose=True)
    return stdin, stdout, stderr, exit_status


def ssh_test():
    my_ssh = SSH(hostname="10.0.0.169", username="pg", password="q1w2e3r4", port=22, retries=1, timeout=30)
    my_ssh.initiate_connection(verbose=True)
    threading.Thread(target=my_ssh.open_shell, args=(True, -1)).start()
    in_str = ''
    while not in_str == 'exit':
        in_str = input()
        my_ssh.send_to_shell(in_str)
    my_ssh.kill_shell = True
    logger.info("The log after loggign is:")
    logger.info(my_ssh.shell_log)
    my_ssh.terminate_connection()


if __name__ == '__main__':
    ssh_cmd_full_output()
