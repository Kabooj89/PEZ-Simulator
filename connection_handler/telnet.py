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
        Contains All Utils related to telnet connection.
"""

import telnetlib
import time
from utilities.connection_handler.connection import Connection
from utilities.logging_utils import logger, log_func_details
from data.connections_data import TelnetConfig


class Telnet(Connection):
    class_doc = '''
        *Telnet: is class aimed to established telnet connection with main functionality:
            1- establish_connection (abstract method)
            2- terminate_connection (abstract method)
            3- send_cmd
            4- send_enter
    '''
    port = TelnetConfig.PORT
    timeout = TelnetConfig.TIMEOUT

    def __init__(self, hostname, username, password, port):
        super().__init__(hostname=hostname, username=username,
                         password=password, port=port)
        self.telnet_prompt = None

    def initiate_connection(self, verbose=False):
        """
        connect telnet
        :param hostname: str - ip for hostname to connect at.
        :param username: str - username used to connection
        :param password: str - password used to connection
        :param port: int - port used for connection
        :return: telnet prompt
        """
        if verbose:
            log_func_details(hostname=self.hostname, password=self.password, verbose=verbose)
        try:
            self._client = telnetlib.Telnet(self.hostname, Telnet.port)
            if self._client is None:
                return False
        except Exception as e:
            logger.error("error connecting to telnet!!")
            raise ConnectionError(e)
        self._client.write(b'\n')
        self._client.read_until(b'login:', timeout=5)
        logger.debug("writing the username:{0} to telnet".format(self.username))
        self._client.write(self.username.encode('ascii') + b'\n')
        self._client.read_until(b'Password:')
        logger.debug("writing the password:{0} to telnet".format(self.password))
        self._client.write(self.password.encode('ascii') + b'\n')
        time.sleep(5)
        self.telnet_prompt = self._client.read_very_eager().decode('ascii').splitlines()[-1]
        logger.info('connected to Telnet!')
        logger.info("the Telnet prompt is: {0}".format(self.telnet_prompt))
        return True

    def exec_command(self, command=None, verbose=False):
        """
        send command to telnet channel
        :param command: command to send <str>
        :param prompt: prompt to read until
        :return: stdout <str>
        """
        if verbose:
            log_func_details(command=command, prompt=self.telnet_prompt, verbose=verbose)
        if command:
            cmd_to_run = command
        else:
            raise ValueError("should receive command but received None in place!!!")
        self._client.write(cmd_to_run.encode('ascii') + b'\n')
        stdout = self._client.read_until(self.telnet_prompt.encode('ascii')).decode('ascii')
        if verbose:
            logger.debug("the stdout after running the following command <{0}> is : {1}".format(command, stdout))
        return stdout

    def terminate_connection(self, sleep_before=0, verbose=False):
        """
        kill connection to telnet
        :param sleep_before: time in sec before kill connection <int>
        :return: None
        """
        if verbose:
            log_func_details(sleep_before=sleep_before, verbose=verbose)
        time.sleep(sleep_before)
        self._client.close()
        logger.info("Telnet connection is closed!")

    def send_enter(self, verbose=False):
        """
        send enter button to telnet channel
        :return: None
        """
        if verbose:
            logger.debug('TelNet Connection to machine: {0} Port: {1}'.format(self.hostname, Telnet.port))
        self._client = telnetlib.Telnet(self.hostname, self.port)
        time.sleep(1)
        logger.debug('Sending "Enter"')
        self._client.write('\r\n'.encode('ascii'))
        logger.debug('Disconnecting')
        self._client.close()


#######################
# for testing purpose #
#######################

def telnet_test():
    my_telnet = Telnet(hostname='10.0.0.71', username='pg', password='q1w2e3r4', port=10)
    my_telnet.initiate_connection(verbose=True)
    output = my_telnet.exec_command('ifconfig', verbose=True)
    my_telnet.terminate_connection(verbose=True)


if __name__ == "__main__":
    telnet_test()
