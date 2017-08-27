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
        Contains All Utils related to ssh tunnel connection.
"""

from sshtunnel import SSHTunnelForwarder
from utilities.connection_handler.connection import Connection
from utilities.logging_utils import log_func_details, logger


class SSHTunnel(Connection):
    """
    SSH Tunnel class
    """
    class_doc = '''
    *SSHTunnel: is class aimed to established SSH Tunnel connection with main functionality:
            1- establish_connection (abstract method)
            2- terminate_connection (abstract method)
            3- start_tunnel
    '''

    def __init__(self, hostname, username, password=None, port=None,
                 remote_bind_port=None, remote_bind_address=None,
                 ssh_pkey_file_path=None):
        """
        initiate parameters of SSHTunnel instance
        :param hostname: address for ssh connection
        :param username: username for ssh connection
        :param password: path for private key file
        :param remote_bind_port: bind port for database connection
        :param remote_bind_address: bind address for database connection
        :param ssh_pkey_file_path: path for private key file
        :type hostname: str
        :type username: str
        :type password: str
        :type remote_bind_port: int
        :type remote_bind_address: str
        :type ssh_pkey_file_path: str
        """

        super().__init__(hostname=hostname, username=username,
                         password=password, port=port)
        self.remote_bind_address = remote_bind_address
        self.remote_bind_port = remote_bind_port
        self.ssh_tunnel = None
        self.local_bind_address = None
        self.local_bind_port = None
        self.ssh_pkey_file_path = ssh_pkey_file_path

    def initiate_connection(self, verbose=False):
        """
         initiate_tunnel via ssh (abstract method)
        :param verbose: boolean - for debug purpose
        :return: True/False if tunnel initiated ot not.
        :rtype : bool
        """
        if verbose:
            log_func_details(ssh_address_or_host=self.hostname, ssh_username=self.username,
                             ssh_pkey_file_path=self.ssh_pkey_file_path, remote_bind_address=self.remote_bind_address,
                             remote_bind_port=self.remote_bind_port, verbose=verbose)
        logger.info("start initiating ssh Tunnel between localhost and remote-host: %s " % self.hostname)
        try:
            self.ssh_tunnel = SSHTunnelForwarder(ssh_address_or_host=self.hostname,
                                                 ssh_username=self.username,
                                                 ssh_password=self.password,
                                                 ssh_pkey=self.ssh_pkey_file_path,
                                                 remote_bind_address=(self.remote_bind_address, self.remote_bind_port),
                                                 ssh_port=self.port)
        except Exception as e:
            logger.error("error getting the tunnel connection via SSHTunnelForwarder")
            raise ConnectionError(e)

        logger.info("starting tunnel...")
        self.ssh_tunnel.start()
        logger.info("check if tunnel is active and up after starting tunnel...")
        if (self.ssh_tunnel.tunnel_is_up is not None):
            logger.info("Tunnel is up and ready to go!!!")
            if verbose:
                logger.info("here is tunnel connction details:")
                logger.info("local_bind_address: {0} ".format(self.ssh_tunnel.local_bind_address))
                logger.info("local_bind_host: {0} ".format(self.ssh_tunnel.local_bind_host))
                logger.info("local_bind_port: {0}".format(self.ssh_tunnel.local_bind_port))
                logger.info(
                    "tunnel_is_up: {0}".format(self.ssh_tunnel.tunnel_is_up[self.ssh_tunnel.local_bind_address]))
            self.local_bind_address = self.ssh_tunnel.local_bind_address[0]
            self.local_bind_port = self.ssh_tunnel.local_bind_port
            logger.info("Initiating SSH Tunnel Passed Greatly !!!")
            return True
        return False

    def start_tunnel(self, getting_tunnel_details=False, verbose=False):
        """
        start tunnel
        :param getting_tunnel_details:
        :param verbose
        :return: True/False if tunnel started or not.
        """
        if verbose:
            log_func_details(getting_tunnel_details=getting_tunnel_details)
            logger.info("starting server...")
        self.ssh_tunnel.start()
        logger.info("check if tunnel is active and up after starting tunnel...")
        if (self.ssh_tunnel.tunnel_is_up is not None):
            logger.info("Tunnel is up and ready to go!!!")
            if getting_tunnel_details:
                logger.info("here is tunnel connction details:")
                logger.info("local_bind_address: {0} ".format(self.ssh_tunnel.local_bind_address))
                logger.info("local_bind_host: {0} ".format(self.ssh_tunnel.local_bind_host))
                logger.info("local_bind_port: {0}".format(self.ssh_tunnel.local_bind_port))
                logger.info(
                    "tunnel_is_up: {0}".format(self.ssh_tunnel.tunnel_is_up[self.ssh_tunnel.local_bind_address]))
            self.local_bind_address = self.ssh_tunnel.local_bind_address[0]
            self.local_bind_port = self.ssh_tunnel.local_bind_port
            return True
        else:
            raise Exception("Tunnel not been up after starting server !!!")

    def terminate_connection(self, sleep_before=0, verbose=False):
        """
        terminate ssh tunnnel
        :param sleep_before: time before terminate in sec
        :type sleep_before: int
        :param verbose: to enable or disable debug mode
        :type verbose: bool
        :return:
        """
        import time
        if verbose:
            log_func_details(sleep_before=sleep_before, verbose=verbose)
        time.sleep(sleep_before)
        logger.info("stopping server...")
        self.ssh_tunnel.close()
        logger.info("check if tunnel is in-active and down after stopping tunnel...")
        if self.ssh_tunnel.tunnel_is_up is not {}:
            logger.info("Tunnel has been closed!!")
            return True
        else:
            raise Exception("Tunnel not been down after stopping it !!!")


if __name__ == "__main__":
    from data.database_data import CpcmsDatabase

    logger.info("this aimed to test the ssh tunnel class!!")
    ssh = SSHTunnel(hostname=CpcmsDatabase.TEST_CPCMS_HOST_ADDRESS, username=CpcmsDatabase.SSH_USERNAME,
                    remote_bind_port=CpcmsDatabase.REMOTE_BIND_PORT
                    , remote_bind_address=CpcmsDatabase.REMOTE_BIND_ADDRESS,
                    ssh_pkey_file_path=CpcmsDatabase.QA_SSH_PUBLIC_KEY_PATH)

    ssh.initiate_connection(verbose=True)
    ssh.terminate_connection(verbose=True)
