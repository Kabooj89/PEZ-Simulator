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
        July 22, 2017
@Purpose:
        this the factory class which supply different type of connection Params
        using factory method (get_params)
         type supported until now:
            1- ssh
            2- telnet
            3- ssh tunnel
            4- sftp
            5- local command
"""

from data.connections_data import SSHConfig, SSHTunnelConfig, TelnetConfig, SFTPConfig
from data.connections_data import ConnectionType
from utilities.logging_utils import log_func_details, logger
from utilities.json_utils import json_print


class ConnParamsFactory:
    @staticmethod
    def get_params(connection_type, hostname=None, username=None, password=None,
                   port=None, ssh_pkey_file_path=None,verbose=False):
        """
        factory method to generate params object reltaed to connection type.
        :param connection_type: the connection type between (ssh,sftp,telnet,tunnel,local ...etc)
        :param hostname: the hostname param
        :param username: username for connection
        :param password: password for connection
        :param ssh_pkey_file_path : pem file for some cases
        :param verbose: True for debug/ False for info
        :return: params object related to connection type
        :type connection_type: str
        :type ssh_pkey_file_path: str
        :type hostname: str
        :type username: str
        :type password: str
        :type verbose: bool
        :return params object from type connection_type
        :rtype Params
        """

        log_func_details(connection_type=connection_type, hostname=hostname,
                         username=username, password=password)
        logger.info("[*] creating connection params object from "
                    "type: {0}...".format(connection_type))
        if connection_type == ConnectionType.SSH:
            params_instance = SSHParams(hostname=hostname, username=username, password=password)

        elif connection_type == ConnectionType.TELNET:
            params_instance = TelnetParams(hostname=hostname, username=username, password=password)

        elif connection_type == ConnectionType.SSH_TUNNEL:
            params_instance = SSHTunnelParams(hostname=hostname, username=username, password=password,
                                              port=port, ssh_pkey_file_path=ssh_pkey_file_path)

        elif connection_type == ConnectionType.SFTP:
            params_instance = SFTPParams(hostname=hostname, username=username, password=password)

        elif connection_type == ConnectionType.LOCAL:
            params_instance = LocalConnParam(hostname=hostname, username=username, password=password)

        else:
            logger.error("can't give you what i don't have!!!, Not supported "
                         "connection params {0}".format(connection_type))
            raise ValueError("Not supported connection params {0}".format(connection_type))

        logger.info("checking if the new connection params follow connection Params standard...")
        if isinstance(params_instance, Params):
            logger.info(
                "the connection params {0} is inherited from connection Params base and "
                "follow Connection Params standard!".format(connection_type))

        else:
            logger.error("requested connection params not upon Params requirement "
                         "- not inherited from Params base class")
            raise Exception("return object not inherited from Params Base")
        logger.info("new instance from {0} Params was created!".format(connection_type))
        return params_instance


class Params:
    def __init__(self, hostname, username, password,
                 port=None, retries=1, timeout=30):
        """
        initiate the params base parameters
        :param hostname: the hostname for the connection
        :param username: the username for the connection
        :param password: the password for the connection
        :param port: the hostname for the connection
        :param retries: time to retry connect before raise exception
        :param timeout: te to wait before raise timeout exception, in sec.
        :type hostname: str
        :type username: str
        :type password: str
        :type port: int
        :type retries: int
        :type timeout: int
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.retries = retries
        self.port = port
        self.timeout = timeout

    def get_params_dict(self, verbose=False):
        params_instance = self.__dict__
        if verbose:
            logger.debug("the params object contains the following params:")
            json_print(params_instance)
        return params_instance


class SSHParams(Params):
    def __init__(self, hostname, username, password):
        super().__init__(hostname, username, password,
                         port=SSHConfig.PORT, retries=3,
                         timeout=SSHConfig.TIMEOUT)


class TelnetParams(Params):
    def __init__(self, hostname, username, password):
        super().__init__(hostname, username, password,
                         port=TelnetConfig.PORT,
                         timeout=TelnetConfig.TIMEOUT)


class SSHTunnelParams(Params):
    def __init__(self, hostname, username, password, port, ssh_pkey_file_path,
                 remote_bind_port=SSHTunnelConfig.REMOTE_BIND_PORT,
                 remote_bind_address=SSHTunnelConfig.REMOTE_BIND_ADDRESS):
        super().__init__(hostname=hostname, username=username,
                         password=password, port=port)
        self.remote_bind_port = remote_bind_port
        self.remote_bind_address = remote_bind_address
        self.ssh_pkey_file_path = ssh_pkey_file_path
        self.local_bind_address = None
        self.local_bind_port = None
        self.ssh_host_key = None,
        self.ssh_private_key_password = None,
        self.ssh_proxy = None,
        self.ssh_proxy_enabled = True,
        self.mute_exceptions = False


class SFTPParams(Params):
    def __init__(self, hostname, username, password):
        super().__init__(hostname, username, password,
                         port=SFTPConfig.PORT,
                         timeout=SFTPConfig.TIMEOUT)


class LocalConnParam(Params):
    def __init__(self, hostname, username, password):
        super().__init__(hostname, username, password)


if __name__ == "__main__":
    from utilities.connection_handler.connections_factory import ConnectionFactory, ssh_casting

    ssh_params = ConnParamsFactory.get_params("ssh", hostname="10.0.0.131", username="pg", password="q1w2e3r4")
    ssh_params.get_params_dict(verbose=True)
    conn = ConnectionFactory.get_connection("ssh", ssh_params)
    ssh_conn = ssh_casting(conn)
    ssh_conn.initiate_connection(verbose=True)
    ssh_conn.exec_command(command="ls -al")
    ssh_conn.terminate_connection(verbose=True)
