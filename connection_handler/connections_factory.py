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
        May 29, 2017
@Purpose: 
        this the factory class which supply different type of connection
        using factory method (get_connection)
         type supported until now:
            1- ssh
            2- telnet
            3- ssh tunnel
            4- sftp
            5- local command
"""

from data.connections_data import ConnectionType
from utilities.logging_utils import log_func_details, logger
from utilities.connection_handler.connection import Connection
from utilities.connection_handler.ssh import SSH
from utilities.connection_handler.telnet import Telnet
from utilities.connection_handler.ssh_tunnel import SSHTunnel
from utilities.connection_handler.sftp import SFTP
from utilities.connection_handler.local_command import LocalCommand


class ConnectionFactory:
    @staticmethod
    def get_connection(connection_type, params, verbose=False):
        """
        factory method to get connection
        :param connection_type: the connection type (look at connection_data->ConnectionType)
        :type connection_type :str
        :param params: params object from type connection_type
        :type params: Params
        :param verbose: True for debug mode/ False for info
        :type verbose: bool
        :return: connection instance
        :rtype: Connection
        """
        if verbose:
            log_func_details(connection_type=connection_type, params=params.get_params_dict())
        logger.debug("[*] in connection factory, trying creating connection from type: {0}...".format(connection_type))
        if connection_type == ConnectionType.SSH:
            connection = SSH(hostname=params.hostname, username=params.username,
                             password=params.password, port=params.port,
                             timeout=params.timeout, retries=params.retries)

        elif connection_type == ConnectionType.TELNET:
            connection = Telnet(hostname=params.hostname, username=params.username,
                                password=params.password, port=params.port)

        elif connection_type == ConnectionType.SSH_TUNNEL:
            connection = SSHTunnel(hostname=params.hostname, username=params.username,
                                   password=params.password, ssh_pkey_file_path=params.ssh_pkey_file_path,
                                   port=params.port,
                                   remote_bind_address=params.remote_bind_address,
                                   remote_bind_port=params.remote_bind_port)

        elif connection_type == ConnectionType.SFTP:
            connection = SFTP(hostname=params.hostname, username=params.username,
                              password=params.password, port=params.port)

        elif connection_type == ConnectionType.LOCAL:
            connection = LocalCommand()

        else:
            logger.error("can't give you what i don't have!!!, Not supported "
                         "connection {0}".format(connection_type))
            raise ValueError("Not supported connection {0}".format(connection_type))

        logger.debug("checking if the new connection follow connection standard...")
        if isinstance(connection, Connection):
            logger.info(
                "the connection {0} is inherited from connection base and follow Connection standard!".format(
                    connection_type))

        else:
            logger.error("requested connection not upon connection requirement "
                         "- not inherited from connection base class")
            raise Exception("return object not inherited from Connection Base")
        logger.info("new instance from {0} was created!".format(connection_type))
        return connection


def ssh_casting(conn):
    """
    :param conn:
    :type conn : Connection
    :return:
    :rtype: SSH
    """
    if isinstance(conn, SSH):
        return conn
    else:
        logger.error("casting error, conn passed is not SSH type")
        raise ValueError("SSH casting error")


def telnet_casting(conn):
    """
    :param conn:
    :type conn : Connection
    :return:
    :rtype: Telnet
    """
    if isinstance(conn, Telnet):
        return conn
    else:
        logger.error("casting error, conn passed is not Telnet type")
        raise ValueError("Telnet casting error")


def sftp_casting(conn):
    """
    :param conn:
    :type conn : Connection
    :return:
    :rtype: SFTP
    """
    if isinstance(conn, SFTP):
        return conn
    else:
        logger.error("casting error, conn passed is not SFTP type")
        raise ValueError("SFTP casting error")


def ssh_tunnel_casting(conn):
    """
    :param conn:
    :type conn : Connection
    :return:
    :rtype: SSHTunnel
    """
    if isinstance(conn, SSHTunnel):
        return conn
    else:
        logger.error("casting error, conn passed is not SSHTunnel type")
        raise ValueError("SSHTunnel casting error")


def local_casting(conn):
    """
    :param conn:
    :type conn : Connection
    :return:
    :rtype: LocalCommand
    """
    if isinstance(conn, LocalCommand):
        return conn
    else:
        logger.error("casting error, conn passed is not LocalCommand type")
        raise ValueError("LocalCommand casting error")


############################################################################
##                          for testing purpose                           ##
############################################################################

def ssh_check():
    from utilities.connection_handler.params_factory import ConnParamsFactory
    ssh_params = ConnParamsFactory.get_params(ConnectionType.SSH, hostname="10.0.0.141",
                                              username="pg", password="q1w2e3r4")
    conn = ConnectionFactory.get_connection(ConnectionType.SSH, ssh_params)
    ssh_conn = ssh_casting(conn)
    ssh_conn.initiate_connection(verbose=True)
    stdin, stdout, stderr, exit_code = ssh_conn.exec_command(command="ls -al", verbose=False)
    logger.info("output is coming")
    logger.info(stdout)
    logger.info(exit_code)
    ssh_conn.terminate_connection(sleep_before=2, verbose=True)


def sftp_check():
    from utilities.connection_handler.params_factory import ConnParamsFactory
    sftp_params = ConnParamsFactory.get_params(ConnectionType.SFTP, hostname="10.0.0.141",
                                               username="pg", password="q1w2e3r4")
    conn = ConnectionFactory.get_connection(ConnectionType.SFTP, sftp_params)
    sftp_conn = sftp_casting(conn)
    sftp_conn.initiate_connection(verbose=True)
    logger.info(sftp_conn.list_dir("/home/pg/"))
    logger.info(sftp_conn.list_dir("/home/pg/"))
    logger.info(sftp_conn.list_dir("/home/pg/"))
    sftp_conn.terminate_connection(verbose=True)


def telnet_check():
    from utilities.connection_handler.params_factory import ConnParamsFactory
    telnet_params = ConnParamsFactory.get_params(ConnectionType.TELNET, hostname="10.0.0.71",
                                                 username="pg", password="q1w2e3r4")
    conn = ConnectionFactory.get_connection(ConnectionType.TELNET, telnet_params)
    telnet_conn = telnet_casting(conn)
    telnet_conn.initiate_connection(verbose=True)
    output = telnet_conn.exec_command(command="netstat")
    telnet_conn.terminate_connection()
    logger.info(output)


def ssh_tunnel_check():
    from data.database_data import CpcmsDatabase
    from utilities.connection_handler.params_factory import ConnParamsFactory
    tunnel_params = ConnParamsFactory.get_params(ConnectionType.SSH_TUNNEL, hostname=CpcmsDatabase.TEST_CPCMS_HOST_ADDRESS,
                                                 username=CpcmsDatabase.SSH_USERNAME,
                                                 ssh_pkey_file_path=CpcmsDatabase.QA_SSH_PUBLIC_KEY_PATH)
    conn = ConnectionFactory.get_connection(ConnectionType.SSH_TUNNEL, tunnel_params)
    ssh_tunnel_conn = ssh_tunnel_casting(conn)
    ssh_tunnel_conn.initiate_connection(verbose=True)
    ssh_tunnel_conn.terminate_connection(verbose=True)


def local_check():
    from utilities.connection_handler.params_factory import ConnParamsFactory
    local_params = ConnParamsFactory.get_params(ConnectionType.LOCAL)
    conn = ConnectionFactory.get_connection(ConnectionType.LOCAL, local_params)
    local_conn = local_casting(conn)
    retCode, stdout, stderr = local_conn.run_command(command="ipconfig")
    logger.info(retCode)
    logger.info(stdout)
    logger.info(stderr)


def main():
    ssh_tunnel_check()


if __name__ == '__main__':
    main()
