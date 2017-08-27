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
        June 11, 2017
@Purpose:
        Contains All Utils related to connection API
"""
import os
import subprocess
from utilities.connection_handler.connections_factory import ConnectionFactory, ssh_casting
from utilities.connection_handler.params_factory import ConnParamsFactory
from utilities.logging_utils import logger, log_func_details
from data.connections_data import ConnectionType, SSHCredentials


def run_command_via_ssh(command, device=None, verbose=False):
    """
    running command using default credentials, Run Shell command
    on local or remote device Return command exit code.
    :param device:  None if Local , String if remote
    :param verbose:  true for debug mode , False for info
    :param command: command string
    :type command: str
    :type device: str
    :type verbose: bool
    :return: return code
    :rtype: int
    :TODO adding more than try statement to try multiple scenarios from username/pass
    """

    if verbose:
        log_func_details(command=command, device=device, verbose=verbose)
    if device is not None:
        try:
            logger.debug("< Device: %s > runCommand : %s" % (device, command))
            logger.debug("trying connection using the using default <pg,q1w2e3r4>....")
            ssh_params = ConnParamsFactory.get_params(ConnectionType.SSH, hostname=device,
                                                      username=SSHCredentials.PG_USERNAME,
                                                      password=SSHCredentials.PG_PASSWORD)
            ssh_params.get_params_dict(True)
            conn = ConnectionFactory.get_connection(ConnectionType.SSH, ssh_params)
            ssh_conn = ssh_casting(conn)
            ssh_conn.initiate_connection(verbose=True)
            _, _, _, rc = ssh_conn.exec_command(command=command)
            logger.info("run command passed successfully!!")
            conn.terminate_connection()
            logger.info("connection closed!")
        except Exception as e:
            raise Exception("Error running command: {0}".format(e))
        return rc

    else:
        if verbose:
            logger.info("runCommand : " + str(command))
        with open(os.devnull, 'w') as tempf:
            proc = subprocess.Popen(command, shell=True,
                                    stdout=tempf, stderr=tempf)
            proc.communicate()
            return proc.returncode


def run_command_status_via_ssh(command, device=None, verbose=False):
    """
    Run Shell command on local or remote device
    Return command rc, stdout, stderr.
    :param device:  None if Local , String if remote
    :param verbose:  true for debug mode , False for info
    :param command: command string
    :type command: str
    :type device: str
    :type verbose: bool
    :return: rc, stdout, stderr
    :rtype: tuple
    """
    if verbose:
        log_func_details(command=command, device=device, verbose=verbose)
    if device is not None:
        if verbose:
            logger.info("runCommandStatus (%s) : %s" % (device, command))
        try:
            logger.info("trying connection using the using default <pg,q1w2e3r4>....")
            ssh_params = ConnParamsFactory.get_params(ConnectionType.SSH, hostname=device,
                                                      username=SSHCredentials.PG_USERNAME,
                                                      password=SSHCredentials.PG_PASSWORD)
            if verbose:
                ssh_params.get_params_dict(True)
            conn = ConnectionFactory.get_connection(ConnectionType.SSH, ssh_params)
            ssh_conn = ssh_casting(conn)
            ssh_conn.initiate_connection(verbose=verbose)
            _, stdout, stderr, return_code = ssh_conn.exec_command(command=command,
                                                                   verbose=verbose)
            logger.info("run command passed successfully!!")
            conn.terminate_connection(verbose=verbose)
            logger.info("connection closed!")
        except Exception as e:
            raise Exception("Error running command status: {0}".format(e))

        return return_code, stdout, stderr

    else:
        if verbose:
            logger.info("runCommandStatus : " + str(command))
        proc = subprocess.Popen(command, shell=True, close_fds=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if verbose:
            logger.info("rc: " + str(proc.returncode))
            logger.info("stdout: " + str(stdout).strip())
            if str(stderr.strip()) != '':
                logger.info("stderr: " + str(stderr).strip())
        return proc.returncode, str(stdout).strip(), str(stderr).strip()


def run_uninterruptible_command(command, device=None, verbose=False):
    """
    Use nohup command to run another uninterruptible command in background that
    can't be terminated if its session was closed or terminated.
    :param command: command to execute
    :param device: None if Local , String if remote
    :param verbose: true for debug mode , False for info
    :type command: str
    :type device: str
    :type verbose: bool
    :return: rc, stdout, stderr
    :rtype: tuple
    """
    if verbose:
        log_func_details(command=command, device=device)
    command = 'nohup sh -c "' + command + '" > /dev/null 2>&1 &'
    return run_command_status_via_ssh(command, device)


#######################
# for testing purpose #
#######################
if __name__ == "__main__":
    rc = run_command_via_ssh(device="10.0.0.131", command="ls -al", verbose=False)
    logger.info(rc)
    rc, stdout, stderr = run_command_status_via_ssh(device="10.0.0.131", command="sudo ifconfig", verbose=False)
    logger.info("rc = {0}".format(rc))
    logger.info("stdout = {0}".format(stdout))
    logger.info("stderr = {0}".format(stderr))
