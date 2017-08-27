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
        Contains All Utils related to local command _Linux
"""
import subprocess
from utilities.connection_handler.connection import Connection
from utilities.logging_utils import logger, log_func_details


class LocalCommand(Connection):
    class_doc = '''
        *LocalCommand: is class aimed to established connection to local device(Linux)
         with main functionality:
            1- establish_connection (abstract method) - no implementation
            2- terminate_connection (abstract method) - no implementation
            3- run_command
            '''

    def __init__(self):
        super().__init__()
        self.retCode = None
        self.stdout = ''
        self.stderr = ''

    def run_command(self, command, shell=True, pipe=True):
        """

        :param command:
        :param shell:
        :param pipe:
        :return:
        """
        log_func_details(command=command, shell=shell, pipe=pipe)
        logger.info("start running command [{0}] on local machine".format(command))
        command = [command]
        stdout_buff = None
        if pipe:
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=shell)
            while p.poll() is None:
                stdout_buff = p.stdout.read()
                stderr_buff = p.stderr.read()
                if stdout_buff:
                    self.stdout += str(stdout_buff)
                if stderr_buff:
                    self.stderr += str(stderr_buff)

            self.retCode = p.wait()
            stdout_buff = p.stdout.read()
            stderr_buff = p.stderr.read()
            if stdout_buff:
                self.stdout += stdout_buff
            if stderr_buff:
                self.stderr += stderr_buff
        else:
            p = subprocess.Popen(command, shell=shell)
            p.communicate()
            self.retCode = p.returncode
        return self.retCode, self.stdout, self.stderr

    def initiate_connection(self, *args):
        pass

    def terminate_connection(self, *args):
        pass


# for module testing
if __name__ == "__main__":
    local = LocalCommand()
    rc, stdout, stderr = local.run_command(command="ipconfig")
    logger.info("rc : {0}".format(rc))
    logger.info("stdout : {0}".format(stdout))
    logger.info("stderr : {0}".format(stderr))
