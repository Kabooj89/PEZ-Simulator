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
        Base Connection constructor
"""
from abc import ABC, abstractmethod
from data.connections_data import DOCUMENTATION


class Connection(ABC):
    def __new__(cls, *args, **kargs):
        """
        :param args:
        :param kargs:
        :return:
        """
        if not hasattr(cls, "class_doc"):
            raise NotImplementedError("'Connection' subclasses should have a 'class_doc' attribute, "
                                      "class_doc include description about the class and the main features!"
                                      "look at the following template :\n {0}".format(DOCUMENTATION.CLASS_DOC_TEMPLATE))
        return object.__new__(cls)

    def __init__(self, hostname=None, username=None, password=None,
                 port=None, timeout=30, retries=1):
        """
        :param hostname: the ip for connection destination
        :param username: the username to be used for connection
        :param password: the password to be used for connection
        :param port: the port to be used for connection
        :param timeout: the timeout trying connection before raise exception Timeout
        :param retries: number of connection tries before throw exception
        :type hostname: str
        :type username: str
        :type password: str
        :type port: int
        :type timeout: int
        :type retries: int
        """

        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._client = None  # the connection instance

    @abstractmethod
    def initiate_connection(self, verbose):
        """
        abstract method to enforce inherited classes to implement it
        :param verbose: to enable or disable debug mode
        :type verbose: bool
        :return: None
        """
        pass

    @abstractmethod
    def terminate_connection(self, sleep_before, verbose):
        """
        abstract method to enforce inherited classes to implement it
        :param sleep_before: time before terminate in sec
        :type sleep_before: int
        :param verbose: to enable or disable debug mode
        :type verbose: bool
        :return:
        """
        pass
