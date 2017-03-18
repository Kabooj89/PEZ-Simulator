#!/usr/bin/python
"""
Author: Mohammad Kabajah
"""
import sys
import os
import re
import logging
import datetime
import mgmt_utils


class MgmtLogUtils:
    """
    Utility functions for log file operations.
    """

    @staticmethod
    def clearLog(log_file_path, device=None):
        """
        Clear logfile content.
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        mgmt_utils.runCommandStatus("> {log_file_path}".format(**locals()), device=device)

    @staticmethod
    def saveLog(log_file_path, device=None):
        """
        Copy log_file_path to temporary file under /tmp/ directory.
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        """
        timestamp = str(datetime.datetime.now()).replace(" ", "-").replace(":", "-").replace(".", "-")
        bkup_file_path = os.path.join("/tmp/", os.path.basename(log_file_path) + "." + timestamp)
        mgmt_utils.runCommandStatus("cp {log_file_path} {bkup_file_path}".format(**locals()), device=device)

    @staticmethod
    def getLogMessages(regexs, device=None, log_file_path=None, logfile=None, ignoreCase=False):
        """
        Retrieve log events.
        @log_file_path: path to log file.
        @logfile: log file content.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        log_messages = []
        try :
            if not logfile and not log_file_path:
                raise Exception("Neither log_file_path or logfile were found!")
            if not logfile:
                returncode, logfile, _ = mgmt_utils.runCommandStatus("cat {log_file_path}".format(**locals()), device=device, verbose=False)
                if returncode > 0:
                    raise Exception("Failed to read '%s' ( no such file or directory ?! )" % log_file_path)
            add_event = log_messages.append
            if(ignoreCase):
                patterns = [re.compile(regex, re.IGNORECASE) for regex in regexs]
            else:
                patterns = [re.compile(regex) for regex in regexs]
            for line in logfile.splitlines():
                for pattern in patterns :
                    found = pattern.match(line)
                    if found:
                        add_event(found.group(0))
        except Exception, exc:
            logging.info("Failed to get log events : '%s'" % exc)
        return log_messages

    @staticmethod
    def getLogEvents(regexs, device=None, log_file_path=None, logfile=None):
        """
        Retrieve log events.
        @log_file_path: path to log file.
        @logfile: log file content.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        log_events = []
        try :
            regexs = [r'[.]+%s[.]+' % regex.upper() for regex in regexs]
            log_events = MgmtLogUtils.getLogMessages(regexs, device, log_file_path, logfile)
        except Exception, exc:
            logging.info("Failed to get log events : '%s'" % exc)
        return log_events

    @staticmethod
    def getErrors(log_file_path, device=None):
        """
        Get log file errors (both critical and standard errors).
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        return MgmtLogUtils.getLogEvents(["[\w\W]+CRITICAL[\w\W]+", "[\w\W]+ERROR[\w\W]+"], device=device,
                                     log_file_path=log_file_path)

    @staticmethod
    def getWarnings(log_file_path, device=None):
        """
        Get log file warnings.
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        return MgmtLogUtils.getLogEvents(["[\w\W]+WARNING[\w\W]+"], device=device,
                                     log_file_path=log_file_path)

    @staticmethod
    def getCritical(log_file_path, device=None):
        """
        Get log file critical.
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        return MgmtLogUtils.getLogEvents(["[\w\W]+CRITICAL[\w\W]+"], device=device,
                                     log_file_path=log_file_path)

    @staticmethod
    def getInfo(log_file_path, device=None):
        """
        Get log file warnings.
        @log_file_path: path to log file.
        @device: remote device (None if running on localhost).
        @return: version (str).
        """
        return MgmtLogUtils.getLogEvents(["[\w\W]+INFO[\w\W]+"], device=device,
                                     log_file_path=log_file_path)
