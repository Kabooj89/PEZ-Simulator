#!/usr/bin/python
"""

Summary
=====================
Useful utilities for X environment (regression).

Author: Mohammad Kabajah
Date: 13 April 2016

"""
import difflib
import datetime
import logging
import os
import sys
import socket
import time
import warnings
import inspect
import json
import re
import requests

import utilities.connection_handler.connections as connect_utils
#from progressbar import ProgressBar
from collections import Iterable
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import paramiko

try:
    from lxml import etree
except ImportError:
    pass

def JsonPrint(JsonDic):
    """
    print any json object in good well format.

    Parameters
    ----------
    JsonDic : any Json Dict or list

    Returns
    -------
        no return just print
    """
    print(json.dumps(JsonDic, indent=2))

def log_func_details(**kwargs):
    print("-" * 50)
    func = inspect.currentframe().f_back.f_code
    print("Function name: " + func.co_name)
    print("kwargs: " + str(kwargs))


def log_separator():
    logging.info("-" * 50)


def isLocalHost(device, verbose=False):
    if verbose:
        logging.info("Checking if device %s is local host" % device)
    if device == None:
        return True
    if ("127" in str(device)):
        return True
    try:
        localhost_ip = socket.gethostbyaddr(socket.gethostname())[2]
        device_ip = socket.gethostbyaddr(device)[2]
        if device_ip == localhost_ip:
            if verbose:
                logging.info("Device %s is local host" % device)
            return True
        else:
            if verbose:
                logging.info("Device %s is not local host" % device)
            return False
    except Exception as exc:
        logging.info("Failed to get device %s ip. running local" % device)
        return False


def getListOfDownDevices(devices_ip):
    """
    Check if devices (I.E: Hosts) are alive
    Return list of devices that are not alive
    """
    log_func_details(devices_ip=devices_ip)
    devices_down_list = []
    for device in devices_ip:
        if isDeviceAlive(device) == False:
            devices_down_list.append(device)
    return devices_down_list


def isDeviceAlive(device_ip):
    """
    Check if device (I.E: Host) is alive
    Return True if alive otherwise False
    """
    try:
        logging.info("Validate %s response on port 22" % device_ip)
        socket.create_connection((device_ip, 22), timeout=15)
    except Exception as exc:
        logging.info(
            "Connection to %s failed. Exception details: %s" % (device_ip, str(exc)))
        return False
    return True


def isFileExist(file_name, device=None,user="root", key="lab123"):
    log_func_details(file_name=file_name, device=device)
    if not device:
        if os.path.exists(file_name):
            logging.info("File exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("File doesn't exist")
            logging.info("-" * 50)
            return False
    else:
        _, std_out, stderr, rc = connect_utils.ssh_cmd_full_output(ip=device,user=user, key=key,cmd="ls " + file_name)
        if rc == 0:
            logging.info("File exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("File doesn't exist")
            logging.info("-" * 50)
            return False

def sendFileUsingSsh(device,username,password,localpath,remotepath):
    '''
    @param device: device ip (Type: str ex:"10.0.14.156") where to send the file
    @param username: username to access the machine
    @param password: password to access the machine
    @param localpath: the source path for the file
    @param remotepath: the destination path to copy the file on the remote machine.
    @return: Boolean if the file send successfully or not.
    '''

    log_func_details(device=device,username=username,password=password,localpath=localpath,remotepath=remotepath)
    print("start sending the file %s using ssh to device %s "%(localpath,device))
    ssh = paramiko.SSHClient()
    #ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device, username=username, password=password)
    sftp = ssh.open_sftp()
    sftp.put(localpath, remotepath)
    sftp.close()
    ssh.close()
    if isFileExist(file_name=remotepath,device=None):
        print("file is transfered to the remote server successfully!!")
        return True
    else:
        return False


def isFolderExist(folder_name, device=None,user="root", key="lab123"):
    log_func_details(folder_name=folder_name, device=device)
    if not device:
        if os.path.exists(folder_name):
            logging.info("Folder exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("Folder doesn't exist")
            logging.info("-" * 50)
            return False
    else:
        _, output, stderr, rc = connect_utils.ssh_cmd_full_output(ip=device, user=user, key=key, cmd="test -d " + folder_name)
        if rc == 0:
            logging.info("Folder exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("Folder doesn't exist")
            logging.info("-" * 50)
            return False


def listFilesByPrefix(folder, prefix, device=None,user="root", key="lab123"):
    log_func_details(folder=folder, prefix=prefix, device=device)
    files_list = []
    if not device:
        for file in os.listdir(folder):
            if file.startswith(prefix):
                files_list.append(file)
    else:
        find_cmd = 'find %s -name  %s*' % (folder, prefix)
        _, output, stderr, rc = connect_utils.ssh_cmd_full_output(ip=device,user=user, key=key,cmd=find_cmd)

        files_list = output.split("\n")

    logging.info("files_list: " + str(files_list))
    return files_list


def removeFile(file_path, device=None,user="root", key="lab123"):
    """
    Remove a file or directory from a server
    """
    command = "rm -rf " + file_path
    _, output, stderr, rc = connect_utils.ssh_cmd_full_output(ip=device, user=user, key=key, cmd=command)



def sleep_with_progress(sleep_time):
    print("Wait " + str(sleep_time))
    bounce = 1
    if sleep_time > 10:
        bounce = sleep_time / 10
    while sleep_time > 0:
        sys.stdout.write("\r%d" % sleep_time)
        sys.stdout.flush()
        time.sleep(bounce)
        sleep_time = sleep_time - bounce


def sleep(sleep_time, with_progress=False):
    """
    Sleep.
    """
    logging.info("Waiting %d seconds" % sleep_time)
    if with_progress:
        pbar = ProgressBar(sleep_time)
        for i in range(sleep_time):
            pbar.update(i)
            time.sleep(1)
    else:
        time.sleep(sleep_time)



def isSSHUp(host, port):
    """
    Establish SSH.
    """
    up = True
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout = 5
        sk.settimeout(timeout)
        sk.connect((host, port))
        sk.close()
    except Exception:
        up = False
        if(sk is not None):
            sk.close()
    return up


def readJson(message, message_type):
    """
    Reading Any Json object which located in (file / string) and putting it in dictionary after make utf-8 encode on all the field recursively.

    Parameters
    ----------
    Message : Any json Object located in (file, string)

    message_Type : where the json object located ( 2 Option supported
                1- 'file'     2 - 'str'    3-'dict'

    Returns
    -------
        A dictionary with the json object in utf-8 format


    Examples On File:
    -----------------
    JsonDict=ReadJson('sample.json','file')

    Examples On String:
    ------------------

    JsonString='''{
    "glossary": {
        "title": "example glossary",
        "GlossDiv": {
            "title": "S",
            "GlossList": {
                "GlossEntry": {
                    "ID": "SGML",
                    "SortAs": "SGML",
                    "GlossTerm": "Standard Generalized Markup Language",
                    "Acronym": "SGML",
                    "Abbrev": "ISO 8879:1986",
                    "GlossDef": {
                        "para": "A meta-markup language, used to create markup languages such as DocBook.",
                        "GlossSeeAlso": ["GML", "XML"]
                    },
                    "GlossSee": "markup"}}}}}'''

        JsonDict=ReadJson(JsonString,'str')

    @author:
        Mohammad Kabajah
    @Contact:
        mkabajah@asaltech.com

    @todo: Support Remote Files, Read Remote Files from Server
    """
    if (message_type.lower() == 'str'):
        try:
            json_object = json.loads(message)
        except ValueError as e:
            raise Exception("ERROR Not Valid Json String")
        else:
            return _decodeDict(json_object)

    elif (message_type.lower() == 'file'):
        try:
            fp = open(message, 'r')
        except IOError as e:
            raise Exception("ERROR the file is containing Invalid Json Object")
        else:
            json_object = json.load(fp)
            fp.close()
            return _decodeDict(json_object)

    elif (message_type.lower() == 'dict'):
        return _decodeDict(message)
    else:
        return None


def _decodeList(data):
    '''
    Reading List  object to convert the data  utf-8 format and pass the other list or dictionary inside it recursively.

    Parameters
    ----------
    data : list object wich may contain field or lists or dictionary.

    '''
    decoded_data = []
    for item in data:
        if isinstance(item, bytes):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decodeList(item)
        elif isinstance(item, dict):
            item = _decodeDict(item)
        decoded_data.append(item)
    return decoded_data


def _decodeDict(data):
    '''
    Reading dictionary  object to convert the data (key,value) to  utf-8 format and pass the other list or dictionary inside it recursively.

    Parameters
    ----------
    data : dictionary object wich may contain field or lists or dictionary.
    '''
    decoded_data = {}
    for key, value in data.items():
        if isinstance(key, bytes):
            key = key.encode('utf-8')
        if isinstance(value, bytes):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decodeList(value)
        elif isinstance(value, dict):
            value = _decodeDict(value)
        decoded_data[key] = value
    return decoded_data


def install_distro_from_ipmi(ipmi_address, device_name,
                             distro=mgmt_constants.DISTRO.CENTOS,
                             major_version="6", minor_version="4",
                             user="lioros"):

    log_func_details(ipmi_address=ipmi_address,
                     device_name=device_name, distro=distro,
                     major_version=major_version,
                     minor_version=minor_version, user=user)
    curl_cmd = '''curl -s "http://l-coreslave/autoinst.dev/''' + \
        '''doInstall.pl?os=''' + distro + \
        '''&major=''' + major_version + '''&minor=''' + \
        minor_version + '''&arch=x86_64&partitioning=''' + \
        '''multi-new&featXxOFED=+&portal_user=''' + \
        user + '''&user=root&ipmi=''' + ipmi_address + \
        + '''&machine=''' + device_name + \
        '''&osGroup=Linuxes&instType=+multi-new"'''

    runCommand(curl_cmd)

def addConfigurationValue(section, key, value,
                          configuration_file, device=None):

    try:
        cmd = (r"sed -e 's/\(\[%s\]\)/\1\n%s=%s/' -i %s" %
               (section, key,
                value,
                configuration_file
                )
               )
        return runCommand(cmd, device, verbose=False)
    except Exception:
        logging.error("Exception in setGvCfg : ")

def setConfigurationValue(section, key, value,
                          configuration_file, device=None):
    """
    Set configuration value
    """
    try:
        cmd = (r"sed -i -e '/^\[%s\]/,/^\[.*\]/ s|^\(%s[ \t]*=[ \t]*\).*$|\1%s|'  %s" %
               (section, key,
                value,
                configuration_file
                )
               )
        return runCommand(cmd, device, verbose=False)
    except Exception:
        logging.error("Exception in setGvCfg : %s")


def get_base_distro(device=None):
    """
    get_base_distro redhat / suse (For example, oel will return redhat)
    """
    _, base_distro, _ = runCommandStatus(mgmt_constants.DISTRO.
                                         GET_BASE_DISTRO_CMD, device)
    return base_distro.strip().strip("\n")


def is_rpm_installed(rpm_name, device=None):
    log_func_details(rpm_name=rpm_name, device=device)
    command = "rpm -qa | grep " + rpm_name
    rpm_exists = False
    if runCommand(command, device) == 0:
        rpm_exists = True
    logging.info("rpm_exists: " + str(rpm_exists))
    return rpm_exists


def isFileExist(file_name, device=None):
    log_func_details(file_name=file_name, device=device)
    if not device:
        if os.path.exists(file_name):
            logging.info("File exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("File doesn't exist")
            logging.info("-" * 50)
            return False
    else:
        rc = runCommand("ls " + file_name, device)
        if rc == 0:
            logging.info("File exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("File doesn't exist")
            logging.info("-" * 50)
            return False


def isFolderExist(folder_name, device=None):
    log_func_details(folder_name=folder_name, device=device)
    if not device:
        if os.path.exists(folder_name):
            logging.info("Folder exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("Folder doesn't exist")
            logging.info("-" * 50)
            return False
    else:
        rc = runCommand("test -d " + folder_name, device)
        if rc == 0:
            logging.info("Folder exists")
            logging.info("-" * 50)
            return True
        else:
            logging.info("Folder doesn't exist")
            logging.info("-" * 50)
            return False


def listFilesByPrefix(folder, prefix, device=None):
    log_func_details(folder=folder, prefix=prefix, device=device)
    files_list = []
    if not device:
        for file in os.listdir(folder):
            if file.startswith(prefix):
                files_list.append(file)
    else:
        find_cmd = 'find %s -name  %s*' % (folder, prefix)
        _, output, _ = runCommandStatus(find_cmd, device)
        files_list = output.split("\n")

    logging.info("files_list: " + str(files_list))
    return files_list


def get_configuration_value(section, key, configuration_file, device=None):
    """
    Get configuration value
    """
    try:
        command = ''' awk -v s="[%s]" -v k=%s -v v=$value '{ FS="="; line=$0; if (substr($1,1,1) == "[") {section=$1}; if (section==s) {key=$1; value=$2; gsub(/[[:space:]]*/,"",key); if(key==k) {print value; exit}}}' %s | tr -d ' ' ''' % (
            section, key, configuration_file)
        _, stdout, _ = runCommandStatus(command, device)
        return stdout.strip()
    except Exception, exc:
        logging.error(
            "get_configuration_value threw unhandled exception %s" % exc)


def killProcByName(proc_name, exclude_proc=None, kill_flag="-9", device=None):
    log_func_details(proc_name=proc_name, device=device)
    proc_ids_cmd = "ps -efw | grep '" + proc_name + "'  | grep -v grep "
    if exclude_proc:
        proc_ids_cmd += " | grep -v " + exclude_proc
    proc_ids_cmd += " | awk '{print $2}'"
    _, stdout, _ = runCommandStatus(proc_ids_cmd, device)
    for proc_id in stdout.split("\n"):
        if proc_id != '':
            runCommand("kill " + kill_flag + " " + proc_id, device)
    # Validate proc is down
    if kill_flag == "-9":
        _, stdout, _ = runCommandStatus(proc_ids_cmd, device)
        if stdout == '':
            logging.info("Success. Process " + proc_name + " isn't running")
        else:
            raise Exception("Error. Process " + proc_name +
                            " is running: " + stdout)


def removeFile(file_path, device=None):
    """
    Remove a file or directory from a server
    """
    command = "rm -rf " + file_path
    runCommand(command, device, verbose=False)


def runSshPassCmd(cmd, server, user, password, output=False):
    '''
    this method uses sshpass to run commands
    '''
    cmd_all = "sshpass -p %s ssh -o StrictHostKeyChecking=no %s@%s %s " % \
              (password, user, server, cmd)
    if output:
        rc, stdout, stderr = runCommandStatus(cmd_all)
        return (rc, stdout, stderr)
    else:
        rc = runCommand(cmd_all)
        return rc


def runSshPassScpCmd(password, src, dest, output=False, is_folder=False):
    cmd = "sshpass -p '%s' scp " % password
    if is_folder:
        cmd += " -r"
    cmd += " -o StrictHostKeyChecking=no %s %s" % \
        (src, dest)
    if output:
        rc, stdout, stderr = runCommandStatus(cmd)
        return (rc, stdout, stderr)
    else:
        rc = runCommand(cmd)
        return rc


def runUninterruptibleCommand(command, device=None):
    """
    Use nohup command to run another uninterruptible command in background that
    can't be terminated if its session was closed or terminated.
    """
    log_func_details(command=command, device=device)
    command = 'nohup sh -c "' + command + '" > /dev/null 2>&1 &'
    return runCommandStatus(command, device)


def killProcByNameWithPidofSearch(proc_name, kill_flag="-9", device=None):
    """
    Get pid of proc using pidof command,
    then send to it kill signal using kill commands.

    The justification to use pidof instead of ps for search is
    that ps sometimes shows irrelevent processes in search result,
    but pidof gives very specific result.
    """
    log_func_details(proc_name=proc_name, device=device)
    command = "kill " + kill_flag + " `pidof " + proc_name + "`"
    runCommandStatus(command, device)

    # Validate proc is down
    if kill_flag == "-9":
        command = "pdiof " + proc_name
        _, stdout, _ = runCommandStatus(command, device)
        if stdout == '':
            logging.info("Success. Process " + proc_name + " isn't running")
        else:
            raise Exception("Error. Process " + proc_name +
                            " is running: " + stdout)


def isProcRunning(proc_name, device=None):
    log_func_details(proc_name=proc_name, device=device)
    ret = True
    proc_ids_cmd = "ps -efw | grep '" + proc_name + \
        "'  | grep -v grep | awk '{print $2}'"
    _, stdout, _ = runCommandStatus(proc_ids_cmd, device)
    if stdout == '':
        logging.info("Process " + proc_name + " isn't running")
        ret = False
    else:
        logging.info("Process " + proc_name +
                     " is running. proc_id(s): " + stdout)
    log_separator()
    return ret


def getProcID(proc_name, device=None):
    log_func_details(proc_name=proc_name, device=device)
    ret = True
    proc_ids_cmd = "ps -efw | grep '" + proc_name + \
        "'  | grep -v grep | awk '{print $2}'"
    _, stdout, _ = runCommandStatus(proc_ids_cmd, device)
    return stdout


def isVM(device=None):
    log_func_details(device=device)
    ret = True
    _, stdout, _ = runCommandStatus("dmesg | grep -i kvm", device)
    if stdout == '':
        logging.info("Device is not a VM")
        ret = False
    else:
        logging.info("Device is a VM")
    log_separator()
    return ret


def isCoverageMode():
    if os.path.isfile(mgmt_constants.COVERAGE.COVERAGE_FLAG):
        t = os.path.getmtime(mgmt_constants.COVERAGE.COVERAGE_FLAG)
        if str(datetime.datetime.fromtimestamp(t)).split(" ")[0] == \
                str(datetime.datetime.now()).split(" ")[0]:
            logging.info("*" * 50)
            logging.info("Running in coverage mode")
            logging.info("*" * 50)
            return True
    return False


def remove_rpms(rpms_list):
    logging.info("remove_rpms: " + str(rpms_list))
    for rpm_name in rpms_list:
        if not os.system("rpm -qa | grep " + rpm_name):
            rc = os.system("rpm -e  " + rpm_name)
            if rc:
                logging.error("Failed to remove RPM: " + rpm_name)
            else:
                logging.info("Removed rpm " + rpm_name)
        else:
            logging.info("No need to remove RPM " +
                         rpm_name + " . It does not exist")


def force_remove_rpms(rpms_list, device=None):
    logging.info("force_remove_rpms: " + str(rpms_list))
    for rpm_name in rpms_list:
        command = "rpm -qa " + rpm_name
        _, stdout, _ = runCommandStatus(command, device)
        rpm_exists = rpm_name in stdout
        if rpm_exists:
            command = "rpm -e --nodeps " + rpm_name
            rc = runCommand(command, device)
            if rc:
                logging.error("Failed to remove RPM: " + rpm_name)
            else:
                logging.info("Removed rpm " + rpm_name)
        else:
            logging.info("No need to remove RPM " +
                         rpm_name + " . It does not exist")


def install_rpms(rpms_list, device=None):
    logging.info("install_rpms: " + str(rpms_list))
    for rpm_name in rpms_list:
        command = "rpm -qa " + rpm_name
        _, stdout, _ = runCommandStatus(command, device)
        rpm_exists = rpm_name in stdout
        if not rpm_exists:
            command = "yes | yum install " + rpm_name
            rc = runCommand(command, device)
            if rc:
                logging.error("Failed to install RPM: " + rpm_name)
            else:
                logging.info("Installed rpm " + rpm_name)
        else:
            logging.info("No need to install RPM " +
                         rpm_name + " . It exists")


def keepLastfolders(parent_folder, number_of_sub_folders=10):
    """
    Keep only the last number_of_sub_folders in a parent_folder.
    """
    try:
        log_func_details(
            parent_folder=parent_folder, number_of_sub_folders=number_of_sub_folders)
        logging.info("Keeping the last %d subfolders in parent_folder '%s'" %
                     (number_of_sub_folders, parent_folder))
        dir_list = []
        for entry in os.listdir(parent_folder):
            if os.path.isdir(os.path.join(parent_folder, entry)):
                dir_list.append(entry)
        dir_list.sort()

        for entry in dir_list[:-number_of_sub_folders]:
            full_dir_name = os.path.join(parent_folder, entry)
            logging.info("Removing : '%s'" % full_dir_name)
            command = "rm -rf {full_dir_name}".format(**locals())
            runCommand(command)

    except Exception:
        logging.error("Failed on  keepLastfolders:")

    logging.info("-" * 50)


def set_date_to_ntp(device=None):
    logging.info("Set to ntp time")
    logging.info("Kill ntp process")
    killProcByName("ntp", device=device)
    distro = get_base_distro(device=device)
    if 'RH' in distro:
        runCommand(
            "ntpdate  ntp.labs.mlnx; service ntpd restart", device=device)
    if 'SLES' in distro:
        runCommand("/usr/sbin/sntp -P no -r ntp.labs.mlnx", device=device)
    logging.info("date: " + commands.getstatusoutput("date")[1])


def search_log(log_name, search_pattern, start_time=None, end_time=None):
    logging.info("search_log")
    logging.info("log_name: " + log_name)
    logging.info("search_pattern: " + search_pattern)
    logging.info("start_time: " + str(start_time))
    logging.info("end_time: " + str(end_time))
    if not start_time:
        start_time = datetime.datetime.now()
        logging.info("setting default start_time: " + str(start_time))
    if not end_time:
        end_time = datetime.datetime.strptime("2034-02-13 09:07:52",
                                              "%Y-%m-%d %H:%M:%S")
        logging.info("setting default end_time: " + str(end_time))
    count = 0
    f = open(log_name)
    for line in f.readlines():
        # search only lines of format year-month-day ...
        date_pattern = re.compile('(\d*-\d*-\d* )(.*)')
        if date_pattern.match(line):
            line_time = line.split(" ")[0] + " " + line.split(" ")[1]
            cur_line_date = datetime.datetime.strptime(line_time,
                                                       "%Y-%m-%d %H:%M:%S")
            if cur_line_date >= start_time and cur_line_date <= end_time:
                if search_pattern in line:
                    logging.info("Found pattern in line: " + line)
                    count += 1

    logging.info("Found " + str(count) + " instances")
    return count


def sleep_with_progress(sleep_time):
    logging.info("Wait " + str(sleep_time))
    bounce = 1
    if sleep_time > 10:
        bounce = sleep_time / 10
    while sleep_time > 0:
        sys.stdout.write("\r%d" % sleep_time)
        sys.stdout.flush()
        time.sleep(bounce)
        sleep_time = sleep_time - bounce


def reboot_with_startup_wait(device, timeOut=500):
    """
    This method is used to rboot linux server and wait for recover.

    """
    try:
        logging.info("=" * 100)
        logging.info("reboot_with_startup_wait")
        logging.info("device: " + device)
        rc = runCommand("reboot", device)
        if rc > 0:
            raise Exception("Failed to send reboot to device: " + device)

        logging.info("Waiting for reboot process to start")
        reboot_started = False
        for _ in range(40):
            if mgmt_ping.do_one(device):
                time.sleep(3)
            else:
                reboot_started = True
                break
        if not reboot_started:
            raise Exception("Device is still active althoguh reboot " +
                            "command was sent. device: " + device)

        logging.info("Reboot was started. Waiting 3 minutes")
        sleep_with_progress(180)
        logging.info("3 minutes passed. Start pinging system until it " +
                     "comes up. Wait up to: " + str(timeOut - 180))
        num_of_ping_loops = (timeOut - 180) / 10
        machine_back_up = False
        for _ in range(num_of_ping_loops):
            if mgmt_ping.do_one(device):
                machine_back_up = True
                break
            else:
                time.sleep(10)

        if not machine_back_up:
            raise Exception(
                "Device is still down althoguh timeout has passed. device: " + device)

        else:
            logging.info(
                'Success. System is up. Waiting for full recovery (2 minutes).')
            sleep_with_progress(120)
            logging.info("=" * 100)

    except Exception, exc:
        raise exc


def install_base_image_using_cli(switch_ip, base_image_suffix):
    logging.info("=" * 50)
    logging.info("install_base_image_using_cli")
    base_image_file = None
    for file_path in os.listdir(BASE_IMAGES_FOLDER):
        if file_path.endswith(base_image_suffix + ".img"):
            logging.info("Found image: " + file_path)
            base_image_file = mgmt_constants.BASE_IMAGES_FOLDER + \
                "/" + file_path
    if not base_image_file:
        raise Exception(
            "Failed to find base image file with suffix: " + base_image_suffix)
    logging.info("Installing " + base_image_file + " on switch " + switch_ip)
    local_ip = socket.gethostbyname(socket.gethostname())
    logging.info("local_ip : " + local_ip)
    logging.info("switch.ip: " + switch_ip)
    conn = SSHSwitch(switch_ip)
    fetch_cmd = "image fetch scp://" + mgmt_constants.FTP_USER_NAME + ":" + \
        mgmt_constants.FTP_PASSWORD + "@" + local_ip + ":" + base_image_file
    conn.send_cmd(fetch_cmd)
    fetch_completed = False
    for _ in range(180):
        output = conn.send_cmd('show images')
        if "image-PPC_M460EX-SX" in output:
            fetch_completed = True
            break
        else:
            time.sleep(60)

    if not fetch_completed:
        raise Exception("Failed to fetch image file within 180 minutes")

    logging.info("=" * 100)
    logging.info("Remanufactring image: " + os.path.basename(base_image_file))
    conn = SSHSwitch(switch_ip)
    remanufacture_cmd = "image remanufacture " + \
        os.path.basename(base_image_file)
    conn.send_cmd(remanufacture_cmd)
    time.sleep(60 * 60)
    logging.info("=" * 100)
    logging.info("Trying to reconnect to switch after remanufacture")
    reconnect_after_manufacture = False
    for _ in range(30):
        conn = SSHSwitch(switch_ip)
        if conn == None:
            # perform double login to avoid configuration
            reconnect_after_manufacture = True
            conn = SSHSwitch(switch_ip)
            conn.close()
            break
        else:
            time.sleep(60 * 5)

    if not reconnect_after_manufacture:
        raise Exception("Failed to reconnect to switch after manufacture")
    logging.info("Remanufacture completed successfully")


def sleep(sleep_time, with_progress=False):
    """
    Sleep.
    """
    logging.info("Waiting %d seconds" % sleep_time)
    if with_progress:
        pbar = ProgressBar(sleep_time)
        for i in range(sleep_time):
            pbar.update(i)
            time.sleep(1)
    else:
        time.sleep(sleep_time)


def convert_request_data_format(data, content_type):
    """
    Converts request data in str format with different encoding formats
    based on its 'content-type'

    @param data:
        data to be sent with request
    @type data:
        dict

    @param content_type:
        content_type of data to be sent with request
    @type content_type:
        str

    @return:
        request data in str format with different encoding formats
        based on its 'content-type'
    @rtype:
        str
    """
    if "json" in content_type:
        data = json.dumps(data)
    if "urlencoded" in content_type:
        data = urllib.urlencode(data)

    return data


def get_response_result(response):
    """
    Returns response result in str|dict|xml format
    from response object based on its 'content-type'

    @param response:
        response object returned from previous sent request

    @type response:
        requests.models.Response

    @return:
        response response result in str|dict|xml format
        based on its 'content-type'
    @rtype:
        str|dict|xml
    """
    result = None
    content_type = response.headers['content-type']

    if "json" in content_type:
        try:
            result = response.json()
        except Exception:
            logging.info("Failed to parse JSON, returning text")
            logging.info("Ignoring exception:" )
            result = str(response.text)
            logging.info("result: %s" % result)

    elif "text" in content_type:
        result = str(response.text)
        if "xml" in content_type:
            result = etree.fromstring(result)

    return result


def send_request(host, url, method="get", request_data={},
                 headers={'content-type': 'application/json'},
                 auth_needed=False, login_url=None, login_method="post",
                 login_headers={'content-type': 'application/json'},
                 login_data={}, exception_on_error=True, return_header=False,
                 verbose=True):
    """
    Sending http request to host with considering if request needs login
    request or not.

    @param host:
        host ip that we need to send request to
    @type host:
        str

    @param url:
        request url
    @type url:
        str

    @param method:
        request method
    @type method:
        str

    @param request_data:
        data to send with request
    @type request_data:
        dict

    @param headers:
        headers determining mainly content-type and other attributes value
    @type headers:
        int

    @param auth_needed:
        determine if login request is needed to be done first or not
    @type auth_needed:
        bool

    @param login_url:
        login request url if login request needed
    @type login_url:
        str

    @param login_method:
        login method if login request needed
    @type login_method:
        str

    @param login_headers:
        login headers determining mainly content-type
        and other attributes value if login request needed
    @type login_headers:
        str

    @param login_data:
        login data (credentials) to send with request if login request needed
    @type login_data:
        str

    @return:
        response status_code, response result
    @rtype:
        int, str | dict | xml

    Example to use this method is:
        controller_ip = "10.224.14.40"
        login_url = "/neo/api/login"
        login_method = "post"
        login_data = {"username": "admin", "password": "123456"}
        login_headers = {'content-type': 'application/x-www-form-urlencoded'}
        headers = {'content-type': 'application/json'}
        capabilities_url = "/neo/api/views/capabilities"

        status_code, result = send_request(controller_ip, capabilities_url,
                                       method="get", data={}, headers=headers,
                                       auth_needed=True, login_url=login_url,
                                       login_method=login_method,
                                       login_headers=login_headers,
                                       login_data=login_data)
    """
    logging.info("send_request")
    status_code, result = (None,) * 2

    request_url = "http://{host}{url}".format(**locals())
    logging.info("request_url: %s " % request_url)
    requests_session = requests.session()

    if(auth_needed):
        logging.info("Authentication is required for request")
        if not (login_url is not None and login_url != ''):
            raise Exception("Missing login url for authenticated request")

        if not (login_data is not None and login_data != {}):
            raise Exception("Missing login data (username, password, " +
                            "other values) for authenticated request")

        if not (login_method is not None and
                login_method.lower() in ['put', 'post']):
            raise Exception("Unsupported login method '" +
                            str(login_method) +
                            "', it should be one of " + str(['put', 'post']))

        if not (login_headers is not None and login_headers != {}):
            raise Exception("Missing  or incorrect login headers '" +
                            str(login_headers) + "'")

        login_data = convert_request_data_format(login_data,
                                                 login_headers['content-type'])

        login_request_url = "http://{host}{login_url}".format(**locals())
        # logging.info("login using url " + login_request_url + "")
        if login_method.lower() == 'put':
            response = requests_session.put(login_request_url,
                                            data=login_data,
                                            headers=login_headers)
        else:
            response = requests_session.post(login_request_url,
                                             data=login_data,
                                             headers=login_headers)

        status_code = response.status_code
        if status_code != httplib.OK:
            result = get_response_result(response)
            raise Exception("Failed to login, status_code is '" +
                            str(status_code) + "', response is '" +
                            str(result) + "'")
        else:
            logging.info("login done")

        if not (url is not None and url != ''):
            raise Exception("Missing request url")

        if not (method is not None and
                method.lower() in ['get', 'put', 'post', 'delete']):
            raise Exception("Unsupported request method '" +
                            str(method) +
                            "', it should be one of " +
                            str(['get', 'put', 'post', 'delete']))

    # data conversion should always be done if data is exist
    # and the contenet type is json or urlencoded
    # not just in case login required
    if(request_data is not None and request_data != {}):
        if not (headers is not None and headers != {}):
            raise Exception("Missing  or incorrect request headers '" +
                            str(login_headers) + "'")

        request_data = convert_request_data_format(
            request_data, headers['content-type'])

    if method.lower() == 'get':
        response = requests_session.get(request_url, headers=headers)
    if method.lower() == 'put':
        response = requests_session.put(request_url, data=request_data,
                                        headers=headers)
    if method.lower() == 'post':
        logging.info("requests_session.post")
        logging.info("request_url  : %s" % request_url)
        logging.info("request_data : %s" % request_data)
        logging.info("headers      : %s" % headers)
        response = requests_session.post(request_url, data=request_data,
                                         headers=headers)
    if method.lower() == 'delete':
        response = requests_session.delete(request_url, data=request_data,
                                           headers=headers)

    status_code = response.status_code
    logging.info("status_code: %s " % status_code)
    if status_code in [httplib.OK, httplib.ACCEPTED, httplib.CREATED]:
        result = get_response_result(response)
        if verbose == True:
            logging.info("result: %s " % result)
    # server error 5XX
    elif status_code in [httplib.INTERNAL_SERVER_ERROR,
                         httplib.INSUFFICIENT_STORAGE,
                         httplib.NOT_IMPLEMENTED,
                         httplib.BAD_GATEWAY,
                         httplib.SERVICE_UNAVAILABLE,
                         httplib.GATEWAY_TIMEOUT,
                         httplib.HTTP_VERSION_NOT_SUPPORTED,
                         httplib.NOT_EXTENDED,
                         ] and exception_on_error:
        exception_message = ("Failed to send request, host : " + str(host) +
                             ", url :" + str(url) + ", method : " + str(method) +
                             ", request_data : " + str(request_data) +
                             ", status_code : '" + str(status_code) +
                             "', response : '" + str(response.text) + "'")

        raise Exception(exception_message)

    else:
        result = response.text


    if return_header is True:
        return status_code, result, response.headers

    return status_code, result


def sendRequestWithBasicAuthentication(host, url, username, password,
                                       method="get", request_data={},
                                       headers={
                                           'content-type': 'application/json'},
                                       ):
    """
    Sending http request to host with considering if request needs login
    request or not.

    @param host:
        host ip that we need to send request to
    @type host:
        str

    @param url:
        request url
    @type url:
        str

    @param method:
        request method
    @type method:
        str

    @param request_data:
        data to send with request
    @type request_data:
        dict

    @param headers:
        headers determining mainly content-type and other attributes value
    @type headers:
        int

    @param username:
        Username (credentials) to send with request.
    @type username:
        str

    @param password:
        Password (credentials) to send with request.
    @type password:
        str

    @return:
        response status_code, response result
    @rtype:
        int, str | dict | xml

    """
    logging.info("send_request")
    status_code, result = (None,) * 2

    request_url = "http://{host}{url}".format(**locals())
    logging.info("request_url: %s " % request_url)

    request_data = convert_request_data_format(request_data,
                                               headers['content-type'])
    auth = HTTPBasicAuth('admin', '123456')

    if method.lower() == 'get':
        response = requests.get(request_url, headers=headers, auth=auth)
    if method.lower() == 'put':
        response = requests.put(request_url, data=request_data,
                                headers=headers, auth=auth)
    if method.lower() == 'post':
        logging.info("requests_session.post")
        logging.info("request_url  : %s" % request_url)
        logging.info("request_data : %s" % request_data)
        logging.info("headers      : %s" % headers)
        response = requests.post(request_url, data=request_data,
                                 headers=headers, auth=auth)
        logging.info("put response: %s " % response)
    if method.lower() == 'delete':
        response = requests.delete(request_url, data=request_data, auth=auth)

    status_code = response.status_code
    if status_code == httplib.OK or httplib.ACCEPTED:
        result = get_response_result(response)
    else:
        raise Exception("Failed to send request, host : " + str(host) +
                        ", url :" + str(url) + ", method : " + str(method) +
                        ", request_data : " + str(request_data) +
                        ", status_code : '" + str(status_code) +
                        "', response : '" + str(result) + "'")

    return status_code, result


def runService(service, options, server=None, verbose=True):
    """
    Run UFM Service with options.
    Run it from shell with the defined options.
    @options - tuple of command arguments (e.g. ("start",)).
    @return a tuple of returncode (int), stdout (str), stderr (str).
    """
    args = (service,)
    args += options
    return runCommandStatus(" ".join(args), device=server, verbose=verbose)


def repeat_check(obj, method_name, expected_result, period_time, max_timeout, args=[]):
    """
    Repeat check with the given maximum timeout max_timeout for
    the expected return value expected_result of a method method_name with its givne arguments list args
    which is called by the given object instance obj.

    @param obj:
        the object instance from which the method with name method_name will be called,
        it can be sys.modules[__name__] for the object of current module
    @type obj:
        object

    @param method_name:
        the name of the method to be called from given object obj
    @type method_name:
        str

    @param expected_result:
        the expected returned result to be returned from the called method with name method_name.
        If the method returns a list of values, the expected result to check for should be the first returned value of that list
    @type expected_result:
        object

    @param period_time:
        the difference of time between two times of repeat check
    @type period_time:
        number

    @param max_timeout:
        the maximum timeout for repeat check of the expected returned result to be returned from the called method with name method_name
    @type max_timeout:
        number

    @param args:
        the list of arguments passed to the called method with name method_name
    @type args:
        list

    @return:
        returned result from called method with name method_name
    @rtype:
        object

    Examples to use this method is:
        1.for call of method with arguments list with expected_result="yes" : repeat_check(obj=sys.modules[__name__], method_name="isInterfaceUp", expected_result="yes", period_time=5, max_timeout=60, args=[cliObj, ifc])
        1.for call of method with empty arguments list with expected_result=True : repeat_check(obj=ifc_cli_obj, method_name="ufmRunning", expected_result=True, period_time=5, max_timeout=120)
    """
    start = datetime.datetime.now()
    current = datetime.datetime.now()
    while current - start < datetime.timedelta(seconds=max_timeout):
        result = getattr(obj, method_name)(*args)
        if(type(result) == tuple or type(result) == list):
            ret = result[0]
        else:
            ret = result
        if(ret == expected_result):
            break
        time.sleep(period_time)
        current = datetime.datetime.now()
    return result


def validateSuccess(error_code, stdout, stderr,
                    error_levels=mgmt_constants.ErrorCodes.ALL,
                    success_msg=None):
    """
    Validate that the result code is 0 and validate that there are no error
    messages in the output

    @param error_code: the error code resulting from the test
    @type error_code: int

    @param stdout: the output results from the command
    @type stdout: str

    @param stdout: the errors results from the command
    @type stdout: str

    @param error_levels: severity level to search errors
    @type error_levels: list

    @param success_msg: the success message to search.
    @type success_msg: str

    @return: 1-> failed, 0-> succeed
    @rtype: int
    """
    if(error_code != 0):
        return 1

    if((stdout is not None) and (stdout.strip() != "")):
        for error_level in error_levels:
            regex = mgmt_constants.RegularExpressions.SEVERITY.get(error_level)
            match = re.search(regex, stdout)
            if(match):
                return 1

        if((success_msg is not None) and (success_msg.strip() != "")):
            match = re.search(success_msg, stdout)
            if(match is None):
                return 1

    if((stderr is not None) and (stderr.strip() != "")):
        for error_level in error_levels:
            regex = mgmt_constants.RegularExpressions.SEVERITY.get(error_level)
            match = re.search(regex, stderr)
            if(match):
                return 1
    return 0
