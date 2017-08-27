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
        Contains All Utils related to connection (ssh , telnet, sftp etc...).
"""

import os
import pysftp
import posixpath
from contextlib import contextmanager
from utilities import logging_utils
from stat import S_ISDIR, S_ISREG
from pysftp.helpers import (WTCallbacks, path_advance, reparent, walktree)
from utilities.connection_handler.connection import Connection
from utilities.logging_utils import logger
from utilities.decorator_utils import alias, aliased


@aliased
class SFTP(Connection):
    """
    class for SFTP connection with main functions related to it.
    """
    class_doc = '''
            *SFTP: is class aimed to established connection to sftp
             with main functionality:
                1- establish_connection (abstract method) 
                2- terminate_connection (abstract method) 
                3- get_cwd
                4- list_dir
                5- chmod
                6- is_dir
                7- is_file
                8- mkdir
                9- make_dirs
                10-read_link
                11-remove
                12-rmdir
                13-rename
                14-stat
                15-lstat
                16-get
                17-pwd
                18-cd
                19-chdir
                20-get_d
                21-get_r
                22-put
                23-put_d
                24-put_r
                '''

    def __init__(self, hostname, username, password, port):
        super().__init__(hostname=hostname, username=username,
                         password=password, port=port)  # the sftp using the
        self._sftp = None

    @alias('initiate_connection_ssh_tunnel')
    def initiate_connection(self, verbose=False):
        """
        Establish the SFTP connection.
        :param host: str ip
        :param username: str username
        :param password:
        :return:
        """
        logging_utils.log_func_details(hostname=self.hostname,
                                       username=self.username,
                                       password=self.password)

        if self._sftp is None:
            logger.info("establishing new sftp connection... ")
            cnopts = pysftp.CnOpts()
            cnopts.hostkeys = None
            self._sftp = pysftp.Connection(host=self.hostname, username=self.username,
                                           password=self.password, cnopts=cnopts)

            logger.info("new sftp connection was established : {0}".format(self._sftp))
        else:
            logger.warning("already has sftp connection : {0}".format(self._sftp))

    def get_cwd(self):
        """return the current working directory on the remote. This is a wrapper
        for paramiko's method and not to be confused with the SFTP command,
        cwd.

        :returns: (str) the current remote path. None, if not set.

        """
        return self._sftp.getcwd()

    def list_dir(self, remote_path='.'):
        """return a list of files/directories for the given remote path.
        Unlike, paramiko, the directory listing is sorted.

        :param str remote_path: path to list on the server

        :returns: (list of str) directory entries, sorted

        """
        logging_utils.log_func_details(remote_path=remote_path)
        return sorted(self._sftp.listdir(remote_path))

    def chmod(self, remote_path, mode=777):

        """set the mode of a remote_path to mode, where mode is an integer
        representation of the octal mode to use.

        :param str remote_path: the remote path/file to modify
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        :raises: IOError, if the file doesn't exist

        """
        logging_utils.log_func_details(remote_path=remote_path, mode=mode)
        self._sftp.chmod(remote_path, mode=int(str(mode), 8))
        logger.info("changed mode of file <{0}> to mode : {1} ".format(remote_path, mode))

    def is_dir(self, remote_path):
        """return true, if remote_path is a directory

        :param str remote_path: the path to test

        :returns: (bool)

        """
        logging_utils.log_func_details(remote_path=remote_path)
        try:
            result = S_ISDIR(self._sftp.stat(remote_path).st_mode)
        except IOError:  # no such file
            result = False
        return result

    def is_file(self, remote_path):
        """return true if remote_path is a file

        :param str remote_path: the path to test

        :returns: (bool)

        """
        logging_utils.log_func_details(remote_path=remote_path)
        try:
            result = S_ISREG(self._sftp.stat(remote_path).st_mode)
        except IOError:  # no such file
            result = False
        return result

    def mkdir(self, remote_path, mode=777):
        """Create a directory named remote_path with mode. On some systems,
        mode is ignored. Where it is used, the current umask value is first
        masked out.

        :param str remote_path: directory to create`
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        """
        logging_utils.log_func_details(remote_path=remote_path, mode=mode)
        self._sftp.mkdir(remote_path, mode=int(str(mode), 8))

    def make_dirs(self, remote_dir, mode=777):
        """create all directories in remotedir as needed, setting their mode
        to mode, if created.

        If remotedir already exists, silently complete. If a regular file is
        in the way, raise an exception.

        :param str remotedir: the directory structure to create
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        :raises: OSError

        """
        logging_utils.log_func_details(remote_dir=remote_dir, mode=mode)
        if self.is_dir(remote_dir):
            pass

        elif self.is_file(remote_dir):
            raise OSError("a file with the same name as the remotedir, "
                          "'%s', already exists." % remote_dir)
        else:

            head, tail = os.path.split(remote_dir)
            if head and not self.is_dir(head):
                self.make_dirs(head, mode)

            if tail:
                self.mkdir(remote_dir, mode=mode)

    def read_link(self, remotelink):
        """Return the target of a symlink (shortcut).  The result will be
        an absolute pathname.

        :param str remotelink: remote path of the symlink

        :return: (str) absolute path to target

        """
        logging_utils.log_func_details(remotelink=remotelink)
        return self._sftp.normalize(self._sftp.read_link(remotelink))

    def remove(self, remote_file):
        """remove the file @ remotefile, remotefile may include a path, if no
        path, then :attr:`.pwd` is used.  This method only works on files

        :param str remotefile: the remote file to delete

        :returns: None

        :raises: IOError

        """
        logging_utils.log_func_details(remote_file=remote_file)
        self._sftp.remove(remote_file)

    def rmdir(self, remote_path):
        """remove remote directory

        :param str remote_path: the remote directory to remove

        :returns: None

        """
        logging_utils.log_func_details(remote_path=remote_path)
        self._sftp.rmdir(remote_path)

    def rename(self, remote_src, remote_dest):
        """rename a file or directory on the remote host.

        :param str remote_src: the remote file/directory to rename

        :param str remote_dest: the remote file/directory to put it

        :returns: None

        :raises: IOError

        """
        logging_utils.log_func_details(remote_src=remote_src, remote_dest=remote_dest)
        self._sftp.rename(remote_src, remote_dest)

    def stat(self, remote_path):
        """return information about file/directory for the given remote path

        :param str remote_path: path to stat

        :returns: (obj) SFTPAttributes

        """
        logging_utils.log_func_details(remote_path=remote_path)
        return self._sftp.stat(remote_path)

    def lstat(self, remote_path):
        """return information about file/directory for the given remote path,
        without following symbolic links. Otherwise, the same as .stat()

        :param str remote_path: path to stat

        :returns: (obj) SFTPAttributes object

        """
        logging_utils.log_func_details(remote_path=remote_path)
        return self._sftp.lstat(remote_path)

    def get(self, remote_path, localpath=None, callback=None,
            preserve_mtime=False):
        """Copies a file between the remote host and the local host.

        :param str remote_path: the remote path and filename, source
        :param str localpath:
            the local path and filename to copy, destination. If not specified,
            file is copied to local current working directory
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool preserve_mtime:
            *Default: False* - make the modification time(st_mtime) on the
            local file match the time on the remote. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)

        :returns: None

        :raises: IOError

        """
        logging_utils.log_func_details(remote_path=remote_path, localpath=localpath, callback=callback,
                                       preserve_mtime=preserve_mtime)
        if not localpath:
            localpath = os.path.split(remote_path)[1]

        if preserve_mtime:
            sftpattrs = self._sftp.stat(remote_path)

        self._sftp.get(remote_path, localpath, callback=callback)
        if preserve_mtime:
            os.utime(localpath, (sftpattrs.st_atime, sftpattrs.st_mtime))

    @property
    def pwd(self):
        '''return the current working directory

        :returns: (str) current working directory

        '''
        return self._sftp.normalize('.')

    @contextmanager
    def cd(self, remote_path=None):  # pylint:disable=c0103
        """context manager that can change to a optionally specified remote
        directory and restores the old pwd on exit.

        :param str|None remote_path: *Default: None* -
            remote_path to temporarily make the current directory
        :returns: None
        :raises: IOError, if remote path doesn't exist
        """
        logging_utils.log_func_details(remote_path=remote_path)
        original_path = self.pwd
        try:
            if remote_path is not None:
                self.chdir(remote_path)
            yield
        finally:
            self.chdir(original_path)

    def chdir(self, remote_path):
        """change the current working directory on the remote

        :param str remote_path: the remote path to change to

        :returns: None

        :raises: IOError, if path does not exist

        """
        logging_utils.log_func_details(remote_path=remote_path)
        self._sftp.chdir(remote_path)

    def get_d(self, remotedir, localdir, preserve_mtime=False):
        """get the contents of remotedir and write to locadir. (non-recursive)

        :param str remotedir: the remote directory to copy from (source)
        :param str localdir: the local directory to copy to (target)
        :param bool preserve_mtime: *Default: False* -
            preserve modification time on files

        :returns: None

        :raises:
        """
        with self.cd(remotedir):
            for sattr in self._sftp.listdir_attr('.'):
                if S_ISREG(sattr.st_mode):
                    rname = sattr.filename
                    self.get(rname, reparent(localdir, rname),
                             preserve_mtime=preserve_mtime)

    def get_r(self, remotedir, localdir, preserve_mtime=False):
        """recursively copy remotedir structure to localdir

        :param str remotedir: the remote directory to copy from
        :param str localdir: the local directory to copy to
        :param bool preserve_mtime: *Default: False* -
            preserve modification time on files

        :returns: None

        :raises:

        """
        logging_utils.log_func_details(remotedir=remotedir, localdir=localdir, preserve_mtime=preserve_mtime)
        wtcb = WTCallbacks()
        self.walktree(remotedir, wtcb.file_cb, wtcb.dir_cb, wtcb.unk_cb)
        # handle directories we recursed through
        for dname in wtcb.dlist:
            for subdir in path_advance(dname):
                try:
                    os.mkdir(reparent(localdir, subdir))
                    # force result to a list for setter,
                    wtcb.dlist = wtcb.dlist + [subdir, ]
                except OSError:  # dir exists
                    pass

        for fname in wtcb.flist:
            # they may have told us to start down farther, so we may not have
            # recursed through some, ensure local dir structure matches
            head, _ = os.path.split(fname)
            if head not in wtcb.dlist:
                for subdir in path_advance(head):
                    if subdir not in wtcb.dlist and subdir != '.':
                        os.mkdir(reparent(localdir, subdir))
                        wtcb.dlist = wtcb.dlist + [subdir, ]

            self.get(fname,
                     reparent(localdir, fname),
                     preserve_mtime=preserve_mtime)

    def walktree(self, remote_path, fcallback, dcallback, ucallback,
                 recurse=True):
        '''recursively descend, depth first, the directory tree rooted at
        remote_path, calling discreet callback functions for each regular file,
        directory and unknown file type.

        :param str remote_path:
            root of remote directory to descend, use '.' to start at
            :attr:`.pwd`
        :param callable fcallback:
            callback function to invoke for a regular file.
            (form: ``func(str)``)
        :param callable dcallback:
            callback function to invoke for a directory. (form: ``func(str)``)
        :param callable ucallback:
            callback function to invoke for an unknown file type.
            (form: ``func(str)``)
        :param bool recurse: *Default: True* - should it recurse

        :returns: None

        :raises:

        '''
        for entry in self.list_dir(remote_path):
            pathname = posixpath.join(remote_path, entry)
            mode = self._sftp.stat(pathname).st_mode
            if S_ISDIR(mode):
                # It's a directory, call the dcallback function
                dcallback(pathname)
                if recurse:
                    # now, recurse into it
                    self.walktree(pathname, fcallback, dcallback, ucallback)
            elif S_ISREG(mode):
                # It's a file, call the fcallback function
                fcallback(pathname)
            else:
                # Unknown file type
                ucallback(pathname)

    def getfo(self, remote_path, flo, callback=None):
        """Copy a remote file (remote_path) to a file-like object, flo.

        :param str remote_path: the remote path and filename, source
        :param flo: open file like object to write, destination.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.

        :returns: (int) the number of bytes written to the opened file object

        :raises: Any exception raised by operations will be passed through.

        """
        return self._sftp.getfo(remote_path, flo, callback=callback)

    def put(self, localpath, remote_path=None, callback=None, confirm=True,
            preserve_mtime=False):
        """Copies a file between the local host and the remote host.

        :param str localpath: the local path and filename
        :param str remote_path:
            the remote path, else the remote :attr:`.pwd` and filename is used.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime:
            *Default: False* - make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)

        :returns:
            (obj) SFTPAttributes containing attributes about the given file

        :raises IOError: if remote_path doesn't exist
        :raises OSError: if localpath doesn't exist

        """
        logging_utils.log_func_details(localpath=localpath, remote_path=remote_path,
                                       callback=callback, confirm=confirm, preserve_mtime=preserve_mtime)
        if not remote_path:
            remote_path = os.path.split(localpath)[1]

        if preserve_mtime:
            local_stat = os.stat(localpath)
            times = (local_stat.st_atime, local_stat.st_mtime)

        sftpattrs = self._sftp.put(localpath, remote_path, callback=callback,
                                   confirm=confirm)
        if preserve_mtime:
            self._sftp.utime(remote_path, times)
            sftpattrs = self._sftp.stat(remote_path)

        return sftpattrs

    def put_d(self, localpath, remote_path, confirm=True, preserve_mtime=False):
        """Copies a local directory's contents to a remote_path

        :param str localpath: the local path to copy (source)
        :param str remote_path:
            the remote path to copy to (target)
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime:
            *Default: False* - make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)

        :returns: None

        :raises IOError: if remote_path doesn't exist
        :raises OSError: if localpath doesn't exist
        """
        wtcb = WTCallbacks()
        cur_local_dir = os.getcwd()
        os.chdir(localpath)
        walktree('.', wtcb.file_cb, wtcb.dir_cb, wtcb.unk_cb,
                 recurse=False)
        for fname in wtcb.flist:
            src = os.path.join(localpath, fname)
            dest = reparent(remote_path, fname)
            # print('put', src, dest)
            self.put(src, dest, confirm=confirm, preserve_mtime=preserve_mtime)

        # restore local directory
        os.chdir(cur_local_dir)

    def put_r(self, localpath, remote_path, confirm=True, preserve_mtime=False):
        """Recursively copies a local directory's contents to a remote_path

        :param str localpath: the local path to copy (source)
        :param str remote_path:
            the remote path to copy to (target)
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime:
            *Default: False* - make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)

        :returns: None

        :raises IOError: if remote_path doesn't exist
        :raises OSError: if localpath doesn't exist
        """
        logging_utils.log_func_details(localpath=localpath, remote_path=remote_path,
                                       confirm=confirm, preserve_mtime=preserve_mtime)
        wtcb = WTCallbacks()
        cur_local_dir = os.getcwd()
        os.chdir(localpath)
        walktree('.', wtcb.file_cb, wtcb.dir_cb, wtcb.unk_cb)
        # restore local directory
        os.chdir(cur_local_dir)
        for dname in wtcb.dlist:
            if dname != '.':
                pth = reparent(remote_path, dname)
                if not self.is_dir(pth):
                    self.mkdir(pth)

        for fname in wtcb.flist:
            head, _ = os.path.split(fname)
            if head not in wtcb.dlist:
                for subdir in path_advance(head):
                    if subdir not in wtcb.dlist and subdir != '.':
                        self.mkdir(reparent(remote_path, subdir))
                        wtcb.dlist = wtcb.dlist + [subdir, ]
            src = os.path.join(localpath, fname)
            dest = reparent(remote_path, fname)
            # print('put', src, dest)
            self.put(src, dest, confirm=confirm, preserve_mtime=preserve_mtime)

    def putfo(self, flo, remote_path=None, file_size=0, callback=None,
              confirm=True):

        """Copies the contents of a file like object to remote_path.

        :param flo: a file-like object that supports .read()
        :param str remote_path: the remote path.
        :param int file_size:
            the size of flo, if not given the second param passed to the
            callback function will always be 0.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size

        :returns:
            (obj) SFTPAttributes containing attributes about the given file

        :raises: TypeError, if remote_path not specified, any underlying error

        """
        return self._sftp.putfo(flo, remote_path, file_size=file_size,
                                callback=callback, confirm=confirm)

    @alias('terminate_connection_ssh_tunnel')
    def terminate_connection(self, sleep_before=0, verbose=False):
        """
        abstract method to enforce inherited classes to implement it
        :param sleep_before: time before terminate in sec
        :type sleep_before: int
        :param verbose: to enable or disable debug mode
        :type verbose: bool
        :return: None
        """
        import time
        logging_utils.log_func_details(sleep_before=sleep_before, verbose=verbose)
        time.sleep(sleep_before)
        self._sftp.close()
        logger.info("the sftp connection is closed!")


def sftp():
    sftp_instance = SFTP(hostname="10.0.0.141", username="pg", password="q1w2e3r4", port=22)
    sftp_instance.initiate_connection_ssh_tunnel(verbose=True)
    logger.info(sftp_instance.stat("/home/pg/"))
    sftp_instance.terminate_connection(verbose=True)


if __name__ == "__main__":
    sftp()
