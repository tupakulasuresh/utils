'''
python utilities to interact with device remotely using ssh/telnet
'''

import os
import logging
from iputils import is_local_ip


SSH_OPTS = "\
        -o ServerAliveInterval=120 \
        -o UserKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=no \
        -q "

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s',
                    datefmt='%m/%d/%Y %T')
logging.basicConfig(format='%(levelname)s: %(message)s')
LOG = logging.getLogger(__name__)


class ReadFile(object):
    '''
    class to create object reference to a file on a remote machine
    '''

    def __init__(self, filename, ip=None, username=None, password=None):
        self.filename = filename
        self.ip = ip
        self.username = username
        self.password = password

        assert self.filename, "File can't be empty"

    def get_data_from_file(self):
        if self.ip is None or is_local_ip(self.ip):
            LOG.debug('Testbed is local machine. Directly access files')
            data = self.get_data_from_local_file()
        else:
            LOG.debug('Testbed is remote machine. Login to access files')
            data = self.get_data_from_remote_file()
        return data

    def get_data_from_local_file(self):
        data = ''
        LOG.info('Accessing %s from localhost', self.filename)
        try:
            with open(os.path.expanduser(self.filename), 'r') as f:
                data = f.read()
        except IOError as e:
            LOG.error(e)
        except Exception as e:
            LOG.error(e)

        return data

    def get_data_from_remote_file(self):
        try:
            return self.get_filedata_using_paramiko()
        except ImportError:
            LOG.debug('Loading paramiko failed')
            return self.get_filedata_using_os_popen()

    def get_filedata_using_paramiko(self):
        import paramiko
        LOG.debug('Connecting to %s using paramiko ...', self.ip)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.ip, timeout=60,
                       username=self.username, password=self.password)
        ftp = client.open_sftp()
        fd = ftp.file(os.path.expanduser(self.filename), "r", -1)
        data = fd.read()
        ftp.close()
        client.close()
        return data

    def get_filedata_using_os_popen(self):
        LOG.debug('Connecting to %s using os module ...', self.ip)
        cmd = 'sshpass -p %s ssh %s %s@%s "cat %s"', (
            self.password, SSH_OPTS, self.username, self.ip,
            self.filename)
        stdout = os.popen(cmd).read()
        return stdout
