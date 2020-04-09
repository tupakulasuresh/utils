from __future__ import print_function
import time
import sys
import re
import os
import logging
# import pdb
import socket
import pexpect
import struct
import fcntl
import termios
import signal

SSH_OPTS = "-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s',
                    datefmt='%m/%d/%Y %T')
LOG = logging.getLogger(__name__)


class Process_File(object):

    def __init__(self, filename, ip=None, username=None, password=None):
        self.filename = filename
        self.ip = ip
        self.username = username
        self.password = password

        if (self.filename is None or
                not os.path.isfile(os.path.expanduser(self.filename))):
            LOG.error('Invalid file : %s' % filename)
            sys.exit(1)

    def get_data_from_file(self):
        if self.ip is None or IpUtils.is_local_ip(self.ip):
            LOG.debug('Testbed is local machine. Directly access files')
            return self.get_data_from_local_file()
        else:
            LOG.debug('Testbed is remote machine. Login to access files')
            return self.get_data_from_remote_file()

    def get_data_from_local_file(self):
        data = ''
        LOG.info('Accessing %s from localhost' % self.filename)
        try:
            with open(os.path.expanduser(self.filename), 'r') as fd:
                data = fd.read()
        except IOError as e:
            LOG.error(e)
        except Exception as e:
            LOG.error(e)
        finally:
            return data

    def get_data_from_remote_file(self):
        try:
            return self.get_filedata_using_paramiko()
        except ImportError:
            LOG.debug('Loading paramiko failed')
            return self.get_filedata_using_os_popen()

    def get_filedata_using_paramiko(self):
        LOG.debug('Connecting to %s using paramiko ...' % self.ip)
        import paramiko
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.connect(self.ip, timeout=60,
                       username=self.username, password=self.password)
        ftp = client.open_sftp()
        file = ftp.file(os.path.expanduser(self.filename), "r", -1)
        data = file.read()
        ftp.close()
        client.close()
        return data

    def get_filedata_using_os_popen(self):
        LOG.debug('Connecting to %s using os module ...' % self.ip)
        cmd = 'sshpass -p %s ssh %s %s@%s "cat %s"' % (
            self.password, SSH_OPTS, self.username, self.ip,
            self.filename)
        stdout = os.popen(cmd).read()
        return stdout


class IpUtils(object):

    @staticmethod
    def is_ip_reachable(ip, count=2, interval=0.2):
        # FIXME : need to support ipv6 ping
        ret_val = os.system('ping -c %d -i %s -q %s > /dev/null 2>&1'
                            % (count, interval, ip)
                            )
        if ret_val == 0:
            return True
        else:
            return False

    @staticmethod
    def is_local_ip(ip):
        if ip == '127.0.0.1' or \
                ip == socket.gethostbyname(socket.gethostname()):
            return True
        else:
            return False

    @staticmethod
    def get_ip_from_name(node_name, dns_suffix=None):
        ip = IpUtils.get_ip_using_nslookup(node_name, dns_suffix)
        LOG.debug('ip = %s' % ip)
        return ip

    @staticmethod
    def get_ip_using_nslookup(node_name, dns_suffix):
        node_name = node_name.strip('.').strip()
        if '.' not in node_name:
            node_name += dns_suffix

        LOG.debug('ip = nslookup %s' % node_name)

        ip_list = []
        try:
            for line in socket.getaddrinfo(node_name, 0, 0):
                ip_list.append(line[-1][0])
            return list(set(ip_list))[0]
        except Exception:
            LOG.error('unable to resolve dns for %s' % node_name)
            return


class Validation(object):

    @staticmethod
    def is_valid_ip(ip):
        if ip is not None:
            LOG.debug('validate ip %s' % ip)
            try:
                socket.inet_aton(ip)
                return True
            except socket.error:
                LOG.warning('%s: not a valid ip.' % ip)
        return False

    @staticmethod
    def is_valid_port(port):
        if port is not None:
            LOG.debug('validate port %s' % port)
            if port.upper() not in ['IPMI', 'DIRECT'] and not port.isdigit():
                LOG.warning('Port \"%s\" is not a digit|IPMI' % port)
                return False
        return True


class SessionManager(object):
    pass_prompt = '[pP]assword:'
    user_prompt = '(l|L)ogin:|Username:'
    sess_prompt = '[#\$>] |-TS#'
    nw_error = "|".join([
        "(No route to host)",
        "(Connection refused)",
        "(Name or service not known)"
        "(Connection closed by foreign host)",
        "(Unknown host)",
    ])
    continuation_prompt = "|".join([
        "(Press any key to continue)",
        "(--More--)",
        "(\[confirm\])",
        "(\[SOL established\])",
    ])
    timeout = 60

    def __init__(self, ip, port=None, username=None, password=None,
                 protocol='ssh', verbose=True, log_file=None):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol
        self.session = None
        self.extra_enter = False
        self.verbose = verbose
        self.log_file = log_file

    def __repr__(self):
        return 'SessionManager(%s, port=%s, username=%s, password=%s,\
            protocol=%s)' % (self.ip, self.port, self.username, self.password,
                             self.protocol)

    def getTelnetSession(self):
        msg = "Using telnet to connect %s" % self.ip
        cmd = 'telnet ' + self.ip
        if self.port:
            cmd = cmd + " " + str(self.port)
            msg = msg + " " + str(self.port)
        LOG.info(msg)
        return self.open_connection(cmd)

    def sigwinch_passthrough(self, sig, data):
        print "Changing window size"
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                              termios.TIOCGWINSZ, s))
        self.session.setwinsize(a[0], a[1])

    def getSshSession(self):
        msg = "Using ssh to connect %s" % self.ip
        cmd = "/usr/bin/ssh %s -l %s %s" % (SSH_OPTS, self.username, self.ip)
        if self.port:
            cmd = cmd + " " + str(self.port)
            msg = msg + " " + str(self.port)
        LOG.info(msg)
        return self.open_connection(cmd)

    def open_connection(self, cmd):
        try:
            self.session = pexpect.spawn(cmd)
            self.session.timeout = self.timeout

            if (self.log_file and len(self.log_file.strip()) > 0 and
                    os.path.exists(self.log_file)):
                fout = open(self.log_file, 'a')
            else:
                fout = sys.stdout

            # setting # display/logging
            if not self.verbose:
                # disable logging to screen
                self.session.logfile_read = None
                self.session.logfile_sent = None
            else:
                self.session.logfile_read = fout
                self.session.logfile_sent = fout

            if self.check_for_prompt():
                if not self.verbose:
                    # enable file logging from now
                    self.session.logfile_read = fout
                    self.session.logfile_sent = fout
                    self.session.sendline(' ')  # for display purpose
                    self.check_for_prompt()
                return True
            else:
                return False
        except Exception:
            if self.verbose:
                raise
            LOG.warning("Failed to open connection")
            return False

    def check_for_prompt(self, username=None, password=None, EOF=False):
        match_list = [
            self.nw_error,
            self.user_prompt,
            self.pass_prompt,
            self.sess_prompt,
            self.continuation_prompt,
            "Escape character|Serial Over LAN:",
            '(y/n).*:',
        ]

        # passing username/password to support command specific credentials
        # which will override instance's credentials
        if not username:
            username = self.username
        if not password:
            password = self.password

        # convert password to list datatype to retry
        if not isinstance(password, list):
            password = password.split(' ')

        try:
            password_sent = 0
            i = 0
            while True:
                i = self.session.expect(match_list)
                if i == 0:
                    LOG.error("Encountered network issues")
                    return False
                if i == 1:
                    line = str(self.session.before) + str(self.session.after)
                    line = line.strip()
                    if (not re.search("Last login|Username:", line)):
                        self.session.sendline(username)
                elif i == 2:
                    if password_sent >= 2:
                        return False
                    else:
                        # try with different passwords if present
                        try:
                            curr_password = password[password_sent]
                        except IndexError:
                            curr_password = password[0]
                        password_sent += 1
                    LOG.info('Sending password %s' % curr_password)
                    self.session.sendline(curr_password)
                elif i == 3:
                    return True
                elif i == 4:
                    self.session.sendline(' ')
                elif i == 5:
                    # TODO need to check for telnet only and not for console
                    self.session.sendline('')
                elif EOF and i == 6:
                    # for reboot prompt
                    self.session.sendline('y')
        except KeyboardInterrupt:
            LOG.warn('KeyboardInterrupt')
        except pexpect.EOF:
            if not EOF:
                raise
        except pexpect.TIMEOUT:
            LOG.error(
                "Encountered timeout (> %ss) while waiting for prompt."
                % self.session.timeout)
        except Exception:
            LOG.info((str(self.session)))
            raise

        self.close_session()
        return False

    def __exit__(self, exc_val, exp_inst, exp_tb):
        self.close_session()

    def close_session(self):
        try:
            self.session.close()
            self.session = None
            return True
        except Exception:
            return False

    def reconnect(self):
        if not self.isalive():
            self.connect_to_node()

    def connect_to_node(self):
        status = False
        # try ssh/telnet if protocol not specified and previous attempt failed
        if "ssh" in self.protocol:
            status = self.getSshSession()
        if not status and "telnet" in self.protocol:
            status = self.getTelnetSession()

        if not status:
            raise EnvironmentError("Unable to connected to %s" % self.ip)

    def isalive(self):
        if not self.session:
            return False
        else:
            return self.session.isalive()

    def interact(self):
        try:
            signal.signal(signal.SIGWINCH, SessionManager.sigwinch_passthrough)
        except Exception:
            pass

        if not self.isalive():
            raise Exception("No active session for %s" % self.ip)

        # FIXME: centos is echoing lines, to suppress it
        if self.session.logfile_read == sys.stdout:
            self.session.logfile_read = None
        else:
            # FIXME : logfile redirection doesn't display the prompt sometimes
            LOG.warn("Interactive session. hit return if u don't see the prompt")

        self.session.interact()

    def process_input_cmds(self, cmd_list):
        new_cmd_list = ""
        for cmd in cmd_list.split(";"):
            cmd = cmd.strip()
            # expanding the path assuming its a file
            cmd = os.path.expanduser(cmd)
            if os.path.isfile(cmd):
                # TODO : add file parsing code
                pass
            else:
                new_cmd_list = new_cmd_list + cmd + ";"
        return new_cmd_list

    def isEOF(self, cmd):
        EOF_cmds = [
            'l',
            'logout',
            'exit',
            'reload',
            'reboot',
            '/sbin/system-reboot',
        ]
        return (cmd in EOF_cmds)

    def execute_cmd(self, cmd_list, username=None, password=None, blocking=True, return_output=False):
        if len(cmd_list) > 0:
            if not self.isalive():
                raise EOFError("No active session for %s" % self.ip)

            for cmd in self.process_input_cmds(cmd_list).split(";"):
                cmd = cmd.strip()
                if (len(cmd) > 0):
                    # for some telnet sessions, this is required
                    if self.extra_enter:
                        cmd += '\r'
                    self.session.sendline(cmd)
                    if blocking:
                        if not self.check_for_prompt(
                                username,
                                password,
                                EOF=self.isEOF(cmd),
                        ):
                            return False
            if return_output:
                return str(self.session.before) + str(self.session.after)
        return True

def timeit(method):
    def timed(*args, **kwargs):
        print("Start %s" % method.__name__)
        ts = time.time()
        result = method(*args, **kwargs)
        te = time.time()
        print("%-30s [Time taken: %.2f ms]" % (method.__name__, (te - ts) * 1000))
        return result
    return timed
