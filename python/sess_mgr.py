'''
python utilities to interact with device remotely using ssh/telnet
'''

import sys
import re
import os
import logging
import getpass
import struct
import fcntl
import termios
import signal
import pexpect


SSH_OPTS = [
    "-q",
    "-o ServerAliveInterval=120",
    "-o UserKnownHostsFile=/dev/null",
    "-o StrictHostKeyChecking=no",
]
SSH_OPTS = " ".join(SSH_OPTS)


# logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s', datefmt='%m/%d/%Y %T')
LOG = logging.getLogger(__name__)


class SessionManager(object):
    '''
    pexpect based utility to connect to a node
    '''

    pass_prompt = '[pP]assword:'
    user_prompt = '(l|L)ogin:|Username:'
    sess_prompt = r'[#\$>]|-TS#'
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
        r"(\[confirm\])",
        r"(\[SOL established\])",
    ])
    timeout = 60

    # pylint: disable=too-many-instance-attributes
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
        msg = 'SessionManager({}, port={}, username={}, password={}, protocol={})'
        return msg.format(self.ip, self.port, self.username, self.password, self.protocol)

    def getTelnetSession(self):
        msg = "Using telnet to connect {}".format(self.ip)
        cmd = 'telnet ' + self.ip
        if self.port:
            cmd = cmd + " " + str(self.port)
            msg = msg + " " + str(self.port)
        LOG.info(msg)
        return self.open_connection(cmd)

    def sigwinch_passthrough(self, _sig, _data):
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                              termios.TIOCGWINSZ, s))
        self.session.setwinsize(a[0], a[1])

    def getSshSession(self):
        msg = "Using ssh to connect {}".format(self.ip)
        cmd = "/usr/bin/ssh {} -l {} {}".format(SSH_OPTS, self.username, self.ip)
        if self.port:
            cmd = cmd + " -p {}".format(self.port)
            msg = msg + " {}".format(self.port)
        LOG.info(msg)
        return self.open_connection(cmd)

    def handle_terminal_resize(self):
        # use current terminal size initially
        rows, cols = map(int, os.popen('stty size', 'r').read().split())
        self.session.setwinsize(rows, cols)
        # trigger automatic resizing
        signal.signal(signal.SIGWINCH, self.sigwinch_passthrough)

    def open_connection(self, cmd):
        try:
            self.session = pexpect.spawn(cmd)
            self.session.timeout = self.timeout
            # to handle changes in terminal size
            self.handle_terminal_resize()

            if (self.log_file and self.log_file.strip() and
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

    def check_for_prompt(self, username=None, password=None, eof=False):
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
                    if not re.search("Last login|Username:", line):
                        self.session.sendline(username)
                elif i == 2:
                    if password_sent >= 2:
                        return False
                    else:
                        if username == getpass.getuser():
                            # username is same current user, prompt for password
                            curr_password = getpass.getpass()
                        else:
                            # try with different passwords if present
                            try:
                                curr_password = password[password_sent]
                            except IndexError:
                                curr_password = password[0]
                            LOG.info('Sending password %s', curr_password)
                        password_sent += 1
                    self.session.sendline(curr_password)
                elif i == 3:
                    return True
                elif i == 4:
                    self.session.sendline(' ')
                elif i == 5:
                    # TODO need to check for telnet only and not for console
                    self.session.sendline('')
                elif eof and i == 6:
                    # for reboot prompt
                    self.session.sendline('y')
        except KeyboardInterrupt:
            LOG.warn('KeyboardInterrupt')
        except pexpect.EOF:
            if not eof:
                raise
        except pexpect.TIMEOUT:
            LOG.error("Encountered timeout (> %ss) while waiting for prompt.",
                      self.session.timeout)
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
            raise EnvironmentError("Unable to connected to {}".format(self.ip))

    def isalive(self):
        return self.session and self.session.isalive()

    def interact(self):
        if not self.isalive():
            raise Exception("No active session for {}".format(self.ip))

        # FIXME: centos is echoing lines, to suppress it
        if self.session.logfile_read == sys.stdout:
            self.session.logfile_read = None
        else:
            # FIXME : logfile redirection doesn't display the prompt sometimes
            LOG.warn("Interactive session. hit return if u don't see the prompt")

        self.session.interact()

    @staticmethod
    def process_input_cmds(cmd_list):
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

    @staticmethod
    def is_eof(cmd):
        eof_cmds = [
            'l',
            'logout',
            'exit',
            'reload',
            'reboot',
            '/sbin/system-reboot',
        ]
        return cmd in eof_cmds

    # pylint: disable=too-many-arguments
    def execute_cmd(self, cmd_list, username=None, password=None, blocking=True,
                    return_output=False):
        if cmd_list:
            if not self.isalive():
                raise EOFError("No active session for {}".format(self.ip))

            for cmd in self.process_input_cmds(cmd_list).split(";"):
                _password = password
                cmd = cmd.strip()
                if cmd:
                    # for some telnet sessions, this is required
                    if self.extra_enter:
                        cmd += '\r'
                    if re.search('tail -f', cmd):
                        self.session.timeout = 86400
                        self.sess_prompt = "__NEVER_MATCH__"

                    # password to use for this specific command
                    if "_my_password:" in cmd:
                        cmd, _password = cmd.split("_my_password:")
                    self.session.sendline(cmd)
                    if blocking:
                        if not self.check_for_prompt(
                                username,
                                _password,
                                eof=self.is_eof(cmd),
                        ):
                            return False
            if return_output:
                return str(self.session.before) + str(self.session.after)
        return True
