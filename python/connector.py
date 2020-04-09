'''
python utilities to interact with device remotely using ssh/telnet
'''
import os
import sys
import time
import optparse
import errno
import getpass
import logging
from iputils import is_ip_reachable, is_valid_ip, ip_to_name, name_to_ip, is_valid_port
from sess_mgr import SessionManager

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s',
                    datefmt='%m/%d/%Y %T')
LOG = logging.getLogger(__name__)

# pylint: disable=too-many-instance-attributes
class ConnectToNode(object):
    # populate nameservers info to resolve hostname
    NAMESERVERS = {}

    TESTBED_PASSWORD = None
    DUT_USERNAME = None
    DUT_PASSWORD = None
    ROOT_USERNAME = 'root'
    ROOT_PASSWORD = None

    def __init__(self, *args):
        self.username = None
        self.password = None
        self.cmd_username = self.DUT_USERNAME
        self.cmd_password = self.DUT_PASSWORD
        self.sess_mgr = None
        self.log_file = None
        self.node_full_name = None
        self.node_ip = None
        self.port = None
        self.cmd = None
        self.module = None
        self.testbed = None
        self.ip = None
        self.proto = None
        self.options = None

        self.status = self.validate_input(*args)

    def parse_cmdline_args(self, input_args):
        if not input_args:
            input_args = ["-h"]

        parser = optparse.OptionParser()
        parser.add_option("-n", "--node", "-d", "--dut", action="store",
                          default=None,
                          dest="node",
                          help="Specify the node name")
        parser.add_option("--ip", action="store", dest="ip",
                          default=None,
                          help="Specify the node ip")
        parser.add_option("--port", action="store", dest="port",
                          default=None,
                          help="Specify the console port")
        parser.add_option("-p", "--password", action="store", dest="password",
                          default=None,
                          help="Specify the access password")
        parser.add_option("-l", "-u", "--login", "--username", action="store",
                          dest="login",
                          default=None,
                          help="Specify the access username")
        parser.add_option("-r", "--root", action="store_true", dest="root",
                          default=False,
                          help="login as root")
        parser.add_option("-c", "--console", action="store_true", dest="console",
                          default=False,
                          help="To connect to the Terminal Console port")
        parser.add_option("--linux", action="store_true", dest="linux",
                          default=False,
                          help="To connect to the linux")
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                          default=False,
                          help="Verbose output")
        parser.add_option("--debug", action="store_true", dest="debug",
                          default=False,
                          help="Debug Mode")
        parser.add_option("-t", "--testbed", action="store", dest="testbed",
                          default=os.uname()[1],
                          help="testbed name")
        parser.add_option("--proto", "--protocol", action="store", dest="proto",
                          default="ssh",
                          help="telnet/ssh to access the Node")
        parser.add_option("--ping", action="store_true", dest="ping",
                          default=False,
                          help="ping to specified Node")
        parser.add_option("--exec", action="store", dest="cmd",
                          default="",
                          help="; seperated list of commands or a file with\
                          list of commands to be exected")
        parser.add_option("--logdir", action="store", dest="logdir",
                          default='/tmp/tdLogs',
                          help="log file path, will use if --log is specified")
        parser.add_option("--log", action="store_true", dest="log",
                          default=False,
                          help="enable logging, logs stored at --logdir=path")
        parser.add_option("--me", action="store_true", dest="me",
                          default=False,
                          help="to login as self")
        parser.add_option("--link", action="store", dest="link",
                          default=None,
                          help="to go to regress link directory")
        parser.add_option("-f", "--follow", action="store_true", dest="follow",
                          default=False,
                          help="to do tail on a file specified by link")

        (options, _args) = parser.parse_args(input_args)
        self.options = options

    def enable_logging(self, path, nodeName):
        try:
            os.mkdir(path)
        except OSError as e:
            assert e.errno == errno.EEXIST, e

        nodeName = nodeName.replace('.', '_')
        nodeName = nodeName + '_' + time.strftime("%d_%b_%Y_%H_%M_%S") + '.log'
        self.log_file = os.path.join(path, nodeName)
        hdlr = logging.FileHandler(self.log_file)
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s',
            datefmt='%m/%d/%Y %T')
        hdlr.setFormatter(formatter)
        LOG.addHandler(hdlr)
        # create empty log file
        try:
            os.system('touch {}'.format(self.log_file))
        except Exception:
            raise
        LOG.info('For logs, check %s', self.log_file)

    # pylint: disable=too-many-branches, too-many-statements
    def validate_input(self, input_args=None):
        LOG.debug('process and validate input args ...')
        if input_args:
            self.parse_cmdline_args(input_args.split(' '))
        else:
            self.parse_cmdline_args(sys.argv[1:])

        options = self.options
        self.cmd = options.cmd
        self.linux = options.linux
        self.console = options.console
        self.testbed = options.testbed
        self.testbed_ip = name_to_ip(self.testbed, searchin=self.NAMESERVERS)
        self.port = options.port
        self.ip = options.ip
        self.proto = options.proto
        self.node = options.node
        self.link = options.link
        self.me = options.me

        if self.link:
            self.process_link(follow=options.follow)

        if (options.verbose or options.debug or options.ping):
            LOG.setLevel(logging.DEBUG)

        # logging
        if options.log:
            log_prefix = "{}_{}".format(options.testbed, options.node)
            if self.console:
                log_prefix += "_cnsl"
            self.enable_logging(options.logdir, log_prefix)

        if options.root:
            self.username = self.ROOT_USERNAME
            self.password = self.ROOT_PASSWORD

        # use user specified credentials
        if options.login is not None:
            self.username = options.login

        if options.password is not None:
            self.password = options.password

        if self.me:
            self.username = getpass.getuser()

        if options.ping:
            if is_ip_reachable(self.ip):
                LOG.debug("%s is reachable", self.ip)
            else:
                LOG.debug("%s is not reachable", self.ip)
            # to skip connecting to the node
            return False

        self.update_connect_info()

        # LOG.debug("---- Node information ----")
        # for key, value in node.__dict__.items():
        #    LOG.debug("{:15} : {}".format(key, value))

        LOG.debug("---- Final information ----")
        LOG.debug('Testbed      : %s', self.testbed)
        LOG.debug('DUT          : %s', self.node)
        LOG.debug('Full Name    : %s', self.node_full_name)
        # LOG.debug('hypervisor   : %s', self.hypervisor)
        LOG.debug('ip           : %s', self.node_ip)
        LOG.debug('port         : %s', self.port)
        LOG.debug('Console      : %s', self.console)
        LOG.debug('Linux        : %s', self.linux)
        LOG.debug('usr/pass     : %s/%s', self.username, self.password)
        LOG.debug('CMD          : %s', self.cmd)
        LOG.debug('cmd usr/pass : %s/%s', self.cmd_username, self.cmd_password)

        if options.debug:
            return False

        assert is_valid_ip(self.testbed_ip),\
            "Invalid Testbed IP: {}".format(self.testbed_ip)

        if self.testbed_ip != self.ip:
            assert is_valid_ip(self.ip),\
                "Invalid IP: {}".format(self.ip)

            if self.console or self.port is not None:
                assert is_valid_port(self.port),\
                    "Invalid port: {}".format(self.port)

        return True

    def process_link(self, follow=False):
        link = filter(None, self.link.split('/'))
        testbed = link[1]
        if is_valid_ip(testbed):
            testbed = ip_to_name(testbed)

        # remove domain name
        self.testbed = testbed.split('.')[0]
        path = '/'.join([""] + [self.testbed] + link[2:-1])
        cmd = ['cd {}'.format(path)]
        if follow is True:
            file_name = link[-1]
            cmd.append("tail -f {}".format(os.path.join(path, file_name)))
        self.cmd = ";".join(cmd)

    def update_connect_info(self):
        '''
        helper method to determine the required commands/ip addresses
        to connect
        '''
        pass

    def update_to_execute_on_testbed(self, cmd):
        self.cmd = ";".join([cmd, self.cmd])
        self.cmd = self.cmd.strip().strip(';')
        self.ip = self.testbed_ip
        self.username = self.testbed
        self.password = self.TESTBED_PASSWORD
        self.port = None

    def connect(self):
        # connect only if parsing is successful or when debug flag is off
        if self.status is True:
            self.sess_mgr = SessionManager(
                ip=self.ip,
                port=self.port,
                username=self.username,
                password=self.password,
                protocol=self.proto,
                log_file=self.log_file,
            )
            self.sess_mgr.connect_to_node()
            self.sess_mgr.execute_cmd(
                self.cmd,
                username=self.cmd_username,
                password=self.cmd_password,
            )

    def interact(self):
        # interact only if parsing is successful or when debug flag is off
        if self.status is True:
            if self.sess_mgr is None:
                raise AttributeError('Session not yet created, \
                                     try connect before interact')
            elif self.sess_mgr.isalive():
                try:
                    self.sess_mgr.interact()
                except OSError:
                    self.sess_mgr.close_session()


if __name__ == '__main__':
    td = ConnectToNode()
    td.connect()
    td.interact()
