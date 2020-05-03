'''
python utilities to perform 'tail -f' operation on remote file
'''

import sys
import re
import os
import logging
import optparse
import time
from datetime import datetime
from iputils import get_ip_from_name
from sess_mgr import SessionManager


logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s',
                    datefmt='%m/%d/%Y %T')
LOG = logging.getLogger(__name__)

# pylint: disable=too-many-instance-attributes
class File_Monitor(object):

    def __init__(self, *args):
        # testbed, username, password, path, filename, wait_for
        self.testbed = None
        self.login = None
        self.password = None
        self.wait_for = None
        self.filename = None
        self.path = None

        self.validate_input(*args)

        self.ip = get_ip_from_name(self.testbed)
        self.sess_mgr = SessionManager(
            ip=self.ip,
            username=self.login,
            password=self.password,
        )
        self.init_session()

    def compute_file_path(self):
        cmd = "ls -d /{}/results/*/Month_??/*/[0-9]?:[0-9]?:[0-9]?.* | tail -1"
        output = self.sess_mgr.execute_cmd(cmd.format(self.testbed), return_output=True)
        return '{}/{}'.format(output.splitlines()[1], self.filename)

    def init_session(self):
        self.sess_mgr.reconnect()
        self.sess_mgr.execute_cmd('stty columns 1000')
        self.sess_mgr.session.timeout = 100

    def get_latest_file(self):
        cmd = "find %s -name \"%s\" -mmin -1 -print -quit 2>/dev/null" \
           , (self.path, self.filename)
        while True:
            output = self.sess_mgr.execute_cmd(cmd, return_output=True)
            try:
                if not re.search('No such file or directory', output):
                    output = output.split("\n")
                    if len(output) >= 3:
                        return output[1]
            except Exception as e:
                LOG.exception(e)
                # usually session would close when there is an exception, reconnecting
                self.init_session()

            LOG.info("Log file not avialable. Will try after %ss ...", self.wait_for)
            time.sleep(self.wait_for)

    @staticmethod
    def to_bool(string):
        return re.search('^(t|true|1)$', string.strip().lower())

    def check_file_exists(self):
        cmd = "[[ -f %s ]] && echo True  || echo False", self.filename
        output = self.sess_mgr.execute_cmd(cmd, return_output=True)
        try:
            if not re.search('No such file or directory', output):
                output = output.split("\n")
                if len(output) >= 3:
                    return self.to_bool(output[1])
        except Exception as e:
            LOG.exception(e)
        return None

    def monitor_file(self):
        if not self.path:
            filename = self.compute_file_path()
        elif self.check_file_exists() is True:
            filename = self.filename
        else:
            filename = self.get_latest_file()
        cmd = "tail -f {}".format(filename)
        # 1 day timeout
        self.sess_mgr.session.timeout = 86400
        self.sess_mgr.sess_prompt = "__NEVER_MATCH__"
        self.sess_mgr.execute_cmd(cmd)

    @staticmethod
    def parse_cmdline_args(input_args):
        if not input_args:
            input_args = ["-h"]

        parser = optparse.OptionParser()
        parser.add_option("-t", "--testbed", action="store", dest="testbed",
                          default=os.uname()[1],
                          help="testbed name")
        parser.add_option("-w", "--wait", action="store", dest="wait_for",
                          default=5,
                          help="testbed name")
        parser.add_option("--password", action="store", dest="password",
                          default='tigris',
                          help="Specify the access password")
        parser.add_option("-l", "-u", "--login", "--username", action="store",
                          dest="login",
                          default=None,
                          help="Specify the access username")
        parser.add_option("-f", "--filename", action="store", dest="filename",
                          default='test_console*.txt',
                          help="file name to be monitored")
        parser.add_option("-p", "--path", action="store", dest="path",
                          default=None,
                          help="path where file is located")
        parser.add_option("--date", action="store", dest="date",
                          default=None,
                          help="date to represent path name foramt(dd/mm/yyyy)")
        (options, _args) = parser.parse_args(input_args)
        if options.login is None:
            options.login = options.testbed
        if options.date is not None:
            try:
                options.date = datetime.strptime(options.date, '%m/%d/%Y')
            except ValueError:
                LOG.error("Invalid date format '%s'. Should in %s", options.date, '%m/%d/%Y')
                raise
        else:
            options.date = datetime.now()

        return options

    def validate_input(self, input_args=None):
        LOG.debug('process and validate input args ...')
        if input_args:
            options = self.parse_cmdline_args(input_args.split(' '))
        else:
            options = self.parse_cmdline_args(sys.argv[1:])

        self.testbed = options.testbed
        if options.login:
            self.login = options.login
        else:
            self.login = self.testbed
        self.password = options.password
        self.path = options.path
        self.filename = options.filename
        self.wait_for = options.wait_for


if __name__ == '__main__':
    try:
        fileObj = File_Monitor()
        fileObj.monitor_file()
    except KeyboardInterrupt:
        LOG.warning("User interrupt. Terminating the process")
    except Exception:
        raise
