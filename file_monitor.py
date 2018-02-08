#!/usr/bin/python

from utils import SessionManager, IpUtils
import time
from datetime import datetime
import optparse
import os
import sys
import re

DNS_SUFFIX = ''


class File_Monitor(object):

    def __init__(self, testbed, username, password, path, filename, wait_for):
        self.testbed = testbed
        self.ip = IpUtils.get_ip_from_name(self.testbed, DNS_SUFFIX)
        self.wait_for = wait_for
        self.filename = filename
        self.path = path
        self.sess_mgr = SessionManager(
            ip=self.ip,
            username=testbed,
            password=password,
        )
        self.init_session()

    def init_session(self):
        self.sess_mgr.reconnect()
        self.sess_mgr.execute_cmd('stty columns 1000')
        self.sess_mgr.session.timeout = 100

    def get_latest_file(self):
        cmd = "find %s -name \"%s\" -mmin -1 -print -quit" % (self.path, self.filename)
        while True:
            output = self.sess_mgr.execute_cmd(cmd, return_output=True)
            try:
                if not re.search('No such file or directory', output):
                    output = output.split("\n")
                    if len(output) >= 3:
                        return output[1]
            except Exception as e:
                print "Got Exception '%s'" % str(e)
                # usually session would close when there is an exception, reconnecting
                self.init_session()

            print "Log file not avialable. Will try after %ss ..." % self.wait_for
            time.sleep(self.wait_for)

    def monitor_file(self):
        filename = self.get_latest_file()
        cmd = "tail -f %s" % filename
        # 1 day timeout
        self.sess_mgr.session.timeout = 86400
        self.sess_mgr.sess_prompt = "__NEVER_MATCH__"
        self.sess_mgr.execute_cmd(cmd)


def parse_cmdline_args(input_args):
    assert len(input_args) != 0, "Specify input args"

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
    (options, args) = parser.parse_args(input_args)
    if options.login is None:
        options.login = options.testbed
    try:
        if options.date is not None:
            options.date = datetime.strptime(options.date, '%m/%d/%Y')
        else:
            options.date = datetime.now()
    except Exception:
        print("Invalid date format '%s'. Should in '%m/%d/%Y'" % options.date)
        sys.exit(-1)

    if options.path is None:
        options.path = '/%s/results/%s' % (
            options.testbed, options.date.strftime('%Y/Month_%m/%b_%d'))
    return options


if __name__ == '__main__':
    try:
        options = parse_cmdline_args(sys.argv[1:])
        fileObj = File_Monitor(options.testbed, options.login, options.password,
                               options.path, options.filename, options.wait_for)
        fileObj.monitor_file()
    except KeyboardInterrupt:
        print "User interrupt. Terminating the process"
        pass
    except Exception:
        raise
