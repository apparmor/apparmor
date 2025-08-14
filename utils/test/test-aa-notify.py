#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#    Copyright (C) 2019 Otto Kekäläinen
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import pwd
import signal
import subprocess
import sys
import time
import unittest
from tempfile import NamedTemporaryFile
from datetime import datetime

import apparmor.aa as aa
from common_test import AATest, setup_aa, setup_all_loops

# The location of the aa-notify utility can be overridden by setting
# the APPARMOR_NOTIFY environment variable; this is useful for running
# these tests in an installed environment
aanotify_bin = ["../aa-notify"]


# http://www.chiark.greenend.org.uk/ucgi/~cjwatson/blosxom/2009-07-02-python-sigpipe.html
# This is needed so that the subprocesses that produce endless output
# actually quit when the reader goes away.
def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def cmd(command):
    """Try to execute given command (array) and return its stdout, or return
    a textual error if it failed."""

    try:
        sp = subprocess.Popen(
            command,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            preexec_fn=subprocess_setup
        )
    except OSError as e:
        return 127, str(e)

    stdout, stderr = sp.communicate(input)

    # If there was some error output, show that instead of stdout to ensure
    # test fails and does not mask potentially major warnings and errors.
    if stderr:
        out = stderr
    else:
        out = stdout

    return sp.returncode, out.decode('utf-8')


class AANotifyBase(AATest):

    def create_logfile_contents(_time):
        """Create temporary log file with 30 entries of different age"""

        test_logfile_contents_999_days_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(_time, 3) - 60 * 60 * 24 * 999)  # noqa: E128

        test_logfile_contents_30_days_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(_time, 3) - 60 * 60 * 24 * 30)  # noqa: E128

        test_logfile_contents_unrelevant_entries = \
'''Feb  1 19:35:44 XPS-13-9370 kernel: [99848.048761] audit: type=1400 audit(1549042544.968:72): apparmor="STATUS" operation="profile_load" profile="unconfined" name="/snap/core/6350/usr/lib/snapd/snap-confine" pid=12871 comm="apparmor_parser"
Feb  2 00:40:09 XPS-13-9370 kernel: [103014.549071] audit: type=1400 audit(1549060809.600:89): apparmor="STATUS" operation="profile_load" profile="unconfined" name="docker-default" pid=17195 comm="apparmor_parser"
Feb  4 20:05:42 XPS-13-9370 kernel: [132557.202931] audit: type=1400 audit(1549303542.661:136): apparmor="STATUS" operation="profile_replace" info="same as current profile, skipping" profile="unconfined" name="snap.atom.apm" pid=11306 comm="apparmor_parser"
'''  # noqa: E128

        test_logfile_contents_0_seconds_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(_time, 3))  # noqa: E128

        return test_logfile_contents_999_days_old \
            + test_logfile_contents_30_days_old \
            + test_logfile_contents_unrelevant_entries \
            + test_logfile_contents_0_seconds_old

    @classmethod
    def setUpClass(cls):
        file_current = NamedTemporaryFile("w+", prefix='test-aa-notify-', delete=False)
        file_last_login = NamedTemporaryFile("w+", prefix='test-aa-notify-', delete=False)
        cls.test_logfile_current = file_current.name
        cls.test_logfile_last_login = file_last_login.name

        current_time_contents = cls.create_logfile_contents(time.time())
        file_current.write(current_time_contents)

        if os.path.isfile('/var/log/wtmp'):
            if os.name == "posix":
                username = pwd.getpwuid(os.geteuid()).pw_name
            else:
                username = os.environ.get('USER')
                if not username and hasattr(os, 'getlogin'):
                    username = os.getlogin()
            if 'SUDO_USER' in os.environ:
                username = os.environ.get('SUDO_USER')

            return_code, output = cmd(['last', username, '--fullnames', '--time-format', 'iso'])
            output = output.split('\n')[0]  # the first line is enough
            # example of output (util-linux last command):
            # ubuntu  tty7         :0               2024-01-05T14:29:11-03:00   gone - no logout
            # example of output (wtmpdb last command, local login):
            # ubuntu  tty7                          2025-01-15T09:32:49-0800   - still logged in
            # example of output (wtmpdb last command, remote login)
            # ubuntu  tty7         192.168.122.1    2024-01-05T14:29:11-03:00   gone - no logout
            # example of output (wtmpdb last command, login via lxd-agent)
            # ubuntu                                 2025-03-18T00:34:25+0000  - still logged in
            if output.startswith(username):
                for col in range(3, 1, -1):
                    try:
                        last_login = output.split()[col]
                        last_login_epoch = datetime.fromisoformat(last_login).timestamp()
                        # add 60 seconds to the epoch so that the time in the logs are AFTER login time
                        last_login_contents = cls.create_logfile_contents(last_login_epoch + 60)
                        file_last_login.write(last_login_contents)
                        break
                    except (IndexError, ValueError):
                        continue

    @classmethod
    def tearDownClass(cls):
        """Remove temporary log file after tests ended"""

        if cls.test_logfile_current and os.path.exists(cls.test_logfile_current):
            os.remove(cls.test_logfile_current)
        if cls.test_logfile_last_login and os.path.exists(cls.test_logfile_last_login):
            os.remove(cls.test_logfile_last_login)


class AANotifyTest(AANotifyBase):

    # The Perl aa-notify script was written so, that it will checked for kern.log
    # before printing help when invoked without arguments (sic!).
    @unittest.skipUnless(os.path.isfile('/var/log/kern.log'), 'Requires kern.log on system')
    def test_no_arguments(self):
        """Test using no arguments at all"""

        expected_return_code = 0
        expected_output_has = 'usage: aa-notify'

        return_code, output = cmd(aanotify_bin)
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    def test_help_contents(self):
        """Test output of help text"""

        expected_return_code = 0
        expected_output_1 = \
'''usage: aa-notify [-h] [-p] [--display DISPLAY] [--xauthority XAUTHORITY]
                 [-f FILE] [-l] [-s NUM] [-v] [-u USER] [-w NUM]
                 [--prompt-filter PF] [--debug] [--filter.profile PROFILE]
                 [--filter.operation OPERATION] [--filter.name NAME]
                 [--filter.denied DENIED] [--filter.family FAMILY]
                 [--filter.socket SOCKET]

Display AppArmor notifications or messages for DENIED entries.
'''  # noqa: E128

        expected_output_2 = \
'''
  -h, --help            show this help message and exit
  -p, --poll            poll AppArmor logs and display notifications
  --display DISPLAY     set the DISPLAY environment variable (might be needed if
                        sudo resets $DISPLAY)
  --xauthority XAUTHORITY
                        set the XAUTHORITY environment variable (might be needed
                        if sudo resets XAUTHORITY)
  -f, --file FILE       search FILE for AppArmor messages
  -l, --since-last      display stats since last login
  -s, --since-days NUM  show stats for last NUM days (can be used alone or with
                        -p)
  -v, --verbose         show messages with stats
  -u, --user USER       user to drop privileges to when not using sudo
  -w, --wait NUM        wait NUM seconds before displaying notifications (with
                        -p)
  --prompt-filter PF    kind of operations which display a popup prompt
  --debug               debug mode

Filtering options:
  Filters are used to reduce the output of information to only those entries
  that will match the filter. Filters use Python's regular expression syntax.

  --filter.profile PROFILE
                        regular expression to match the profile
  --filter.operation OPERATION
                        regular expression to match the operation
  --filter.name NAME    regular expression to match the name
  --filter.denied DENIED
                        regular expression to match the denied mask
  --filter.family FAMILY
                        regular expression to match the network family
  --filter.socket SOCKET
                        regular expression to match the network socket type
'''  # noqa: E128

        if sys.version_info[:2] < (3, 13):
            # Python 3.13 tweaked argparse output [1]. When running on older
            # Python versions, we adapt the expected output to match.
            #
            # https://github.com/python/cpython/pull/103372
            patches = [(
                ', --file FILE     ',
                ' FILE, --file FILE',
            ), (
                ', --since-days NUM  show stats for last NUM days (can be used alone or with',
                ' NUM, --since-days NUM\n'
                + '                        show stats for last NUM days (can be used alone or with',
            ), (
                ', --user USER     ',
                ' USER, --user USER',
            ), (
                ', --wait NUM    ',
                ' NUM, --wait NUM',
            )]
            for patch in patches:
                expected_output_2 = expected_output_2.replace(patch[0], patch[1])

        return_code, output = cmd(aanotify_bin + ['--help'])
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)

        self.assertIn(expected_output_1, output)
        self.assertIn(expected_output_2, output)

    def test_entries_since_100_days(self):
        """Test showing log entries since 100 days"""

        expected_return_code = 0
        expected_output_has = 'AppArmor denials: 20 (since'

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile_current, '-s', '100'])
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_entries_since_login(self):
        """Test showing log entries since last login"""

        expected_return_code = 0
        expected_output_has = 'AppArmor denials: 10 (since'

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile_last_login, '-l'])
        if "ERROR: Could not find last login" in output:
            self.skipTest('Could not find last login')
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_entries_since_login_verbose(self):
        """Test showing log entries since last login in verbose mode"""

        expected_return_code = 0
        expected_output_has = \
'''Profile: libreoffice-soffice
Operation: exec
Name: /bin/uname
Denied: x
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_inherit
Name: /dev/null
Denied: w
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /bin/uname
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /lib/x86_64-linux-gnu/ld-2.27.so
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /etc/ld.so.cache
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /lib/x86_64-linux-gnu/libc-2.27.so
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /lib/x86_64-linux-gnu/libc-2.27.so
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /usr/lib/locale/locale-archive
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice
Operation: exec
Name: /usr/bin/file
Denied: x
Logfile: {logfile}

Profile: libreoffice-soffice//null-/usr/bin/file
Operation: file_mmap
Name: /usr/bin/file
Denied: rm
Logfile: {logfile}

AppArmor denials: 10 (since'''.format(logfile=self.test_logfile_last_login)  # noqa: E128

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile_last_login, '-l', '-v'])
        if "ERROR: Could not find last login" in output:
            self.skipTest('Could not find last login')
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)


class AANotifyProfileFilterTest(AANotifyBase):

    def test_profile_regex_since_100_days(self):
        profile_tests = (
            (['--filter.profile', 'libreoffice'], (0, 'AppArmor denials: 20 (since')),
            (['--filter.profile', 'libreoffice-soffice'], (0, 'AppArmor denials: 20 (since')),
            (['--filter.profile', 'libreoffice-soffice$'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.profile', '^libreoffice-soffice$'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/bin/uname'], (0, 'AppArmor denials: 14 (since')),
            (['--filter.profile', 'uname'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', '.*uname'], (0, 'AppArmor denials: 14 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/.*'], (0, 'AppArmor denials: 16 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/foo'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', 'libreoffice-soffice/foo'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', 'bar'], (0, 'AppArmor denials: 0 (since')),
        )
        days_params = ['-f', self.test_logfile_current, '-s', '100']

        for test in profile_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + days_params + params)
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_profile_regex_since_login(self):
        profile_tests = (
            (['--filter.profile', 'libreoffice'], (0, 'AppArmor denials: 10 (since')),
            (['--filter.profile', 'libreoffice-soffice'], (0, 'AppArmor denials: 10 (since')),
            (['--filter.profile', 'libreoffice-soffice$'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.profile', '^libreoffice-soffice$'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/bin/uname'], (0, 'AppArmor denials: 7 (since')),
            (['--filter.profile', 'uname'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', '.*uname'], (0, 'AppArmor denials: 7 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/.*'], (0, 'AppArmor denials: 8 (since')),
            (['--filter.profile', 'libreoffice-soffice//null-/foo'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', 'libreoffice-soffice/foo'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.profile', 'bar'], (0, 'AppArmor denials: 0 (since')),
        )
        login_params = ['-f', self.test_logfile_last_login, '-l']

        for test in profile_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + login_params + params)
                if 'ERROR: Could not find last login' in output:
                    self.skipTest('Could not find last login')
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)


class AANotifyOperationFilterTest(AANotifyBase):

    def test_operation_regex_since_100_days(self):
        operation_tests = (
            (['--filter.operation', 'exec'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.operation', 'file_inherit'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.operation', 'file_mmap'], (0, 'AppArmor denials: 8 (since')),
            (['--filter.operation', 'open'], (0, 'AppArmor denials: 6 (since')),
            (['--filter.operation', 'file.*'], (0, 'AppArmor denials: 10 (since')),
            (['--filter.operation', 'profile_load'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'profile_replace'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'bar'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'userns_create'], (0, 'AppArmor denials: 0 (since')),
        )
        days_params = ['-f', self.test_logfile_current, '-s', '100']

        for test in operation_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + days_params + params)
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_operation_regex_since_login(self):
        operation_tests = (
            (['--filter.operation', 'exec'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.operation', 'file_inherit'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.operation', 'file_mmap'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.operation', 'open'], (0, 'AppArmor denials: 3 (since')),
            (['--filter.operation', 'file.*'], (0, 'AppArmor denials: 5 (since')),
            (['--filter.operation', 'profile_load'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'profile_replace'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'bar'], (0, 'AppArmor denials: 0 (since')),
            (['--filter.operation', 'userns_create'], (0, 'AppArmor denials: 0 (since')),
        )
        login_params = ['-f', self.test_logfile_last_login, '-l']

        for test in operation_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + login_params + params)
                if 'ERROR: Could not find last login' in output:
                    self.skipTest('Could not find last login')
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)


class AANotifyNameFilterTest(AANotifyBase):

    def test_name_regex_since_100_days(self):
        name_tests = (
            (['--filter.name', '/bin/uname'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.name', '/dev/null'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/lib/x86_64-linux-gnu/ld-2.27.so'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/lib/x86_64-linux-gnu/libc-2.27.so'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.name', '/etc/ld.so.cache'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/usr/lib/locale/locale-archive'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/usr/bin/file'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.name', '/'], (0, 'AppArmor denials: 20 (since')),
            (['--filter.name', '/.*'], (0, 'AppArmor denials: 20 (since')),
            (['--filter.name', '.*bin.*'], (0, 'AppArmor denials: 8 (since')),
            (['--filter.name', '/(usr/)?bin.*'], (0, 'AppArmor denials: 8 (since')),
            (['--filter.name', '/foo'], (0, 'AppArmor denials: 0 (since')),
        )
        days_params = ['-f', self.test_logfile_current, '-s', '100']

        for test in name_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + days_params + params)
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_name_regex_since_login(self):
        name_tests = (
            (['--filter.name', '/bin/uname'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/dev/null'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.name', '/lib/x86_64-linux-gnu/ld-2.27.so'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.name', '/lib/x86_64-linux-gnu/libc-2.27.so'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/etc/ld.so.cache'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.name', '/usr/lib/locale/locale-archive'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.name', '/usr/bin/file'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.name', '/'], (0, 'AppArmor denials: 10 (since')),
            (['--filter.name', '/.*'], (0, 'AppArmor denials: 10 (since')),
            (['--filter.name', '.*bin.*'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.name', '/(usr/)?bin.*'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.name', '/foo'], (0, 'AppArmor denials: 0 (since')),
        )
        login_params = ['-f', self.test_logfile_last_login, '-l']

        for test in name_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + login_params + params)
                if 'ERROR: Could not find last login' in output:
                    self.skipTest('Could not find last login')
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)


class AANotifyDeniedFilterTest(AANotifyBase):

    def test_denied_regex_since_100_days(self):
        denied_tests = (
            (['--filter.denied', 'x'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.denied', 'w'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.denied', 'rm'], (0, 'AppArmor denials: 8 (since')),
            (['--filter.denied', 'r'], (0, 'AppArmor denials: 14 (since')),
            (['--filter.denied', '^r$'], (0, 'AppArmor denials: 6 (since')),
            (['--filter.denied', 'x|w'], (0, 'AppArmor denials: 6 (since')),
            (['--filter.denied', '^(?!rm).*'], (0, 'AppArmor denials: 12 (since')),
            (['--filter.denied', '.(?!m).*'], (0, 'AppArmor denials: 12 (since')),
            (['--filter.denied', 'r.?'], (0, 'AppArmor denials: 14 (since')),
        )
        days_params = ['-f', self.test_logfile_current, '-s', '100']

        for test in denied_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + days_params + params)
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_denied_regex_since_login(self):
        denied_tests = (
            (['--filter.denied', 'x'], (0, 'AppArmor denials: 2 (since')),
            (['--filter.denied', 'w'], (0, 'AppArmor denials: 1 (since')),
            (['--filter.denied', 'rm'], (0, 'AppArmor denials: 4 (since')),
            (['--filter.denied', 'r'], (0, 'AppArmor denials: 7 (since')),
            (['--filter.denied', '^r$'], (0, 'AppArmor denials: 3 (since')),
            (['--filter.denied', 'x|w'], (0, 'AppArmor denials: 3 (since')),
            (['--filter.denied', '^(?!rm).*'], (0, 'AppArmor denials: 6 (since')),
            (['--filter.denied', '.(?!m).*'], (0, 'AppArmor denials: 6 (since')),
            (['--filter.denied', 'r.?'], (0, 'AppArmor denials: 7 (since')),
        )
        login_params = ['-f', self.test_logfile_last_login, '-l']

        for test in denied_tests:
            params = test[0]
            expected = test[1]

            with self.subTest(params=params, expected=expected):
                expected_return_code = expected[0]
                expected_output_has = expected[1]

                return_code, output = cmd(aanotify_bin + login_params + params)
                if 'ERROR: Could not find last login' in output:
                    self.skipTest('Could not find last login')
                result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
                self.assertEqual(expected_return_code, return_code, result + output)
                result = 'Got output "{}", expected "{}"\n'.format(output, expected_output_has)
                self.assertIn(expected_output_has, output, result + output)


setup_aa(aa)  # Wrapper for aa.init_aa()
setup_all_loops(__name__)
if __name__ == '__main__':
    if 'APPARMOR_NOTIFY' in os.environ:
        aanotify_bin = [os.environ['APPARMOR_NOTIFY']]

    if sys.executable:
        aanotify_bin = [sys.executable] + aanotify_bin

    if '__AA_CONFDIR' in os.environ:
        aanotify_bin = aanotify_bin + ['--configdir', os.getenv('__AA_CONFDIR')]

    unittest.main(verbosity=1)
