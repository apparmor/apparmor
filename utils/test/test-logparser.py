# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import unittest

from apparmor.common import AppArmorException
from apparmor.logparser import ReadLog
from common_test import AATest, setup_all_loops  # , setup_aa


class TestParseEvent(AATest):
    tests = ()

    def setUp(self):
        self.parser = ReadLog('', '', '')

    def test_parse_event_audit_1(self):
        event = 'type=AVC msg=audit(1345027352.096:499): apparmor="ALLOWED" operation="rename_dest" parent=6974 profile="/usr/sbin/httpd2-prefork//vhost_foo" name=2F686F6D652F7777772F666F6F2E6261722E696E2F68747470646F63732F61707061726D6F722F696D616765732F746573742F696D61676520312E6A7067 pid=20143 comm="httpd2-prefork" requested_mask="wc" denied_mask="wc" fsuid=30 ouid=30'
        parsed_event = self.parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/home/www/foo.bar.in/httpdocs/apparmor/images/test/image 1.jpg')
        self.assertEqual(parsed_event['profile'], '/usr/sbin/httpd2-prefork//vhost_foo')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], 'wc')

        self.assertIsNotNone(ReadLog.RE_LOG_ALL.search(event))

    def test_parse_event_audit_2(self):
        event = 'type=AVC msg=audit(1322614918.292:4376): apparmor="ALLOWED" operation="file_perm" parent=16001 profile=666F6F20626172 name="/home/foo/.bash_history" pid=17011 comm="bash" requested_mask="rw" denied_mask="rw" fsuid=0 ouid=1000'
        parsed_event = self.parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/home/foo/.bash_history')
        self.assertEqual(parsed_event['profile'], 'foo bar')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], 'rw')

        self.assertIsNotNone(ReadLog.RE_LOG_ALL.search(event))

    def test_parse_event_syslog_1(self):
        # from https://bugs.launchpad.net/apparmor/+bug/1399027
        event = '2014-06-09T20:37:28.975070+02:00 geeko kernel: [21028.143765] type=1400 audit(1402339048.973:1421): apparmor="ALLOWED" operation="open" profile="/home/cb/linuxtag/apparmor/scripts/hello" name="/dev/tty" pid=14335 comm="hello" requested_mask="rw" denied_mask="rw" fsuid=1000 ouid=0'
        parsed_event = self.parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/dev/tty')
        self.assertEqual(parsed_event['profile'], '/home/cb/linuxtag/apparmor/scripts/hello')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], 'rw')

        self.assertIsNotNone(ReadLog.RE_LOG_ALL.search(event))

    def test_parse_event_syslog_2(self):
        # from https://bugs.launchpad.net/apparmor/+bug/1399027
        event = 'Dec  7 13:18:59 rosa kernel: audit: type=1400 audit(1417954745.397:82): apparmor="ALLOWED" operation="open" profile="/home/simi/bin/aa-test" name="/usr/bin/" pid=3231 comm="ls" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0'
        parsed_event = self.parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/usr/bin/')
        self.assertEqual(parsed_event['profile'], '/home/simi/bin/aa-test')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], 'r')

        self.assertIsNotNone(ReadLog.RE_LOG_ALL.search(event))

    def test_parse_disconnected_path(self):
        # from https://bugzilla.opensuse.org/show_bug.cgi?id=918787
        event = 'type=AVC msg=audit(1424425690.883:716630): apparmor="ALLOWED" operation="file_mmap" info="Failed name lookup - disconnected path" error=-13 profile="/sbin/klogd" name="var/run/nscd/passwd" pid=25333 comm="id" requested_mask="r" denied_mask="r" fsuid=1002 ouid=0'
        parsed_event = self.parser.parse_event(event)

        self.assertEqual(parsed_event, {
            'aamode': 'ERROR',   # aamode for disconnected paths overridden aamode in parse_event()
            'active_hat': None,
            'attr': None,
            'denied_mask': 'r',
            'error_code': 13,
            'fsuid': 1002,
            'info': 'Failed name lookup - disconnected path',
            'magic_token': 0,
            'name': 'var/run/nscd/passwd',
            'name2': None,
            'operation': 'file_mmap',
            'ouid': 0,
            'parent': 0,
            'pid': 25333,
            'profile': '/sbin/klogd',
            'request_mask': 'r',
            'resource': 'Failed name lookup - disconnected path',
            'task': 0,
            'time': 1424425690,
            'family': None,
            'protocol': None,
            'sock_type': None,
            'class': None,
        })

        self.assertIsNotNone(ReadLog.RE_LOG_ALL.search(event))

    def test_get_rule_type(self):
        rules = [
            ('mount fstype=bpf options=(rw) random_label -> /sys/fs/bpf/,', 'mount'),
            ('unix send addr=@foo{a,b} peer=(label=splat),',                'unix'),
            ('userns create, # cmt',                                        'userns'),
            ('allow /tmp/foo ra,',                                          'file'),
            ('file rwix /foo,',                                             'file'),
            ('signal set=quit peer=unconfined,',                            'signal')
        ]
        for r, exp in rules:
            self.assertEqual(self.parser.get_rule_type(r)[0], exp)

        self.assertEqual(self.parser.get_rule_type('invalid rule,'), None)

    def test_create_rule_from_ev(self):
        events = [
            ('Sep  9 12:51:50 ubuntu-desktop kernel: [ 1612.746129] type=1400 audit(1284061910.975:672): apparmor="DENIED" operation="capable" parent=2663 profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/syscall_setpriority" pid=7292 comm="syscall_setprio" capability=23  capname="sys_nice"',                                                    'capability',       'capability sys_nice,'),
            ('[ 1612.746129] audit: type=1400 audit(1284061910.975:672): apparmor="DENIED" operation="capable" parent=2663 profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/syscall_setpriority" pid=7292 comm="syscall_setprio" capability=23  capname="sys_nice"',                                                                                    'capability',       'capability sys_nice,'),
            ('Sep  9 12:51:36 ubuntu-desktop kernel: [   97.492562] audit: type=1400 audit(1431116353.523:77): apparmor="DENIED" operation="change_profile" profile="/tests/regression/apparmor/changeprofile" pid=3459 comm="changeprofile" target="/tests/regression/apparmor/rename"',                                                                           'change_profile',   'change_profile -> /tests/regression/apparmor/rename,'),
            ('Jul 31 17:10:35 dbusdev-saucy-amd64 dbus[1692]: apparmor="DENIED" operation="dbus_method_call"  bus="session" name="org.freedesktop.DBus" path="/org/freedesktop/DBus" interface="org.freedesktop.DBus" member="Hello" mask="send" pid=2922 profile="/tmp/apparmor-2.8.0/tests/regression/apparmor/dbus_service" peer_profile="unconfined"',          'dbus',             'dbus send bus=session path=/org/freedesktop/DBus interface=org.freedesktop.DBus member=Hello peer=(label=unconfined),'),
            ('Jul 31 17:11:16 dbusdev-saucy-amd64 dbus[1692]: apparmor="DENIED" operation="dbus_bind"  bus="session" name="com.apparmor.Test" mask="bind" pid=2940 profile="/tmp/apparmor-2.8.0/tests/regression/apparmor/dbus_service"',                                                                                                                           'dbus',             'dbus bind bus=session name=com.apparmor.Test,'),
            ('type=AVC msg=audit(1345027352.096:499): apparmor="ALLOWED" operation="rename_dest" parent=6974 profile="/usr/sbin/httpd2-prefork//vhost_foo" name=2F686F6D652F7777772F666F6F2E6261722E696E2F68747470646F63732F61707061726D6F722F696D616765732F746573742F696D61676520312E6A7067 pid=20143 comm="httpd2-prefork" requested_mask="wc" denied_mask="wc" fsuid=30 ouid=30',
                                                                                                                                                                                                                                                                                                                                                                    'file',             'owner "/home/www/foo.bar.in/httpdocs/apparmor/images/test/image 1.jpg" w,'),  # noqa: E127
            ('2014-06-09T20:37:28.975070+02:00 geeko kernel: [21028.143765] type=1400 audit(1402339048.973:1421): apparmor="ALLOWED" operation="open" profile="/home/cb/linuxtag/apparmor/scripts/hello" name="/dev/tty" pid=14335 comm="hello" requested_mask="rw" denied_mask="rw" fsuid=1000 ouid=0',                                                            'file',             '/dev/tty rw,'),
            ('[ 4584.703379] audit: type=1400 audit(1680266735.359:69): apparmor="DENIED" operation="uring_sqpoll" class="io_uring" profile="/root/apparmor/tests/regression/apparmor/io_uring" pid=1320 comm="io_uring" requested="sqpoll" denied="sqpoll"',                                                                                                       'io_uring',         'io_uring sqpoll,'),
            ('[ 4584.491076] audit: type=1400 audit(1680266735.147:63): apparmor="DENIED" operation="uring_override" class="io_uring" profile="/root/apparmor/tests/regression/apparmor/io_uring" pid=1193 comm="io_uring" requested="override_creds" denied="override_creds" tcontext="/root/apparmor/tests/regression/apparmor/io_uring"',                        'io_uring',         'io_uring override_creds label=/root/apparmor/tests/regression/apparmor/io_uring,'),
            ('type=AVC msg=audit(1409700640.016:547457): apparmor="DENIED" operation="mount" info="failed mntpnt match" error=-13 profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/mount" name="/tmp/sdtest.19033-29001-MPfz98/mountpoint/" pid=19085 comm="mount" fstype="ext2" srcname="/dev/loop0/" flags="rw, mand"',                               'mount',            'mount fstype=ext2 options=(mand, rw) /dev/loop0/ -> /tmp/sdtest.19033-29001-MPfz98/mountpoint/,'),
            ('type=AVC msg=audit(1709108389.303:12383): apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match" error=-13 profile="/home/user/test/testmount" name="/tmp/foo/" pid=14155 comm="testmount" flags="ro, remount"',                                                                                                                'mount',            'mount options=(remount, ro) -> /tmp/foo/,'),
            ('type=AVC msg=audit(1709025786.045:43147): apparmor="DENIED" operation="umount" class="mount" profile="/home/user/test/testmount" name="/mnt/a/" pid=26697 comm="testmount"',                                                                                                                                                                          'mount',            'umount /mnt/a/,'),
            ('Apr 05 19:36:19 ubuntu kernel: audit: type=1400 audit(1649187379.660:255): apparmor="DENIED" operation="create" profile="/root/apparmor/tests/regression/apparmor/posix_mq_rcv" name="/queuename" pid=791 comm="posix_mq_rcv" requested="create" denied="create" class="posix_mqueue" fsuid=0 ouid=0',                                                'mqueue',           'mqueue create type=posix /queuename,'),
            ('Apr 05 19:36:29 ubuntu kernel: audit: type=1400 audit(1649187389.828:262): apparmor="DENIED" operation="open" profile="/root/apparmor/tests/regression/apparmor/posix_mq_rcv" name="/queuename" pid=848 comm="posix_mq_rcv" requested="read create" denied="read" class="posix_mqueue" fsuid=0 ouid=0',                                               'mqueue',           'mqueue read type=posix /queuename,'),
            ('Apr  5 19:30:56 precise-amd64 kernel: [153073.826757] type=1400 audit(1308766940.698:3704): apparmor="DENIED" operation="sendmsg" parent=24737 profile="/usr/bin/evince-thumbnailer" pid=24743 comm="evince-thumbnai" laddr=192.168.66.150 lport=765 faddr=192.168.66.200 fport=2049 family="inet" sock_type="stream" protocol=6',                    'network',          'network inet stream ip=192.168.66.150 port=765 peer=(ip=192.168.66.200 port=2049),'),
            ('Apr  5 19:31:04 precise-amd64 kernel: [153073.826757] type=1400 audit(1308766940.698:3704): apparmor="DENIED" operation="sendmsg" parent=24737 profile="/usr/bin/evince-thumbnailer" pid=24743 comm="evince-thumbnai" lport=765 fport=2049 family="inet" sock_type="stream" protocol=6',                                                              'network',          'network inet stream port=765 peer=(port=2049),'),
            ('type=AVC msg=audit(1409700678.384:547594): apparmor="DENIED" operation="pivotroot" profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/pivot_root" name="/tmp/sdtest.21082-7446-EeefO6/new_root/" pid=21162 comm="pivot_root" srcname="/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/"',                                                    'pivot_root',       'pivot_root oldroot=/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/ /tmp/sdtest.21082-7446-EeefO6/new_root/,'),
            ('type=AVC msg=audit(1409700683.304:547661): apparmor="DENIED" operation="ptrace" profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/ptrace" pid=22465 comm="ptrace" requested_mask="tracedby" denied_mask="tracedby" peer="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/ptrace"',                                                     'ptrace',           'ptrace tracedby peer=/home/ubuntu/bzr/apparmor/tests/regression/apparmor/ptrace,'),
            ('type=AVC msg=audit(1409438250.564:201): apparmor="DENIED" operation="signal" profile="/usr/bin/pulseaudio" pid=2531 comm="pulseaudio" requested_mask="send" denied_mask="send" signal=term peer="/usr/bin/pulseaudio///usr/lib/pulseaudio/pulse/gconf-helper"',                                                                                       'signal',           'signal send set=term peer=/usr/bin/pulseaudio///usr/lib/pulseaudio/pulse/gconf-helper,'),
            ('type=AVC msg=audit(1711454639.955:322): apparmor="DENIED" operation="connect" class="net" profile="/home/user/test/client.py" pid=80819 comm="client.py" family="unix" sock_type="stream" protocol=0 requested="send receive connect" denied="send receive connect" addr=none peer_addr="@test_abstract_socket" peer="/home/user/test/server.py"',    'unix',             'unix (connect, receive, send) type=stream peer=(addr=@test_abstract_socket),'),
            ('type=AVC msg=audit(1711214183.107:298): apparmor="DENIED" operation="connect" class="net" profile="/home/user/test/client.py" pid=65262 comm="server.py" family="unix" sock_type="stream" protocol=0 requested="send receive accept" denied="send accept" addr="@test_abstract_socket" peer_addr=none peer="unconfined"',                             'unix',             'unix (accept, send) type=stream addr=@test_abstract_socket,'),
            ('[  176.385388] audit: type=1400 audit(1666891380.570:78): apparmor="DENIED" operation="userns_create" class="namespace" profile="/usr/bin/userns_child_exec" pid=1785 comm="userns_child_ex" requested="userns_create" denied="userns_create"',                                                                                                       'userns',           'userns create,'),
            ('[  429.272003] audit: type=1400 audit(1720613712.153:168): apparmor="AUDIT" operation="userns_create" class="namespace" info="Userns create - transitioning profile" profile="unconfined" pid=5630 comm="unshare" requested="userns_create" target="unprivileged_userns" execpath="/usr/bin/unshare"',                                                'userns',           'userns create,'),
        ]
        for ev, expected_type, expected_rule in events:
            parsed_event = self.parser.parse_event(ev)
            r = self.parser.create_rule_from_ev(parsed_event)
            self.assertIsNotNone(r)
            clean_rule = r.get_clean()
            self.assertEqual(self.parser.get_rule_type(clean_rule)[0], expected_type)
            self.assertEqual(expected_rule, clean_rule)


class TestParseEventForTreeInvalid(AATest):
    tests = (
        ('type=AVC msg=audit(1556742870.707:3614): apparmor="ALLOWED" operation="open" profile="/bin/hello" name="/dev/tty" pid=12856 comm="hello" requested_mask="wr" denied_mask="foo" fsuid=1000 ouid=0',   AppArmorException),  # invalid file permissions "foo"
        ('type=AVC msg=audit(1556742870.707:3614): apparmor="ALLOWED" operation="open" profile="/bin/hello" name="/dev/tty" pid=12856 comm="hello" requested_mask="wr" denied_mask="wr::w" fsuid=1000 ouid=0', AppArmorException),  # "wr::w" mixes owner and other
    )

    def setUp(self):
        self.parser = ReadLog('', '', '')

    def _fake_profile_exists(self, program):
        return True

    def test_invalid_create_rule_from_ev(self):
        events = [
            'Jul 31 17:11:16 dbusdev-saucy-amd64 dbus[1692]: apparmor="DENIED" operation="invalid"  bus="session" name="com.apparmor.Test" mask="bind" pid=2940 profile="/tmp/apparmor-2.8.0/tests/regression/apparmor/dbus_service"',  # operation is invalid
            'type=AVC msg=audit(1709108389.303:12383): apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match" error=-13 profile="/home/user/test/testmount" name="/tmp/foo/" pid=14155 comm="testmount" flags="invalid"',  # invalid flag
            '[  176.385388] audit: type=1400 audit(1666891380.570:78): apparmor="DENIED" operation="userns_create" class="namespace" profile="/usr/bin/userns_child_exec" pid=1785 comm="userns_child_ex" requested="userns_create" denied="invalid"'  # invalid denied
        ]
        for ev in events:
            parsed_event = self.parser.parse_event(ev)
            r = self.parser.create_rule_from_ev(parsed_event)
            self.assertEqual(r, None)

    def _run_test(self, params, expected):
        self.parser.profile_exists = self._fake_profile_exists  # inject fake function that always returns True - much easier than handing over a ProfileList object to __init__
        parsed_event = self.parser.parse_event(params)
        with self.assertRaises(expected):
            self.parser.parse_event_for_tree(parsed_event)


setup_all_loops(__name__)
if __name__ == "__main__":
    unittest.main(verbosity=1)
