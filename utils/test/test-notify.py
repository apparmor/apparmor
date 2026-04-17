#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2021 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest

from apparmor.common import AppArmorBug
from apparmor.notify import get_last_login_timestamp, get_last_login_timestamp_wtmp, sane_timestamp, get_event_special_type, set_userns_special_profile
from apparmor.logparser import ReadLog
from common_test import AATest, setup_all_loops


class TestGet_last_login_timestamp(AATest):
    tests = (
        #  wtmp file         lastlog2 db         user           expected login timestamp
        (('wtmp-x86_64',    'lastlog2.db',     'root'),         1723749426),  # Thu Aug 15 19:17:06 UTC 2024
        (('wtmp-x86_64',    'lastlog2.db',     'whoever'),      0),
        (('wtmp-x86_64',    'lastlog2.db',     'cb'),           1726995194),  # Sun Sep 22 08:53:14 UTC 2024
        (('wtmp-x86_64',    'lastlog2.db',     'sddm'),         1721084423),  # Mon Jul 15 23:00:23 UTC 2024

        (('wtmp-x86_64',    'does-not-exist',   'root'),        1635070346),  # Sun Oct 24 12:12:26 CEST 2021
        (('wtmp-x86_64',    'does-not-exist',   'whoever'),     0),

        (('wtmp-s390x',     'lastlog2.db',      'root'),        1723749426),  # Thu Aug 15 19:17:06 UTC 2024
        (('wtmp-s390x',     'lastlog2.db',      'whoever'),     0),
        (('wtmp-s390x',     'does-not-exist',   'linux1'),      1626368772),  # Thu Jul 15 19:06:12 CEST 2021
        (('wtmp-s390x',     'does-not-exist',   'whoever'),     0),

        (('wtmp-aarch64',   'lastlog2.db',      'whoever'),     0),
        (('wtmp-aarch64',   'does-not-exist',   'guillaume'),   1611562789),  # Mon Jan 25 09:19:49 CET 2021
        (('wtmp-aarch64',   'does-not-exist',   'whoever'),     0),

        (('wtmp-truncated', 'does-not-exist',   'root'),        0),
        (('wtmp-truncated', 'does-not-exist',   'whoever'),     0),
    )

    def _run_test(self, params, expected):
        wtmpdb, lastlog2_db, user = params
        wtmpdb = 'wtmp-examples/' + wtmpdb
        lastlog2_db = 'wtmp-examples/' + lastlog2_db
        self.assertEqual(get_last_login_timestamp(user, wtmpdb, lastlog2_db), expected)

    def test_date_1999(self):
        with self.assertRaises(AppArmorBug):
            # wtmp-x86_64-past is hand-edited to Thu Dec 30 00:00:00 CET 1999, which is outside the expected data range
            get_last_login_timestamp('root', 'wtmp-examples/wtmp-x86_64-past', 'wtmp-examples/does-not-exist')

    def test_nonexistent_file(self):
        self.assertEqual(get_last_login_timestamp('root', filename='/does/not/exist', lastlog2_db='/also/does/not/exist'), 0)


class TestSane_timestamp(AATest):
    tests = (
        (2524704400, False),  # Sun Jan  2 03:46:40 CET 2050
        (944780400, False),  # Fri Dec 10 00:00:00 CET 1999
        (1635026400, True),  # Sun Oct 24 00:00:00 CEST 2021
    )

    def _run_test(self, params, expected):
        self.assertEqual(sane_timestamp(params), expected)


class TestGet_last_login_timestamp_wtmp(AATest):
    tests = (
        (('wtmp-x86_64',    'root'),      1635070346),  # Sun Oct 24 12:12:26 CEST 2021
        (('wtmp-x86_64',    'whoever'),   0),
        (('wtmp-s390x',     'root'),      1626368763),  # Thu Jul 15 19:06:03 CEST 2021
        (('wtmp-s390x',     'linux1'),    1626368772),  # Thu Jul 15 19:06:12 CEST 2021
        (('wtmp-s390x',     'whoever'),   0),
        (('wtmp-aarch64',   'guillaume'), 1611562789),  # Mon Jan 25 09:19:49 CET 2021
        (('wtmp-aarch64',   'whoever'),   0),
        (('wtmp-truncated', 'root'),      0),
        (('wtmp-truncated', 'whoever'),   0),
    )

    def _run_test(self, params, expected):
        filename, user = params
        filename = 'wtmp-examples/' + filename
        self.assertEqual(get_last_login_timestamp_wtmp(user, filename), expected)

    def test_date_1999(self):
        with self.assertRaises(AppArmorBug):
            # wtmp-x86_64-past is hand-edited to Thu Dec 30 00:00:00 CET 1999, which is outside the expected data range
            get_last_login_timestamp_wtmp('root', 'wtmp-examples/wtmp-x86_64-past')


class TestEventSpecialType(AATest):
    userns_special_profiles = set_userns_special_profile(['unconfined', 'unprivileged_userns', 'unpriv_.*'])
    parser = ReadLog('', '', '')
    tests = (
        ('[  176.385388] audit: type=1400 audit(1666891380.570:78): apparmor="DENIED" operation="userns_create" class="namespace" profile="/usr/bin/bwrap-userns-restrict" pid=1785 comm="userns_child_ex" requested="userns_create" denied="userns_create"',                                                                                           'normal'),
        ('[  839.488169] audit: type=1400 audit(1752065668.819:208): apparmor="DENIED" operation="userns_create" class="namespace" info="Userns create restricted - failed to find unprivileged_userns profile" error=-13 profile="unconfined" pid=12124 comm="unshare" requested="userns_create" denied="userns_create" target="unprivileged_userns"', 'userns_denied'),
        ('[  429.272003] audit: type=1400 audit(1720613712.153:168): apparmor="AUDIT" operation="userns_create" class="namespace" info="Userns create - transitioning profile" profile="unconfined" pid=5630 comm="unshare" requested="userns_create" target="unprivileged_userns" execpath="/usr/bin/unshare"',                                        'userns_change_profile'),
        ('[   52.901383] audit: type=1400 audit(1752064882.228:82): apparmor="DENIED" operation="capable" class="cap" profile="unprivileged_userns" pid=6700 comm="electron" capability=21  capname="sys_admin"',                                                                                                                                       'userns_capable'),
        ('Jul 31 17:11:16 dbusdev-saucy-amd64 dbus[1692]: apparmor="DENIED" operation="dbus_bind"  bus="session" name="com.apparmor.Test" mask="bind" pid=2940 profile="/tmp/apparmor-2.8.0/tests/regression/apparmor/dbus_service"',                                                                                                                   'normal'),
        ('[103975.623545] audit: type=1400 audit(1481284511.494:2807): apparmor="DENIED" operation="change_onexec" info="no new privs" error=-1 namespace="root//lxd-tor_<var-lib-lxd>" profile="unconfined" name="system_tor" pid=18593 comm="(tor)" target="system_tor"',                                                                             'userns_change_profile'),
        ('[78661.551820] audit: type=1400 audit(1752661047.170:350): apparmor="DENIED" operation="capable" class="cap" profile="unpriv_bwrap" pid=1412550 comm="node" capability=21  capname="sys_admin"',                                                                                                                                              'userns_capable'),
    )

    def _run_test(self, ev, expected):
        parsed_event = self.parser.parse_event(ev)
        r = self.parser.create_rule_from_ev(parsed_event)
        self.assertIsNotNone(r)

        real_type = get_event_special_type(parsed_event, self.userns_special_profiles)
        self.assertEqual(expected, real_type,
                         "ev {}: {} != {}".format(ev, expected, real_type))

    def test_invalid(self):
        ev = 'type=AVC msg=audit(1333698107.128:273917): apparmor="DENIED" operation="recvmsg" parent=1596 profile="unprivileged_userns" pid=1875 comm="nc" laddr=::ffff:127.0.0.1 lport=2048 faddr=::ffff:127.0.0.1 fport=59180 family="inet6" sock_type="stream" protocol=6'
        parsed_event = self.parser.parse_event(ev)
        parsed_event['comm'] = 'something'  # Artificially crafted invalid event
        with self.assertRaises(AppArmorBug):
            get_event_special_type(parsed_event, self.userns_special_profiles)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
