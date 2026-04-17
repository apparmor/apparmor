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
from apparmor.notify import get_last_login_timestamp, get_last_login_timestamp_wtmp, sane_timestamp
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


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
