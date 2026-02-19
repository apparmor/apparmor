#!/usr/bin/env python3
# ------------------------------------------------------------------
#
#  Copyright (C) 2013-2020 Canonical Ltd.
#  Authors: Steve Beattie <steve.beattie@canonical.com>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of version 2 of the GNU General Public
#  License published by the Free Software Foundation.
#
#  Simple test script for checking for errors and warnings emitted by
#  the apparmor parser.
#
# ------------------------------------------------------------------

import os
import subprocess
import sys
import unittest
from argparse import ArgumentParser
from shutil import rmtree
from tempfile import mkdtemp

import testlib

config = None


class AAErrorTests(testlib.AATestTemplate):
    def setUp(self):
        self.maxDiff = None
        self.cmd_prefix = [config.parser, '--config-file=./parser.conf', '-S', '-I', 'errors']

        self.tmpdir = os.path.realpath(mkdtemp(prefix='test-aa-parser-errors-'))
        self.profile_dir = os.path.join(self.tmpdir, 'profile')
        os.mkdir(self.profile_dir)


    def tearDown(self):
        if os.path.exists(self.tmpdir):
            rmtree(self.tmpdir)

    def _run_test(self, profile, message='', is_error=True):
        cmd = self.cmd_prefix + [profile]

        (rc, out, outerr) = self._run_cmd(cmd, stdout=subprocess.DEVNULL)
        report = "\nCommand: {}\nExit value:{}\nSTDERR\n{}".format(" ".join(cmd), rc, outerr)
        if is_error:
            self.assertNotEqual(rc, 0, report)
        else:
            self.assertEqual(rc, 0, report)

        ignore_messages = (
            'Cache read/write disabled: interface file missing. (Kernel needs AppArmor 2.4 compatibility patch.)\n',
            'WARNING: Kernel does not support compressed policies. Defaulting to uncompressed\n',
        )
        for ign in ignore_messages:
            if ign in outerr:
                outerr = outerr.replace(ign, '')

        self.assertEqual(message, outerr, report)

    def test_okay(self):
        self._run_test('errors/okay.sd', is_error=False)

    def test_single(self):
        self._run_test(
            'errors/single.sd',
            "AppArmor parser error for errors/single.sd in profile errors/single.sd at line 3: Could not open 'failure'\n",
        )

    def test_double(self):
        self._run_test(
            'errors/double.sd',
            "AppArmor parser error for errors/double.sd in profile errors/includes/busted at line 66: Could not open 'does-not-exist'\n",
        )

    def test_modefail(self):
        self._run_test(
            'errors/modefail.sd',
            "AppArmor parser error for errors/modefail.sd in profile errors/modefail.sd at line 6: syntax error, unexpected TOK_ID, expecting TOK_MODE\n",
        )

    def test_multi_include(self):
        self._run_test(
            'errors/multi_include.sd',
            "AppArmor parser error for errors/multi_include.sd in profile errors/multi_include.sd at line 12: Could not open 'failure'\n",
        )

    def test_deprecation1(self):
        self.cmd_prefix.append('--warn=deprecated')
        self._run_test(
            'errors/deprecation1.sd',
            "Warning from errors/deprecation1.sd (errors/deprecation1.sd line 6): The use of file paths as profile names is deprecated. See man apparmor.d for more information\n",
            is_error=False
        )

    def test_deprecation2(self):
        self.cmd_prefix.append('--warn=deprecated')
        self._run_test(
            'errors/deprecation2.sd',
            "Warning from errors/deprecation2.sd (errors/deprecation2.sd line 6): The use of file paths as profile names is deprecated. See man apparmor.d for more information\n",
            is_error=False
        )

    def test_non_existant_profile(self):
        test_profile = os.path.join(self.profile_dir, "does-not-exist.sd")
        self._run_test(
            test_profile,
            "File {} not found, skipping...\n".format(test_profile),
        )

    # We can run this test with multiple different arguments
    def _test_non_existant_symlink_target(self):
        """Helper Function to test the parser on a symlink with a non-existent target"""

        test_profile = os.path.join(self.profile_dir, "non-existant-target.sd")
        os.symlink('does-not-exist.sd', test_profile)
        self._run_test(
            test_profile,
            "File {} not found, skipping...\n".format(test_profile),
        )

    def test_non_existant_symlink_target(self):
        '''Basic symlink test that goes nowhere'''
        self._test_non_existant_symlink_target()

    def test_non_existant_symlink_target_j0(self):
        '''Basic symlink test that goes nowhere with 0 jobs'''
        self.cmd_prefix.append('-j0')
        self._test_non_existant_symlink_target()

    def test_non_existant_symlink_target_j1(self):
        '''Basic symlink test that goes nowhere with 1 job arg'''
        self.cmd_prefix.append('-j1')
        self._test_non_existant_symlink_target()

    def test_non_existant_symlink_target_j8(self):
        '''Basic symlink test that goes nowhere with 8 job arg'''
        self.cmd_prefix.append('-j8')
        self._test_non_existant_symlink_target()

    def test_non_existant_symlink_target_jauto(self):
        '''Basic symlink test that goes nowhere with auto job arg'''
        self.cmd_prefix.append('-jauto')
        self._test_non_existant_symlink_target()

    def test_non_existant_symlink_target_in_directory(self):
        '''Symlink test passing a directory to the parser'''
        test_profile = os.path.join(self.profile_dir, "non-existant-target.sd")
        os.symlink('does-not-exist.sd', test_profile)
        self._run_test(
            self.profile_dir,
            "There was an error while loading profiles from {}\n".format(self.profile_dir),
        )

def main():
    global config
    p = ArgumentParser()
    p.add_argument('-p', '--parser', default=testlib.DEFAULT_PARSER, action="store", dest='parser',
                   help="Specify path of apparmor parser to use [default = %(default)s]")
    config, args = p.parse_known_args()

    unittest.main(argv=sys.argv[:1] + args)

if __name__ == "__main__":
    main()
