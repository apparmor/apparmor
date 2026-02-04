#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2025 Maxime Bélair <maxime.belair@canonical.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import sys
import unittest
import subprocess

import apparmor.aa as aa
from apparmor.common import cmd
from common_test import AATest, setup_aa, setup_all_loops


class AAShowUsageTest(AATest):

    def test_help_contents(self):
        """Test output of help text"""

        expected_return_code = 0

        expected_output_1 = \
'''usage: aa-show-usage [-h] [-s {all,used,unused}] [-j] [-d DIR]
                     [--show-matching-path] [--filter.flags FLAGS]
                     [--filter.profile_name PROFILE_NAME]
                     [--filter.profile_attach PROFILE_ATTACH]
                     [--filter.profile_path PROFILE_PATH]

Check which profiles are used
'''  # noqa: E128

        expected_output_2 = \
'''
  -h, --help            show this help message and exit
  -s, --show-type {all,used,unused}
                        Type of profiles to show
  -j, --json            Output in JSON
  -d, --dir DIR         Path to profiles
  --show-matching-path  Show the path of a file matching the profile

Filtering options:
  Filters are used to reduce the output of information to only those entries
  that will match the filter. Filters use Python's regular expression syntax.

  --filter.flags FLAGS  Filter by flags
  --filter.profile_name PROFILE_NAME
                        Filter by profile name
  --filter.profile_attach PROFILE_ATTACH
                        Filter by profile attachment
  --filter.profile_path PROFILE_PATH
                        Filter by profile path
'''  # noqa: E128

        if sys.version_info[:2] < (3, 13):
            # Python 3.13 tweaked argparse output [1]. When running on older
            # Python versions, we adapt the expected output to match.
            #
            # https://github.com/python/cpython/pull/103372
            patches = [(
                '-s, --show-type {all,used,unused}',
                '-s {all,used,unused}, --show-type {all,used,unused}',
            ), (
                '-d, --dir DIR         Path to profiles',
                '-d DIR, --dir DIR     Path to profiles'
            )]
            for patch in patches:
                expected_output_2 = expected_output_2.replace(patch[0], patch[1])

        return_code, output = cmd(aashowusage_bin + ['--help'])
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)

        self.assertIn(expected_output_1, output)
        self.assertIn(expected_output_2, output)

    def test_show_unconfined_profiles(self):
        expected_return_code = 0
        return_code, output = cmd(aashowusage_bin + ['--filter.flags=unconfined', '-d', aa.profile_dir])
        result = 'Got return code {}, expected {}\n'.format(return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)

        nb_profile = 0

        for line in output.splitlines():
            if line.startswith('  Profile '):
                nb_profile += 1

        command = ['grep', '-Er', r'flags=.*unconfined.*\{']

        # Remove disabled profiles from grep
        disable_dir = os.path.join(aa.profile_dir, 'disable')
        if os.path.isdir(disable_dir):
            for name in os.listdir(disable_dir):
                command.append('--exclude=' + name)

        command.extend(['--', aa.profile_dir])

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        self.assertEqual(
            len(result.stdout.splitlines()), nb_profile,
            "Error found {} profiles, expected {}\n\n Output was: \n {}. Grepped profiles are: {}".format(
                nb_profile, len(result.stdout.splitlines()), output, result.stdout)
        )


setup_aa(aa)  # Wrapper for aa.init_aa()
setup_all_loops(__name__)

# The location of the aa-show-usage utility can be overridden by setting
# the APPARMOR_SHOW_USAGE or USE_SYSTEM environment variable;
# this is useful for running these tests in an installed environment
aashowusage_bin = ["../aa-show-usage"]

if __name__ == '__main__':
    if 'APPARMOR_SHOW_USAGE' in os.environ:
        aashowusage_bin = [os.environ['APPARMOR_SHOW_USAGE']]
    elif 'USE_SYSTEM' in os.environ:
        aashowusage_bin = ['aa-show-usage']
    else:
        aashowusage_bin = [sys.executable] + aashowusage_bin

    unittest.main(verbosity=1)
