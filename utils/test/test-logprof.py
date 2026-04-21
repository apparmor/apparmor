#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2023 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import shutil
import subprocess
import sys
import unittest

# import apparmor.aa as aa  # see the setup_aa() call for details
from common_test import AATest, read_file, setup_all_loops  # , setup_aa


class TestLogprof(AATest):
    # This test expects a set of files:
    # - logprof/TESTNAME.auditlog - audit.log
    # - logprof/TESTNAME.jsonlog - expected aa-logprof --json input and output (gathered with json_log=1 in logprof.conf)
    # - logprof/TESTNAME.PROFILE - one or more profiles in the expected state
    # where TESTNAME is the name given in the first column of 'tests'
    tests = (
        # test name         # profiles to verify
        ('ping',            ['bin.ping']),
    )

    def AASetup(self):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir,
                        symlinks=True)

    def AATeardown(self):
        self._terminate()

    def _startLogprof(self, auditlog, mode):
        exe = [sys.executable]

        if 'coverage' in sys.modules:
            exe = exe + ['-m', 'coverage', 'run', '--branch', '-p']

        exe = exe + ['../aa-logprof', '--' + mode, '--configdir', './', '-f', auditlog, '-d', self.profile_dir, '--no-check-mountpoint', '--output-dir', self.tmpdir]

        process = subprocess.Popen(
            exe,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # stderr=subprocess.STDOUT,
            env={'LANG': 'C',
                 'PYTHONPATH': os.environ.get('PYTHONPATH', ''),
                 'LD_LIBRARY_PATH': os.environ.get('LD_LIBRARY_PATH', ''),
                 },
        )

        return process

    def _terminate(self):
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.terminate()
        self.process.wait(timeout=0.6)

    def _run_test(self, params, expected):
        auditlog = './logprof/%s.auditlog' % params
        jsonlog = './logprof/%s.jsonlog' % params

        jlog = read_file(jsonlog)
        jlog = jlog.replace('/etc/apparmor.d', self.profile_dir)
        jlog = jlog.replace('/var/log/audit/audit.log', auditlog)
        jlog = jlog.strip().split('\n')

        self.process = self._startLogprof(auditlog, 'json')

        for line in jlog:
            if line.startswith('o '):  # read from stdout
                while True:
                    output = self.process.stdout.readline().decode("utf-8").strip()
                    if "skipping unparseable" not in output:
                        break
                self.assertEqual(output, line[2:])

            elif line.startswith('i '):  # send to stdin
                # expect an empty prompt line
                output = self.process.stdout.readline().decode("utf-8").strip()
                self.assertEqual(output, '')

                # "type" answer
                self.process.stdin.write(line[2:].encode("utf-8") + b"\n")
                self.process.stdin.flush()

            else:
                raise Exception('Unknown line in json log %s: %s' % (jsonlog, line))

        # give logprof some time to write the updated profile and terminate
        self.process.wait(timeout=10)
        self.assertEqual(self.process.returncode, 0)

        for file in expected:
            exp = read_file('./logprof/%s.%s' % (params, file))
            actual = read_file(os.path.join(self.tmpdir, file))

            # remove '# Last Modified:' line from updated profile
            actual = actual.split('\n')
            if actual[0].startswith('# Last Modified:'):
                actual = actual[1:]
            actual = '\n'.join(actual)

            self.assertEqual(actual, exp)

    def test_allow_all(self):
        auditlog = './logprof/%s.auditlog' % 'ping'
        allowlog = './logprof/%s.allowlog' % 'ping'

        slog = read_file(allowlog)
        slog = slog.replace('/etc/apparmor.d', self.profile_dir)
        slog = slog.replace('/var/log/audit/audit.log', auditlog)
        slog = slog.strip().split('\n')

        self.process = self._startLogprof(auditlog, 'allow-all')

        for line in slog:
            while True:
                output = self.process.stdout.readline().decode("utf-8").strip()
                if not output.startswith("skipping unparseable"):
                    break
            self.assertEqual(output, line)
        # give logprof some time to write the updated profile and terminate
        self.process.wait(timeout=1.2)
        self.assertEqual(self.process.returncode, 0)


# if you import apparmor.aa and call init_aa() in your tests, uncomment this
# setup_aa(aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
