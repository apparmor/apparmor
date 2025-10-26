#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2015-2021 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import sys
import unittest

import apparmor.aa
from apparmor.common import hasher, open_file_read, split_name
from apparmor.logparser import ReadLog
from apparmor.profile_list import ProfileList
from common_test import AATest, read_file, setup_aa, setup_all_loops


class TestLibapparmorTestMulti(AATest):
    """Parse all libraries/libapparmor/testsuite/test_multi tests and compare the result with the *.out files"""

    tests = 'invalid'  # filled by parse_test_profiles()

    def _run_test(self, params, expected):
        # tests[][expected] is a dummy, replace it with the real values
        if params.split('/')[-1] in log_to_skip:
            return

        expected = self._parse_libapparmor_test_multi(params)

        loglines = []
        with open_file_read(params + '.in') as f_in:
            for line in f_in:
                if line.strip():
                    loglines.append(line)

        self.assertEqual(len(loglines), 1, params + '.in should only contain one line!')

        parser = ReadLog('', '', '')
        parsed_event = parser.parse_event(loglines[0])

        if parsed_event and expected:
            parsed_items = dict(parsed_event.items())

            # check if the line passes the regex in logparser.py
            if not parser.RE_LOG_ALL.search(loglines[0]):
                raise Exception("Log event doesn't match RE_LOG_ALL")

            for label in expected:
                if label in (
                        'file',  # filename of the *.in file
                        'event_type',  # mapped to aamode
                        'audit_id', 'audit_sub_id',  # not set nor relevant
                        'comm',  # not set, and not too useful
                        # XXX most of the keywords listed below mean "TODO"
                        'fsuid', 'ouid',  # file events
                        'flags', 'fs_type',  # mount
                        'namespace',  # file_lock only?? (at least the tests don't contain this in other event types with namespace)
                        'net_local_addr', 'net_foreign_addr', 'net_local_port', 'net_foreign_port',  # detailed network events
                        'peer', 'signal',  # signal
                        'src_name',  # pivotroot
                        'dbus_bus', 'dbus_interface', 'dbus_member', 'dbus_path',  # dbus
                        'peer_pid', 'peer_profile',  # dbus
                        'net_addr', 'peer_addr',  # unix

                ):
                    pass
                elif parsed_items['operation'] == 'exec' and label in ('sock_type', 'family', 'protocol'):
                    pass  # XXX 'exec' + network? really?
                elif parsed_items['operation'] == 'ptrace' and label == 'name2' and params.endswith('/ptrace_garbage_lp1689667_1'):
                    pass  # libapparmor would better qualify this case as invalid event
                elif not parsed_items.get(label, None):
                    raise Exception('parsed_items[{}] not set'.format(label))
                elif not expected.get(label, None):
                    raise Exception('expected[{}] not set'.format(label))
                else:
                    self.assertEqual(str(parsed_items[label]), expected[label], label + ' differs')
        elif expected:
            self.assertIsNone(parsed_event)  # that's why we end up here
            self.assertEqual(dict(), expected, 'parsed_event is none')  # effectively print the content of expected
        elif parsed_event:
            self.assertIsNone(expected)  # that's why we end up here
            self.assertEqual(parsed_event, dict(), 'expected is none')  # effectively print the content of parsed_event
        else:
            self.assertIsNone(expected)  # that's why we end up here
            self.assertIsNone(parsed_event)  # that's why we end up here
            self.assertEqual(parsed_event, expected)  # both are None

    # list of labels that use a different name in logparser.py than in the test_multi *.out files
    # (additionally, .lower() is applied to all labels)
    label_map = {
        'Mask': 'request_mask',
        'Command': 'comm',
        'Token': 'magic_token',
        'ErrorCode': 'error_code',
        'Network family': 'family',
        'Socket type': 'sock_type',
        'Local addr': 'net_local_addr',
        'Foreign addr': 'net_foreign_addr',
        'Local port': 'net_local_port',
        'Foreign port': 'net_foreign_port',
        'Audit subid': 'audit_sub_id',
        'Attribute': 'attr',
        'Epoch': 'time',
    }

    def _parse_libapparmor_test_multi(self, file_with_path):
        """parse the libapparmor test_multi *.in tests and their expected result in *.out"""

        with open_file_read(file_with_path + '.out') as f_in:
            expected = f_in.readlines()

        if expected[0].rstrip('\n') != 'START':
            raise Exception("{}.out doesn't have 'START' in its first line! ({})".format(
                file_with_path, expected[0]))

        expected.pop(0)

        exresult = dict()
        for line in expected:
            label, value = line.split(':', 1)

            # test_multi doesn't always use the original labels :-/
            if label in self.label_map.keys():
                label = self.label_map[label]
            label = label.replace(' ', '_').lower()
            exresult[label] = value.strip()

        if not exresult['event_type'].startswith('AA_RECORD_'):
            raise Exception("event_type doesn't start with AA_RECORD_: {} in file {}".format(
                exresult['event_type'], file_with_path))

        exresult['aamode'] = exresult['event_type'].replace('AA_RECORD_', '')
        if exresult['aamode'] == 'ALLOWED':
            exresult['aamode'] = 'PERMITTING'
        if exresult['aamode'] == 'DENIED':
            exresult['aamode'] = 'REJECTING'

        if exresult['event_type'] == 'AA_RECORD_INVALID':  # or exresult.get('error_code', 0) != 0:  # XXX should events with errors be ignored?
            exresult = None

        return exresult


# tests that cause crashes or need user interaction (will be skipped)
log_to_skip = [
    'testcase_dbus_09',  # multiline log not currently supported
]

# tests that do not produce the expected profile (checked with assertNotEqual)
log_to_profile_known_failures = [
    # exec events
    'testcase01',
    'testcase12',
    'testcase13',
]

# tests that cause crashes or need user interaction (will be skipped)
log_to_profile_skip = [
    'testcase31',  # XXX AppArmorBug: Log contains unknown mode mrwIxl

    'testcase_dmesg_changehat_negative_error',   # fails in write_header -> quote_if_needed because data is None
    'testcase_syslog_changehat_negative_error',  # fails in write_header -> quote_if_needed because data is None

    'testcase_changehat_01',  # interactive, asks to add a hat
    'testcase_dbus_09',  # multiline log not currently supported
]

# tests that cause an empty log
log_to_profile_known_empty_log = [
    'change_onexec_lp1648143',  # change_onexec not supported in logparser.py yet (and the log is about "no new privs" error)
    'ptrace_garbage_lp1689667_1',  # no denied= in log
    'ptrace_no_denied_mask',  # no denied= in log
    'unconfined-change_hat',  # unconfined trying to change_hat, which isn't allowed
    'testcase_unix_no_denied_issue541',  # no denied_mask in log
]


class TestLogToProfile(AATest):
    """Check if the libraries/libapparmor/testsuite/test_multi tests result in the expected profile"""

    tests = 'invalid'  # filled by parse_test_profiles()

    def _run_test(self, params, expected):
        logfile = params + '.in'

        if params.split('/')[-1] in log_to_profile_skip:
            return

        profile, new_profile = logfile_to_profile(logfile)
        if profile is None:
            return

        expected_profile = read_file(params + '.profile')

        if params.split('/')[-1] in log_to_profile_known_failures:
            self.assertNotEqual(new_profile, expected_profile)  # known failure
        else:
            self.assertEqual(new_profile, expected_profile)


def logfile_to_profile(logfile):
    profile_dummy_file = 'AATest_does_exist'

    # we need to find out the profile name and aamode (complain vs. enforce mode) so that the test can access the correct place in storage
    parser = ReadLog('', '', '')
    parsed_event = parser.parse_event(read_file(logfile))

    if not parsed_event:  # AA_RECORD_INVALID
        return None, 'INVALID'

    aamode = parsed_event['aamode']

    if aamode in ('AUDIT', 'STATUS', 'HINT'):  # ignore some event types  # XXX maybe we shouldn't ignore AUDIT events?
        return None, aamode

    if aamode not in ('PERMITTING', 'REJECTING'):
        raise Exception('Unexpected aamode {}'.format(parsed_event['aamode']))

    # cleanup apparmor.aa storage
    apparmor.aa.log = dict()
    apparmor.aa.aa = hasher()

    profile, hat = split_name(parsed_event['profile'])

    apparmor.aa.active_profiles = ProfileList()

    dummy_prof = apparmor.aa.ProfileStorage('TEST DUMMY for active_profiles', profile_dummy_file, 'logprof_to_profile()')

    # optional for now, might be needed one day
    # if profile.startswith('/'):
    #     apparmor.aa.active_profiles.add_profile(profile_dummy_file, profile, profile, dummy_prof)
    # else:
    apparmor.aa.active_profiles.add_profile(profile_dummy_file, profile, '', dummy_prof)

    log_reader = ReadLog(logfile, apparmor.aa.active_profiles, '')
    hashlog = log_reader.read_log('')

    apparmor.aa.ask_exec(hashlog)
    apparmor.aa.ask_addhat(hashlog)

    log_dict = apparmor.aa.collapse_log(hashlog, ignore_null_profiles=False)

    if list(log_dict[aamode].keys()) != [parsed_event['profile']]:
        raise Exception('log_dict[{}] contains unexpected keys. Logfile: {}, keys {}'.format(aamode, logfile, log_dict.keys()))

    if '//' in parsed_event['profile']:
        # log event for a child profile means log_dict only contains the child profile
        # initialize parent profile in log_dict as ProfileStorage to ensure writing the profile doesn't fail
        # (in "normal" usage outside of this test, log_dict will not be handed over to serialize_profile())

        log_dict[aamode][profile] = apparmor.aa.ProfileStorage('TEST DUMMY for empty parent profile', profile_dummy_file, 'logfile_to_profile()')
        log_dict[aamode][parsed_event['profile']]['is_hat'] = True  # for historical reasons, generate hats, not child profiles

    log_is_empty = True

    for tmpaamode in hashlog:
        for tmpprofile in hashlog[tmpaamode]:
            for tmpruletype in hashlog[tmpaamode][tmpprofile]:
                if tmpruletype == 'final_name' and hashlog[tmpaamode][tmpprofile]['final_name'] == tmpprofile:
                    continue  # final_name is a copy of the profile name (may be changed by ask_exec(), but that won't happen in this test)
                if hashlog[tmpaamode][tmpprofile][tmpruletype]:
                    log_is_empty = False

    if logfile.split('/')[-1][:-3] in log_to_profile_known_empty_log:
        # unfortunately this function might be called outside Unittest.TestCase, therefore we can't use assertEqual / assertNotEqual
        if not log_is_empty:
            raise Exception('got non-empty log for logfile in log_to_profile_known_empty_log: {} {}'.format(logfile, hashlog))
    else:
        if log_is_empty:
            raise Exception('got empty log for logfile not in log_to_profile_known_empty_log: {} {}'.format(logfile, hashlog))

    new_profile = apparmor.aa.serialize_profile(log_dict[aamode], profile, {})

    return profile, new_profile


def find_test_multi(log_dir):
    """find all log sniplets in the given log_dir"""

    log_dir = os.path.abspath(log_dir)

    tests = []
    for root, dirs, files in os.walk(log_dir):
        for file in files:
            if file.endswith('.in'):
                file_with_path = os.path.join(root, file[:-3])  # filename without '.in'
                tests.append((file_with_path, True))  # True is a dummy testresult, parsing of the *.out files is done while running the tests

            elif file.endswith('.out') or file.endswith('.err') or file.endswith('.profile'):
                pass
            else:
                raise Exception('Found unknown file {} in libapparmor test_multi'.format(file))

    return tests


# if a logfile is given as parameter, print the resulting profile and exit (with $? = 42 to make sure tests break if the caller accidentally hands over a parameter)
if __name__ == '__main__' and len(sys.argv) == 2:
    print(logfile_to_profile(sys.argv[1])[1])
    sys.exit(42)

# still here? That means a normal test run
print('Testing libapparmor test_multi tests...')
TestLibapparmorTestMulti.tests = find_test_multi('../../libraries/libapparmor/testsuite/test_multi/')
TestLogToProfile.tests = find_test_multi('../../libraries/libapparmor/testsuite/test_multi/')

setup_aa(apparmor.aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
