#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import unittest

import apparmor.aa as apparmor
from apparmor.common import AppArmorException, is_skippable_file, open_file_read
from common_test import AATest, setup_aa, setup_all_loops

# This testcase will parse all parser/tst/simple_tests with parse_profile_data(),
# except the files listed in one of the arrays below.
#
# Files listed in skip_startswith will be completely skipped.
# Files listed in the other arrays will be checked, but with the opposite of the expected result.


# XXX tests listed here will be *** SKIPPED *** XXX
skip_startswith = (
    # the tools don't check for conflicting x permissions (yet?)
    'generated_x/conflict-',
    'generated_x/ambiguous-',
    'generated_x/dominate-',

    # 'safe' and 'unsafe' keywords
    'generated_perms_safe/',

    # Pux and Cux (which actually mean PUx and CUx) get rejected by the tools
    'generated_x/exact-',

    # profiles that use undefined autovars like @{exec_path} when no attachment
    'vars/vars_auto_exec_path_bad_2.sd',
    'vars/vars_auto_attach_path_bad_2.sd',
    'vars/vars_auto_exec_path_bad_3.sd',
    'vars/vars_auto_attach_path_bad_3.sd',
    'vars/vars_auto_exec_path_bad_5.sd',
    'vars/vars_auto_attach_path_bad_5.sd',
)

# testcases that should raise an exception, but don't
exception_not_raised = (
    # most abi/bad_* aren't detected as bad by the basic implementation in the tools
    'abi/bad_10.sd',
    'abi/bad_11.sd',
    'abi/bad_12.sd',

    # interesting[tm] profile name
    'change_hat/bad_parsing.sd',

    'dbus/bad_regex_04.sd',
    'dbus/bad_regex_05.sd',
    'dbus/bad_regex_06.sd',
    'file/bad_re_brace_1.sd',
    'file/bad_re_brace_2.sd',
    'file/bad_re_brace_3.sd',

    # The tools don't detect conflicting change_profile exec modes
    'change_profile/onx_conflict_unsafe1.sd',
    'change_profile/onx_conflict_unsafe2.sd',

    # duplicated conditionals aren't detected by the tools
    'generated_dbus/duplicated-conditionals-45127.sd',
    'generated_dbus/duplicated-conditionals-45131.sd',
    'generated_dbus/duplicated-conditionals-45124.sd',
    'generated_dbus/duplicated-conditionals-45130.sd',
    'generated_dbus/duplicated-conditionals-45125.sd',
    'generated_dbus/duplicated-conditionals-45128.sd',
    'generated_dbus/duplicated-conditionals-45129.sd',

    'dbus/bad_modifier_2.sd',
    'dbus/bad_peer_2.sd',  # We do not enforce the presence of a separator between peer fields
    'dbus/bad_regex_01.sd',
    'dbus/bad_regex_02.sd',
    'dbus/bad_regex_03.sd',
    'dbus/bad_regex_04.sd',
    'dbus/bad_regex_05.sd',
    'dbus/bad_regex_06.sd',
    'file/bad_re_brace_1.sd',
    'file/bad_re_brace_2.sd',
    'file/bad_re_brace_3.sd',

    # We do not check that options are compatible
    'mount/bad_opt_29.sd',
    'mount/bad_opt_30.sd',
    'mount/bad_opt_31.sd',
    'mount/bad_1.sd',
    'mount/bad_2.sd',
    'mount/bad_3.sd',
    'mount/bad_4.sd',

    'profile/flags/flags_bad10.sd',
    'profile/flags/flags_bad11.sd',
    'profile/flags/flags_bad12.sd',
    'profile/flags/flags_bad13.sd',
    'profile/flags/flags_bad15.sd',
    'profile/flags/flags_bad18.sd',
    'profile/flags/flags_bad19.sd',
    'profile/flags/flags_bad2.sd',
    'profile/flags/flags_bad3.sd',
    'profile/flags/flags_bad4.sd',
    'profile/flags/flags_bad5.sd',
    'profile/flags/flags_bad6.sd',
    'profile/flags/flags_bad7.sd',
    'profile/flags/flags_bad8.sd',
    'profile/flags/flags_bad_debug_1.sd',
    'profile/flags/flags_bad_debug_2.sd',
    'profile/flags/flags_bad_debug_3.sd',
    # detection of conflicting flags not supported
    'profile/flags/flags_bad30.sd',
    'profile/flags/flags_bad31.sd',
    'profile/flags/flags_bad32.sd',
    'profile/flags/flags_bad33.sd',
    'profile/flags/flags_bad34.sd',
    'profile/flags/flags_bad35.sd',
    'profile/flags/flags_bad36.sd',
    'profile/flags/flags_bad37.sd',
    'profile/flags/flags_bad38.sd',
    'profile/flags/flags_bad39.sd',
    'profile/flags/flags_bad40.sd',
    'profile/flags/flags_bad41.sd',
    'profile/flags/flags_bad42.sd',
    'profile/flags/flags_bad43.sd',
    'profile/flags/flags_bad44.sd',
    'profile/flags/flags_bad45.sd',
    'profile/flags/flags_bad46.sd',
    'profile/flags/flags_bad47.sd',
    'profile/flags/flags_bad48.sd',
    'profile/flags/flags_bad49.sd',
    'profile/flags/flags_bad50.sd',
    'profile/flags/flags_bad51.sd',
    'profile/flags/flags_bad52.sd',
    'profile/flags/flags_bad53.sd',
    'profile/flags/flags_bad54.sd',
    'profile/flags/flags_bad55.sd',
    'profile/flags/flags_bad56.sd',
    'profile/flags/flags_bad64.sd',
    'profile/flags/flags_bad65.sd',
    'profile/flags/flags_bad66.sd',
    'profile/flags/flags_bad67.sd',
    'profile/flags/flags_bad68.sd',
    'profile/flags/flags_bad69.sd',
    'profile/flags/flags_bad70.sd',
    'profile/flags/flags_bad71.sd',
    'profile/flags/flags_bad72.sd',
    'profile/flags/flags_bad73.sd',
    'profile/flags/flags_bad74.sd',
    'profile/flags/flags_bad75.sd',
    'profile/flags/flags_bad76.sd',
    'profile/flags/flags_bad77.sd',
    'profile/flags/flags_bad78.sd',
    'profile/flags/flags_bad79.sd',
    'profile/flags/flags_bad80.sd',
    'profile/flags/flags_bad81.sd',
    'profile/flags/flags_bad82.sd',
    'profile/flags/flags_bad83.sd',
    'profile/flags/flags_bad84.sd',
    'profile/flags/flags_bad85.sd',
    'profile/flags/flags_bad86.sd',
    # flags=(error=EXX)
    'profile/flags/flags_bad87.sd',
    'profile/flags/flags_bad88.sd',
    'profile/flags/flags_bad89.sd',

    'profile/flags/flags_bad_disconnected_path1.sd',
    'profile/flags/flags_bad_disconnected_path2.sd',
    'profile/flags/flags_bad_disconnected_path3.sd',
    'profile/flags/flags_bad_disconnected_path4.sd',
    'profile/flags/flags_bad_disconnected_path5.sd',

    'profile/flags/flags_bad_disconnected_ipc1.sd',
    'profile/flags/flags_bad_disconnected_ipc2.sd',
    'profile/flags/flags_bad_disconnected_ipc3.sd',
    'profile/flags/flags_bad_disconnected_ipc4.sd',
    'profile/flags/flags_bad_disconnected_ipc5.sd',
    'profile/flags/flags_bad_disconnected_ipc6.sd',
    'profile/flags/flags_bad_disconnected_ipc7.sd',
    'profile/flags/flags_bad_disconnected_ipc8.sd',

    'profile/profile_ns_bad8.sd',  # 'profile :ns/t' without terminating ':'
    'ptrace/bad_10.sd',  # peer with invalid regex
    'signal/bad_21.sd',  # invalid regex

    # Invalid regexes
    'unix/bad_regex_01.sd',
    'unix/bad_regex_02.sd',
    'unix/bad_regex_03.sd',
    'unix/bad_regex_04.sd',

    'unix/bad_modifier_2.sd',  # We do not check for duplicated keywords
    'unix/bad_bind_2.sd',  # We do not check bind coherency
    'unix/bad_peer_3.sd',  # We do not enforce the presence of a separator between peer fields

    'vars/vars_bad_3.sd',
    'vars/vars_bad_4.sd',
    'vars/vars_bad_5.sd',
    'vars/vars_dbus_bad_01.sd',
    'vars/vars_dbus_bad_02.sd',
    'vars/vars_dbus_bad_03.sd',
    'vars/vars_dbus_bad_04.sd',
    'vars/vars_dbus_bad_05.sd',
    'vars/vars_dbus_bad_06.sd',
    'vars/vars_dbus_bad_07.sd',
    'vars/vars_file_evaluation_8.sd',

    # profile name in var doesn't start with /
    'vars/vars_profile_name_bad_1.sd',

    # profile name is undefined variable
    'vars/vars_profile_name_bad_2.sd',
    'vars/vars_profile_name_23.sd',

    # attachment in var doesn't start with /
    'vars/vars_profile_name_07.sd',
    'vars/vars_profile_name_08.sd',
    'vars/vars_profile_name_12.sd',
    'vars/vars_profile_name_13.sd',
    'vars/vars_profile_name_15.sd',
    'vars/vars_profile_name_22.sd',

    'vars/vars_recursion_1.sd',
    'vars/vars_recursion_2.sd',
    'vars/vars_recursion_3.sd',
    'vars/vars_recursion_4.sd',
    'vars/vars_simple_assignment_3.sd',
    'vars/vars_simple_assignment_8.sd',
    'vars/vars_simple_assignment_9.sd',
    'xtrans/simple_bad_conflicting_x_10.sd',
    'xtrans/simple_bad_conflicting_x_11.sd',
    'xtrans/simple_bad_conflicting_x_12.sd',
    'xtrans/simple_bad_conflicting_x_13.sd',
    'xtrans/simple_bad_conflicting_x_2.sd',
    'xtrans/simple_bad_conflicting_x_4.sd',
    'xtrans/simple_bad_conflicting_x_6.sd',
    'xtrans/simple_bad_conflicting_x_8.sd',
    'xtrans/x-conflict.sd',

    'network/perms/bad_modifier_2.sd',
)

# testcases with lines that don't match any regex and end up as "unknown line"
unknown_line = (
    # 'other' keyword
    'file/allow/ok_other_1.sd',
    'file/allow/ok_other_2.sd',
    'file/ok_other_1.sd',
    'file/ok_other_2.sd',
    'file/ok_other_3.sd',
    'file/priority/ok_other_1.sd',
    'file/priority/ok_other_2.sd',
    'file/priority/ok_other_3.sd',

    # 'unsafe' keyword
    'file/file/front_perms_ok_2.sd',
    'file/front_perms_ok_2.sd',
    'xtrans/simple_ok_cx_1.sd',
    'file/priority/front_perms_ok_3.sd',
    'file/priority/front_perms_ok_4.sd',

    # owner / audit {...} blocks
    'file/file/owner/ok_1.sd',
    'file/owner/ok_1.sd',
    'profile/entry_mods_audit_ok1.sd',

    # namespace
    'profile/profile_ns_named_ok1.sd',  # profile keyword?
    'profile/profile_ns_named_ok2.sd',  # profile keyword?
    'profile/profile_ns_named_ok3.sd',  # profile keyword?
    'profile/profile_ns_ok1.sd',
    'profile/profile_ns_ok2.sd',
    'profile/profile_ns_ok3.sd',  # profile keyword?
    'profile/re_named_ok4.sd',  # profile keyword
    'profile/re_ok4.sd',

    # multiple rules in one line
    'bare_include_tests/ok_14.sd',
    'bare_include_tests/ok_19.sd',
    'bare_include_tests/ok_64.sd',
    'bare_include_tests/ok_69.sd',

    # include with quoted relative path
    'bare_include_tests/ok_11.sd',
    'bare_include_tests/ok_12.sd',
    'bare_include_tests/ok_13.sd',
    'bare_include_tests/ok_15.sd',
    # include with unquoted relative path
    'bare_include_tests/ok_16.sd',
    'bare_include_tests/ok_17.sd',
    'bare_include_tests/ok_18.sd',
    'bare_include_tests/ok_20.sd',
    # include with quoted relative path with spaces
    'bare_include_tests/ok_26.sd',
    'bare_include_tests/ok_27.sd',
    # include with quoted magic path with spaces
    'bare_include_tests/ok_28.sd',
    'bare_include_tests/ok_29.sd',
    # include with magic path with spaces
    'bare_include_tests/ok_30.sd',
    'bare_include_tests/ok_31.sd',
    # include if exists with quoted relative path
    'bare_include_tests/ok_61.sd',
    'bare_include_tests/ok_62.sd',
    'bare_include_tests/ok_63.sd',
    # include if exists with unquoted relative path
    'bare_include_tests/ok_65.sd',
    'bare_include_tests/ok_66.sd',
    'bare_include_tests/ok_67.sd',
    'bare_include_tests/ok_68.sd',
    'bare_include_tests/ok_70.sd',
    # include if exists with quoted relative path with spaces
    'bare_include_tests/ok_76.sd',
    'bare_include_tests/ok_77.sd',
    # include if exists with quoted magic path with spaces
    'bare_include_tests/ok_78.sd',
    'bare_include_tests/ok_79.sd',
    # include if exists with unquoted magic path with spaces
    'bare_include_tests/ok_80.sd',
    'bare_include_tests/ok_81.sd',
    # include if exists with quoted relative path, non-existing include file
    'bare_include_tests/ok_82.sd',
    'bare_include_tests/ok_84.sd',
    'bare_include_tests/ok_85.sd',
    'bare_include_tests/ok_86.sd',
)

# testcases with various unexpected failures
syntax_failure = (
    # missing profile keywords
    'profile/re_named_ok2.sd',

    # Syntax Errors caused by boolean conditions (parse_profile_data() gets confused by the closing '}')
    'conditional/defined_1.sd',
    'conditional/defined_2.sd',
    'conditional/else_1.sd',
    'conditional/else_2.sd',
    'conditional/else_3.sd',
    'conditional/else_if_1.sd',
    'conditional/else_if_2.sd',
    'conditional/else_if_3.sd',
    'conditional/else_if_5.sd',
    'conditional/ok_1.sd',
    'conditional/ok_2.sd',
    'conditional/ok_3.sd',
    'conditional/ok_4.sd',
    'conditional/ok_5.sd',
    'conditional/ok_6.sd',
    'conditional/ok_7.sd',
    'conditional/ok_8.sd',
    'conditional/ok_9.sd',
    'conditional/stress_1.sd',

    # unexpected uppercase vs. lowercase in *x rules
    'file/ok_5.sd',  # Invalid mode UX
    'file/ok_2.sd',  # Invalid mode RWM
    'file/ok_4.sd',  # Invalid mode iX
    'file/priority/ok_5.sd',  # Invalid mode UX
    'file/priority/ok_2.sd',  # Invalid mode RWM
    'file/priority/ok_4.sd',  # Invalid mode iX
    'xtrans/simple_ok_pix_1.sd',  # Invalid mode pIx
    'xtrans/simple_ok_pux_1.sd',  # Invalid mode rPux

    # unexpected uppercase vs. lowercase in *x rules - generated_perms_leading directory
    'generated_perms_leading/exact-re-Puxtarget.sd',
    'generated_perms_leading/dominate-ownerCuxtarget2.sd',
    'generated_perms_leading/ambiguous-Cux.sd',
    'generated_perms_leading/dominate-ownerPux.sd',
    'generated_perms_leading/exact-re-ownerPux.sd',
    'generated_perms_leading/overlap-ownerCuxtarget.sd',
    'generated_perms_leading/exact-re-ownerCuxtarget.sd',
    'generated_perms_leading/dominate-Puxtarget2.sd',
    'generated_perms_leading/dominate-ownerCuxtarget.sd',
    'generated_perms_leading/dominate-ownerPuxtarget.sd',
    'generated_perms_leading/ambiguous-Pux.sd',
    'generated_perms_leading/ambiguous-Cuxtarget2.sd',
    'generated_perms_leading/exact-Puxtarget2.sd',
    'generated_perms_leading/ambiguous-ownerCux.sd',
    'generated_perms_leading/exact-ownerPux.sd',
    'generated_perms_leading/ambiguous-ownerPuxtarget.sd',
    'generated_perms_leading/exact-re-ownerPuxtarget.sd',
    'generated_perms_leading/exact-re-Cuxtarget.sd',
    'generated_perms_leading/exact-re-Puxtarget2.sd',
    'generated_perms_leading/dominate-Cux.sd',
    'generated_perms_leading/exact-re-ownerCuxtarget2.sd',
    'generated_perms_leading/ambiguous-ownerCuxtarget.sd',
    'generated_perms_leading/exact-re-Cuxtarget2.sd',
    'generated_perms_leading/ambiguous-Puxtarget.sd',
    'generated_perms_leading/overlap-Puxtarget.sd',
    'generated_perms_leading/ambiguous-Puxtarget2.sd',
    'generated_perms_leading/overlap-Puxtarget2.sd',
    'generated_perms_leading/exact-Puxtarget.sd',
    'generated_perms_leading/overlap-ownerPuxtarget.sd',
    'generated_perms_leading/exact-ownerCuxtarget.sd',
    'generated_perms_leading/exact-re-ownerCux.sd',
    'generated_perms_leading/exact-ownerPuxtarget2.sd',
    'generated_perms_leading/exact-ownerCux.sd',
    'generated_perms_leading/overlap-Cuxtarget2.sd',
    'generated_perms_leading/ambiguous-Cuxtarget.sd',
    'generated_perms_leading/ambiguous-ownerPuxtarget2.sd',
    'generated_perms_leading/dominate-ownerCux.sd',
    'generated_perms_leading/exact-Pux.sd',
    'generated_perms_leading/exact-Cuxtarget.sd',
    'generated_perms_leading/overlap-ownerCuxtarget2.sd',
    'generated_perms_leading/overlap-Pux.sd',
    'generated_perms_leading/overlap-ownerPux.sd',
    'generated_perms_leading/ambiguous-ownerCuxtarget2.sd',
    'generated_perms_leading/exact-re-Cux.sd',
    'generated_perms_leading/exact-re-Pux.sd',
    'generated_perms_leading/overlap-Cuxtarget.sd',
    'generated_perms_leading/exact-re-ownerPuxtarget2.sd',
    'generated_perms_leading/exact-Cuxtarget2.sd',
    'generated_perms_leading/exact-Cux.sd',
    'generated_perms_leading/overlap-Cux.sd',
    'generated_perms_leading/overlap-ownerCux.sd',
    'generated_perms_leading/exact-ownerPuxtarget.sd',
    'generated_perms_leading/dominate-Pux.sd',
    'generated_perms_leading/exact-ownerCuxtarget2.sd',
    'generated_perms_leading/dominate-Puxtarget.sd',
    'generated_perms_leading/ambiguous-ownerPux.sd',
    'generated_perms_leading/overlap-ownerPuxtarget2.sd',
    'generated_perms_leading/dominate-Cuxtarget2.sd',
    'generated_perms_leading/dominate-Cuxtarget.sd',
    'generated_perms_leading/dominate-ownerPuxtarget2.sd',

    # escaping with "\"
    'file/ok_embedded_spaces_4.sd',  # \-escaped space
    'file/file/ok_embedded_spaces_4.sd',  # \-escaped space
    'file/ok_quoted_4.sd',  # quoted string including \"
    'file/priority/ok_quoted_4.sd',  # quoted string including \"
    'file/priority/ok_embedded_spaces_4.sd',  # \-escaped space

    # misc
    'vars/vars_dbus_12.sd',  # AARE starting with {{ are not handled
    'vars/vars_simple_assignment_12.sd',  # Redefining existing variable @{BAR} ('\' not handled)
    'bare_include_tests/ok_2.sd',  # two #include<...> in one line

    # network port range
    'network/network_ok_17.sd',
    'network/network_ok_45.sd',
    'network/network_ok_46.sd',
)


class TestParseParserTests(AATest):
    tests = []  # filled by parse_test_profiles()

    def _run_test(self, params, expected):
        with open_file_read(params['file']) as f_in:
            data = f_in.readlines()

        if params['disabled']:
            # skip disabled testcases
            return

        if params['tools_wrong']:
            # if the tools are marked as being wrong about a profile, expect the opposite result
            # this makes sure we notice any behaviour change, especially not being wrong anymore
            expected = not expected

        # make sure the profile is known in active_profiles.files
        apparmor.active_profiles.init_file(params['file'])

        if expected:
            apparmor.parse_profile_data(data, params['file'], 0, True)
            apparmor.active_profiles.get_all_merged_variables(params['file'], apparmor.include_list_recursive(apparmor.active_profiles.files[params['file']]))

        else:
            with self.assertRaises(AppArmorException):
                apparmor.parse_profile_data(data, params['file'], 0, True)
                apparmor.active_profiles.get_all_merged_variables(params['file'], apparmor.include_list_recursive(apparmor.active_profiles.files[params['file']]))


def parse_test_profiles(file_with_path):
    """parse the test-related headers of a profile (for example EXRESULT) and add the profile to the set of tests"""
    exresult = None
    exresult_found = False
    description = None
    todo = False
    disabled = False

    with open_file_read(file_with_path) as f_in:
        data = f_in.readlines()

    relfile = os.path.relpath(file_with_path, apparmor.profile_dir)

    for line in data:
        if line.startswith('#=EXRESULT '):
            exresult = line.split()[1]
            if exresult == 'PASS':
                exresult = True
                exresult_found = True
            elif exresult == 'FAIL':
                exresult = False
                exresult_found = True
            else:
                raise Exception('{} contains unknown EXRESULT {}'.format(file_with_path, exresult))

        elif line.upper().startswith('#=DESCRIPTION '):
            description = line.split()[1]

        elif line.rstrip() == '#=TODO':
            todo = True

        elif line.rstrip() == '#=DISABLED':
            disabled = True

    if not exresult_found:
        raise Exception(file_with_path + ' does not contain EXRESULT')

    if not description:
        raise Exception(file_with_path + ' does not contain description')

    tools_wrong = False
    if relfile in exception_not_raised:
        if exresult:
            raise Exception(file_with_path + " listed in exception_not_raised, but has EXRESULT PASS")
        tools_wrong = 'EXCEPTION_NOT_RAISED'
    elif relfile.startswith(skip_startswith):
        return 1  # XXX *** SKIP *** those tests
    elif relfile in unknown_line:
        if not exresult:
            raise Exception(file_with_path + " listed in unknown_line, but has EXRESULT FAIL")
        tools_wrong = 'UNKNOWN_LINE'
    elif relfile in syntax_failure:
        if not exresult:
            raise Exception(file_with_path + " listed in syntax_failure, but has EXRESULT FAIL")
        tools_wrong = 'SYNTAX_FAILURE'

    params = {
        'file': file_with_path,
        'relfile': relfile,
        'todo': todo,
        'disabled': disabled,
        'tools_wrong': tools_wrong,
        'exresult': exresult,
    }

    TestParseParserTests.tests.append((params, exresult))
    return 0


def find_and_setup_test_profiles(profile_dir):
    """find all profiles in the given profile_dir, excluding
    - skippable files
    - include directories
    - files in the main directory (readme, todo etc.)
    """
    skipped = 0

    profile_dir = os.path.abspath(profile_dir)

    apparmor.profile_dir = profile_dir

    print('Searching for parser simple_tests... (this will take a while)')

    for root, dirs, files in os.walk(profile_dir):
        relpath = os.path.relpath(root, profile_dir)

        if relpath == '.':
            # include files are checked as part of the profiles that include them (also, they don't contain EXRESULT)
            dirs.remove('includes')
            dirs.remove('include_tests')
            dirs.remove('includes-preamble')

        for file in files:
            file_with_path = os.path.join(root, file)
            if not is_skippable_file(file) and relpath != '.':
                skipped += parse_test_profiles(file_with_path)

    if skipped:
        print('Skipping {} test profiles listed in skip_startswith.'.format(skipped))

    print('Running {} parser simple_tests...'.format(len(TestParseParserTests.tests)))


setup_aa(apparmor)
profile_dir = os.path.abspath('../../parser/tst/simple_tests/')
find_and_setup_test_profiles(profile_dir)

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
