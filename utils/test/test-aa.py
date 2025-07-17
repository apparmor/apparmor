#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2014-2021 Christian Boltz
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import shutil
import unittest

import apparmor.aa  # needed to set global vars in some tests
from apparmor.aa import (
    change_profile_flags, check_for_apparmor, create_new_profile, get_file_perms, get_interpreter_and_abstraction, get_profile_flags,
    merged_to_split, parse_profile_data, propose_file_rules, set_options_audit_mode, set_options_owner_mode, split_to_merged, is_known_rule)
from apparmor.aare import AARE
from apparmor.common import AppArmorBug, AppArmorException, is_skippable_file
from apparmor.rule.file import FileRule
from apparmor.rule.include import IncludeRule
from common_test import AATest, read_file, setup_aa, setup_all_loops, write_file


class AaTestWithTempdir(AATest):
    def AASetup(self):
        self.createTmpdir()


class AaTest_check_for_apparmor(AaTestWithTempdir):
    FILESYSTEMS_WITH_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsecurityfs\nnodev\tsockfs\n\text3\n\text2\n\text4'
    FILESYSTEMS_WITHOUT_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsockfs\n\text3\n\text2\n\text4'

    MOUNTS_WITH_SECURITYFS = (
        'proc /proc proc rw,relatime 0 0\n'
        'securityfs %s/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0')

    MOUNTS_WITHOUT_SECURITYFS = (
        'proc /proc proc rw,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0')

    def test_check_for_apparmor_None_1(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITHOUT_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_None_2(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITHOUT_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITHOUT_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_None_3(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITHOUT_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_invalid_filesystems(self):
        filesystems = ''
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % (self.tmpdir,))
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_invalid_mounts(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = ''
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_invalid_securityfs_path(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % ('xxx',))
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_mounted(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % (self.tmpdir,))
        self.assertEqual(self.tmpdir + '/security/apparmor', check_for_apparmor(filesystems, mounts))


class AaTest_create_new_profile(AATest):
    tests = (
        # file content         filename        expected interpreter  expected abstraction (besides 'base')  expected profiles
        (('#!/bin/bash\ntrue', 'script'),      (u'/bin/bash',        'abstractions/bash',                   ['script'])),
        (('foo bar',           'fake_binary'), (None,                None,                                  ['fake_binary'])),
        (('hats expected',     'apache2'),     (None,                None,                                  ['apache2', 'apache2//DEFAULT_URI', 'apache2//HANDLING_UNTRUSTED_INPUT'])),
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        # load the abstractions we need in the test
        apparmor.aa.profile_dir = self.profile_dir
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/base'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/bash'))

        exp_interpreter_path, exp_abstraction, exp_profiles = expected

        # damn symlinks!
        if exp_interpreter_path:
            exp_interpreter_path = os.path.realpath(exp_interpreter_path)

        file_content, filename = params
        program = self.writeTmpfile(filename, file_content)
        profile = create_new_profile(program)

        expected_profiles = []
        for prof in exp_profiles:
            expected_profiles.append('{}/{}'.format(self.tmpdir, prof))  # actual profile names start with tmpdir, prepend it to the expected profile names

        self.assertEqual(list(profile.keys()), expected_profiles)

        if exp_interpreter_path:
            self.assertEqual(
                set(profile[program]['file'].get_clean()),
                {'{} ix,'.format(exp_interpreter_path), '{} r,'.format(program), ''})
        else:
            self.assertEqual(set(profile[program]['file'].get_clean()), {'{} mr,'.format(program), ''})

        if exp_abstraction:
            self.assertEqual(profile[program]['inc_ie'].get_clean(), ['include <abstractions/base>', 'include <{}>'.format(exp_abstraction), ''])
        else:
            self.assertEqual(profile[program]['inc_ie'].get_clean(), ['include <abstractions/base>', ''])


class AaTest_get_interpreter_and_abstraction(AATest):
    tests = (
        ('#!/bin/bash',          ('/bin/bash',          'abstractions/bash')),
        ('#!/bin/dash',          ('/bin/dash',          'abstractions/bash')),
        ('#!/bin/sh',            ('/bin/sh',            'abstractions/bash')),
        ('#!  /bin/sh  ',        ('/bin/sh',            'abstractions/bash')),
        ('#!  /bin/sh  -x ',     ('/bin/sh',            'abstractions/bash')),  # '-x' is not part of the interpreter path
        ('#!/usr/bin/perl',      ('/usr/bin/perl',      'abstractions/perl')),
        ('#!/usr/bin/perl -w',   ('/usr/bin/perl',      'abstractions/perl')),  # '-w' is not part of the interpreter path
        ('#!/usr/bin/python',    ('/usr/bin/python',    'abstractions/python')),
        ('#!/usr/bin/python2',   ('/usr/bin/python2',   'abstractions/python')),
        ('#!/usr/bin/python2.7', ('/usr/bin/python2.7', 'abstractions/python')),
        ('#!/usr/bin/python3',   ('/usr/bin/python3',   'abstractions/python')),
        ('#!/usr/bin/python4',   ('/usr/bin/python4',   None)),  # python abstraction is only applied to py2 and py3
        ('#!/usr/bin/ruby',      ('/usr/bin/ruby',      'abstractions/ruby')),
        ('#!/usr/bin/ruby2.2',   ('/usr/bin/ruby2.2',   'abstractions/ruby')),
        ('#!/usr/bin/ruby1.9.1', ('/usr/bin/ruby1.9.1', 'abstractions/ruby')),
        ('#!/usr/bin/foobarbaz', ('/usr/bin/foobarbaz', None)),  # we don't have an abstraction for "foobarbaz"
        ('foo',                  (None,                 None)),  # no hashbang - not a script
    )

    def _run_test(self, params, expected):
        exp_interpreter_path, exp_abstraction = expected

        program = self.writeTmpfile('program', params + "\nfoo\nbar")
        interpreter_path, abstraction = get_interpreter_and_abstraction(program)

        # damn symlinks!
        if exp_interpreter_path:
            exp_interpreter_path = os.path.realpath(exp_interpreter_path)

        self.assertEqual(interpreter_path, exp_interpreter_path)
        self.assertEqual(abstraction, exp_abstraction)

    def test_special_file(self):
        self.assertEqual((None, None), get_interpreter_and_abstraction('/dev/null'))

    def test_file_not_found(self):
        self.createTmpdir()
        self.assertEqual((None, None), get_interpreter_and_abstraction(self.tmpdir + '/file-not-found'))


class AaTest_get_profile_flags(AaTestWithTempdir):
    def _test_get_flags(self, profile_header, expected_flags):
        file = write_file(self.tmpdir, 'profile', profile_header + ' {\n}\n')
        flags = get_profile_flags(file, '/foo')
        self.assertEqual(flags, expected_flags)

    def test_get_flags_01(self):
        self._test_get_flags('/foo', None)

    def test_get_flags_02(self):
        self._test_get_flags('/foo (  complain  )', '  complain  ')

    def test_get_flags_04(self):
        self._test_get_flags('/foo (complain)', 'complain')

    def test_get_flags_05(self):
        self._test_get_flags('/foo flags=(complain)', 'complain')

    def test_get_flags_06(self):
        self._test_get_flags('/foo flags=(complain,  audit)', 'complain,  audit')

    def test_get_flags_invalid_01(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/foo ()', None)

    def test_get_flags_invalid_02(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/foo flags=()', None)

    def test_get_flags_invalid_03(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/foo (  )', '  ')

    def test_get_flags_other_profile(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/no-such-profile flags=(complain)', 'complain')


class AaTest_change_profile_flags(AaTestWithTempdir):
    def _test_change_profile_flags(
            self, profile, old_flags, flags_to_change, set_flag, expected_flags, whitespace='',
            comment='', more_rules='', expected_more_rules='@-@-@', check_new_flags=True, profile_name='/foo'):
        if old_flags:
            old_flags = ' ' + old_flags

        if expected_flags:
            expected_flags = ' flags=({})'.format(expected_flags)
        else:
            expected_flags = ''

        if expected_more_rules == '@-@-@':
            expected_more_rules = more_rules

        if comment:
            comment = ' ' + comment

        dummy_profile_content = '  #include <abstractions/base>\n  capability chown,\n  /bar r,'
        prof_template = '%s%s%s {%s\n%s\n%s\n}\n'
        old_prof = prof_template % (whitespace, profile, old_flags,      comment, more_rules,          dummy_profile_content)
        new_prof = prof_template % ('',         profile, expected_flags, comment, expected_more_rules, dummy_profile_content)

        self.file = write_file(self.tmpdir, 'profile', old_prof)
        change_profile_flags(self.file, profile_name, flags_to_change, set_flag)
        if check_new_flags:
            real_new_prof = read_file(self.file)
            self.assertEqual(new_prof, real_new_prof)

    # tests that actually don't change the flags
    def test_change_profile_flags_nochange_02(self):
        self._test_change_profile_flags('/foo', '(  complain  )', 'complain', True, 'complain', whitespace='   ')

    def test_change_profile_flags_nochange_03(self):
        self._test_change_profile_flags('/foo', '(complain)', 'complain', True, 'complain')

    def test_change_profile_flags_nochange_04(self):
        self._test_change_profile_flags('/foo', 'flags=(complain)', 'complain', True, 'complain')

    def test_change_profile_flags_nochange_05(self):
        self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', 'complain', True, 'audit, complain', whitespace='     ')

    def test_change_profile_flags_nochange_06(self):
        self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', 'complain', True, 'audit, complain', whitespace='     ', comment='# a comment')

    def test_change_profile_flags_nochange_07(self):
        self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', 'audit', True, 'audit, complain', whitespace='     ', more_rules='  # a comment\n#another  comment')

    def test_change_profile_flags_nochange_08(self):
        self._test_change_profile_flags('profile /foo', 'flags=(complain)', 'complain', True, 'complain')

    def test_change_profile_flags_nochange_09(self):
        self._test_change_profile_flags('profile xy /foo', 'flags=(complain)', 'complain', True, 'complain', profile_name='xy')

    def test_change_profile_flags_nochange_10(self):
        self._test_change_profile_flags('profile "/foo bar"', 'flags=(complain)', 'complain', True, 'complain', profile_name='/foo bar')

    def test_change_profile_flags_nochange_11(self):
        self._test_change_profile_flags('/foo', '(complain)', 'complain', True, 'complain', profile_name=None)

    def test_change_profile_flags_nochange_12(self):
        # XXX changes the flags for the child profile (which happens to have the same profile name) to 'complain'
        self._test_change_profile_flags('/foo', 'flags=(complain)', 'complain', True, 'complain', more_rules='  profile /foo {\n}', expected_more_rules='  profile /foo flags=(complain) {\n}')

    # tests that change the flags
    def test_change_profile_flags_01(self):
        self._test_change_profile_flags('/foo', '', 'audit', True, 'audit')

    def test_change_profile_flags_02(self):
        self._test_change_profile_flags('/foo', '(  complain  )', 'audit', True, 'audit, complain', whitespace='  ')

    def test_change_profile_flags_04(self):
        self._test_change_profile_flags('/foo', '(complain)', 'audit', True, 'audit, complain')

    def test_change_profile_flags_05(self):
        self._test_change_profile_flags('/foo', 'flags=(complain)', 'audit', True, 'audit, complain')

    def test_change_profile_flags_06(self):
        self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', 'complain', False, 'audit', whitespace='    ')

    def test_change_profile_flags_07(self):
        self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', 'audit', False, 'complain')

    def test_change_profile_flags_08(self):
        self._test_change_profile_flags('/foo', '(  complain  )', 'audit', True, 'audit, complain', whitespace='  ', profile_name=None)

    def test_change_profile_flags_09(self):
        self._test_change_profile_flags('profile /foo', 'flags=(complain)', 'audit', True, 'audit, complain')

    def test_change_profile_flags_10(self):
        self._test_change_profile_flags('profile xy /foo', 'flags=(complain)', 'audit', True, 'audit, complain', profile_name='xy')

    def test_change_profile_flags_11(self):
        self._test_change_profile_flags('profile "/foo bar"', 'flags=(complain)', 'audit', True, 'audit, complain', profile_name='/foo bar')

    def test_change_profile_flags_12(self):
        self._test_change_profile_flags('profile xy "/foo bar"', 'flags=(complain)', 'audit', True, 'audit, complain', profile_name='xy')

    def test_change_profile_flags_13(self):
        self._test_change_profile_flags('/foo', '(audit)', 'audit', False, '')

    # test handling of hat flags
    def test_set_flags_with_hat_01(self):
        self._test_change_profile_flags(
            '/foo', 'flags=(complain)', 'audit', True, 'audit, complain',
            more_rules='\n  ^foobar {\n}\n',
            expected_more_rules='\n  ^foobar flags=(audit) {\n}\n'
        )

    def test_change_profile_flags_with_hat_02(self):
        self._test_change_profile_flags(
            '/foo', 'flags=(complain)', 'audit', False, 'complain',
            profile_name=None,
            more_rules='\n  ^foobar flags=(audit) {\n}\n',
            expected_more_rules='\n  ^foobar {\n}\n'
        )

    def test_change_profile_flags_with_hat_03(self):
        self._test_change_profile_flags(
            '/foo', 'flags=(complain)', 'audit', True, 'audit, complain',
            more_rules='\n^foobar (attach_disconnected) { # comment\n}\n',
            expected_more_rules='\n  ^foobar flags=(attach_disconnected, audit) { # comment\n}\n'
        )

    def test_change_profile_flags_with_hat_04(self):
        self._test_change_profile_flags(
            '/foo', '', 'audit', True, 'audit',
            more_rules='\n  hat foobar (attach_disconnected) { # comment\n}\n',
            expected_more_rules='\n  hat foobar flags=(attach_disconnected, audit) { # comment\n}\n'
        )

    def test_change_profile_flags_with_hat_05(self):
        self._test_change_profile_flags(
            '/foo', '(audit)', 'audit', False, '',
            more_rules='\n  hat foobar (attach_disconnected) { # comment\n}\n',
            expected_more_rules='\n  hat foobar flags=(attach_disconnected) { # comment\n}\n'
        )

    # test handling of child profiles
    def test_change_profile_flags_with_child_01(self):
        self._test_change_profile_flags(
            '/foo', 'flags=(complain)', 'audit', True, 'audit, complain',
            profile_name=None,
            more_rules='\n  profile /bin/bar {\n}\n',
            expected_more_rules='\n  profile /bin/bar flags=(audit) {\n}\n'
        )

    def test_change_profile_flags_with_child_02(self):
        # XXX child profile flags aren't changed if profile parameter is not None
        self._test_change_profile_flags(
            '/foo', 'flags=(complain)', 'audit', True, 'audit, complain',
            more_rules='\n  profile /bin/bar {\n}\n',
            expected_more_rules='\n  profile /bin/bar {\n}\n'  # flags(audit) should be added
        )

    def test_change_profile_flags_invalid_01(self):
        with self.assertRaises(AppArmorBug):
            self._test_change_profile_flags('/foo', '()', None, False, '', check_new_flags=False)

    def test_change_profile_flags_invalid_02(self):
        with self.assertRaises(AppArmorBug):
            self._test_change_profile_flags('/foo', 'flags=()', None, True, '', check_new_flags=False)

    def test_change_profile_flags_invalid_03(self):
        with self.assertRaises(AppArmorBug):
            self._test_change_profile_flags('/foo', '(  )', '', True, '', check_new_flags=False)

    def test_change_profile_flags_invalid_04(self):
        with self.assertRaises(AppArmorBug):
            self._test_change_profile_flags('/foo', 'flags=(complain,  audit)', '  ', True, 'audit, complain', check_new_flags=False)  # whitespace-only newflags

    def test_change_profile_flags_other_profile(self):
        # test behaviour if the file doesn't contain the specified /foo profile
        orig_prof = '/no-such-profile flags=(complain) {\n}'
        self.file = write_file(self.tmpdir, 'profile', orig_prof)

        with self.assertRaises(AppArmorException):
            change_profile_flags(self.file, '/foo', 'audit', True)

        # the file should not be changed
        real_new_prof = read_file(self.file)
        self.assertEqual(orig_prof, real_new_prof)

    def test_change_profile_flags_no_profile_found(self):
        # test behaviour if the file doesn't contain any profile
        orig_prof = '# /comment flags=(complain) {\n# }'
        self.file = write_file(self.tmpdir, 'profile', orig_prof)

        with self.assertRaises(AppArmorException):
            change_profile_flags(self.file, None, 'audit', True)

        # the file should not be changed
        real_new_prof = read_file(self.file)
        self.assertEqual(orig_prof, real_new_prof)

    def test_change_profile_flags_file_not_found(self):
        with self.assertRaises(IOError):
            change_profile_flags(self.tmpdir + '/file-not-found', '/foo', 'audit', True)


class AaTest_set_options_audit_mode(AATest):
    tests = (
        ((FileRule.create_instance('audit /foo/bar r,'), ['/foo/bar r,', '/foo/* r,', '/** r,']),                       ['audit /foo/bar r,', 'audit /foo/* r,', 'audit /** r,']),
        ((FileRule.create_instance('audit /foo/bar r,'), ['/foo/bar r,', 'audit /foo/* r,', 'audit /** r,']),           ['audit /foo/bar r,', 'audit /foo/* r,', 'audit /** r,']),
        ((FileRule.create_instance('/foo/bar r,'),       ['/foo/bar r,', '/foo/* r,', '/** r,']),                       ['/foo/bar r,', '/foo/* r,', '/** r,']),
        ((FileRule.create_instance('/foo/bar r,'),       ['audit /foo/bar r,', 'audit /foo/* r,', 'audit /** r,']),     ['/foo/bar r,', '/foo/* r,', '/** r,']),
        ((FileRule.create_instance('audit /foo/bar r,'), ['/foo/bar r,', '/foo/* r,', '#include <abstractions/base>']), ['audit /foo/bar r,', 'audit /foo/* r,', '#include <abstractions/base>']),
    )

    def _run_test(self, params, expected):
        rule_obj, options = params
        new_options = set_options_audit_mode(rule_obj, options)
        self.assertEqual(new_options, expected)


class AaTest_set_options_owner_mode(AATest):
    tests = (
        ((FileRule.create_instance('owner /foo/bar r,'),       ['/foo/bar r,', '/foo/* r,', '/** r,']),                                   ['owner /foo/bar r,', 'owner /foo/* r,', 'owner /** r,']),
        ((FileRule.create_instance('owner /foo/bar r,'),       ['/foo/bar r,', 'owner /foo/* r,', 'owner /** r,']),                       ['owner /foo/bar r,', 'owner /foo/* r,', 'owner /** r,']),
        ((FileRule.create_instance('/foo/bar r,'),             ['/foo/bar r,', '/foo/* r,', '/** r,']),                                   ['/foo/bar r,', '/foo/* r,', '/** r,']),
        ((FileRule.create_instance('/foo/bar r,'),             ['owner /foo/bar r,', 'owner /foo/* r,', 'owner /** r,']),                 ['/foo/bar r,', '/foo/* r,', '/** r,']),
        ((FileRule.create_instance('audit owner /foo/bar r,'), ['audit /foo/bar r,', 'audit /foo/* r,', '#include <abstractions/base>']), ['audit owner /foo/bar r,', 'audit owner /foo/* r,', '#include <abstractions/base>']),
    )

    def _run_test(self, params, expected):
        rule_obj, options = params
        new_options = set_options_owner_mode(rule_obj, options)
        self.assertEqual(new_options, expected)


class AaTest_is_skippable_file(AATest):
    def test_not_skippable_01(self):
        self.assertFalse(is_skippable_file('bin.ping'))

    def test_not_skippable_02(self):
        self.assertFalse(is_skippable_file('usr.lib.dovecot.anvil'))

    def test_not_skippable_03(self):
        self.assertFalse(is_skippable_file('bin.~ping'))

    def test_not_skippable_04(self):
        self.assertFalse(is_skippable_file('bin.rpmsave.ping'))

    def test_not_skippable_05(self):
        # normally is_skippable_file should be called without directory, but it shouldn't hurt too much
        self.assertFalse(is_skippable_file('/etc/apparmor.d/bin.ping'))

    def test_not_skippable_06(self):
        self.assertFalse(is_skippable_file('bin.pingrej'))

    def test_skippable_01(self):
        self.assertTrue(is_skippable_file('bin.ping.dpkg-new'))

    def test_skippable_02(self):
        self.assertTrue(is_skippable_file('bin.ping.dpkg-old'))

    def test_skippable_03(self):
        self.assertTrue(is_skippable_file('bin.ping..dpkg-dist'))

    def test_skippable_04(self):
        self.assertTrue(is_skippable_file('bin.ping..dpkg-bak'))

    def test_skippable_05(self):
        self.assertTrue(is_skippable_file('bin.ping.dpkg-remove'))

    def test_skippable_06(self):
        self.assertTrue(is_skippable_file('bin.ping.pacsave'))

    def test_skippable_07(self):
        self.assertTrue(is_skippable_file('bin.ping.pacnew'))

    def test_skippable_08(self):
        self.assertTrue(is_skippable_file('bin.ping.rpmnew'))

    def test_skippable_09(self):
        self.assertTrue(is_skippable_file('bin.ping.rpmsave'))

    def test_skippable_10(self):
        self.assertTrue(is_skippable_file('bin.ping.orig'))

    def test_skippable_11(self):
        self.assertTrue(is_skippable_file('bin.ping.rej'))

    def test_skippable_12(self):
        self.assertTrue(is_skippable_file('bin.ping~'))

    def test_skippable_13(self):
        self.assertTrue(is_skippable_file('.bin.ping'))

    def test_skippable_14(self):
        self.assertTrue(is_skippable_file(''))  # empty filename

    def test_skippable_15(self):
        self.assertTrue(is_skippable_file('/etc/apparmor.d/'))  # directory without filename

    def test_skippable_16(self):
        self.assertTrue(is_skippable_file('README'))


class AaTest_parse_profile_data(AATest):
    def test_parse_empty_profile_01(self):
        prof = parse_profile_data('/foo {\n}\n'.split(), 'somefile', False, False)

        self.assertEqual(list(prof.keys()), ['/foo'])
        self.assertEqual(prof['/foo']['name'], '/foo')
        self.assertEqual(prof['/foo']['filename'], 'somefile')
        self.assertEqual(prof['/foo']['flags'], None)

    def test_parse_duplicate_profile(self):
        with self.assertRaises(AppArmorException):
            # file contains two profiles with the same name
            parse_profile_data('profile /foo {\n}\nprofile /foo {\n}\n'.split(), 'somefile', False, False)

    def test_parse_duplicate_child_profile(self):
        with self.assertRaises(AppArmorException):
            # file contains two child profiles with the same name
            parse_profile_data('profile /foo {\nprofile /bar {\n}\nprofile /bar {\n}\n}\n'.split(), 'somefile', False, False)

    def test_parse_duplicate_hat(self):
        with self.assertRaises(AppArmorException):
            # file contains two hats with the same name
            parse_profile_data('profile /foo {\n^baz {\n}\n^baz {\n}\n}\n'.split(), 'somefile', False, False)

    def test_parse_xattrs_01(self):
        prof = parse_profile_data('/foo xattrs=(user.bar=bar) {\n}\n'.split(), 'somefile', False, False)

        self.assertEqual(list(prof.keys()), ['/foo'])
        self.assertEqual(prof['/foo']['name'], '/foo')
        self.assertEqual(prof['/foo']['filename'], 'somefile')
        self.assertEqual(prof['/foo']['flags'], None)
        self.assertEqual(prof['/foo']['xattrs'], 'user.bar=bar')

    def test_parse_xattrs_02(self):
        prof = parse_profile_data('/foo xattrs=(user.bar=bar user.foo=*) {\n}\n'.split(), 'somefile', False, False)

        self.assertEqual(list(prof.keys()), ['/foo'])
        self.assertEqual(prof['/foo']['name'], '/foo')
        self.assertEqual(prof['/foo']['filename'], 'somefile')
        self.assertEqual(prof['/foo']['flags'], None)
        self.assertEqual(prof['/foo']['xattrs'], 'user.bar=bar user.foo=*')

    def test_parse_xattrs_03(self):
        d = '/foo xattrs=(user.bar=bar) flags=(complain) {\n}\n'
        prof = parse_profile_data(d.split(), 'somefile', False, False)

        self.assertEqual(list(prof.keys()), ['/foo'])
        self.assertEqual(prof['/foo']['name'], '/foo')
        self.assertEqual(prof['/foo']['filename'], 'somefile')
        self.assertEqual(prof['/foo']['flags'], 'complain')
        self.assertEqual(prof['/foo']['xattrs'], 'user.bar=bar')

    def test_parse_xattrs_04(self):
        with self.assertRaises(AppArmorException):
            # flags before xattrs
            d = '/foo flags=(complain) xattrs=(user.bar=bar) {\n}\n'
            parse_profile_data(d.split(), 'somefile', False, False)


class AaTest_get_file_perms_1(AATest):
    tests = (
        ('/usr/share/common-licenses/foo/bar', {'allow': {'all': set(),           'owner': {'w'}}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/usr/share/common-licenses/**'}}),
        ('/dev/null',                          {'allow': {'all': {'r', 'w', 'k'}, 'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/dev/null'}}),
        ('/foo/bar',                           {'allow': {'all': {'r', 'w'},      'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/foo/bar'}}),  # exec perms not included
        ('/no/thing',                          {'allow': {'all': set(),           'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': set()}),
        ('/usr/lib/ispell/',                   {'allow': {'all': set(),           'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': set()}),
        ('/usr/lib/aspell/*.so',               {'allow': {'all': set(),           'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': set()}),
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        profile = apparmor.aa.ProfileStorage('/test', '/test', 'test-aa.py')

        # simple profile without any includes
        profile['file'].add(FileRule.create_instance('owner /usr/share/common-licenses/**  w,'))
        profile['file'].add(FileRule.create_instance('/dev/null rwk,'))
        profile['file'].add(FileRule.create_instance('/foo/bar rwix,'))

        perms = get_file_perms(profile, params, False, False)  # only testing with audit and deny = False
        self.assertEqual(perms, expected)


class AaTest_get_file_perms_2(AATest):
    tests = (
        ('/usr/share/common-licenses/foo/bar',   {'allow': {'all': {'r'},           'owner': {'w'}}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/usr/share/common-licenses/**'}}),
        ('/usr/share/common-licenses/what/ever', {'allow': {'all': {'r'},           'owner': {'w'}}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/usr/share/common-licenses/**', '/usr/share/common-licenses/what/ever'}}),
        ('/dev/null',                            {'allow': {'all': {'r', 'w', 'k'}, 'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/dev/null'}}),
        ('/foo/bar',                             {'allow': {'all': {'r', 'w'},      'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/foo/bar'}}),  # exec perms not included
        ('/no/thing',                            {'allow': {'all': set(),           'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': set()}),
        ('/usr/lib/ispell/',                     {'allow': {'all': {'r'},           'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/usr/lib/ispell/', '/{usr/,}lib{,32,64}/**'}}),  # from abstractions/enchant
        ('/usr/lib/aspell/*.so',                 {'allow': {'all': {'m', 'r'},      'owner': set()}, 'deny': {'all': set(), 'owner': set()}, 'paths': {'/usr/lib/aspell/*', '/usr/lib/aspell/*.so', '/{usr/,}lib{,32,64}/**', '/{usr/,}lib{,32,64}/**.so*'}}),  # from abstractions/aspell via abstractions/enchant and from abstractions/base
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        # load the abstractions we need in the test
        apparmor.aa.profile_dir = self.profile_dir
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/base'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/bash'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/enchant'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/aspell'))

        profile = apparmor.aa.ProfileStorage('/test', '/test', 'test-aa.py')
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/base>'))
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/bash>'))
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/enchant>'))

        profile['file'].add(FileRule.create_instance('owner /usr/share/common-licenses/**  w,'))
        profile['file'].add(FileRule.create_instance('owner /usr/share/common-licenses/what/ever a,'))  # covered by the above 'w' rule, so 'a' should be ignored
        profile['file'].add(FileRule.create_instance('/dev/null rwk,'))
        profile['file'].add(FileRule.create_instance('/foo/bar rwix,'))

        perms = get_file_perms(profile, params, False, False)  # only testing with audit and deny = False
        self.assertEqual(perms, expected)


class AaTest_propose_file_rules(AATest):
    tests = (
        # log event path                   and perms   expected proposals
        (('/usr/share/common-licenses/foo/bar', 'w'),  ['/usr/share/common*/foo/* rw,', '/usr/share/common-licenses/** rw,', '/usr/share/common-licenses/foo/bar rw,']),
        (('/dev/null',                          'wk'), ['/dev/null rwk,']),
        (('/foo/bar',                           'rw'), ['/foo/bar rw,']),
        (('/usr/lib/ispell/',                   'w'),  ['/{usr/,}lib{,32,64}/** rw,', '/usr/lib/ispell/ rw,']),
        (('/usr/lib/aspell/some.so',            'k'),  ['/usr/lib/aspell/* mrk,', '/usr/lib/aspell/*.so mrk,', '/{usr/,}lib{,32,64}/** mrk,', '/{usr/,}lib{,32,64}/**.so* mrk,', '/usr/lib/aspell/some.so mrk,']),
        (('/foo/log',                           'w'),  ['/foo/log w,']),
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        # load the abstractions we need in the test
        apparmor.aa.profile_dir = self.profile_dir
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/base'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/bash'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/enchant'))
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/aspell'))

        # add some user_globs ('(N)ew') to simulate a professional aa-logprof user (and to make sure that part of the code also gets tested)
        apparmor.aa.user_globs['/usr/share/common*/foo/*'] = AARE('/usr/share/common*/foo/*', True)
        apparmor.aa.user_globs['/no/thi*ng'] = AARE('/no/thi*ng', True)

        profile = apparmor.aa.ProfileStorage('/test', '/test', 'test-aa.py')
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/base>'))
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/bash>'))
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/enchant>'))

        profile['file'].add(FileRule.create_instance('owner /usr/share/common-licenses/**  w,'))
        profile['file'].add(FileRule.create_instance('/dev/null rwk,'))
        profile['file'].add(FileRule.create_instance('/foo/bar rwix,'))
        profile['file'].add(FileRule.create_instance('/foo/log a,'))  # will be replaced with '/foo/log w,' (not 'wa')

        rule_obj = FileRule(params[0], params[1], None, FileRule.ALL, owner=False, log_event=True)
        proposals = propose_file_rules(profile, rule_obj)
        self.assertEqual(proposals, expected)


class AaTest_propose_file_rules_with_absolute_includes(AATest):
    tests = (
        # log event path       and perms  expected proposals
        (('/not/found/anywhere',    'r'), ['/not/found/anywhere r,']),
        (('/dev/null',              'w'), ['/dev/null rw,']),
        (('/some/random/include',   'r'), ['/some/random/include rw,']),
        (('/some/other/include',    'w'), ['/some/other/* rw,', '/some/other/inc* rw,', '/some/other/include rw,']),
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        # load the abstractions we need in the test
        apparmor.aa.profile_dir = self.profile_dir
        apparmor.aa.load_include(os.path.join(self.profile_dir, 'abstractions/base'))

        abs_include1 = write_file(self.tmpdir, 'test-abs1', "/some/random/include rw,")
        apparmor.aa.load_include(abs_include1)

        abs_include2 = write_file(self.tmpdir, 'test-abs2', "/some/other/* rw,")
        apparmor.aa.load_include(abs_include2)

        abs_include3 = write_file(self.tmpdir, 'test-abs3', "/some/other/inc* rw,")
        apparmor.aa.load_include(abs_include3)

        profile = apparmor.aa.ProfileStorage('/test', '/test', 'test-aa.py')
        profile['inc_ie'].add(IncludeRule.create_instance('include <abstractions/base>'))
        profile['inc_ie'].add(IncludeRule.create_instance('include "{}"'.format(abs_include1)))
        profile['inc_ie'].add(IncludeRule.create_instance('include "{}"'.format(abs_include2)))
        profile['inc_ie'].add(IncludeRule.create_instance('include "{}"'.format(abs_include3)))

        rule_obj = FileRule(params[0], params[1], None, FileRule.ALL, owner=False, log_event=True)
        proposals = propose_file_rules(profile, rule_obj)
        self.assertEqual(proposals, expected)


class AaTest_nonexistent_includes(AATest):
    tests = (
        ("/nonexistent/absolute/path", AppArmorException),
        ("nonexistent/relative/path",  AppArmorBug),  # load_include() only accepts absolute paths
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            apparmor.aa.load_include(params)


class AaTest_merged_to_split(AATest):
    tests = (
        ("foo",           ("foo", "foo")),
        ("foo//bar",      ("foo", "bar")),
        ("foo//bar//baz", ("foo", "bar")),  # XXX known limitation
    )

    def _run_test(self, params, expected):
        merged = {}
        merged[params] = True  # simplified, but enough for this test
        result = merged_to_split(merged)

        profile, hat = expected

        self.assertEqual(list(result.keys()), [profile])
        self.assertEqual(list(result[profile].keys()), [hat])
        self.assertTrue(result[profile][hat])


class AaTest_split_to_merged(AATest):
    tests = (
        (("foo", "foo"), "foo"),
        (("foo", "bar"), "foo//bar"),
    )

    def _run_test(self, params, expected):
        old = {}
        profile = params[0]
        hat = params[1]

        old[profile] = {}
        old[profile][hat] = True  # simplified, but enough for this test
        result = split_to_merged(old)

        self.assertEqual(list(result.keys()), [expected])
        self.assertTrue(result[expected])


class AaTest_is_known_rule(AATest):
    tests = (
        (FileRule.create_instance("priority=-1 audit deny /foo r,"),    True),
        (FileRule.create_instance("priority=1 audit deny /foo r,"),     False)
    )

    def _run_test(self, params, expected):
        d = '/foo xattrs=(user.bar=bar) flags=(complain) {\n}\n'
        fr = FileRule.create_instance("audit deny /foo r,")

        prof = parse_profile_data(d.split(), 'somefile', False, False)
        prof['/foo']['file'].add(fr)

        self.assertEqual(is_known_rule(prof['/foo'], 'file', params), expected)
        self.assertEqual(prof['/foo']['file'].is_covered(params), expected)


setup_aa(apparmor.aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
