#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2017-2021 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.profile_storage import ProfileStorage, add_or_remove_flag, split_flags, var_transform
from apparmor.rule.all import AllRule
from apparmor.rule.file import FileRule
from common_test import AATest, setup_all_loops


class TestUnknownKey(AATest):
    def AASetup(self):
        self.storage = ProfileStorage('/test/foo', 'hat', 'TEST')

    def test_read(self):
        with self.assertRaises(AppArmorBug):
            self.storage['foo']

    def test_get(self):
        with self.assertRaises(AppArmorBug):
            self.storage.get('foo')

    def test_get_with_fallback(self):
        with self.assertRaises(AppArmorBug):
            self.storage.get('foo', 'bar')

    def test_set(self):
        with self.assertRaises(AppArmorBug):
            self.storage['foo'] = 'bar'


class AaTest_get_rules_clean(AATest):
    def test_all_rule_is_written(self):
        # 'all' was missing from the write order, which made every tool that
        # rewrites a profile drop the rule
        prof_storage = ProfileStorage('/foo', '', 'test')
        prof_storage['all'].add(AllRule())
        prof_storage['file'].add(FileRule.create_instance('/bar r,'))

        self.assertEqual(prof_storage.get_rules_clean(1), ['  all,', '', '  /bar r,', ''])


class AaTest_get_header(AATest):
    tests = (
        # name       embedded_hat  depth  flags       attachment  xattrs          prof.keyw.  comment  expected
        (('/foo',    False,        1,     'complain', '',         '',             False,      ''),     '  /foo flags=(complain) {'),
        (('/foo',    True,         1,     'complain', '',         '',             False,      ''),     '  profile /foo flags=(complain) {'),
        (('/foo sp', False,        2,     'complain', '',         '',             False,      ''),     '    "/foo sp" flags=(complain) {'),
        (('/foo',    True,         2,     'complain', '',         '',             False,      ''),     '    profile /foo flags=(complain) {'),
        (('/foo',    False,        0,     None,       '',         '',             False,      ''),     '/foo {'),
        (('/foo',    False,        0,     None,       '',         'user.foo=bar', False,      ''),     '/foo xattrs=(user.foo=bar) {'),
        (('/foo',    True,         0,     None,       '',         '',             False,      ''),     'profile /foo {'),
        (('bar',     False,        1,     'complain', '',         '',             False,      ''),     '  profile bar flags=(complain) {'),
        (('bar',     False,        1,     'complain', '/foo',     '',             False,      ''),     '  profile bar /foo flags=(complain) {'),
        (('bar',     True,         1,     'complain', '/foo',     '',             False,      ''),     '  profile bar /foo flags=(complain) {'),
        (('bar baz', False,        1,     None,       '/foo',     '',             False,      ''),     '  profile "bar baz" /foo {'),
        (('bar',     True,         1,     None,       '/foo',     '',             False,      ''),     '  profile bar /foo {'),
        (('bar baz', False,        1,     'complain', '/foo sp',  '',             False,      ''),     '  profile "bar baz" "/foo sp" flags=(complain) {'),
        (('bar baz', False,        1,     'complain', '/foo sp',  'user.foo=bar', False,      ''),     '  profile "bar baz" "/foo sp" xattrs=(user.foo=bar) flags=(complain) {'),
        (('^foo',    False,        1,     'complain', '',         '',             False,      ''),     '  profile ^foo flags=(complain) {'),
        (('^foo',    True,         1,     'complain', '',         '',             False,      ''),     '  ^foo flags=(complain) {'),
        (('^foo',    True,         1.5,   'complain', '',         '',             False,      ''),     '   ^foo flags=(complain) {'),
        (('^foo',    True,         1.3,   'complain', '',         '',             False,      ''),     '  ^foo flags=(complain) {'),
        (('/foo',    False,        1,     'complain', '',         '',             True,       ''),     '  profile /foo flags=(complain) {'),
        (('/foo',    True,         1,     'complain', '',         '',             True,       ''),     '  profile /foo flags=(complain) {'),
        (('/foo',    False,        1,     'complain', '',         '',             False,      '# x'),  '  /foo flags=(complain) { # x'),
        (('/foo',    True,         1,     None,       '',         '',             False,      '# x'),  '  profile /foo { # x'),
        (('/foo',    False,        1,     None,       '',         '',             True,       '# x'),  '  profile /foo { # x'),
        (('/foo',    True,         1,     'complain', '',         '',             True,       '# x'),  '  profile /foo flags=(complain) { # x'),
    )

    def _run_test(self, params, expected):
        name = params[0]
        embedded_hat = params[1]
        depth = params[2]

        prof_storage = ProfileStorage(name, '', 'test')
        prof_storage['flags'] = params[3]
        prof_storage['attachment'] = params[4]
        prof_storage['xattrs'] = params[5]
        prof_storage['profile_keyword'] = params[6]
        prof_storage['header_comment'] = params[7]

        result = prof_storage.get_header(depth, name, embedded_hat)
        self.assertEqual(result, [expected])


class AaTest_get_header_01(AATest):
    tests = (
        ({'name': '/foo', 'depth': 1,                          'flags': 'complain'                                             }, '  /foo flags=(complain) {'),
        ({'name': '/foo', 'depth': 1,                          'flags': 'complain', 'profile_keyword': True                    }, '  profile /foo flags=(complain) {'),
        ({'name': '/foo',                                      'flags': 'complain'                                             }, '/foo flags=(complain) {'),
        ({'name': '/foo',            'xattrs': 'user.foo=bar', 'flags': 'complain'                                             }, '/foo xattrs=(user.foo=bar) flags=(complain) {'),
        ({'name': '/foo',            'xattrs': 'user.foo=bar',                                             'embedded_hat': True}, 'profile /foo xattrs=(user.foo=bar) {'),
    )

    def _run_test(self, params, expected):
        name = params['name']
        embedded_hat = params.get('embedded_hat', False)
        depth = params.get('depth', 0)

        prof_storage = ProfileStorage(name, '', 'test')

        for param in ('flags', 'attachment', 'profile_keyword', 'header_comment', 'xattrs'):
            if params.get(param) is not None:
                prof_storage[param] = params[param]

        result = prof_storage.get_header(depth, name, embedded_hat)
        self.assertEqual(result, [expected])


class TestSetInvalid(AATest):
    tests = (
        (('profile_keyword', None),  AppArmorBug),  # expects bool
        (('profile_keyword', 'foo'), AppArmorBug),
        (('attachment',      False), AppArmorBug),  # expects string
        (('attachment',      None),  AppArmorBug),
        (('filename',        True),  AppArmorBug),  # expects string or None
        (('allow',           None),  AppArmorBug),  # doesn't allow overwriting at all
    )

    def _run_test(self, params, expected):
        self.storage = ProfileStorage('/test/foo', 'hat', 'TEST')
        with self.assertRaises(expected):
            self.storage[params[0]] = params[1]


class AaTest_parse_profile_start(AATest):
    tests = (
        # profile start line                                    profile  hat     profile                 hat                attachment   xattrs                     flags       pps_set_hat_external
        (('/foo {',                                             None,    None), ('/foo',                 '/foo',                 '',     '',                        None,       False)),
        (('/foo (complain) {',                                  None,    None), ('/foo',                 '/foo',                 '',     '',                        'complain', False)),
        (('profile foo /foo {',                                 None,    None), ('foo',                  'foo',                  '/foo', '',                        None,       False)),  # named profile
        (('profile /foo {',                                     '/bar',  None), ('/bar',                 '/foo',                 '',     '',                        None,       False)),  # child profile
        (('/foo//bar {',                                        None,    None), ('/foo',                 'bar',                  '',     '',                        None,       True)),   # external hat
        (('profile "/foo" (complain) {',                        None,    None), ('/foo',                 '/foo',                 '',     '',                        'complain', False)),
        (('profile "/foo" xattrs=(user.bar=bar) {',             None,    None), ('/foo',                 '/foo',                 '',     'user.bar=bar',            None,       False)),
        (('profile "/foo" xattrs=(user.bar=bar user.foo=*) {',  None,    None), ('/foo',                 '/foo',                 '',     'user.bar=bar user.foo=*', None,       False)),
        (('/usr/bin/xattrs-test xattrs=(myvalue="foo.bar") {',  None,    None), ('/usr/bin/xattrs-test', '/usr/bin/xattrs-test', '',     'myvalue="foo.bar"',       None,       False)),
    )

    def _run_test(self, params, expected):
        (profile, hat, prof_storage) = ProfileStorage.parse(params[0], 'somefile', 1, params[1], params[2])

        self.assertEqual(profile,                    expected[0])
        self.assertEqual(hat,                        expected[1])
        self.assertEqual(prof_storage['attachment'], expected[2])
        self.assertEqual(prof_storage['xattrs'],     expected[3])
        self.assertEqual(prof_storage['flags'],      expected[4])
        self.assertEqual(prof_storage['is_hat'],     False)
        self.assertEqual(prof_storage['external'],   expected[5])


class AaTest_parse_profile_start_errors(AATest):
    tests = (
        (('/foo///bar///baz {', None,   None),   AppArmorException),  # XXX deeply nested external hat
        (('profile asdf {',     '/foo', '/bar'), AppArmorException),  # nested child profile
        (('/foo {',             '/bar', None),   AppArmorException),  # child profile without profile keyword
        (('/foo {',             '/bar', '/bar'), AppArmorException),  # child profile without profile keyword
        (('xy',                 '/bar', None),   AppArmorBug),        # not a profile start
        (('xy',                 '/bar', '/bar'), AppArmorBug),        # not a profile start
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            ProfileStorage.parse(params[0], 'somefile', 1, params[1], params[2])


class AaTest_add_or_remove_flag(AATest):
    tests = (
        # existing flag(s)   flag to change   add or remove?   expected flags
        (([],                'complain',            True),     ['complain']),
        (([],                'complain',            False),    []),
        ((['complain'],      'complain',            True),     ['complain']),
        ((['complain'],      'complain',            False),    []),
        (([],                'audit',               True),     ['audit']),
        (([],                'audit',               False),    []),
        ((['complain'],      'audit',               True),     ['audit', 'complain']),
        ((['complain'],      'audit',               False),    ['complain']),
        (('',                'audit',               True),     ['audit']),
        ((None,              'audit',               False),    []),
        (('complain',        'audit',               True),     ['audit', 'complain']),
        (('  complain  ',    'audit',               False),    ['complain']),
        (('audit complain',  ('audit', 'complain'), False),    []),
        (('audit complain',  'audit complain',      False),    []),
        (('audit complain',  ('audit', 'enforce'),  False),    ['complain']),
        (('audit complain',  'audit enforce',       False),    ['complain']),
        (('',                ('audit', 'complain'), True),     ['audit', 'complain']),
        (('',                'audit complain',      True),     ['audit', 'complain']),
        (('audit',           ('audit', 'enforce'),  True),     ['audit', 'enforce']),
        (('audit',           'audit enforce',       True),     ['audit', 'enforce']),
    )

    def _run_test(self, params, expected):
        new_flags = add_or_remove_flag(*params)
        self.assertEqual(new_flags, expected)


class AaTest_split_flags(AATest):
    tests = (
        (None,                               []),
        ('',                                 []),
        ('       ',                          []),
        ('  ,       ',                       []),
        ('complain',                         ['complain']),
        ('  complain   attach_disconnected', ['attach_disconnected', 'complain']),
        ('  complain , attach_disconnected', ['attach_disconnected', 'complain']),
        ('  complain , , audit , , ',        ['audit', 'complain']),
    )

    def _run_test(self, params, expected):
        split = split_flags(params)
        self.assertEqual(split, expected)


class AaTest_var_transform(AATest):
    tests = (
        (('foo', ''),        '"" foo'),
        (('foo', 'bar'),     'bar foo'),
        (('',),              '""'),
        (('bar baz', 'foo'), '"bar baz" foo'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(var_transform(params), expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
