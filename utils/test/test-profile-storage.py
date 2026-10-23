#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2017-2024 Christian Boltz <apparmor@cboltz.de>
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
from apparmor.rule.capability import CapabilityRule
from apparmor.rule.file import FileRule
from apparmor.rule.include import IncludeRule
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
        (('/foo',    False,        1,     'complain', '',         {},             False,      ''),     '  /foo flags=(complain) {'),
        (('/foo',    True,         1,     'complain', '',         {},             False,      ''),     '  profile /foo flags=(complain) {'),
        (('/foo sp', False,        2,     'complain', '',         {},             False,      ''),     '    "/foo sp" flags=(complain) {'),
        (('/foo',    True,         2,     'complain', '',         {},             False,      ''),     '    profile /foo flags=(complain) {'),
        (('/foo',    False,        0,     None,       '',         {},             False,      ''),     '/foo {'),
        (('/foo',    False,        0,     None,       '',         {'user.foo': 'bar'}, False,      ''),     '/foo xattrs=(user.foo=bar) {'),
        (('/foo',    True,         0,     None,       '',         {},             False,      ''),     'profile /foo {'),
        (('bar',     False,        1,     'complain', '',         {},             False,      ''),     '  profile bar flags=(complain) {'),
        (('bar',     False,        1,     'complain', '/foo',     {},             False,      ''),     '  profile bar /foo flags=(complain) {'),
        (('bar',     True,         1,     'complain', '/foo',     {},             False,      ''),     '  profile bar /foo flags=(complain) {'),
        (('bar baz', False,        1,     None,       '/foo',     {},             False,      ''),     '  profile "bar baz" /foo {'),
        (('bar',     True,         1,     None,       '/foo',     {},             False,      ''),     '  profile bar /foo {'),
        (('bar baz', False,        1,     'complain', '/foo sp',  {},             False,      ''),     '  profile "bar baz" "/foo sp" flags=(complain) {'),
        (('bar baz', False,        1,     'complain', '/foo sp',  {'user.foo': 'bar'}, False,      ''),     '  profile "bar baz" "/foo sp" xattrs=(user.foo=bar) flags=(complain) {'),
        (('^foo',    False,        1,     'complain', '',         {},             False,      ''),     '  profile ^foo flags=(complain) {'),
        (('^foo',    True,         1,     'complain', '',         {},             False,      ''),     '  ^foo flags=(complain) {'),
        (('^foo',    True,         1.5,   'complain', '',         {},             False,      ''),     '   ^foo flags=(complain) {'),
        (('^foo',    True,         1.3,   'complain', '',         {},             False,      ''),     '  ^foo flags=(complain) {'),
        (('/foo',    False,        1,     'complain', '',         {},             True,       ''),     '  profile /foo flags=(complain) {'),
        (('/foo',    True,         1,     'complain', '',         {},             True,       ''),     '  profile /foo flags=(complain) {'),
        (('/foo',    False,        1,     'complain', '',         {},             False,      '# x'),  '  /foo flags=(complain) { # x'),
        (('/foo',    True,         1,     None,       '',         {},             False,      '# x'),  '  profile /foo { # x'),
        (('/foo',    False,        1,     None,       '',         {},             True,       '# x'),  '  profile /foo { # x'),
        (('/foo',    True,         1,     'complain', '',         {},             True,       '# x'),  '  profile /foo flags=(complain) { # x'),
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

        result = prof_storage.get_header(depth, embedded_hat)
        self.assertEqual(result, [expected])


class AaTest_get_header_01(AATest):
    tests = (
        ({'name': '/foo', 'depth': 1,                          'flags': 'complain'},                                              '  /foo flags=(complain) {'),
        ({'name': '/foo', 'depth': 1,                          'flags': 'complain', 'profile_keyword': True},                     '  profile /foo flags=(complain) {'),
        ({'name': '/foo',                                      'flags': 'complain'},                                              '/foo flags=(complain) {'),
        ({'name': '/foo',            'xattrs': {'user.foo': 'bar'}, 'flags': 'complain'},                                              '/foo xattrs=(user.foo=bar) flags=(complain) {'),
        ({'name': '/foo',            'xattrs': {'user.foo': 'bar'},                                             'embedded_hat': True}, 'profile /foo xattrs=(user.foo=bar) {'),
        ({'name': '/foo',            'xattrs': {'user.foo': None},                                             'embedded_hat': True}, 'profile /foo xattrs=(user.foo) {'),
        ({'name': '/foo',            'xattrs': {'user.foo': None, 'user.bar': None},                                             'embedded_hat': True}, 'profile /foo xattrs=(user.bar user.foo) {'),
    )

    def _run_test(self, params, expected):
        name = params['name']
        embedded_hat = params.get('embedded_hat', False)
        depth = params.get('depth', 0)

        prof_storage = ProfileStorage(name, '', 'test')

        for param in ('flags', 'attachment', 'profile_keyword', 'header_comment', 'xattrs'):
            if params.get(param) is not None:
                prof_storage[param] = params[param]

        result = prof_storage.get_header(depth, embedded_hat)
        self.assertEqual(result, [expected])


class AaTest_get_header_after_parse(AATest):
    tests = (
        # profile start line                                   profile  hat   embedded_hat depth  clean header
        (('/foo {',                                            None,    None, False,       0),   ('/foo {')),
        (('/foo flags=(complain) {',                           None,    None, False,       0),   ('/foo flags=(complain) {')),
        (('profile /foo {',                                    None,    None, False,       2),   ('    profile /foo {')),
        (('profile /foo {',                                    '/bar',  None, False,       1),   ('  profile /foo {')),  # child profile
        (('profile /foo flags=(complain) {',                   None,    None, False,       0),   ('profile /foo flags=(complain) {')),
        (('profile foo /foo {',                                None,    None, False,       0),   ('profile foo /foo {')),  # named profile
        (('profile foo /foo flags=(complain) {',               None,    None, False,       0),   ('profile foo /foo flags=(complain) {')),  # named profile and flags
        (('profile foo /foo flags=(enforce) {',                '/bar',  None, False,       0),   ('profile foo /foo flags=(enforce) {')),  # child profile and flags
        (('/foo//bar {',                                       None,    None, True,        1),   ('  profile /foo//bar {')),  # external hat
        (('/bin/bash///bin/cat {',                             None,    None, True,        1),   ('  profile /bin/bash///bin/cat {')),  # external hat
        (('profile /foo//bar {',                               None,    None, True,        1),   ('  profile /foo//bar {')),  # external hat and name is attachment
        (('profile foo//bar {',                                None,    None, True,        2),   ('    profile foo//bar {')),  # external hat and no attachment
        (('profile foo//bar /attachment {',                    None,    None, True,        2),   ('    profile foo//bar /attachment {')),  # external hat and attachment
        (('/foo//bar flags=(enforce) {',                       None,    None, True,        1),   ('  profile /foo//bar flags=(enforce) {')),  # external hat and flags
        (('profile /foo//bar flags=(attach_disconnected) {',   None,    None, True,        1),   ('  profile /foo//bar flags=(attach_disconnected) {')),  # external hat, name is attachment and flags
        (('profile foo//bar flags=(complain) {',               None,    None, True,        2),   ('    profile foo//bar flags=(complain) {')),  # external hat, no attachment and flags
        (('profile foo//bar /attachment flags=(complain) {',   None,    None, True,        2),   ('    profile foo//bar /attachment flags=(complain) {')),  # external hat, attachment and flags
        (('profile "foo//has spaces" {',                       None,    None, True,        1),   ('  profile "foo//has spaces" {')),  # quoted external hat
        (('profile "/path/with spaces/foo//has spaces" {',     None,    None, True,        0),   ('profile "/path/with spaces/foo//has spaces" {')),  # quoted external hat
        (('profile "foo//has spaces" flags=(complain) {',      None,    None, True,        1),   ('  profile "foo//has spaces" flags=(complain) {')),  # quoted external hat and flags
        (('profile "/p h/foo//has spaces" flags=(complain) {', None,    None, True,        0),   ('profile "/p h/foo//has spaces" flags=(complain) {')),  # quoted external hat and flags
        (('profile /foo xattrs=(user.bar=bar) {',              None,    None, False,       1),   ('  profile /foo xattrs=(user.bar=bar) {')),
        (('profile "/foo" xattrs=(user.bar=bar user.foo=*) {', None,    None, False,       0),   ('profile /foo xattrs=(user.bar=bar user.foo=*) {')),
        (('/usr/bin/xattrs-test xattrs=(myvalue="foo.bar") {', None,    None, False,       0),   ('/usr/bin/xattrs-test xattrs=(myvalue="foo.bar") {')),
        (('profile /foo xattrs=(user.bar=bar) {',              '/bar',  None, False,       1),   ('  profile /foo xattrs=(user.bar=bar) {')),  # child profile
        (('profile "/foo" xattrs=(user.bar=bar user.foo=*) {', '/bar',  None, False,       0),   ('profile /foo xattrs=(user.bar=bar user.foo=*) {')),  # child profile
        (('profile /bin/xattr xattrs=(myvalue="foo.bar") {',   '/bar',  None, False,       0),   ('profile /bin/xattr xattrs=(myvalue="foo.bar") {')),  # child profile needs profile keyword
        (('profile /foo//bar xattrs=(user.bar=bar) {',         None,    None, True,        1),   ('  profile /foo//bar xattrs=(user.bar=bar) {')),  # external hat
        (('profile foo//bar /foo xattrs=(user.bar=bar) {',     None,    None, True,        1),   ('  profile foo//bar /foo xattrs=(user.bar=bar) {')),  # external hat
        (('profile "foo//bar" xattrs=(user.bar=b user.f=*) {', None,    None, True,        0),   ('profile foo//bar xattrs=(user.bar=b user.f=*) {')),  # external hat
        (('/bin/xattrs//test xattrs=(myvalue="foo.bar") {',    None,    None, True,        0),   ('profile /bin/xattrs//test xattrs=(myvalue="foo.bar") {')),  # external hat

        (('^foo {',                                            None,    None, True,        1),   ('  ^foo {')),
        (('hat foo {',                                         None,    None, True,        1),   ('  hat foo {')),
        (('^foo flags=(complain) {',                           None,    None, True,        0),   ('^foo flags=(complain) {')),
        (('hat foo flags=(attach_disconnected) {',             None,    None, True,        0),   ('hat foo flags=(attach_disconnected) {')),
        (('^foo {',                                            '/bar',  None, True,        1),   ('  ^foo {')),
        (('hat foo {',                                         '/bar',  None, True,        0),   ('hat foo {')),
        (('^foo flags=(complain) {',                           '/bar',  None, True,        0),   ('^foo flags=(complain) {')),
        (('hat foo flags=(attach_disconnected) {',             '/bar',  None, True,        2),   ('    hat foo flags=(attach_disconnected) {')),
        (('^/bar//foo {',                                      None,    None, True,        0),   ('^/bar//foo {')),
        (('hat /bar//foo {',                                   None,    None, True,        1),   ('  hat /bar//foo {')),
        (('^/bar//foo flags=(complain) {',                     None,    None, True,        1),   ('  ^/bar//foo flags=(complain) {')),
        (('hat /bar//foo flags=(attach_disconnected) {',       None,    None, True,        0),   ('hat /bar//foo flags=(attach_disconnected) {')),
        (('^bar//foo {',                                       None,    None, True,        0),   ('^bar//foo {')),
        (('hat bar//foo {',                                    None,    None, True,        1),   ('  hat bar//foo {')),
        (('^bar//foo flags=(complain) {',                      None,    None, True,        1),   ('  ^bar//foo flags=(complain) {')),
        (('hat bar//foo flags=(attach_disconnected) {',        None,    None, True,        0),   ('hat bar//foo flags=(attach_disconnected) {')),
        (('^"/bar//foo space" {',                              None,    None, True,        1),   ('  ^"/bar//foo space" {')),
        (('hat "bar//foo space" {',                            None,    None, True,        0),   ('hat "bar//foo space" {')),
        (('^"/space bar//foo" flags=(complain) {',             None,    None, True,        1),   ('  ^"/space bar//foo" flags=(complain) {')),
        (('hat "space ba//foo" flags=(attach_disconnected) {', None,    None, True,        0),   ('hat "space ba//foo" flags=(attach_disconnected) {')),
    )

    def _run_test(self, params, expected):
        (profile, hat, prof_storage) = ProfileStorage.parse(params[0], 'somefile', 1, params[1], params[2])
        header = prof_storage.get_header(params[4], params[3])
        self.assertEqual(header, [expected], prof_storage.data)


class TestSetInvalid(AATest):
    tests = (
        (('profile_keyword', None),  AppArmorBug),  # expects bool
        (('profile_keyword', 'foo'), AppArmorBug),
        (('attachment',      False), AppArmorBug),  # expects string
        (('attachment',      None),  AppArmorBug),
        (('filename',        True),  AppArmorBug),  # expects string or None
        (('allow',           None),  AppArmorBug),  # doesn't allow overwriting at all
        (('xattrs',          0),     AppArmorBug),  # Invalid type
    )

    def _run_test(self, params, expected):
        self.storage = ProfileStorage('/test/foo', 'hat', 'TEST')
        with self.assertRaises(expected):
            self.storage[params[0]] = params[1]

    def testInvalidTypeChange(self):
        storage = ProfileStorage('/test/foo', 'hat', 'TEST')
        storage.data['invalid'] = 42  # manually set behind __setitem__'s back to avoid checks
        with self.assertRaises(AppArmorBug):
            storage['invalid'] = 'foo'  # attempt to change type from int to str


class AaTest_repr(AATest):
    def testRepr(self):
        prof_storage = ProfileStorage('foo', 'hat', 'TEST')
        prof_storage['name'] = 'foo'
        prof_storage['xattrs'] = {'user.bar': 'bar'}
        prof_storage['capability'].add(CapabilityRule('dac_override'))

        self.assertEqual(str(prof_storage), '\n<ProfileStorage>\nprofile foo xattrs=(user.bar=bar) {\n  capability dac_override,\n\n}\n</ProfileStorage>\n')


class AaTest_parse_profile_start(AATest):
    tests = (
        # profile start line                                    profile  hat     parent     name                       profile                 hat                attachment   xattrs                     flags       pps_set_hat_external
        (('/foo {',                                             None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {},                        None,       False)),
        (('/foo (complain) {',                                  None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {},                        'complain', False)),
        (('profile foo /foo {',                                 None,    None), ('',        'foo',                     'foo',                  'foo',                  '/foo', {},                        None,       False)),  # named profile
        (('profile /foo {',                                     '/bar',  None), ('/bar',    '/foo',                    '/bar',                 '/foo',                 '',     {},                        None,       False)),  # child profile
        (('profile /foo xattrs=() {',                           '/bar',  None), ('/bar',    '/foo',                    '/bar',                 '/foo',                 '',     {},                        None,       False)),
        (('/foo//bar {',                                        None,    None), ('/foo',    '/foo//bar',               '/foo',                 'bar',                  '',     {},                        None,       True)),   # external hat
        (('profile "/foo" (complain) {',                        None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {},                        'complain', False)),
        (('profile "/foo" xattrs=() {',                         None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {},                        None,       False)),
        (('profile "/foo" xattrs=(user.bar) {',                 None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {'user.bar': None},        None,       False)),
        (('profile "/foo" xattrs=(user.foo user.bar) {',        None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {'user.bar': None, 'user.foo': None},
                                                                                                                                                                                                          None,       False)),  # noqa: E127
        (('profile "/foo" xattrs=(user.bar=bar) {',             None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {'user.bar': 'bar'},       None,       False)),
        (('profile "/foo" xattrs=(user.bar=bar user.foo=*) {',  None,    None), ('',        '/foo',                    '/foo',                 '/foo',                 '',     {'user.bar': 'bar', 'user.foo': '*'},
                                                                                                                                                                                                          None,       False)),  # noqa: E127
        (('/usr/bin/xattrs-test xattrs=(myvalue="foo.bar") {',  None,    None), ('',        '/usr/bin/xattrs-test',    '/usr/bin/xattrs-test', '/usr/bin/xattrs-test', '',     {'myvalue': '"foo.bar"'},  None,       False)),
    )

    def _run_test(self, params, expected):
        (profile, hat, prof_storage) = ProfileStorage.parse(params[0], 'somefile', 1, params[1], params[2])

        self.assertEqual(prof_storage['parent'],     expected[0])
        self.assertEqual(prof_storage['name'],       expected[1])
        self.assertEqual(profile,                    expected[2])
        self.assertEqual(hat,                        expected[3])
        self.assertEqual(prof_storage['attachment'], expected[4])
        self.assertEqual(prof_storage['xattrs'],     expected[5])
        self.assertEqual(prof_storage['flags'],      expected[6])
        self.assertEqual(prof_storage['is_hat'],     False)
        self.assertEqual(prof_storage['external'],   expected[7])


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


class AaTest_include(AATest):
    tests = (
        (('profile foo /foo {', []),                                        None),  # No include
        (('profile foo /foo {', ['elsewhere/foo']),                         None),  # No include in local/
        (('profile foo /foo {', ['local/foo']),                             "local/foo"),  # Single include, we pick it
        (('profile foo /foo {', ['local/bar']),                             "local/bar"),  # Single include, we pick it
        (('profile x//y /y {',  ['local/x..y', 'local/y']),                 "local/x..y"),  # Pick the include that matches the profile nam
        (('profile foo /foo {', ['local/bar', 'local/foo', 'local/baz']),   "local/foo"),  # Pick the include that matches the profile name
        (('/usr/bin/xx {',      ['local/usr.bin.xx', 'local/xx']),          "local/usr.bin.xx"),  # Pick the include that matches the profile name
        (('profile foo /foo {', ['local/bar', 'local/baz', 'local/qux']),   "local/qux"),  # No match, pick the last one
    )

    def _run_test(self, params, expected):
        (profile, hat, prof_storage) = ProfileStorage.parse(params[0], 'somefile', 1, None, None)

        for inc in params[1]:
            prof_storage.data['inc_ie'].add(IncludeRule(inc, True, True))

        self.assertEqual(prof_storage.get_local_include(), expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
