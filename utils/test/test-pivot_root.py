#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------

import unittest
from collections import namedtuple

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.logparser import ReadLog
from apparmor.aare import AARE
from apparmor.rule.pivot_root import PivotRootRule, PivotRootRuleset
from apparmor.translations import init_translation
from common_test import AATest, setup_all_loops

_ = init_translation()

exp = namedtuple(
    'exp', ('audit', 'allow_keyword', 'deny', 'comment', 'oldroot', 'all_oldroots', 'newroot',
            'all_newroots', 'profile_name', 'all_profile_names'),
)


# # --- tests for single PivotRootRule --- #

class PivotRootTest(AATest):
    def _compare_obj(self, obj, expected):
        self.assertEqual(expected.audit, obj.audit)
        self.assertEqual(expected.allow_keyword, obj.allow_keyword)
        self.assertEqual(expected.deny, obj.deny)
        self.assertEqual(expected.comment, obj.comment)

        if type(obj.oldroot) is AARE:
            self.assertEqual(expected.oldroot, obj.oldroot.regex)
        else:
            self.assertEqual(expected.oldroot, obj.oldroot)

        self.assertEqual(expected.all_oldroots, obj.all_oldroots)

        if type(obj.newroot) is AARE:
            self.assertEqual(expected.newroot, obj.newroot.regex)
        else:
            self.assertEqual(expected.newroot, obj.newroot)

        self.assertEqual(expected.all_newroots, obj.all_newroots)

        if type(obj.profile_name) is AARE:
            self.assertEqual(expected.profile_name, obj.profile_name.regex)
        else:
            self.assertEqual(expected.profile_name, obj.profile_name)

        self.assertEqual(expected.all_profile_names, obj.all_profile_names)


class PivotRootTestParse(PivotRootTest):
    tests = (
        # PivotRootRule object                                              audit  allow  deny   comment   oldroot      all?    newroot         all?    profile_name    all?
        ('pivot_root,',                                                 exp(False, False, False, '',       None,        True,   None,           True,   None,           True)),
        ('pivot_root oldroot=/oldroot,                         # cmt',  exp(False, False, False, ' # cmt', '/oldroot',  False,  None,           True,   None,           True)),
        ('pivot_root oldroot=/oldroot /new/root,               # cmt',  exp(False, False, False, ' # cmt', '/oldroot',  False,  '/new/root',    False,  None,           True)),
        ('pivot_root oldroot=/oldroot /new/root -> targetprof, # cmt',  exp(False, False, False, ' # cmt', '/oldroot',  False,  '/new/root',    False,  'targetprof',   False)),
        ('pivot_root oldroot=/oldroot           -> targetprof, # cmt',  exp(False, False, False, ' # cmt', '/oldroot',  False,  None,           True,   'targetprof',   False)),
        ('pivot_root                  /new/root,               # cmt',  exp(False, False, False, ' # cmt', None,        True,   '/new/root',    False,  None,           True)),
        ('pivot_root                  /new/root -> targetprof, # cmt',  exp(False, False, False, ' # cmt', None,        True,   '/new/root',    False,  'targetprof',   False)),
        ('pivot_root                            -> targetprof, # cmt',  exp(False, False, False, ' # cmt', None,        True,   None,           True,   'targetprof',   False)),
        ('pivot_root oldroot="/oldroot",                       # cmt',  exp(False, False, False, ' # cmt', '/oldroot',  False,  None,           True,   None,           True)),
        ('pivot_root                  "/new/root",             # cmt',  exp(False, False, False, ' # cmt', None,        True,   '/new/root',    False,  None,           True)),
        ('pivot_root                          -> "targetprof", # cmt',  exp(False, False, False, ' # cmt', None,        True,   None,           True,   'targetprof',   False)),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(PivotRootRule.match(rawrule))
        obj = PivotRootRule.create_instance(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)


class PivotRootTestParseInvalid(PivotRootTest):
    tests = (
        #                                    exception          matches regex
        ('pivot_root foo,',                 (AppArmorException, True)),
        ('pivot_root foo bar,',             (AppArmorException, True)),
        ('pivot_root oldroot= ,',           (AppArmorException, True)),
        ('pivot_root ->  ,',                (AppArmorException, True)),
        ('priority=a pivot_root,',          (AppArmorException, False)),
        ('priority=-1042 pivot_root,',      (AppArmorException, True)),
        ('pivot_rootbeer,',                 (AppArmorException, False))
    )

    def _run_test(self, rawrule, expected):
        self.parseInvalidRule(PivotRootRule, rawrule, expected)


class PivotRootTestParseFromLog(PivotRootTest):
    def test_pivot_root_from_log(self):
        parser = ReadLog('', '', '')
        event = 'type=AVC msg=audit(1409700678.384:547594): apparmor="DENIED" operation="pivotroot" profile="/home/ubuntu/bzr/apparmor/tests/regression/apparmor/pivot_root" name="/tmp/sdtest.21082-7446-EeefO6/new_root/" pid=21162 comm="pivot_root" srcname="/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/"'

        parsed_event = parser.parse_event(event)

        self.assertEqual(parsed_event, {
            'request_mask': None,
            'denied_mask': None,
            'error_code': 0,
            'magic_token': 0,
            'parent': 0,
            'profile': '/home/ubuntu/bzr/apparmor/tests/regression/apparmor/pivot_root',
            'operation': 'pivotroot',
            'resource': None,
            'info': None,
            'aamode': 'DENIED',
            'time': 1409700678,
            'active_hat': None,
            'pid': 21162,
            'task': 0,
            'attr': None,
            'name2': None,
            'src_name': '/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/',
            'name': '/tmp/sdtest.21082-7446-EeefO6/new_root/',
            'family': None,
            'protocol': None,
            'sock_type': None,
            'class': None,
        })

        obj = PivotRootRule(parsed_event['src_name'], parsed_event['name'], PivotRootRule.ALL, log_event=parsed_event)

        #             audit  allow  deny  comment   oldroot                                            all?   newroot                                    all?   target all?
        expected = exp(False, False, False, '',     '/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/', False, '/tmp/sdtest.21082-7446-EeefO6/new_root/', False, None, True)

        self._compare_obj(obj, expected)

        self.assertEqual(
            obj.get_raw(1),
            '  pivot_root oldroot=/tmp/sdtest.21082-7446-EeefO6/new_root/put_old/ /tmp/sdtest.21082-7446-EeefO6/new_root/,')


class PivotRootFromInit(PivotRootTest):
    tests = (
        # PivotRootRule object                                                                  audit  allow  deny   comment    oldroot     all?    newroot         all?    profile_name    all?
        (PivotRootRule('/oldroot',        '/new/root',       'some_profile',    deny=True), exp(False, False, True,  '',        '/oldroot', False,  '/new/root',    False,  'some_profile', False)),
        (PivotRootRule('/oldroot',        '/new/root',       PivotRootRule.ALL, deny=True), exp(False, False, True,  '',        '/oldroot', False,  '/new/root',    False,  None,           True)),
        (PivotRootRule('/oldroot',        PivotRootRule.ALL, '/someprofile',    deny=True), exp(False, False, True,  '',        '/oldroot', False,  None,           True,   '/someprofile', False)),
        (PivotRootRule(PivotRootRule.ALL, '/new/root',       '/someprofile',    deny=True), exp(False, False, True,  '',        None,       True,   '/new/root',    False,  '/someprofile', False)),
        (PivotRootRule('/oldroot',        PivotRootRule.ALL, PivotRootRule.ALL, deny=True), exp(False, False, True,  '',        '/oldroot', False,  None,           True,   None,           True)),
        (PivotRootRule(PivotRootRule.ALL, '/new/root',       PivotRootRule.ALL, deny=True), exp(False, False, True,  '',        None,       True,   '/new/root',    False,  None,           True)),
        (PivotRootRule(PivotRootRule.ALL, PivotRootRule.ALL, 'some_profile',    deny=True), exp(False, False, True,  '',        None,       True,   None,           True,   'some_profile', False)),
        (PivotRootRule(PivotRootRule.ALL, PivotRootRule.ALL, PivotRootRule.ALL, deny=True), exp(False, False, True,  '',        None,       True,   None,           True,   None,           True)),
    )

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidPivotRootInit(AATest):
    tests = (
        # (init params, expected exception)
        (('',     '/foo', 'bar'), AppArmorBug),        # empty oldroot
        (('/old', '',     'bar'), AppArmorBug),        # empty newroot
        (('/old', '/foo', ''   ), AppArmorBug),        # empty targetprof # noqa: E202

        (('old',  '/foo', 'bar'), AppArmorException),  # oldroot is not a path
        (('/old', 'foo',  'bar'), AppArmorException),  # newroot is not a path


        ((None,   '/foo', 'bar'), AppArmorBug),        # wrong type
        (('/old', None,   'bar'), AppArmorBug),        #
        (('/old', '/foo', None ), AppArmorBug),                           # noqa: E202

        ((dict(), '/foo', 'bar'), AppArmorBug),        # wrong type
        (('/old', dict(), 'bar'), AppArmorBug),        #
        (('/old', '/foo', dict()), AppArmorBug),       #
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            PivotRootRule(*params)

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            PivotRootRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            PivotRootRule('/foo')

    def test_missing_params_3(self):
        with self.assertRaises(TypeError):
            PivotRootRule('/foo', '/bar')

    def test_invalid_priority_1(self):
        with self.assertRaises(TypeError):
            PivotRootRule(PivotRootRule.ALL, PivotRootRule.ALL, PivotRootRule.ALL, priority=PivotRootRule.ALL)

    def test_invalid_priority_2(self):
        with self.assertRaises(AppArmorException):
            PivotRootRule(PivotRootRule.ALL, PivotRootRule.ALL, PivotRootRule.ALL, priority='invalid')


class InvalidPivotRootTest(AATest):
    def _check_invalid_rawrule(self, rawrule):
        obj = None
        self.assertFalse(PivotRootRule.match(rawrule))
        with self.assertRaises(AppArmorException):
            obj = PivotRootRule.create_instance(rawrule)

        self.assertIsNone(obj, 'PivotRootRule handed back an object unexpectedly')

    def test_invalid_pivot_root_missing_comma(self):
        self._check_invalid_rawrule('pivot_root')  # missing comma

    def test_invalid_non_PivotRootRule(self):
        self._check_invalid_rawrule('dbus,')  # not a pivot_root rule

    def test_empty_data_1(self):
        obj = PivotRootRule('/foo', '/bar', 'prof')
        obj.oldroot = ''
        # no oldroot set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)

    def test_empty_data_2(self):
        obj = PivotRootRule('/foo', '/bar', 'prof')
        obj.newroot = ''
        # no newroot set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)

    def test_empty_data_3(self):
        obj = PivotRootRule('/foo', '/bar', 'prof')
        obj.profile_name = ''
        # no profile_name set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)


class WritePivotRootTestAATest(AATest):
    def _run_test(self, rawrule, expected):
        self.assertTrue(PivotRootRule.match(rawrule))
        obj = PivotRootRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    tests = (
        #  raw rule                                           clean rule
        ('pivot_root,',                                           'pivot_root,'),
        ('     pivot_root         ,    # foo        ',            'pivot_root, # foo'),
        ('    audit     pivot_root /foo,',                        'audit pivot_root /foo,'),
        ('   deny pivot_root         /foo      ,# foo bar',       'deny pivot_root /foo, # foo bar'),
        ('   deny pivot_root        "/foo"     ,# foo bar',       'deny pivot_root /foo, # foo bar'),
        ('   allow pivot_root                        ,# foo bar', 'allow pivot_root, # foo bar'),
        ('   pivot_root  oldroot=/old       ,    # foo        ',            'pivot_root oldroot=/old, # foo'),
        ('   pivot_root  oldroot="/old"     ,    # foo        ',            'pivot_root oldroot=/old, # foo'),
        ('   pivot_root  oldroot=/old    ->  some_profile ,   ',            'pivot_root oldroot=/old -> some_profile,'),
        ('   pivot_root  oldroot=/old /new   ->  some_profile ,   ',            'pivot_root oldroot=/old /new -> some_profile,'),
        ('priority=1 pivot_root  oldroot=/old /new   ->  some_profile ,   ',    'priority=1 pivot_root oldroot=/old /new -> some_profile,'),
        ('priority=0 pivot_root  oldroot=/old /new   ->  some_profile ,   ',    'priority=0 pivot_root oldroot=/old /new -> some_profile,'),
        ('priority=-1 pivot_root  oldroot=/old /new   ->  some_profile ,  ',    'priority=-1 pivot_root oldroot=/old /new -> some_profile,'),
        ('priority=+1 pivot_root  oldroot=/old /new   ->  some_profile ,  ',    'priority=1 pivot_root oldroot=/old /new -> some_profile,'),
    )

    def test_write_manually(self):
        obj = PivotRootRule('/old', '/new', 'target', allow_keyword=True)

        expected = '    allow pivot_root oldroot=/old /new -> target,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class PivotRootCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = PivotRootRule.create_instance(self.rule)
        check_obj = PivotRootRule.create_instance(param)

        self.assertTrue(PivotRootRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected {}'.format(expected[0]))
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected {}'.format(expected[1]))

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected {}'.format(expected[2]))
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected {}'.format(expected[3]))


class PivotRootCoveredTest_01(PivotRootCoveredTest):
    rule = 'pivot_root /new,'

    tests = (
        #   rule                                         equal  strict equal  covered  covered exact
        ('pivot_root,',                                 (False, False,        False,   False)),
        ('pivot_root              /n*,',                (False, False,        False,   False)),
        ('pivot_root oldroot=/old,',                    (False, False,        False,   False)),
        ('pivot_root              /new,',               (True,  False,        True,    True)),
        ('pivot_root                   -> target,',     (False, False,        False,   False)),
        ('pivot_root oldroot=/old /new,',               (False, False,        True,    True)),
        ('pivot_root              /new -> target,',     (False, False,        True,    True)),
        ('pivot_root oldroot=/old      -> target,',     (False, False,        False,   False)),
        ('pivot_root oldroot=/old /new -> target,',     (False, False,        True,    True)),
    )


class PivotRootCoveredTest_02(PivotRootCoveredTest):
    rule = 'audit pivot_root oldroot=/ol*,'

    tests = (
        #   rule                                               equal  strict equal  covered  covered exact
        ('audit pivot_root,',                                 (False, False,        False,   False)),
        ('audit pivot_root oldroot=/ol*,',                    (True,  True,         True,    True)),
        ('audit pivot_root oldroot=/old,',                    (False, False,        True,    True)),
        ('audit pivot_root              /new,',               (False, False,        False,   False)),
        ('audit pivot_root                   -> target,',     (False, False,        False,   False)),
        ('audit pivot_root oldroot=/old /new,',               (False, False,        True,    True)),
        ('audit pivot_root              /new -> target,',     (False, False,        False,   False)),
        ('audit pivot_root oldroot=/old      -> target,',     (False, False,        True,    True)),  # covered exact - really?
        ('audit pivot_root oldroot=/old /new -> target,',     (False, False,        True,    True)),  # covered exact - really?
    )


class PivotRootCoveredTest_03(PivotRootCoveredTest):
    rule = 'pivot_root -> target,'

    tests = (
        #   rule                                         equal  strict equal  covered  covered exact
        ('pivot_root,',                                 (False, False,        False,   False)),
        ('pivot_root oldroot=/ol*,',                    (False, False,        False,   False)),
        ('pivot_root oldroot=/old,',                    (False, False,        False,   False)),
        ('pivot_root              /new,',               (False, False,        False,   False)),
        ('pivot_root                   -> target,',     (True,  False,        True,    True)),
        ('pivot_root oldroot=/old /new,',               (False, False,        False,   False)),
        ('pivot_root              /new -> target,',     (False, False,        True,    True)),
        ('pivot_root oldroot=/old      -> target,',     (False, False,        True,    True)),
        ('pivot_root oldroot=/old /new -> target,',     (False, False,        True,    True)),
    )


class PivotRootCoveredTest_04(PivotRootCoveredTest):
    rule = 'deny pivot_root /foo,'

    tests = (
        #   rule                         equal  strict equal  covered   covered exact
        ('      deny pivot_root /foo,',     (True,  True,         True,    True)),
        ('audit deny pivot_root /foo,',     (False, False,        False,   False)),
        ('           pivot_root /foo,',     (False, False,        False,   False)),  # XXX should covered be true here?
        ('      deny pivot_root /bar,',     (False, False,        False,   False)),
        ('      deny pivot_root,',          (False, False,        False,   False)),
    )


class PivotRootCoveredTest_Invalid(AATest):
    # TODO: should this be detected?
    # def test_borked_obj_is_covered_1(self):
    #     obj = PivotRootRule.create_instance('pivot_root oldroot=/old /new -> target,')

    #     testobj = PivotRootRule('/old', '/foo', 'targetprof')
    #     testobj.oldrooot = None

    #     with self.assertRaises(AppArmorBug):
    #         obj.is_covered(testobj)

    def test_borked_obj_is_covered_2(self):
        obj = PivotRootRule.create_instance('pivot_root oldroot=/old /new -> target,')

        testobj = PivotRootRule('/old', '/foo', 'targetprof')
        testobj.newroot = ''

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    # def test_borked_obj_is_covered_3(self):
    # TODO: should this be detected?
    #     obj = PivotRootRule.create_instance('pivot_root oldroot=/old /new -> target,')

    #     testobj = PivotRootRule('/old', '/foo', 'targetprof')
    #     testobj.profile_name = ''

    #     with self.assertRaises(AppArmorBug):
    #         obj.is_covered(testobj)

    def test_invalid_is_covered(self):
        raw_rule = 'pivot_root oldroot=/old /new -> target,'

        class SomeOtherClass(PivotRootRule):
            pass

        obj = PivotRootRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal_1(self):
        raw_rule = 'pivot_root oldroot=/old /new -> target,'

        class SomeOtherClass(PivotRootRule):
            pass

        obj = PivotRootRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

#   def test_invalid_is_equal_2(self):
    # TODO: should this be detected?
#       obj = PivotRootRule.create_instance('pivot_root oldroot=/old /new -> target,')

#       testobj = PivotRootRule.create_instance('pivot_root oldroot=/old /new -> target,')
#       testobj.all_oldroots = False  # make testobj invalid (should trigger exception in _is_equal_aare())

#       with self.assertRaises(AppArmorBug):
#           obj.is_equal(testobj)


class PivotRootLogprofHeaderTest(AATest):
    tests = (
        ('pivot_root,',                             [                              _('Old root'), _('ALL'),  _('New root'), _('ALL'),  _('Target profile'), _('ALL')]),  # noqa: E201
        ('pivot_root oldroot=/old,',                [                              _('Old root'), '/old',    _('New root'), _('ALL'),  _('Target profile'), _('ALL')]),  # noqa: E201
        ('deny pivot_root,',                        [_('Qualifier'), 'deny',       _('Old root'), _('ALL'),  _('New root'), _('ALL'),  _('Target profile'), _('ALL')]),
        ('allow pivot_root oldroot=/old,',          [_('Qualifier'), 'allow',      _('Old root'), '/old',    _('New root'), _('ALL'),  _('Target profile'), _('ALL')]),
        ('audit pivot_root /new,',                  [_('Qualifier'), 'audit',      _('Old root'), _('ALL'),  _('New root'), '/new',    _('Target profile'), _('ALL')]),
        ('audit deny pivot_root /new -> target,',   [_('Qualifier'), 'audit deny', _('Old root'), _('ALL'),  _('New root'), '/new',    _('Target profile'), 'target']),
        ('pivot_root oldroot=/old /new -> target,', [                              _('Old root'), '/old',    _('New root'), '/new',    _('Target profile'), 'target']),  # noqa: E201
    )

    def _run_test(self, params, expected):
        obj = PivotRootRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class PivotRootEditHeaderTest(AATest):
    def _run_test(self, params, expected):
        rule_obj = PivotRootRule.create_instance(params)
        self.assertEqual(rule_obj.can_edit, True)
        prompt, path_to_edit = rule_obj.edit_header()
        self.assertEqual(path_to_edit, expected)

    tests = (
        ('pivot_root oldroot=/old /foo/bar/baz -> target,',     '/foo/bar/baz'),
        ('pivot_root /foo/**/baz,',                             '/foo/**/baz'),
        ('pivot_root /foo/** -> /bar,',                         '/foo/**'),
    )

    def test_edit_header_bare_pivot_root(self):
        rule_obj = PivotRootRule.create_instance('pivot_root,')
        self.assertEqual(rule_obj.can_edit, False)
        with self.assertRaises(AppArmorBug):
            rule_obj.edit_header()


class PivotRootValidateAndStoreEditTest(AATest):
    def _run_test(self, params, expected):
        rule_obj = PivotRootRule('/old/', '/foo/bar/baz', 'target', log_event=True)

        self.assertEqual(rule_obj.validate_edit(params), expected)

        rule_obj.store_edit(params)
        self.assertEqual(rule_obj.get_raw(), 'pivot_root oldroot=/old/ ' + params + ' -> target,')

    tests = (
        # edited path     match
        ('/foo/bar/baz',  True),
        ('/foo/bar/*',    True),
        ('/foo/bar/???',  True),
        ('/foo/xy**',     False),
        ('/foo/bar/baz/', False),
    )

    def test_validate_not_a_path(self):
        rule_obj = PivotRootRule.create_instance('pivot_root /foo/bar/baz,')

        with self.assertRaises(AppArmorException):
            rule_obj.validate_edit('foo/bar/baz')

        with self.assertRaises(AppArmorException):
            rule_obj.store_edit('foo/bar/baz')

    def test_validate_edit_bare_pivot_root(self):
        rule_obj = PivotRootRule.create_instance('pivot_root,')
        self.assertEqual(rule_obj.can_edit, False)

        with self.assertRaises(AppArmorBug):
            rule_obj.validate_edit('/foo/bar')

        with self.assertRaises(AppArmorBug):
            rule_obj.store_edit('/foo/bar')


# --- tests for PivotRootRuleset --- #

class PivotRootRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = PivotRootRuleset()
        ruleset_2 = PivotRootRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

        # test __repr__() for empty ruleset
        self.assertEqual(str(ruleset), '<PivotRootRuleset (empty) />')

    def test_ruleset_1(self):
        ruleset = PivotRootRuleset()
        rules = (
            'pivot_root oldroot=/foo,',
            'pivot_root /new,',
        )

        expected_raw = [
            'pivot_root oldroot=/foo,',
            'pivot_root /new,',
            '',
        ]

        expected_clean = [
            'pivot_root /new,',
            'pivot_root oldroot=/foo,',
            '',
        ]

        for rule in rules:
            ruleset.add(PivotRootRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

        # test __repr__() for non-empty ruleset
        self.assertEqual(
            str(ruleset), '<PivotRootRuleset>\n  pivot_root oldroot=/foo,\n  pivot_root /new,\n</PivotRootRuleset>')


class PivotRootGlobTestAATest(AATest):
    def test_glob(self):
        glob_list = [(
            'pivot_root /foo/bar,',
            'pivot_root /foo/*,',
            'pivot_root /**,',
        )]
        for globs in glob_list:
            for i in range(len(globs) - 1):
                rule = PivotRootRule.create_instance(globs[i])
                rule.glob()
                self.assertEqual(rule.get_clean(), globs[i + 1])

    def test_glob_all(self):
        glob_list = [(
            'pivot_root,',
            'pivot_root,',
        )]
        for globs in glob_list:
            for i in range(len(globs) - 1):
                rule = PivotRootRule.create_instance(globs[i])
                rule.glob()
                self.assertEqual(rule.get_clean(), globs[i + 1])


#   def test_glob_ext(self):
#       # rule = PivotRootRule.create_instance('pivot_root /foo/bar,')
#       with self.assertRaises(NotImplementedError):
#           # get_glob_ext is not available for pivot_root rules
#           self.ruleset.get_glob_ext('pivot_root /foo,')


# class PivotRootDeleteTestAATest(AATest):
#     pass


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
