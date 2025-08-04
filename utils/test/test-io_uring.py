#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2023 Canonical, Ltd.
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
from common_test import AATest, setup_all_loops

from apparmor.rule.io_uring import IOUringRule, IOUringRuleset
from apparmor.common import AppArmorException, AppArmorBug
from apparmor.translations import init_translation
_ = init_translation()


class IOUringTestParse(AATest):
    tests = (
        #                                                             access                        label            audit  deny   allow  comment
        ('io_uring,',                                     IOUringRule(IOUringRule.ALL,              IOUringRule.ALL, False, False, False, '')),
        ('io_uring sqpoll,',                              IOUringRule(('sqpoll'),                   IOUringRule.ALL, False, False, False, '')),
        ('io_uring override_creds,',                      IOUringRule(('override_creds'),           IOUringRule.ALL, False, False, False, '')),
        ('io_uring override_creds label=/foo,',           IOUringRule(('override_creds'),           '/foo',          False, False, False, '')),
        ('io_uring sqpoll label=bar,',                    IOUringRule(('sqpoll'),                    'bar',           False, False, False, '')),
        ('io_uring (override_creds, sqpoll) label=/foo,', IOUringRule(('override_creds', 'sqpoll'), '/foo',          False, False, False, '')),
        ('audit io_uring sqpoll,',                        IOUringRule(('sqpoll'),                   IOUringRule.ALL, True,  False, False, '')),
        ('deny io_uring,',                                IOUringRule(IOUringRule.ALL,              IOUringRule.ALL, False, True,  False, '')),
        ('deny io_uring (sqpoll, override_creds),',       IOUringRule(('sqpoll', 'override_creds'), IOUringRule.ALL, False, True,  False, '')),
        ('audit allow io_uring,',                         IOUringRule(IOUringRule.ALL,              IOUringRule.ALL, True,  False, True,  '')),
        ('io_uring override_creds, # cmt',                IOUringRule(('override_creds'),           IOUringRule.ALL, False, False, False, ' # cmt')),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(IOUringRule.match(rawrule))
        obj = IOUringRule.create_instance(rawrule)
        expected.raw_rule = rawrule.strip()
        self.assertTrue(obj.is_equal(expected, True))


class IOUringTestParseInvalid(AATest):
    tests = (
        ('io_uring invalidaccess,',           AppArmorException),
        ('io_uring label=,',                  AppArmorException),
        ('io_uring invalidaccess label=foo,', AppArmorException),
        ('io_uring sqpoll label=,',           AppArmorException),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(IOUringRule.match(rawrule))  # the above invalid rules still match the main regex!
        with self.assertRaises(expected):
            IOUringRule.create_instance(rawrule)

    def test_parse_fail(self):
        with self.assertRaises(AppArmorException):
            IOUringRule.create_instance('foo,')

    def test_diff_non_iouringrule(self):
        exp = namedtuple('exp', ('audit', 'deny', 'priority'))
        obj = IOUringRule(('sqpoll'), IOUringRule.ALL)
        with self.assertRaises(AppArmorBug):
            obj.is_equal(exp(False, False, None), False)

    def test_diff_access(self):
        obj1 = IOUringRule(IOUringRule.ALL, IOUringRule.ALL)
        obj2 = IOUringRule(('sqpoll'), IOUringRule.ALL)
        self.assertFalse(obj1.is_equal(obj2, False))

    def test_diff_label(self):
        obj1 = IOUringRule(IOUringRule.ALL, 'foo')
        obj2 = IOUringRule(IOUringRule.ALL, '/bar')
        self.assertFalse(obj1.is_equal(obj2, False))


class InvalidIOUringInit(AATest):
    tests = (
        # access    label      expected exception
        (('',       'label'),  AppArmorBug),        # empty access
        (('    ',   'label'),  AppArmorBug),        # whitespace access
        (('xyxy',   'label'),  AppArmorException),  # invalid access
        ((dict(),   'label'),  AppArmorBug),        # wrong type for access
        ((None,     'label'),  AppArmorBug),        # wrong type for access
        (('sqpoll', ''),       AppArmorBug),        # empty label
        (('sqpoll', '    '),   AppArmorBug),        # whitespace label
        (('sqpoll', dict()),   AppArmorBug),        # wrong type for label
        (('sqpoll', None),     AppArmorBug),        # wrong type for label
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            IOUringRule(*params)

    def test_missing_params1(self):
        with self.assertRaises(TypeError):
            IOUringRule()

    def test_missing_params2(self):
        with self.assertRaises(TypeError):
            IOUringRule('override_creds')


class WriteIOUringTestAATest(AATest):
    tests = (
        #  raw rule                                                  clean rule
        ('     io_uring         ,    # foo        ',                 'io_uring, # foo'),
        ('    audit     io_uring sqpoll,',                           'audit io_uring sqpoll,'),
        ('    audit     io_uring (override_creds  ),',               'audit io_uring override_creds,'),
        ('    audit     io_uring (sqpoll , override_creds ),',       'audit io_uring (override_creds sqpoll),'),
        ('   deny io_uring         sqpoll      label=bar,# foo bar', 'deny io_uring sqpoll label=bar, # foo bar'),
        ('   deny io_uring         override_creds      ,# foo bar',  'deny io_uring override_creds, # foo bar'),
        ('   allow io_uring             label=tst    ,# foo bar',    'allow io_uring label=tst, # foo bar'),
        ('io_uring,',                                                'io_uring,'),
        ('io_uring (override_creds),',                               'io_uring override_creds,'),
        ('io_uring (sqpoll),',                                       'io_uring sqpoll,'),
        ('io_uring (sqpoll override_creds),',                        'io_uring (override_creds sqpoll),'),
        ('io_uring sqpoll label="tst",',                             'io_uring sqpoll label="tst",'),
        ('io_uring (override_creds) label=bar,',                     'io_uring override_creds label=bar,'),
        ('io_uring (sqpoll override_creds) label=/foo,',             'io_uring (override_creds sqpoll) label=/foo,'),
        (' priority=1   deny io_uring  override_creds  ,# foo bar',  'priority=1 deny io_uring override_creds, # foo bar'),
        (' priority=0   deny io_uring  override_creds  ,# foo bar',  'priority=0 deny io_uring override_creds, # foo bar'),
        (' priority=-23 deny io_uring  override_creds  ,# foo bar',  'priority=-23 deny io_uring override_creds, # foo bar'),
        (' priority=+21 deny io_uring  override_creds  ,# foo bar',  'priority=21 deny io_uring override_creds, # foo bar'),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(IOUringRule.match(rawrule))
        obj = IOUringRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_manually(self):
        obj = IOUringRule('sqpoll', IOUringRule.ALL, allow_keyword=True)

        expected = '    allow io_uring sqpoll,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_invalid_access(self):
        obj = IOUringRule('sqpoll', IOUringRule.ALL)
        obj.access = ''
        with self.assertRaises(AppArmorBug):
            obj.get_clean()

    def test_write_invalid_label(self):
        obj = IOUringRule(IOUringRule.ALL, 'bar')
        obj.label = ''
        with self.assertRaises(AppArmorBug):
            obj.get_clean()


class IOUringIsCoveredTest(AATest):
    def test_is_covered(self):
        obj = IOUringRule(IOUringRule.ALL, 'ba*')
        self.assertTrue(obj.is_covered(IOUringRule(('sqpoll'), 'ba')))
        self.assertTrue(obj.is_covered(IOUringRule(IOUringRule.ALL, 'baz')))

    def test_is_not_covered(self):
        obj = IOUringRule(('sqpoll'), 'foo')
        self.assertFalse(obj.is_covered(IOUringRule(IOUringRule.ALL, 'foo')))
        self.assertFalse(obj.is_covered(IOUringRule(('sqpoll'), IOUringRule.ALL)))

    def test_is_covered_priority(self):
        obj = IOUringRule(IOUringRule.ALL, 'ba*', priority=0)
        prio_obj = IOUringRule(IOUringRule.ALL, 'ba*', priority=1)
        self.assertFalse(obj.is_covered(prio_obj))
        self.assertTrue(prio_obj.is_covered(obj))

    def test_is_covered_priority_2(self):
        obj = IOUringRule(IOUringRule.ALL, 'ba*')
        obj2 = IOUringRule(IOUringRule.ALL, 'ba*', priority=0)
        self.assertTrue(obj.is_covered(obj2))
        self.assertTrue(obj2.is_covered(obj))
        self.assertTrue(obj.is_equal(obj2))
        self.assertTrue(obj2.is_equal(obj))
        self.assertFalse(obj.is_equal(obj2, strict=True))
        self.assertFalse(obj2.is_equal(obj, strict=True))


class IOUringLogprofHeaderTest(AATest):
    tests = (
        ('io_uring,',        [_('Access mode'), _('ALL'), _('Label'), _('ALL')]),
        ('io_uring sqpoll,', [_('Access mode'), 'sqpoll', _('Label'), _('ALL')]),
        ('io_uring override_creds,', [_('Access mode'), 'override_creds', _('Label'), _('ALL')]),
        ('io_uring (sqpoll,override_creds),', [_('Access mode'), 'override_creds sqpoll', _('Label'), _('ALL')]),
        ('io_uring sqpoll label=/foo,', [_('Access mode'), 'sqpoll', _('Label'), '/foo']),
        ('io_uring override_creds label=bar,', [_('Access mode'), 'override_creds', _('Label'), 'bar']),
        ('io_uring (sqpoll,override_creds) label=baz,', [_('Access mode'), 'override_creds sqpoll', _('Label'), 'baz']),
    )

    def _run_test(self, params, expected):
        obj = IOUringRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class IOUringGlobTestAATest(AATest):
    def test_glob(self):
        self.assertEqual(IOUringRuleset().get_glob('io_uring sqpoll,'), 'io_uring,')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
