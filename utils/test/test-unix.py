#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2024 Canonical, Ltd.
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
from common_test import AATest, setup_all_loops

from apparmor.common import AppArmorException
from apparmor.translations import init_translation

from apparmor.rule.unix import UnixRule

_ = init_translation()


class UnixTestParse(AATest):

    tests = (
        #                   Rule                                     Accesses           Rule conds                        Local expr                    Peer expr                       Audit  Deny   Allow  Comment
        ('unix,',                                           UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                 UnixRule.ALL,                   False, False, False, '')),
        ('unix rw,',                                        UnixRule('rw',              UnixRule.ALL,                     UnixRule.ALL,                 UnixRule.ALL,                   False, False, False, '')),
        ('unix (accept, rw),',                              UnixRule(('accept', 'rw'),  UnixRule.ALL,                     UnixRule.ALL,                 UnixRule.ALL,                   False, False, False, '')),
        ('unix peer=(addr=AA label=bb),',                   UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                 {'addr': 'AA', 'label': 'bb'},  False, False, False, '')),
        ('unix opt=AA label=bb,',                           UnixRule(UnixRule.ALL,      UnixRule.ALL,                     {'opt': 'AA', 'label': 'bb'}, UnixRule.ALL,                   False, False, False, '')),
        ('unix (accept rw) type=AA protocol=BB,',           UnixRule(('accept', 'rw'),  {'type': 'AA', 'protocol': 'BB'}, UnixRule.ALL,                 UnixRule.ALL,                   False, False, False, '')),
        ('unix (accept, rw) protocol=AA type=BB,',          UnixRule(('accept', 'rw'),  {'type': 'BB', 'protocol': 'AA'}, UnixRule.ALL,                 UnixRule.ALL,                   False, False, False, '')),
        ('unix shutdown addr=@srv,',                        UnixRule('shutdown',        UnixRule.ALL,                     {'addr': '@srv'},             UnixRule.ALL,                   False, False, False, '')),
        ('unix send addr=@foo{a,b} peer=(label=splat),',    UnixRule('send',            UnixRule.ALL,                     {'addr': '@foo{a,b}'},        {'label': 'splat'},             False, False, False, '')),
        ('unix peer=(addr=@/tmp/foo-??????),',              UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                 {'addr': '@/tmp/foo-??????'},   False, False, False, '')),
        ('unix peer=(addr="@/tmp/f o-??????"),',            UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                 {'addr': '@/tmp/f o-??????'},   False, False, False, '')),
        ('unix peer=(addr=@/tmp/foo-*),',                   UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                 {'addr': '@/tmp/foo-*'},        False, False, False, '')),
        ('unix (accept, rw) protocol=AA type=BB opt=AA label=bb peer=(addr=a label=bb),',
                                                            UnixRule(('accept', 'rw'),  {'type': 'BB', 'protocol': 'AA'}, {'opt': 'AA', 'label': 'bb'}, {'addr': 'a', 'label': 'bb'},   False, False, False, '')),  # noqa: E127
        ('unix peer=( label=la, addr="@/h"),',              UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,                {'addr': '@/h', 'label': 'la,'}, False, False, False, '')),
        ('unix peer=(addr="@/h o", label="l a"),',          UnixRule(UnixRule.ALL,      UnixRule.ALL,                     UnixRule.ALL,              {'addr': '@/h o', 'label': 'l a'}, False, False, False, '')),
        ('unix addr="@/h" label=la,',                       UnixRule(UnixRule.ALL,      UnixRule.ALL,                     {'addr': '@/h', 'label': 'la'},    UnixRule.ALL,              False, False, False, '')),
        ('unix addr="@/h o" label="l a",',                  UnixRule(UnixRule.ALL,      UnixRule.ALL,                     {'addr': '@/h o', 'label': 'l a'}, UnixRule.ALL,              False, False, False, '')),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UnixRule.match(rawrule))
        obj = UnixRule.create_instance(rawrule)
        expected.raw_rule = rawrule.strip()
        self.assertTrue(obj.is_equal(expected, True), f'\n  {rawrule}   expected,\n  {obj.get_clean()}   returned by obj.get_clean()\n  {expected.get_clean()}   returned by expected.get_clean()')

    def test_diff_local(self):
        obj1 = UnixRule('send', UnixRule.ALL, {'addr': 'foo'}, UnixRule.ALL, )
        obj2 = UnixRule('send', UnixRule.ALL, UnixRule.ALL, {'addr': 'bar'})
        self.assertFalse(obj1.is_equal(obj2, False))

    def test_diff_peer(self):
        obj1 = UnixRule('send', UnixRule.ALL, UnixRule.ALL, {'addr': 'foo'})
        obj2 = UnixRule('send', UnixRule.ALL, UnixRule.ALL, {'addr': 'bar'})
        self.assertFalse(obj1.is_equal(obj2, False))


class UnixTestParseInvalid(AATest):
    tests = (
        ('unix invalid,',   AppArmorException),
        ('unix (invalid),', AppArmorException),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UnixRule.match(rawrule))  # the above invalid rules still match the main regex!
        with self.assertRaises(expected):
            UnixRule.create_instance(rawrule)

    def test_parse_fail(self):
        with self.assertRaises(AppArmorException):
            UnixRule.create_instance('foo,')

    def test_invalid_key(self):
        with self.assertRaises(AppArmorException):
            UnixRule('send', UnixRule.ALL, {'invalid': 'whatever'}, UnixRule.ALL,  False, False, False, '')

    def test_invalid_access(self):
        with self.assertRaises(AppArmorException):
            UnixRule('invalid', UnixRule.ALL, UnixRule.ALL, UnixRule.ALL,  False, False, False, '')

    def test_invalid_access2(self):
        with self.assertRaises(AppArmorException):
            UnixRule(('rw', 'invalid'), UnixRule.ALL, UnixRule.ALL, UnixRule.ALL,  False, False, False, '')

    def test_invalid_peer_expr(self):
        with self.assertRaises(AppArmorException):
            UnixRule('create', UnixRule.ALL, UnixRule.ALL, {'addr': 'foo'}, False, False, False, '')


class UnixIsCoveredTest(AATest):
    def test_is_covered(self):
        obj = UnixRule(('accept', 'rw'), {'type': 'F*', 'protocol': 'AA'}, {'addr': 'AA'}, {'addr': 'AA', 'label': 'bb'})
        tests = [
            (('accept',),       {'type': 'F*', 'protocol': 'AA'},   {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'F*'},                     {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'Foo'},                    {'addr': 'AA'},                 {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'Foo'},                    {'addr': 'AA', 'opt': 'BB'},    {'addr': 'AA', 'label': 'bb'})
        ]
        for test in tests:
            self.assertTrue(obj.is_covered(UnixRule(*test)))
            self.assertFalse(obj.is_equal(UnixRule(*test)))

    def test_is_covered2(self):
        obj = UnixRule(('accept', 'rw'), UnixRule.ALL, {'addr': 'AA'}, {'addr': 'AA', 'label': 'bb'})
        tests = [
            (('accept',),       {'type': 'F*', 'protocol': 'AA'},   {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'F*'},                     {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'Foo'},                    {'addr': 'AA'},                 {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'Foo'},                    {'addr': 'AA', 'opt': 'BB'},    {'addr': 'AA', 'label': 'bb'})
        ]
        for test in tests:
            self.assertTrue(obj.is_covered(UnixRule(*test)))
            self.assertFalse(obj.is_equal(UnixRule(*test)))

    def test_is_not_covered(self):
        obj = UnixRule(('accept', 'rw'), {'type': 'F'}, {'opt': 'AA'}, {'addr': 'AA', 'label': 'bb'})
        tests = [
            (('r',),            {'type': 'F*', 'protocol': 'AA'},   {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'B'},                      {'opt': 'AA', 'label': 'bb'},   {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'F'},                      {'opt': 'AA', 'label': 'bb'},   UnixRule.ALL),
            (('accept', 'rw'),  {'type': 'F'},                      {'opt': 'notcovered'},          {'addr': 'AA', 'label': 'bb'}),
            (('accept', 'rw'),  {'type': 'F'},                      {'opt': 'AA'},                  {'addr': 'notcovered'}),
        ]
        for test in tests:
            self.assertFalse(obj.is_covered(UnixRule(*test)), test)
            self.assertFalse(obj.is_equal(UnixRule(*test)))

    def test_is_covered_priority(self):
        obj = UnixRule(('accept', 'rw'), {'type': 'F*', 'protocol': 'AA'}, {'addr': 'AA'}, {'addr': 'AA', 'label': 'bb'}, priority=0)
        prio_obj = UnixRule(('accept', 'rw'), {'type': 'F*', 'protocol': 'AA'}, {'addr': 'AA'}, {'addr': 'AA', 'label': 'bb'}, priority=1)

        self.assertFalse(obj.is_covered(prio_obj))
        self.assertTrue(prio_obj.is_covered(obj))


class UnixLogprofHeaderTest(AATest):
    tests = (
        ('unix,',                                           [_('Accesses'), 'ALL',  _('Rule'), 'ALL', _('Local'), 'ALL',                        _('Peer'), 'ALL']),
        ('unix rw,',                                        [_('Accesses'), 'rw',   _('Rule'), 'ALL', _('Local'), 'ALL',                        _('Peer'), 'ALL']),
        ('unix send addr=@foo{one,two peer=(label=splat),', [_('Accesses'), 'send', _('Rule'), 'ALL', _('Local'), {'addr': '@foo{one,two'},     _('Peer'), {'label': 'splat'}])
    )

    def _run_test(self, params, expected):
        obj = UnixRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class UnixTestGlob(AATest):
    def test_glob(self):
        glob_list = [(
            'unix (accept, rw) type=BB protocol=AA label=bb opt=AA peer=(addr=a label=bb),',
            'unix (accept, rw) type=BB protocol=AA label=bb opt=AA,',
            'unix (accept, rw) type=BB protocol=AA,',
            'unix (accept, rw),',
            'unix,',
        )]
        for globs in glob_list:
            for i in range(len(globs) - 1):
                rule = UnixRule.create_instance(globs[i])
                rule.glob()
                self.assertEqual(rule.get_clean(), globs[i + 1])


class UnixTestClean(AATest):
    tests = (
        ('     audit  unix                                                                                                                   ,    # foo  ', 'audit unix, # foo'),
        ('     audit deny unix                                                   label  =  foo                                               ,           ', 'audit deny unix label=foo,'),
        ('     audit allow unix                                                  peer  =  (addr  =  a)                                       ,    # foo  ', 'audit allow unix peer=(addr=a), # foo'),
        ('     deny unix                                                   type  =  foo                                                      ,           ', 'deny unix type=foo,'),
        ('     allow unix                                                              peer  =  (label=bb)                                   ,    # foo  ', 'allow unix peer=(label=bb), # foo'),
        ('     unix                                                                                                                          ,    # foo  ', 'unix, # foo'),
        ('     unix                                                   addr  =  foo                                                           ,           ', 'unix addr=foo,'),
        ('     unix    (  accept  , rw)  protocol  =  AA  type =  BB  opt  =  myopt  label  =  bb peer  =  (addr  =  a label  =  bb )        ,           ', 'unix (accept, rw) type=BB protocol=AA label=bb opt=myopt peer=(addr=a label=bb),'),
        ('priority=-42 unix    (  accept  , rw)  protocol  =  AA  type =  BB  opt  =  myopt  label  =  bb peer  =  (addr  =  a label  =  bb ),           ', 'priority=-42 unix (accept, rw) type=BB protocol=AA label=bb opt=myopt peer=(addr=a label=bb),'),
        ('priority = 0 unix    (  accept  , rw)  protocol  =  AA  type =  BB  opt  =  myopt  label  =  bb peer  =  (addr  =  a label  =  bb ),           ', 'priority=0 unix (accept, rw) type=BB protocol=AA label=bb opt=myopt peer=(addr=a label=bb),'),
        ('priority=211 unix    (  accept  , rw)  protocol  =  AA  type =  BB  opt  =  myopt  label  =  bb peer  =  (addr  =  a label  =  bb ),           ', 'priority=211 unix (accept, rw) type=BB protocol=AA label=bb opt=myopt peer=(addr=a label=bb),'),
        ('priority=+45 unix    (  accept  , rw)  protocol  =  AA  type =  BB  opt  =  myopt  label  =  bb peer  =  (addr  =  a label  =  bb ),           ', 'priority=45 unix (accept, rw) type=BB protocol=AA label=bb opt=myopt peer=(addr=a label=bb),'),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UnixRule.match(rawrule))
        obj = UnixRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected, clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
