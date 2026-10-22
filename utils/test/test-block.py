#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2026 Canonical, Ltd.
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

import apparmor.aa
from apparmor.aa import parse_profile_data
from apparmor.common import AppArmorBug, AppArmorException
from apparmor.rule.block import BlockRule
from apparmor.rule.file import FileRule
from apparmor.severity import Severity
from common_test import AATest, setup_aa, setup_all_loops


def parse_block_profile(rules):
    """parse a profile containing the given lines and return its ProfileStorage"""

    profile_data = parse_profile_data(('/t {\n%s\n}\n' % rules).split('\n'), 'somefile', False, False)

    return profile_data['/t']


def clean_profile(rules):
    """parse a profile containing the given lines and return its clean rules"""

    return '\n'.join(parse_block_profile(rules).get_rules_clean(1))


class BlockTestParse(AATest):
    tests = (
        # block                                         clean rules
        ('  audit {\n    /foo r,\n  }',                 '  audit {\n    /foo r,\n\n  }\n'),
        ('  {\n    /foo r,\n  }',                       '  {\n    /foo r,\n\n  }\n'),
        ('  owner {\n    /foo r,\n  }',                 '  owner {\n    /foo r,\n\n  }\n'),
        ('  deny {\n    /foo r,\n  }',                  '  deny {\n    /foo r,\n\n  }\n'),
        ('  allow {\n    /foo r,\n  }',                 '  allow {\n    /foo r,\n\n  }\n'),
        ('  audit deny {\n    /foo r,\n  }',            '  audit deny {\n    /foo r,\n\n  }\n'),
        ('  audit deny owner {\n    /foo r,\n  }',      '  audit deny owner {\n    /foo r,\n\n  }\n'),
        ('  audit  owner  {\n    /foo r,\n  }',         '  audit owner {\n    /foo r,\n\n  }\n'),  # normalised whitespace
        ('  audit{\n    /foo r,\n  }',                  '  audit {\n    /foo r,\n\n  }\n'),  # no space before the brace
        ('  prompt {\n    /foo r,\n  }',                '  prompt {\n    /foo r,\n\n  }\n'),
        ('  audit prompt owner {\n    /foo r,\n  }',    '  audit prompt owner {\n    /foo r,\n\n  }\n'),
        ('  other {\n    /foo r,\n  }',                 '  other {\n    /foo r,\n\n  }\n'),
        ('  audit { }',                                 '  audit {\n  }\n'),  # empty block on one line
        ('  audit {\n  }',                              '  audit {\n  }\n'),  # empty block
        ('  audit { # comment\n    /foo r,\n  }',       '  audit { # comment\n    /foo r,\n\n  }\n'),
        ('  audit {\n    deny {\n      /foo r,\n    }\n  }',
         '  audit {\n    deny {\n      /foo r,\n\n    }\n\n  }\n'),  # nested
        ('  {\n    set rlimit cpu <= 10,\n  }',         '  {\n    set rlimit cpu <= 10,\n\n  }\n'),  # no qualifier, so rlimit is fine
        ('  audit {\n    capability net_admin,\n    network inet stream,\n    signal receive,\n  }',
         '  audit {\n    capability net_admin,\n\n    network inet stream,\n\n    signal receive,\n\n  }\n'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(clean_profile(params), expected)


class BlockTestParseInvalid(AATest):
    tests = (
        # block                                                     expected exception
        ('  priority=1 {\n    /foo r,\n  }',                        AppArmorException),  # priority isn't allowed on a block
        ('  audit audit {\n    /foo r,\n  }',                       AppArmorException),  # duplicate qualifier
        ('  owner owner {\n    /foo r,\n  }',                       AppArmorException),
        ('  allow deny {\n    /foo r,\n  }',                        AppArmorException),  # conflicting access type
        ('  deny {\n    allow /foo r,\n  }',                        AppArmorException),  # conflicting with the rule inside
        ('  allow {\n    deny /foo r,\n  }',                        AppArmorException),
        ('  prompt {\n    deny /foo r,\n  }',                       AppArmorException),
        ('  audit {\n    deny {\n      allow /foo r,\n    }\n  }',  AppArmorException),  # conflict with a nested rule
        ('  deny {\n    prompt {\n      /foo r,\n    }\n  }',       AppArmorException),  # conflict with a nested block
        ('  owner {\n    capability net_admin,\n  }',               AppArmorException),  # capability rules take no owner
        ('  other {\n    capability net_admin,\n  }',               AppArmorException),
        ('  owner {\n    {\n      capability net_admin,\n    }\n  }', AppArmorException),  # via a nested block
        ('  audit {\n    set rlimit cpu <= 10,\n  }',               AppArmorException),  # rlimit takes no qualifier
        ('  deny {\n    set rlimit cpu <= 10,\n  }',                AppArmorException),
        ('  owner {\n    set rlimit cpu <= 10,\n  }',               AppArmorException),
        ('  audit { /foo r, }',                                     AppArmorException),  # rules on the opening line
        ('  audit {\n    /foo r,',                                  AppArmorException),  # missing '}'
        ('  audit {\n    profile c {\n    }\n  }',                  AppArmorException),  # child profile inside a block
        ('  audit {\n    ^hat {\n    }\n  }',                       AppArmorException),  # hat inside a block
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            clean_profile(params)


class BlockTestBodyFromText(AATest):
    def test_create_instance_keeps_the_body_or_raises(self):
        # a block rebuilt from its own clean text would silently lose its rules
        block = parse_block_profile('  owner {\n    /foo r,\n  }')['block'].rules[0]

        with self.assertRaises(AppArmorException):
            BlockRule.create_instance(block.get_clean())

    def test_create_instance_of_an_empty_block(self):
        self.assertTrue(BlockRule.create_instance('audit { }').is_empty())
        self.assertIsNone(BlockRule.create_instance('audit {').raw_rule)
        self.assertEqual(BlockRule.create_instance('audit {').get_clean(), 'audit {\n}')


class BlockTestNesting(AATest):
    def test_hat_inside_a_conditional_inside_a_block(self):
        # the hat used to leak its rules into the enclosing block
        rules = '  audit {\n    if $v {\n      ^hat {\n        /h r,\n      }\n    }\n  }'
        with self.assertRaises(AppArmorException):
            clean_profile(rules)

    def test_lineno_inside_a_block(self):
        # an error inside a block has to point at the line it is really on
        rules = '  /a r,\n  audit {\n    owner {\n      ^hat {\n        /h r,\n      }\n    }\n  }'
        with self.assertRaises(AppArmorException) as cm:
            clean_profile(rules)

        self.assertIn('line: 5', str(cm.exception))

    def test_blocks_nested_too_deeply(self):
        # a RecursionError would abort the tools with a traceback
        rules = '\n'.join(['  audit {'] * 200 + ['    /foo r,'] + ['  }'] * 200)
        with self.assertRaises(AppArmorException):
            clean_profile(rules)


class BlockTestQualifierSupport(AATest):
    tests = (
        # a block around a rule type that takes the qualifier
        ('  owner {\n    {\n      /foo r,\n    }\n  }',
         '  owner {\n    {\n      /foo r,\n\n    }\n\n  }\n'),  # a nested block accepts owner
        ('  owner {\n    change_profile -> /bin/foo,\n  }',
         '  owner {\n    change_profile -> /bin/foo,\n\n  }\n'),  # as the parser does
        ('  owner {\n    include <abstractions/base>\n  }',
         '  owner {\n    include <abstractions/base>\n\n  }\n'),  # ... and on an include
        ('  owner {\n    signal receive,\n  }',
         '  owner {\n    signal receive,\n\n  }\n'),
        ('  other {\n    network inet stream,\n  }',
         '  other {\n    network inet stream,\n\n  }\n'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(clean_profile(params), expected)


class BlockTestPreamble(AATest):
    def test_block_in_preamble(self):
        with self.assertRaises(AppArmorException):
            parse_profile_data('audit {\n  /foo r,\n}\n/t {\n}\n'.split('\n'), 'somefile', False, True)

    def test_empty_block_in_preamble(self):
        # no rule inside the block, so no other error can be raised instead
        with self.assertRaises(AppArmorException) as cm:
            parse_profile_data('audit {\n}\n/t {\n}\n'.split('\n'), 'somefile', False, True)

        self.assertIn('rule block outside of a profile', str(cm.exception))


class BlockTestOwner(AATest):
    tests = (
        # rule inside an owner block         expected clean rules
        ('  owner {\n    /foo r,\n  }',      '  owner {\n    /foo r,\n\n  }\n'),  # file rules take owner
        ('  owner {\n    link /a -> /b,\n  }',
         '  owner {\n    link /a -> /b,\n\n  }\n'),  # ... including link rules
        ('  owner {\n    file,\n  }',        '  owner {\n    file,\n\n  }\n'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(clean_profile(params), expected)


class BlockTestIsCovered(AATest):
    tests = (
        # block, other block                                                      covered? equal?
        (('  audit {\n    /foo r,\n  }', '  audit {\n    /foo r,\n  }'),          (True,   True)),
        (('  audit {\n    /foo r,\n  }', '  audit {\n    /foo r,\n    /bar r,\n  }'), (False, False)),
        (('  audit {\n    /foo r,\n  }', '  deny {\n    /foo r,\n  }'),           (False,  False)),
        (('  audit {\n    /foo r,\n  }', '  audit owner {\n    /foo r,\n  }'),    (False,  False)),
        (('  audit {\n    /foo r,\n  }', '  {\n    /foo r,\n  }'),                (True,   False)),  # as 'audit /foo r,' covers '/foo r,'
        (('  audit { # why\n    /foo r,\n  }', '  audit {\n    /foo r,\n  }'),  (True,   True)),  # a comment isn't part of the rule
        (('  {\n  }',                    '  {\n  }'),                             (True,   True)),
    )

    def _run_test(self, params, expected):
        block = parse_block_profile(params[0])['block'].rules[0]
        other = parse_block_profile(params[1])['block'].rules[0]
        self.assertEqual((block.is_covered(other), block.is_equal(other)), expected)

    def test_block_does_not_cover_a_file_rule(self):
        block = parse_block_profile('  audit {\n    /foo r,\n  }')['block'].rules[0]
        with self.assertRaises(AppArmorBug):
            block.is_covered(FileRule.create_instance('audit /foo r,'))


class BlockTestSeverity(AATest):
    tests = (
        ('  audit {\n    /etc/shadow r,\n  }',                      5),
        ('  audit {\n    /etc/passwd r,\n    /etc/shadow w,\n  }',  9),  # the highest one wins
        ('  audit {\n    /etc/passwd r,\n  }',                      4),
        ('  audit {\n    {\n      /etc/shadow w,\n    }\n  }',      9),  # nested
        ('  audit {\n  }',                                          '_-*not*implemented*-_'),
        ('  audit {\n    network inet stream,\n  }',                '_-*not*implemented*-_'),
    )

    def _run_test(self, params, expected):
        sev_db = Severity('severity.db', 'unknown')
        block = parse_block_profile(params)['block'].rules[0]
        self.assertEqual(block.severity(sev_db), expected)


class BlockTestIsEmpty(AATest):
    tests = (
        ('  audit {\n  }',                                 True),
        ('  audit { }',                                    True),
        ('  audit {\n    # just a comment\n  }',           True),
        ('  audit {\n    /foo r,\n  }',                    False),
        ('  audit {\n    {\n      /foo r,\n    }\n  }',    False),
        ('  audit {\n    {\n    }\n  }',                   False),  # the nested block is a rule
    )

    def _run_test(self, params, expected):
        block = parse_block_profile(params)['block'].rules[0]
        self.assertEqual(block.is_empty(), expected)


class BlockTestGetClean(AATest):
    tests = (
        # depth  expected
        (0,      '{\n}'),
        (1,      '  {\n  }'),
        (2,      '    {\n    }'),
    )

    def _run_test(self, params, expected):
        block = BlockRule.create_instance('{')
        self.assertEqual(block.get_clean(params), expected)

    def test_qualifiers_str(self):
        self.assertEqual(BlockRule.create_instance('audit deny owner {').qualifiers_str(), 'audit deny owner ')
        self.assertEqual(BlockRule.create_instance('{').qualifiers_str(), '')


class BlockTestLogprofHeader(AATest):
    def test_logprof_header(self):
        block = parse_block_profile('  audit {\n    /foo r,\n  }')['block'].rules[0]
        self.assertEqual(block.logprof_header(), ['Qualifier', 'audit', 'Rule block', 'audit {\n  /foo r,\n\n}'])


setup_aa(apparmor.aa)
setup_all_loops(__name__)

if __name__ == '__main__':
    unittest.main(verbosity=1)
