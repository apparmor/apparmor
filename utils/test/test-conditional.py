#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2025 Canonical, Ltd.
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

from apparmor.common import AppArmorException, AppArmorBug, combine_profname
from apparmor.profile_storage import ProfileStorage
from apparmor.profile_list import ProfileList
from apparmor.rule.file import FileRule
from apparmor.rule.variable import VariableRule
from apparmor.rule.boolean import BooleanRule
from apparmor.rule.conditional import ConditionalBlock, AppArmorAst, Term, CompareCondition, ConditionalRule, BooleanCondition
from common_test import AATest, setup_all_loops


class TestConditional(AATest):
    """ Base class to test conditionals, profile_data does not contain any rules """
    filename = 'somefile'
    condition_contents = '\n'

    tests = (
        # ConditionalBlock                                                        clean rule
        (['if $FOO {', '} else if $BAR {', '} else {'],                           'if $FOO {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not $FOO {', '} else if not $BAR {', '} else {'],                   'if not $FOO {' + condition_contents + '} else if not $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if defined $FOO {', '} else if not defined $BAR {', '} else {'],       'if defined $FOO {' + condition_contents + '} else if not defined $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else if defined @{VAR1} {', '} else {'], 'if not defined @{VAR2} {' + condition_contents + '} else if defined @{VAR1} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else {'],                                'if not defined @{VAR2} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {'],                                            'if not defined @{VAR2} {' + condition_contents + '}'),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditional, cls).setUpClass()
        cls.active_profiles = ProfileList()
        cls.profile_data = {}
        cls.condition_contents = '\n'
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.active_profiles.add_rule(cls.filename, 'variable', VariableRule.create_instance('@{VAR1} = "test"'))
        cls.active_profiles.add_rule(cls.filename, 'variable', VariableRule.create_instance('@{VAR2} = "test1 test2"'))
        cls.active_profiles.add_rule(cls.filename, 'variable', VariableRule.create_instance('@{VAR3} = 10'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$FOO=true'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$BAR=false'))

    def _run_test(self, params, expected):
        conditional_block = None
        for condition in params:
            if condition == params[0]:
                conditional_block = ConditionalBlock(condition, self.active_profiles.files[self.filename])
                conditional_block.store_profile_data(self.profile_data)
            else:
                conditional_block.add_conditional(condition, self.active_profiles.files[self.filename])
                conditional_block.store_profile_data(self.profile_data)

        self.assertEqual(conditional_block.get_clean(), expected)


class TestConditionalComplex(TestConditional):
    """ Class to test complex conditionals (and, ors, comparisons and boolean operations), profile_data contains one file rule """
    # directly related to how setUpClass sets up profile_data
    condition_contents = '\n  /bin/false rix,\n\n'

    tests = (
        # ConditionalBlock                                                            clean rule
        (['if $FOO and ($BAR) {', '} else if $BAR {', '} else {'],                    'if $FOO and $BAR {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if $FOO and ($BAR or defined @{VAR1}) {', '} else if $BAR {', '} else {'], 'if $FOO and ($BAR or defined @{VAR1}) {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if $FOO or ($BAR or defined @{VAR1}) {', '} else if $BAR {', '} else {'],  'if $FOO or $BAR or defined @{VAR1} {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if $FOO or ($BAR and defined @{VAR1}) {', '} else if $BAR {', '} else {'], 'if $FOO or $BAR and defined @{VAR1} {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not $FOO {', '} else if not not $BAR {', '} else {'],                   'if not $FOO {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if ((test in @{VAR1})) and defined $FOO {'],                               'if test in @{VAR1} and defined $FOO {' + condition_contents + '}'),
        (['if test3 in @{VAR2} {'],                                                   'if test3 in @{VAR2} {' + condition_contents + '}'),
        (['if 9 < @{VAR3} {'],                                                        'if 9 < @{VAR3} {' + condition_contents + '}'),
        (['if test in "test2 test" {'],                                               'if test in "test2 test" {' + condition_contents + '}'),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalComplex, cls).setUpClass()
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/bin/false rix,'))


class TestConditionalSimple(TestConditional):
    """ Class to test simple conditionals (boolean and defined operations), profile_data contains one file rule """
    # directly related to how setUpClass sets up profile_data
    condition_contents = '\n  /bin/false rix,\n\n'

    tests = (
        # ConditionalBlock                                                        clean rule
        (['if $FOO {', '} else if $BAR {', '} else {'],                           'if $FOO {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not $FOO {', '} else if not $BAR {', '} else {'],                   'if not $FOO {' + condition_contents + '} else if not $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if defined $FOO {', '} else if not defined ${BAR} {', '} else {'],     'if defined $FOO {' + condition_contents + '} else if not defined ${BAR} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else if defined @{VAR1} {', '} else {'], 'if not defined @{VAR2} {' + condition_contents + '} else if defined @{VAR1} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else {'],                                'if not defined @{VAR2} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {'],                                            'if not defined @{VAR2} {' + condition_contents + '}'),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalSimple, cls).setUpClass()
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/bin/false rix,'))


class TestConditionalSubProfile(TestConditional):
    """ Class to test simple conditionals, profile_data contains hat definition """
    # directly related to how setUpClass sets up profile_data
    condition_contents = '\n  /** w,\n  /bin/false rix,\n\n  ^bar {\n    /bin/true rix,\n\n  }\n'

    tests = (
        # ConditionalBlock                                                        clean rule
        (['if $FOO {', '} else if $BAR {', '} else {'],                           'if $FOO {' + condition_contents + '} else if $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not $FOO {', '} else if not $BAR {', '} else {'],                   'if not $FOO {' + condition_contents + '} else if not $BAR {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if defined $FOO {', '} else if not defined ${BAR} {', '} else {'],     'if defined $FOO {' + condition_contents + '} else if not defined ${BAR} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else if defined @{VAR1} {', '} else {'], 'if not defined @{VAR2} {' + condition_contents + '} else if defined @{VAR1} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {', '} else {'],                                'if not defined @{VAR2} {' + condition_contents + '} else {' + condition_contents + '}'),
        (['if not defined @{VAR2} {'],                                            'if not defined @{VAR2} {' + condition_contents + '}'),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalSubProfile, cls).setUpClass()
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/bin/false rix,'))
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/** w,'))
        (profile, hat, prof_storage) = ProfileStorage.parse('^bar {', cls.filename, 0, profile, None)
        profname = combine_profname((profile, hat))
        cls.profile_data[profname] = prof_storage
        cls.profile_data[profname]['in_cond'] = True
        cls.profile_data[profname]['file'].add(FileRule.create_instance('/bin/true rix,'))


class TestConditionalLogprof(TestConditional):
    """ Class to test output of Logprof """
    # directly related to how setUpClass sets up profile_data
    condition_contents = '\n  /** w,\n  /bin/false rix,\n\n  ^bar {\n    /bin/true rix,\n\n  }\n'

    tests = (
        (['if $FOO {', '} else if $BAR {', '} else {'],
         ['ConditionalBlock', [['Conditional', 'if $FOO {' + condition_contents + '}'],
                               ['Conditional', 'else if $BAR {' + condition_contents + '}'],
                               ['Conditional', 'else {' + condition_contents + '}']]]),
        (['if not $FOO {', '} else if not $BAR {', '} else {'],
         ['ConditionalBlock', [['Conditional', 'if not $FOO {' + condition_contents + '}'],
                               ['Conditional', 'else if not $BAR {' + condition_contents + '}'],
                               ['Conditional', 'else {' + condition_contents + '}']]]),
        (['if defined $FOO {', '} else if not defined $BAR {', '} else {'],
         ['ConditionalBlock', [['Conditional', 'if defined $FOO {' + condition_contents + '}'],
                               ['Conditional', 'else if not defined $BAR {' + condition_contents + '}'],
                               ['Conditional', 'else {' + condition_contents + '}']]]),
        (['if not defined @{VAR2} {', '} else if defined @{VAR1} {', '} else {'],
         ['ConditionalBlock', [['Conditional', 'if not defined @{VAR2} {' + condition_contents + '}'],
                               ['Conditional', 'else if defined @{VAR1} {' + condition_contents + '}'],
                               ['Conditional', 'else {' + condition_contents + '}']]]),
        (['if not defined @{VAR2} {', '} else {'],
         ['ConditionalBlock', [['Conditional', 'if not defined @{VAR2} {' + condition_contents + '}'],
                               ['Conditional', 'else {' + condition_contents + '}']]]),
        (['if not defined @{VAR2} {'],
         ['ConditionalBlock', [['Conditional', 'if not defined @{VAR2} {' + condition_contents + '}']]]),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalLogprof, cls).setUpClass()
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/bin/false rix,'))
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/** w,'))
        (profile, hat, prof_storage) = ProfileStorage.parse('^bar {', cls.filename, 0, profile, None)
        profname = combine_profname((profile, hat))
        cls.profile_data[profname] = prof_storage
        cls.profile_data[profname]['in_cond'] = True
        cls.profile_data[profname]['file'].add(FileRule.create_instance('/bin/true rix,'))

    def _run_test(self, params, expected):
        conditional_block = None
        for condition in params:
            if condition == params[0]:
                conditional_block = ConditionalBlock(condition, self.active_profiles.files[self.filename])
                conditional_block.store_profile_data(self.profile_data)
            else:
                conditional_block.add_conditional(condition, self.active_profiles.files[self.filename])
                conditional_block.store_profile_data(self.profile_data)

        self.assertEqual(conditional_block.logprof_header(), expected)


class TestConditionalEquality(AATest):
    """ Class to test equality tests """
    filename = 'somefile'
    profile_data = {}

    tests = (
        # should always be different
        # first condition                                   second condition
        ((['if not $FOO {'], profile_data),                 (['if $FOO {'], profile_data)),
        ((['if defined $FOO {'], profile_data),             (['if $FOO {'], profile_data)),
        ((['if $BAR {'], profile_data),                     (['if $FOO {'], profile_data)),
        ((['if $FOO {'], None),                             (['if $FOO {'], profile_data)),
        ((['if $FOO {', '} else if $BAR {'], profile_data), (['if $FOO {', '} else {'], profile_data)),
        ((['if $FOO and $BAR {'], profile_data),            (['if $FOO and $BAR and defined $BAZ{'], profile_data)),
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalEquality, cls).setUpClass()
        cls.active_profiles = ProfileList()
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/bin/false rix,'))
        cls.profile_data[profile]['file'].add(FileRule.create_instance('/** w,'))
        (profile, hat, prof_storage) = ProfileStorage.parse('^bar {', cls.filename, 0, profile, None)
        profname = combine_profname((profile, hat))
        cls.profile_data[profname] = prof_storage
        cls.profile_data[profname]['in_cond'] = True
        cls.profile_data[profname]['file'].add(FileRule.create_instance('/bin/true rix,'))
        cls.active_profiles.add_rule(cls.filename, 'variable', VariableRule.create_instance('@{VAR1} = "test"'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$FOO=true'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$BAR=false'))

    def init_cond(self, conds, profile_data):
        block = None
        for cond in conds:
            if cond == conds[0]:
                block = ConditionalBlock(cond, self.active_profiles.files[self.filename])
                block.store_profile_data(profile_data)
            else:
                block.add_conditional(cond, self.active_profiles.files[self.filename])
                block.store_profile_data(profile_data)
        return block

    def _run_test(self, cond1, cond2):
        conditional_block1 = self.init_cond(cond1[0], cond1[1])
        conditional_block2 = self.init_cond(cond2[0], cond2[1])

        self.assertFalse(conditional_block1.is_equal(conditional_block2))
        self.assertFalse(conditional_block1.is_covered(conditional_block2))

    def test_is_equal_condition(self):
        conditional_block1 = self.init_cond(['if $FOO {', '} else if $BAR {', '} else {'], self.profile_data)
        conditional_block2 = self.init_cond(['if $FOO {', '} else {'], self.profile_data)

        self.assertFalse(conditional_block1.is_equal(conditional_block2))
        self.assertFalse(conditional_block1.is_covered(conditional_block2))

    def test_is_equal(self):
        conditional_block1 = ConditionalBlock('if not defined $FOO {', self.active_profiles.files[self.filename])
        conditional_block1.store_profile_data(self.profile_data)

        self.assertTrue(conditional_block1.is_equal(conditional_block1))
        self.assertTrue(conditional_block1.is_covered(conditional_block1))


class TestConditionalException(AATest):
    filename = 'somefile'
    profile_data = {}

    tests = (
        (['if @{VAR1} {', '} else if $BAR {', '} else {'], AppArmorException),  # set variable used in boolean comparison
        (['if $FOO {', '} else if @{VAR} {', '} else {'],  AppArmorException),  # undefined variable in else if
        (['if ${BAZ} {', '} else {'],                      AppArmorException),  # undefined boolean variable with else
        (['if ${VAR} {'],                                  AppArmorException),  # undefined boolean variable
        (['if foo in @{UNDERFINED} {'],                    AppArmorException),  # undefined set variable
    )

    @classmethod
    def setUpClass(cls):
        super(TestConditionalException, cls).setUpClass()
        cls.active_profiles = ProfileList()
        cls.condition_contents = '\n'
        (profile, hat, prof_storage) = ProfileStorage.parse('profile foo {', cls.filename, 0, False, False)
        cls.profile_data[profile] = prof_storage
        cls.active_profiles.add_rule(cls.filename, 'variable', VariableRule.create_instance('@{VAR1} = "test"'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$FOO=true'))
        cls.active_profiles.add_rule(cls.filename, 'boolean', BooleanRule.create_instance('$BAR=false'))

    def _run_test(self, params, expected):
        conditional_block = None
        with self.assertRaises(expected):
            for condition in params:
                if condition == params[0]:
                    conditional_block = ConditionalBlock(condition, self.active_profiles.files[self.filename])
                    conditional_block.store_profile_data(self.profile_data)
                else:
                    conditional_block.add_conditional(condition, self.active_profiles.files[self.filename])
                    conditional_block.store_profile_data(self.profile_data)

    def test_create_instance_block1(self):
        with self.assertRaises(NotImplementedError):
            ConditionalBlock.create_instance('test')

    def test_create_instance_block2(self):
        with self.assertRaises(NotImplementedError):
            ConditionalBlock._create_instance('test', None)


class TestAppArmorAstException(AATest):
    tests = (
        ('foo = "1"',    AppArmorBug),  # AppArmorAst only supports the actual condition
        ('~ $FOO',       AppArmorBug),  # Invalid unary operator
        ('func(${BAZ})', AppArmorBug),  # Invalid function name
    )

    def _run_test(self, params, expected):
        ast = AppArmorAst(params)
        with self.assertRaises(expected):
            ast.get_clean()
        with self.assertRaises(expected):
            ast.evaluate(None)


class TestMiscClassException(AATest):
    def test_invalid_op_1(self):
        term = Term.create_instance('10')
        op = 'is'
        with self.assertRaises(AppArmorBug):
            CompareCondition(term, op, term)

    def test_invalid_op_2(self):
        term = Term.create_instance('10')
        cond = CompareCondition(term, 'in', term)
        cond.op = 'is'
        with self.assertRaises(AppArmorBug):
            cond.evaluate(None)

    def test_invalid_term(self):
        with self.assertRaises(AppArmorBug):
            Term.create_instance('#')

    def test_invalid_conditional_condition(self):
        with self.assertRaises(AppArmorBug):
            ConditionalRule('invalid', AppArmorAst('defined $BAR'))

    def test_invalid_conditional_ast_tree(self):
        with self.assertRaises(AppArmorBug):
            ConditionalRule(ConditionalRule.IF, 'defined $BAR')

    def test_invalid_conditional_clean(self):
        cond = ConditionalRule(ConditionalRule.IF, AppArmorAst('defined $BAR'))
        cond.condition = 'invalid'
        with self.assertRaises(AppArmorBug):
            cond.get_clean()

    def test_invalid_boolean_defined(self):
        with self.assertRaises(AppArmorBug):
            BooleanCondition(None, Term.create_instance('10'))

    def test_invalid_boolean_varible(self):
        with self.assertRaises(AppArmorBug):
            BooleanCondition('defined', '10')

    def test_invalid_compare_left(self):
        with self.assertRaises(AppArmorBug):
            CompareCondition(None, '==', Term.create_instance('10'))

    def test_invalid_compare_right(self):
        with self.assertRaises(AppArmorBug):
            CompareCondition(Term.create_instance('10'), '==', None)

    def test_invalid_compare_op(self):
        with self.assertRaises(AppArmorBug):
            CompareCondition(Term.create_instance('10'), '~', Term.create_instance('10'))

    def test_invalid_compare(self):
        term = Term.create_instance('10')
        cond = CompareCondition(term, '==', term)
        with self.assertRaises(AppArmorBug):
            cond.compare(cond.op, term.get_set(None), 10)

    def test_invalid_compare_evaluate(self):
        term = InvalidTerm(10)
        cond = CompareCondition(term, '==', term)
        with self.assertRaises(AppArmorBug):
            cond.evaluate(None)


class InvalidTerm(Term):
    def __init__(self, value):
        self.value = value

    def get_set(self, prof_storage):
        return self.value  # not a set


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
