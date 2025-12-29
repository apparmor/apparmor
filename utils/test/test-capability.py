#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2014-2025 Christian Boltz <apparmor@cboltz.de>
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

import apparmor.severity as severity
from apparmor.common import AppArmorBug, AppArmorException, cmd, hasher
from apparmor.logparser import ReadLog
from apparmor.rule.capability import CapabilityRule, CapabilityRuleset, capability_keywords
from apparmor.translations import init_translation
from common_test import AATest, setup_all_loops

_ = init_translation()


# --- check if the keyword list is up to date --- #

class CapabilityKeywordsTest(AATest):
    def test_capability_keyword_list(self):
        rc, output = cmd('../../common/list_capabilities.sh')
        self.assertEqual(rc, 0)

        cap_list = output.replace('CAP_', '').strip().lower().split('\n')

        missing_caps = []
        for keyword in cap_list:
            if keyword not in capability_keywords:
                # keywords missing in the system are ok (= older kernel), but cap_list needs to have the full list
                missing_caps.append(keyword)

        self.assertEqual(
            missing_caps, [],
            'Missing capabilities in CapabilityRule capabilities list. This test is likely running '
            'on an newer kernel and will require updating the list of capability keywords in '
            'utils/apparmor/rule/capability.py')


# --- tests for single CapabilityRule --- #
class CapabilityTest(AATest):
    def _compare_obj_with_rawrule(self, rawrule, expected):

        obj = CapabilityRule.create_instance(rawrule)

        self.assertTrue(CapabilityRule.match(rawrule))
        self.assertEqual(rawrule.strip(), obj.raw_rule)

        self._compare_obj(obj, expected)

    def _compare_obj(self, obj, expected):
        self.assertEqual(expected['allow_keyword'], obj.allow_keyword)
        self.assertEqual(expected['audit'], obj.audit)
        self.assertEqual(expected['capability'], obj.capability)
        self.assertEqual(expected['all_caps'], obj.all_caps)
        self.assertEqual(expected['deny'], obj.deny)
        self.assertEqual(expected['comment'], obj.comment)

    def test_cap_allow_all(self):
        self._compare_obj_with_rawrule("capability,", {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': set(),
            'all_caps': True,
            'comment': "",
        })

    def test_cap_allow_sys_admin(self):
        self._compare_obj_with_rawrule("capability sys_admin,", {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': {'sys_admin'},
            'all_caps': False,
            'comment': "",
        })

    def test_cap_deny_sys_admin(self):
        self._compare_obj_with_rawrule("     deny capability sys_admin,  # some comment", {
            'allow_keyword': False,
            'deny': True,
            'audit': False,
            'capability': {'sys_admin'},
            'all_caps': False,
            'comment': " # some comment",
        })

    def test_cap_multi(self):
        self._compare_obj_with_rawrule("capability sys_admin dac_override,", {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': {'sys_admin', 'dac_override'},
            'all_caps': False,
            'comment': "",
        })

    # Template for test_cap_* functions
    # def test_cap_(self):
    #     self._compare_obj_with_rawrule("capability,", {
    #         'allow_keyword': False,
    #         'deny': False,
    #         'audit': False,
    #         'capability': set(),  # (or {'foo'} if not empty)
    #         'all_caps': False,
    #         'comment': "",
    #     })

    def test_cap_from_log(self):
        parser = ReadLog('', '', '')
        event = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="net_raw"'

        parsed_event = parser.parse_event(event)

        self.assertEqual(parsed_event, {
            'request_mask': None,
            'denied_mask': None,
            'error_code': 0,
            'magic_token': 0,
            'parent': 0,
            'profile': '/bin/ping',
            'operation': 'capable',
            'resource': None,
            'info': None,
            'aamode': 'ALLOWED',
            'time': 1415403814,
            'active_hat': None,
            'pid': 15454,
            'task': 0,
            'comm': 'ping',
            'attr': None,
            'name2': None,
            'name': 'net_raw',
            'family': None,
            'protocol': None,
            'sock_type': None,
            'class': None,
        })

        obj = CapabilityRule(parsed_event['name'], log_event=parsed_event)

        self._compare_obj(obj, {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': {'net_raw'},
            'all_caps': False,
            'comment': "",
        })

        self.assertEqual(obj.get_raw(1), '  capability net_raw,')

    # def test_cap_from_invalid_log(self):
    #     parser = ReadLog('', '', '')
    #     # invalid log entry, name= should contain the capability name
    #     event = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname=""'
    #
    #     parsed_event = parser.parse_event(event)
    #
    #     obj = CapabilityRule()
    #
    #     with self.assertRaises(AppArmorBug):
    #         obj.set_log(parsed_event)
    #
    #     with self.assertRaises(AppArmorBug):
    #         obj.get_raw(1)
    #
    # def test_cap_from_non_cap_log(self):
    #     parser = ReadLog('', '', '')
    #     # log entry for different rule type
    #     event = 'type=AVC msg=audit(1415403814.973:667): apparmor="ALLOWED" operation="setsockopt" profile="/home/sys-tmp/ping" pid=15454 comm="ping" lport=1 family="inet" sock_type="raw" protocol=1'
    #
    #     parsed_event = parser.parse_event(event)
    #
    #     obj = CapabilityRule()
    #
    #     with self.assertRaises(AppArmorBug):
    #         obj.set_log(parsed_event)
    #
    #     with self.assertRaises(AppArmorBug):
    #         obj.get_raw(1)

    def test_cap_from_init_01(self):
        obj = CapabilityRule('chown')

        self._compare_obj(obj, {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': {'chown'},
            'all_caps': False,
            'comment': "",
        })

    def test_cap_from_init_02(self):
        obj = CapabilityRule(['chown'])

        self._compare_obj(obj, {
            'allow_keyword': False,
            'deny': False,
            'audit': False,
            'capability': {'chown'},
            'all_caps': False,
            'comment': "",
        })

    def test_cap_from_init_03(self):
        obj = CapabilityRule('chown', audit=True, deny=True)

        self._compare_obj(obj, {
            'allow_keyword': False,
            'deny': True,
            'audit': True,
            'capability': {'chown'},
            'all_caps': False,
            'comment': "",
        })

    def test_cap_from_init_04(self):
        obj = CapabilityRule(['chown', 'fsetid'], deny=True)

        self._compare_obj(obj, {
            'allow_keyword': False,
            'deny': True,
            'audit': False,
            'capability': {'chown', 'fsetid'},
            'all_caps': False,
            'comment': "",
        })


class CapabilityTestParseInvalid(AATest):
    tests = (
        # rule                           exception,         matches regex?
        ('capability',                  (AppArmorException, False)),  # missing comma
        ('network,',                    (AppArmorException, False)),  # not a capability rule
        ('priority=1042 capability,',   (AppArmorException, True)),
        ('priority=a capability,',      (AppArmorException, False)),
    )

    def _run_test(self, rawrule, expected):
        self.parseInvalidRule(CapabilityRule, rawrule, expected)


class InvalidCapabilityTest(AATest):
    def test_empty_cap_set(self):
        obj = CapabilityRule('chown')
        obj.capability.clear()
        # no capability set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)

    def test_empty_cap_list(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule([])

    def test_no_cap_list_arg(self):
        with self.assertRaises(TypeError):
            CapabilityRule()

    def test_space_cap(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule('    ')  # the whitespace capability ;-)

    def test_space_list_1(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(['    ', '   ', '   '])  # the whitespace capability ;-)

    def test_space_list_2(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(['chown', '   ', 'setgid'])  # includes the whitespace capability ;-)

    def test_wrong_type_for_cap(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(dict())

    def test_invalid_priority_1(self):
        with self.assertRaises(TypeError):
            CapabilityRule(CapabilityRule.ALL, priority=CapabilityRule.ALL)

    def test_invalid_priority_2(self):
        with self.assertRaises(AppArmorException):
            CapabilityRule(CapabilityRule.ALL, priority='invalid')


class WriteCapabilityTest(AATest):
    def _check_write_rule(self, rawrule, cleanrule):
        obj = CapabilityRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertTrue(CapabilityRule.match(rawrule))
        self.assertEqual(cleanrule.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_all(self):
        self._check_write_rule('     capability      ,    # foo        ', 'capability, # foo')

    def test_write_sys_admin(self):
        self._check_write_rule('    audit     capability sys_admin,', 'audit capability sys_admin,')

    def test_write_sys_multi(self):
        self._check_write_rule('   deny capability      sys_admin      audit_write,# foo bar', 'deny capability audit_write sys_admin, # foo bar')

    def test_write_manually(self):
        obj = CapabilityRule(['sys_ptrace', 'audit_write'], allow_keyword=True)

        expected = '    allow capability audit_write sys_ptrace,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_priority_1(self):
        self._check_write_rule('    priority  = 923   audit     capability sys_admin,', 'priority=923 audit capability sys_admin,')

    def test_write_priority_2(self):
        self._check_write_rule('    priority  = 0     audit     capability sys_admin,', 'priority=0 audit capability sys_admin,')

    def test_write_priority_3(self):
        self._check_write_rule('    priority=-12      audit     capability sys_admin,', 'priority=-12 audit capability sys_admin,')

    def test_write_priority_4(self):
        self._check_write_rule('    priority=+99      audit     capability sys_admin,', 'priority=99 audit capability sys_admin,')


class CapabilityCoveredTest(AATest):
    def _is_covered(self, obj, rule_to_test):
        self.assertTrue(CapabilityRule.match(rule_to_test))
        return obj.is_covered(CapabilityRule.create_instance(rule_to_test))

    def _is_covered_exact(self, obj, rule_to_test):
        self.assertTrue(CapabilityRule.match(rule_to_test))
        return obj.is_covered(CapabilityRule.create_instance(rule_to_test), True, True)

    def _is_equal(self, obj, rule_to_test, strict):
        self.assertTrue(CapabilityRule.match(rule_to_test))
        return obj.is_equal(CapabilityRule.create_instance(rule_to_test), strict)

    def test_covered_single(self):
        obj = CapabilityRule.create_instance('capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_audit(self):
        obj = CapabilityRule.create_instance('audit capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'audit capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_check_audit(self):
        obj = CapabilityRule.create_instance('audit capability sys_admin,')

        self.assertFalse(self._is_covered_exact(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered_exact(obj, 'audit capability sys_admin,'))

        self.assertFalse(self._is_covered_exact(obj, 'audit capability,'))
        self.assertFalse(self._is_covered_exact(obj, 'capability chown,'))
        self.assertFalse(self._is_covered_exact(obj, 'capability,'))

    def test_equal(self):
        obj = CapabilityRule.create_instance('capability sys_admin,')

        self.assertTrue(self._is_equal(obj, 'capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'allow capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'allow capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'audit capability sys_admin,', True))

        self.assertTrue(self._is_equal(obj, 'capability sys_admin,', False))
        self.assertTrue(self._is_equal(obj, 'allow capability sys_admin,', False))
        self.assertFalse(self._is_equal(obj, 'audit capability sys_admin,', False))

    def test_covered_multi(self):
        obj = CapabilityRule.create_instance('capability audit_write sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability sys_admin audit_write,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_all(self):
        obj = CapabilityRule.create_instance('capability,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability sys_admin audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))

    def test_covered_deny(self):
        obj = CapabilityRule.create_instance('capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_deny_2(self):
        obj = CapabilityRule.create_instance('deny capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'deny capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'deny capability chown,'))
        self.assertFalse(self._is_covered(obj, 'deny capability,'))

    def test_invalid_is_covered(self):
        raw_rule = 'capability sys_admin,'

        class SomeOtherClass(CapabilityRule):
            pass

        obj = CapabilityRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_borked_obj_is_covered(self):
        obj = CapabilityRule.create_instance('capability sys_admin,')

        testobj = CapabilityRule('chown')
        testobj.capability.clear()

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        raw_rule = 'capability sys_admin,'

        class SomeOtherClass(CapabilityRule):
            pass

        obj = CapabilityRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

    def test_empty_init(self):
        # add to internal set instead of using .set_* (which overwrites the internal set) to make sure obj and obj2 use separate storage
        obj = CapabilityRule('fsetid')
        obj2 = CapabilityRule('fsetid')
        obj.capability.add('sys_admin')
        obj2.capability.add('sys_ptrace')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability sys_ptrace,'))
        self.assertFalse(self._is_covered(obj2, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj2, 'capability sys_ptrace,'))


class CapabiliySeverityTest(AATest):
    tests = (
        ('fsetid',                      9),
        ('dac_read_search',             7),
        (['fsetid', 'dac_read_search'], 9),
        (CapabilityRule.ALL,            10),
    )

    def _run_test(self, params, expected):
        sev_db = severity.Severity('../severity.db', 'unknown')
        obj = CapabilityRule(params)
        rank = obj.severity(sev_db)
        self.assertEqual(rank, expected)

    def test_all_caps(self):
        ''' make sure all capabilities have a severity defined '''

        sev_db = severity.Severity('../severity.db', 'unknown')

        for cap in capability_keywords:
            obj = CapabilityRule(cap)
            rank = obj.severity(sev_db)
            # capabilities have a severity of 7..10, with the exception of 0 for the unused CAP_NET_BROADCAST
            # (might need adjustment if a new capability gets a different severity assigned)
            self.assertTrue(rank in [0, 7, 8, 9, 10], 'unexpected severity for capability %s: %s' % (cap, rank))

    def test_unknown_cap(self):
        sev_db = severity.Severity('../severity.db', 'unknown')
        obj = CapabilityRule('sys_admin')
        obj.capability = {'unknown_and_broken'}  # override capability with an unknown one to test for 'unknown' severity (creating obj with this invalid capability would raise an error)
        rank = obj.severity(sev_db)
        self.assertEqual(rank, 'unknown')


class CapabilityLogprofHeaderTest(AATest):
    tests = (
        ('capability,',                    [                              _('Capability'), _('ALL')]),  # noqa: E201
        ('capability chown,',              [                              _('Capability'), 'chown']),  # noqa: E201
        ('capability chown fsetid,',       [                              _('Capability'), 'chown fsetid']),  # noqa: E201
        ('audit capability,',              [_('Qualifier'), 'audit',      _('Capability'), _('ALL')]),
        ('deny capability chown,',         [_('Qualifier'), 'deny',       _('Capability'), 'chown']),
        ('allow capability chown fsetid,', [_('Qualifier'), 'allow',      _('Capability'), 'chown fsetid']),
        ('audit deny capability,',         [_('Qualifier'), 'audit deny', _('Capability'), _('ALL')]),
    )

    def _run_test(self, params, expected):
        obj = CapabilityRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


# --- tests for CapabilityRuleset --- #
class CapabilityRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = CapabilityRuleset()
        ruleset_2 = CapabilityRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = CapabilityRuleset()
        rules = [
            'capability sys_admin,',
            'capability chown,',
        ]

        expected_raw = [
            'capability sys_admin,',
            'capability chown,',
            '',
        ]

        expected_clean = [
            'capability chown,',
            'capability sys_admin,',
            '',
        ]

        for rule in rules:
            ruleset.add(CapabilityRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

    def test_ruleset_2(self):
        ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'allow capability sys_admin,',
            'deny capability fowner, # example comment',
        ]

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        for rule in rules:
            ruleset.add(CapabilityRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))

    def test_ruleset_add(self):
        rule = CapabilityRule('fowner', comment=' # example comment')

        ruleset = CapabilityRuleset()
        ruleset.add(rule)

        expected_raw = [
            '  capability fowner, # example comment',
            '',
        ]

        expected_clean = expected_raw

        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))


class CapabilityRulesCoveredTest(AATest):
    def AASetup(self):
        self.ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'capability setuid setgid,',
            'allow capability sys_admin,',
            'audit capability kill,',
            'deny capability fowner, # example comment',
        ]

        for rule in rules:
            self.ruleset.add(CapabilityRule.create_instance(rule))

    def test_ruleset_is_covered_1(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability chown,')))

    def test_ruleset_is_covered_2(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability sys_admin,')))

    def test_ruleset_is_covered_3(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('allow capability sys_admin,')))

    def test_ruleset_is_covered_4(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability setuid,')))

    def test_ruleset_is_covered_5(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('allow capability setgid,')))

    def test_ruleset_is_covered_6(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability setgid setuid,')))

    def test_ruleset_is_covered_7(self):
        pass  # self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability sys_admin chown,')))  # fails because it is split over two rule objects internally

    def test_ruleset_is_covered_8(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability kill,')))

    # deny
    def test_ruleset_is_covered_9(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability chown,')))

    def test_ruleset_is_covered_10(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability sys_admin,')))

    def test_ruleset_is_covered_11(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability sys_admin chown,')))

    def test_ruleset_is_covered_12(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability setgid,')))

    def test_ruleset_is_covered_13(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability kill,')))

    # audit
    def test_ruleset_is_covered_14(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability chown,')))

    def test_ruleset_is_covered_15(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability sys_admin,')))

    def test_ruleset_is_covered_16(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability sys_admin chown,')))

    def test_ruleset_is_covered_17(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability setgid,')))

    def test_ruleset_is_covered_18(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability kill,')))

    # combined flags
    def test_ruleset_is_covered_19(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability fowner,')))

    def test_ruleset_is_covered_20(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit deny capability fowner,')))

    def test_ruleset_is_covered_21(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('audit capability fowner,')))

    def test_ruleset_is_covered_22(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('capability fowner,')))

    def test_ruleset_is_covered_23(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.create_instance('capability fowner,'), check_allow_deny=False))

    def test_ruleset_is_covered_24(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.create_instance('deny capability chown,'), check_allow_deny=False))

# XXX - disabling these until we decide whether or not checking whether
# a log is covered by rules should be a separate entry point, possibly
# handling the log structure directly, or whether coverage should be
# solely based on Rule objects and marshaling of a log message into a
# Rule object should occur outside of the Rule classes themselves.
#
#    def _test_log_covered(self, expected, capability):
#        event_base = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="%s"'

#        parser = ReadLog('', '', '')
#        self.assertEqual(expected, self.ruleset.is_log_covered(parser.parse_event(event_base%capability)))
#
#    def test_ruleset_is_log_covered_1(self):
#        self._test_log_covered(False, 'net_raw')
#    def test_ruleset_is_log_covered_2(self):
#        self._test_log_covered(True, 'chown')
#    def test_ruleset_is_log_covered_3(self):
#        self._test_log_covered(True, 'sys_admin')
#    def test_ruleset_is_log_covered_4(self):
#        self._test_log_covered(True, 'kill')
#    def test_ruleset_is_log_covered_5(self):
#        self._test_log_covered(False, 'fowner')
#    def test_ruleset_is_log_covered_6(self):
#        event_base = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="%s"'
#
#        parser = ReadLog('', '', '')
#        self.assertEqual(True, self.ruleset.is_log_covered(parser.parse_event(event_base%'fowner'), False))  # ignores allow/deny


class CapabilityGlobTest(AATest):
    def AASetup(self):
        self.ruleset = CapabilityRuleset()

    def test_glob(self):
        self.assertEqual(self.ruleset.get_glob('capability net_raw,'), 'capability,')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            self.ruleset.get_glob_ext('capability net_raw,')


class CapabilityDeleteTest(AATest):
    def AASetup(self):
        self.ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'allow capability sys_admin,',
            'deny capability fowner, # example comment',
        ]

        for rule in rules:
            self.ruleset.add(CapabilityRule.create_instance(rule))

    def test_delete(self):
        expected_raw = [
            '  capability chown,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  capability chown,',
            '',
        ]

        self.ruleset.delete(CapabilityRule(['sys_admin']))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_allcaps(self):
        expected_raw = [
            '  capability chown,',
            '  deny capability fowner, # example comment',
            '  capability,',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  capability chown,',
            '  capability,',
            '',
        ]

        self.ruleset.add(CapabilityRule(CapabilityRule.ALL))
        self.ruleset.delete(CapabilityRule('sys_admin'))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_multi(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.ruleset.add(CapabilityRule(['audit_read', 'audit_write']))
        self.ruleset.delete(CapabilityRule(['audit_read', 'audit_write']))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_multi_2(self):
        self.ruleset.add(CapabilityRule(['audit_read', 'audit_write']))

        with self.assertRaises(AppArmorBug):
            # XXX ideally delete_raw should remove audit_read from the "capability audit_read audit_write," ruleset
            #     but that's quite some work to cover a corner case.
            self.ruleset.delete(CapabilityRule('audit_read'))

    def test_delete_raw_notfound(self):
        with self.assertRaises(AppArmorBug):
            self.ruleset.delete(CapabilityRule('audit_write'))

    def test_delete_duplicates(self):
        inc = CapabilityRuleset()
        rules = [
            'capability chown,',
            'deny capability fowner, # example comment',
        ]

        for rule in rules:
            inc.add(CapabilityRule.create_instance(rule))

        expected_raw = [
            '  allow capability sys_admin,',
            '',
        ]

        expected_clean = expected_raw

        self.assertEqual(self.ruleset.delete_duplicates(inc), 2)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_2(self):
        inc = CapabilityRuleset()
        rules = [
            'capability audit_write,',
            'capability fowner, # example comment',
        ]

        for rule in rules:
            inc.add(CapabilityRule.create_instance(rule))

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_3(self):
        self.ruleset.add(CapabilityRule.create_instance('audit capability dac_override,'))

        inc = CapabilityRuleset()
        rules = [
            'capability dac_override,',
        ]

        for rule in rules:
            inc.add(CapabilityRule.create_instance(rule))

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '  audit capability dac_override,',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  audit capability dac_override,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_4(self):
        inc = CapabilityRuleset()
        rules = ['capability,']

        for rule in rules:
            inc.add(CapabilityRule.create_instance(rule))

        expected_raw = [
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 2)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_none(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(None), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_hasher(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability fowner, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability fowner, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(hasher()), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def _check_test_delete_duplicates_in_profile(self, rules, expected_raw, expected_clean, expected_deleted):
        obj = CapabilityRuleset()

        for rule in rules:
            obj.add(CapabilityRule.create_instance(rule))

        deleted = obj.delete_duplicates(None)

        self.assertEqual(expected_raw, obj.get_raw(1))
        self.assertEqual(expected_clean, obj.get_clean(1))
        self.assertEqual(deleted, expected_deleted)

    def test_delete_duplicates_in_profile_01(self):
        rules = [
            'audit capability chown,',
            'audit capability,',
            'capability dac_override,',
        ]

        expected_raw = [
            '  audit capability,',
            '',
        ]

        expected_clean = [
            '  audit capability,',
            '',
        ]

        expected_deleted = 2

        self._check_test_delete_duplicates_in_profile(rules, expected_raw, expected_clean, expected_deleted)

    def test_delete_duplicates_in_profile_02(self):
        rules = [
            'audit capability chown,',
            'audit capability,',
            'audit capability dac_override,',
            'capability ,',
            'audit capability ,',
        ]

        expected_raw = [
            '  audit capability,',
            '',
        ]

        expected_clean = [
            '  audit capability,',
            '',
        ]

        expected_deleted = 4

        self._check_test_delete_duplicates_in_profile(rules, expected_raw, expected_clean, expected_deleted)

    def test_delete_duplicates_in_profile_03(self):
        rules = [
            'audit capability chown,',
            'capability dac_override,',
            'deny capability dac_override,',
            'capability dac_override,',
            'audit capability chown,',
            'deny capability chown,',
            'audit deny capability chown,',
            'capability,',
            'audit capability,',
        ]

        expected_raw = [
            '  deny capability dac_override,',
            '  audit deny capability chown,',
            '  audit capability,',
            '',
        ]

        expected_clean = [
            '  audit deny capability chown,',
            '  deny capability dac_override,',
            '',
            '  audit capability,',
            '',
        ]

        expected_deleted = 6

        self._check_test_delete_duplicates_in_profile(rules, expected_raw, expected_clean, expected_deleted)

    def test_delete_duplicates_in_profile_04(self):
        rules = [
            'audit capability chown,',
            'deny capability chown,',
        ]

        expected_raw = [
            '  audit capability chown,',
            '  deny capability chown,',
            '',
        ]

        expected_clean = [
            '  deny capability chown,',
            '',
            '  audit capability chown,',
            '',
        ]

        expected_deleted = 0

        self._check_test_delete_duplicates_in_profile(rules, expected_raw, expected_clean, expected_deleted)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
