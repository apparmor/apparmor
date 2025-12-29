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

from apparmor.common import AppArmorBug, AppArmorException, cmd
from apparmor.logparser import ReadLog
from apparmor.rule.network import NetworkRule, NetworkRuleset, network_domain_keywords, network_ipv6
from apparmor.translations import init_translation
from common_test import AATest, setup_all_loops
import re

_ = init_translation()

exp = namedtuple('exp', ('audit', 'allow_keyword', 'deny', 'comment',
                         'accesses', 'domain', 'all_domains', 'type_or_protocol',
                         'all_type_or_protocols', 'local_expr', 'peer_expr'))

# --- check if the keyword list is up to date --- #


class NetworkKeywordsTest(AATest):
    def test_network_keyword_list(self):
        rc, output = cmd('../../common/list_af_names.sh')
        self.assertEqual(rc, 0)

        af_names = []
        af_pairs = output.replace('AF_', '').strip().lower().split(",")
        for af_pair in af_pairs:
            af_name = af_pair.lstrip().split(" ")[0]
            # skip max af name definition
            if af_name and af_name != "max":
                af_names.append(af_name)

        missing_af_names = []
        for keyword in af_names:
            if keyword not in network_domain_keywords:
                # keywords missing in the system are ok (= older kernel), but network_domain_keywords needs to have the full list
                missing_af_names.append(keyword)

        self.assertEqual(
            missing_af_names, [],
            'Missing af_names in NetworkRule network_domain_keywords. This test is likely running '
            'on an newer kernel and will require updating the list of network domain keywords in '
            'utils/apparmor/rule/network.py')


class NetworkPV6Test(AATest):
    def test_ipv6(self):
        tests = [
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),  # Standard IPv6
            ("2001:db8::8a2e:370:7334", True),  # Zero Compression
            ("::1", True),  # IPv6 Loopback
            ("::", True),  # IPv6 Unspecified
            ("::ffff:192.168.236.159", True),  # IPv6-mapped IPv4
            ("fe80::1ff:fe23:4567:890a%eth0", True),  # IPv6 with Zone Identifier
            ("1234:5678::abcd:ef12:3456", True),  # Mixed groups and zero compression
            ("12345::6789", False),  # Erroneous IP (invalid hex group length)
            ("192.168.1.1", False),  # IPv4 only
        ]

        for test in tests:
            self.assertEqual(bool(re.match(network_ipv6, test[0])), test[1])


# --- tests for single NetworkRule --- #
class NetworkTest(AATest):
    def _compare_obj(self, obj, expected):
        self.assertEqual(expected.allow_keyword, obj.allow_keyword)
        self.assertEqual(expected.audit, obj.audit)
        self.assertEqual(expected.accesses, obj.accesses)
        self.assertEqual(expected.domain, obj.domain)
        self.assertEqual(expected.type_or_protocol, obj.type_or_protocol)
        self.assertEqual(expected.all_domains, obj.all_domains)
        self.assertEqual(expected.all_type_or_protocols, obj.all_type_or_protocols)
        self.assertEqual(expected.deny, obj.deny)
        self.assertEqual(expected.comment, obj.comment)
        self.assertEqual(expected.local_expr, obj.local_expr)
        self.assertEqual(expected.peer_expr, obj.peer_expr)


class NetworkTestParse(NetworkTest):
    tests = (
        # rawrule                                       audit  allow  deny   comment       access               domain  all?   type/proto  all?   local_expr                             peer_expr
        ('network,',                                exp(False, False, False, '',           None,                None,   True,  None,       True,  NetworkRule.ALL,                       NetworkRule.ALL)),
        ('network inet,',                           exp(False, False, False, '',           None,                'inet', False, None,       True,  NetworkRule.ALL,                       NetworkRule.ALL)),
        ('network inet stream,',                    exp(False, False, False, '',           None,                'inet', False, 'stream',   False, NetworkRule.ALL,                       NetworkRule.ALL)),
        ('deny network inet stream, # comment',     exp(False, False, True,  ' # comment', None,                'inet', False, 'stream',   False, NetworkRule.ALL,                       NetworkRule.ALL)),
        ('audit allow network tcp,',                exp(True,  True,  False, '',           None,                None,   True,  'tcp',      False, NetworkRule.ALL,                       NetworkRule.ALL)),
        ('network stream,',                         exp(False, False, False, '',           None,                None,   True,  'stream',   False, NetworkRule.ALL,                       NetworkRule.ALL)),
        ('network stream peer=(ip=::1 port=22),',   exp(False, False, False, '',           None,                None,   True,  'stream',   False, NetworkRule.ALL,                       {"ip": "::1", 'port': '22'},)),
        ('network stream ip=::1 port=22,',          exp(False, False, False, '',           None,                None,   True,  'stream',   False, {"ip": "::1", 'port': '22'},           NetworkRule.ALL)),
        ('network (bind,listen) stream,',           exp(False, False, False, '',           {'listen', 'bind'},  None,   True,  'stream',   False, NetworkRule.ALL,                       NetworkRule.ALL)),
        ('network peer=(ip=::1, port=22),',         exp(False, False, False, '',           None,                None,   True,  None,       True,  NetworkRule.ALL,                       {"ip": "::1", 'port': '22'})),
        ('network (connect, rw) stream ip=192.168.122.2 port=22 peer=(ip=192.168.122.3 port=22),',
                                                    exp(False, False, False, '',           {'connect', 'rw'},   None,   True,  'stream',   False, {'ip': '192.168.122.2', 'port': '22'}, {"ip": "192.168.122.3", 'port': '22'})),  # noqa: E127
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(NetworkRule.match(rawrule))
        obj = NetworkRule.create_instance(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)


class NetworkTestParseInvalid(NetworkTest):
    tests = (
        #                                                    exception          matches regex
        ('network foo,',                                    (AppArmorException, True)),
        ('network foo bar,',                                (AppArmorException, True)),
        ('network foo tcp,',                                (AppArmorException, True)),
        ('network inet bar,',                               (AppArmorException, True)),
        ('network ip=999.999.999.999,',                     (AppArmorException, True)),
        ('network port=99999,',                             (AppArmorException, True)),
        ('network inet ip=in:va::li:d0,',                   (AppArmorException, True)),
        ('network inet ip=in:va::li:d0,',                   (AppArmorException, True)),
        ('network inet ip=1:2:3:4:5:6:7:8:9:0:0:0,',        (AppArmorException, True)),  # too many segments
        ('network inet peer=(ip=1:2:3:4:5:6:7:8:9:0:0:0),', (AppArmorException, True)),  # too many segments
        ('network packet ip=1::,',                          (AppArmorException, True)),  # Only inet[6] domains can be used in conjunction with a local expression
        ('network packet peer=(ip=1::),',                   (AppArmorException, True)),  # Only inet[6] domains can be used in conjunction with a peer expression
        ('priority=a network,',                             (AppArmorException, False)),
        ('priority=-1042 network,',                         (AppArmorException, True)),
    )

    def _run_test(self, rawrule, expected):
        self.parseInvalidRule(NetworkRule, rawrule, expected)


class NetworkTestParseFromLog(NetworkTest):
    def test_net_from_log(self):
        parser = ReadLog('', '', '')
        event = 'type=AVC msg=audit(1428699242.551:386): apparmor="DENIED" operation="create" profile="/bin/ping" pid=10589 comm="ping" family="inet" sock_type="raw" protocol=1 lport=1234'

        parsed_event = parser.parse_event(event)

        self.assertEqual(parsed_event, {
            'request_mask': None,
            'denied_mask': None,
            'error_code': 0,
            'family': 'inet',
            'magic_token': 0,
            'parent': 0,
            'profile': '/bin/ping',
            'protocol': 'icmp',
            'sock_type': 'raw',
            'operation': 'create',
            'resource': None,
            'info': None,
            'aamode': 'DENIED',
            'accesses': None,
            'addr': None,
            'peer_addr': None,
            'port': 1234,
            'remote_port': None,
            'time': 1428699242,
            'active_hat': None,
            'pid': 10589,
            'task': 0,
            'attr': None,
            'name2': None,
            'name': None,
            'class': None,
        })

        obj = NetworkRule(NetworkRule.ALL, parsed_event['family'], parsed_event['sock_type'], NetworkRule.ALL, NetworkRule.ALL, log_event=parsed_event)

        #              audit  allow  deny   comment  domain  all?   type/proto  all?
        expected = exp(False, False, False, '',     None, 'inet', False, 'raw',      False, NetworkRule.ALL, NetworkRule.ALL)

        self._compare_obj(obj, expected)

        self.assertEqual(obj.get_raw(1), '  network inet raw,')


class NetworkFromInit(NetworkTest):
    tests = (
        # NetworkRule object                                                                                                   audit  allow  deny   comment access               domain  all?   type/proto  all?     Local expr          Peer expr
        (NetworkRule(NetworkRule.ALL,    'inet',           'raw',           NetworkRule.ALL, NetworkRule.ALL, deny=True),  exp(False, False, True,  '',      None,               'inet', False, 'raw',     False, NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    'inet',           'raw',           NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      None,               'inet', False, 'raw',     False, NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    'inet',           NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      None,               'inet', False, None,      True,  NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    NetworkRule.ALL,  NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      None,               None,   True,  None,      True,  NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    NetworkRule.ALL, 'tcp',            NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      None,               None,   True,  'tcp',     False, NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    NetworkRule.ALL, 'stream',         NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      None,               None,   True,  'stream',  False, NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule('bind',             NetworkRule.ALL, 'stream',         NetworkRule.ALL, NetworkRule.ALL),             exp(False, False, False, '',      {'bind'},           None,   True,  'stream',  False, NetworkRule.ALL,  NetworkRule.ALL)),
        (NetworkRule({'bind', 'listen'}, NetworkRule.ALL, 'stream',         {'port': '22'},  NetworkRule.ALL),             exp(False, False, False, '',      {'bind', 'listen'}, None,   True,  'stream',  False, {'port': '22'},  NetworkRule.ALL)),
        (NetworkRule(NetworkRule.ALL,    NetworkRule.ALL, 'stream',         NetworkRule.ALL, {'port': '22'}),              exp(False, False, False, '',      None,               None,   True,  'stream',  False, NetworkRule.ALL,  {'port': '22'})),
        (NetworkRule(NetworkRule.ALL,    NetworkRule.ALL, 'stream',         NetworkRule.ALL, {'ip': '::1', 'port': '22'}), exp(False, False, False, '',      None,               None,   True,  'stream',  False, NetworkRule.ALL,  {'ip': '::1', 'port': '22'})),
    )

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidNetworkInit(AATest):
    tests = (
        # init params                                                           expected exception
        ((NetworkRule.ALL,   'inet', '',     NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # empty type_or_protocol
        ((NetworkRule.ALL,   '',     'tcp',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # empty domain
        ((NetworkRule.ALL,   '    ', 'tcp',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # whitespace domain
        ((NetworkRule.ALL,   'inet', '   ',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # whitespace type_or_protocol
        ((NetworkRule.ALL,   'xyxy', 'tcp',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # invalid domain
        ((NetworkRule.ALL,   'inet', 'xyxy', NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # invalid type_or_protocol
        ((NetworkRule.ALL,   dict(), 'tcp',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # wrong type for domain
        ((NetworkRule.ALL,   None,   'tcp',  NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # wrong type for domain
        ((NetworkRule.ALL,   'inet', dict(), NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # wrong type for type_or_protocol
        ((NetworkRule.ALL,   'inet', None,   NetworkRule.ALL, NetworkRule.ALL),  AppArmorBug),        # wrong type for type_or_protocol
        (('invalid_access',  'inet', None,   NetworkRule.ALL, NetworkRule.ALL),  AppArmorException),  # Invalid Access
        (({'bind', 'invld'}, 'inet', None,   NetworkRule.ALL, NetworkRule.ALL),  AppArmorException),  # Invalid Access
        ((NetworkRule.ALL,   'inet', None,   {'ip': ':::::'}, NetworkRule.ALL),  AppArmorException),  # Invalid ip in local expression
        ((NetworkRule.ALL,   'inet', None,   NetworkRule.ALL, {'ip': ':::::'}),  AppArmorException),  # Invalid ip in peer expression
        ((NetworkRule.ALL,   'inet', None,   {'invld': '0'},  NetworkRule.ALL),  AppArmorException),  # Invalid keyword in local expression
        ((NetworkRule.ALL,   'inet', None,   NetworkRule.ALL, {'invld': '0'}),   AppArmorException),  # Invalid keyword in peer expression
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            NetworkRule(*params)

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            NetworkRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            NetworkRule('inet')

    def test_invalid_priority_1(self):
        with self.assertRaises(TypeError):
            NetworkRule(NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, priority=NetworkRule.ALL)

    def test_invalid_priority_2(self):
        with self.assertRaises(AppArmorException):
            NetworkRule(NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, NetworkRule.ALL, priority='invalid')


class InvalidNetworkTest(AATest):
    def _check_invalid_rawrule(self, rawrule):
        obj = None
        self.assertFalse(NetworkRule.match(rawrule))
        with self.assertRaises(AppArmorException):
            obj = NetworkRule.create_instance(rawrule)

        self.assertIsNone(obj, 'NetworkRule handed back an object unexpectedly')

    def test_invalid_net_missing_comma(self):
        self._check_invalid_rawrule('network')  # missing comma

    def test_invalid_net_non_NetworkRule(self):
        self._check_invalid_rawrule('dbus,')  # not a network rule

    def test_empty_net_data_1(self):
        obj = NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL)
        obj.domain = ''
        # no domain set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)

    def test_empty_net_data_2(self):
        obj = NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL)
        obj.type_or_protocol = ''
        # no type_or_protocol set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)


class WriteNetworkTestAATest(AATest):
    def _run_test(self, rawrule, expected):
        self.assertTrue(NetworkRule.match(rawrule))
        obj = NetworkRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    tests = (
        #  raw rule                                                          clean rule
        ('     network         ,    # foo        ',                          'network, # foo'),
        ('    audit     network inet,',                                      'audit network inet,'),
        ('   deny network         inet      stream,# foo bar',               'deny network inet stream, # foo bar'),
        ('   deny network         inet      ,# foo bar',                     'deny network inet, # foo bar'),
        ('   allow network         tcp      ,# foo bar',                     'allow network tcp, # foo bar'),
        ('   network     stream    peer  =  (  ip=::1  port=22  )  ,',       'network stream peer=(ip=::1 port=22),'),
        ('   network   (  bind , listen  ) stream  ip  =  ::1 port  = 22 ,', 'network (bind, listen) stream ip=::1 port=22,'),
        ('   allow network         tcp      ,# foo bar',                     'allow network tcp, # foo bar'),
        (' priority =  -02  allow network         tcp      ,# foo bar',       'priority=-2 allow network tcp, # foo bar'),
        (' priority = 0     allow network         tcp      ,# foo bar',       'priority=0 allow network tcp, # foo bar'),
        (' priority = 43    allow network         tcp      ,# foo bar',       'priority=43 allow network tcp, # foo bar'),
        (' priority=+123    allow network         tcp      ,# foo bar',       'priority=123 allow network tcp, # foo bar'),

    )

    def test_write_manually(self):
        obj = NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL,  allow_keyword=True)

        expected = '    allow network inet stream,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class NetworkCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = NetworkRule.create_instance(self.rule)
        check_obj = NetworkRule.create_instance(param)

        self.assertTrue(NetworkRule.match(param))

        self.assertEqual(
            obj.is_equal(check_obj), expected[0],
            'Mismatch in is_equal, expected {}'.format(expected[0]))
        self.assertEqual(
            obj.is_equal(check_obj, True), expected[1],
            'Mismatch in is_equal/strict, expected {}'.format(expected[1]))

        self.assertEqual(
            obj.is_covered(check_obj), expected[2],
            'Mismatch in is_covered, expected {}'.format(expected[2]))
        self.assertEqual(
            obj.is_covered(check_obj, True, True), expected[3],
            'Mismatch in is_covered/exact, expected {}'.format(expected[3]))


class NetworkCoveredTest_01(NetworkCoveredTest):
    rule = 'network inet,'

    tests = (
        #   rule                      equal  strict equal  covered  covered exact
        ('network,',                 (False, False,        False,   False)),
        ('network inet,',            (True,  True,         True,    True)),
        ('network inet, # comment',  (True,  False,        True,    True)),
        ('allow network inet,',      (True,  False,        True,    True)),
        ('network     inet,',        (True,  False,        True,    True)),
        ('network inet stream,',     (False, False,        True,    True)),
        ('network inet tcp,',        (False, False,        True,    True)),
        ('audit network inet,',      (False, False,        False,   False)),
        ('audit network,',           (False, False,        False,   False)),
        ('network unix,',            (False, False,        False,   False)),
        ('network tcp,',             (False, False,        False,   False)),
        ('audit deny network inet,', (False, False,        False,   False)),
        ('deny network inet,',       (False, False,        False,   False)),
    )


class NetworkCoveredTest_02(NetworkCoveredTest):
    rule = 'audit network inet,'

    tests = (
        #   rule                        equal  strict equal  covered  covered exact
        ('      network inet,',        (False, False,        True,    False)),
        ('audit network inet,',        (True,  True,         True,    True)),
        ('      network inet stream,', (False, False,        True,    False)),
        ('audit network inet stream,', (False, False,        True,    True)),
        ('      network,',             (False, False,        False,   False)),
        ('audit network,',             (False, False,        False,   False)),
        ('      network unix,',        (False, False,        False,   False)),
    )


class NetworkCoveredTest_03(NetworkCoveredTest):
    rule = 'network inet stream,'

    tests = (
        #   rule                        equal  strict equal  covered  covered exact
        ('      network inet stream,', (True,  True,         True,    True)),
        ('allow network inet stream,', (True,  False,        True,    True)),
        ('      network inet,',        (False, False,        False,   False)),
        ('      network,',             (False, False,        False,   False)),
        ('      network inet tcp,',    (False, False,        False,   False)),
        ('audit network,',             (False, False,        False,   False)),
        ('audit network inet stream,', (False, False,        False,   False)),
        ('      network unix,',        (False, False,        False,   False)),
        ('      network,',             (False, False,        False,   False)),
    )


class NetworkCoveredTest_04(NetworkCoveredTest):
    rule = 'network,'

    tests = (
        #   rule                         equal  strict equal  covered  covered exact
        ('      network,',              (True,  True,         True,    True)),
        ('allow network,',              (True,  False,        True,    True)),
        ('      network inet,',         (False, False,        True,    True)),
        ('      network inet6 stream,', (False, False,        True,    True)),
        ('      network tcp,',          (False, False,        True,    True)),
        ('      network inet raw,',     (False, False,        True,    True)),
        ('audit network,',              (False, False,        False,   False)),
        ('deny  network,',              (False, False,        False,   False)),
    )


class NetworkCoveredTest_05(NetworkCoveredTest):
    rule = 'deny network inet,'

    tests = (
        #   rule                      equal  strict equal  covered  covered exact
        ('      deny network inet,', (True,  True,         True,    True)),
        ('audit deny network inet,', (False, False,        False,   False)),
        ('           network inet,', (False, False,        False,   False)),  # XXX should covered be true here?
        ('      deny network unix,', (False, False,        False,   False)),
        ('      deny network,',      (False, False,        False,   False)),
    )


class NetworkCoveredTest_06(NetworkCoveredTest):
    rule = 'network (rw, connect) port=127 peer=(ip=192.168.122.3),'

    tests = (
        #   rule                                                                                     equal strict equal covered covered exact
        ('network (rw, connect) port=127 peer=(ip=192.168.122.3),',                                  (True,  True,       True,   True)),
        ('network (rw, connect) port=127 ip=192.168.122.2 peer=(ip=192.168.122.3),',                 (False, False,      True,   True)),
        ('network (rw, connect) inet port=127 ip=192.168.122.2 peer=(ip=192.168.122.3),',            (False, False,      True,   True)),
        ('network (rw, connect) port=127 ip=192.168.122.2 peer=(ip=192.168.122.3 port=12345),',      (False, False,      True,   True)),
        ('network (rw, connect) inet port=127 ip=192.168.122.2 peer=(ip=192.168.122.3 port=12345),', (False, False,      True,   True)),
        ('network connect port=12345 ip=192.168.122.2 peer=(ip=192.168.122.3),',                     (False, False,      False,  False)),
        ('network (r, connect) port=12345 ip=192.168.122.2 peer=(ip=192.168.122.3),',                (False, False,      False,  False)),
        ('network (r, connect) port=128 peer=(ip=192.168.122.3),',                                   (False, False,      False,  False)),
        ('network (rw, connect) port=127 peer=(ip=127.0.0.1),',                                      (False, False,      False,  False)),
        ('network (rw, connect) port=127,',                                                          (False, False,      False,  False)),
    )


class NetworkCoveredTest_Invalid(AATest):
    def test_borked_obj_is_covered_1(self):
        obj = NetworkRule.create_instance('network inet,')

        testobj = NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL)
        testobj.domain = ''

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_borked_obj_is_covered_2(self):
        obj = NetworkRule.create_instance('network inet,')

        testobj = NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL)
        testobj.type_or_protocol = ''

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_covered(self):
        raw_rule = 'network inet,'

        class SomeOtherClass(NetworkRule):
            pass

        obj = NetworkRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        raw_rule = 'network inet,'

        class SomeOtherClass(NetworkRule):
            pass

        obj = NetworkRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)


class NetworkLogprofHeaderTest(AATest):
    tests = (
        ('network,',                                        [                              _('Accesses'), _('ALL'),      _('Network Family'), _('ALL'), _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),   # noqa: E201
        ('network inet,',                                   [                              _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),  # noqa: E201
        ('network inet stream,',                            [                              _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), 'stream', _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),  # noqa: E201
        ('deny network,',                                   [_('Qualifier'), 'deny',       _('Accesses'), _('ALL'),      _('Network Family'), _('ALL'), _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),
        ('allow network inet,',                             [_('Qualifier'), 'allow',      _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),
        ('audit network inet stream,',                      [_('Qualifier'), 'audit',      _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), 'stream', _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),
        ('audit deny network inet,',                        [_('Qualifier'), 'audit deny', _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), _('ALL')]),
        ('network (bind, listen) stream ip=::1 port=22,',   [                              _('Accesses'), 'bind listen', _('Network Family'), _('ALL'), _('Socket Type'), 'stream', _('Local'), {'ip': '::1', 'port': '22'}, _('Peer'), _('ALL')]),  # noqa: E201
        ('audit deny network inet peer=(ip=::1),',          [_('Qualifier'), 'audit deny', _('Accesses'), _('ALL'),      _('Network Family'), 'inet',   _('Socket Type'), _('ALL'), _('Local'), _('ALL'),                    _('Peer'), {'ip': '::1'}]),
    )

    def _run_test(self, params, expected):
        obj = NetworkRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class NetworkRuleReprTest(AATest):
    tests = (
        (NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL),                                       '<NetworkRule> network inet stream,'),
        (NetworkRule.create_instance(' allow  network  inet  stream, # foo'), '<NetworkRule> allow  network  inet  stream, # foo'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(str(params), expected)


# --- tests for NetworkRuleset --- #
class NetworkRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = NetworkRuleset()
        ruleset_2 = NetworkRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = NetworkRuleset()
        rules = (
            'network tcp,',
            'network inet,',
        )

        expected_raw = [
            'network tcp,',
            'network inet,',
            '',
        ]

        expected_clean = [
            'network inet,',
            'network tcp,',
            '',
        ]

        for rule in rules:
            ruleset.add(NetworkRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

    def test_ruleset_2(self):
        ruleset = NetworkRuleset()
        rules = (
            'network inet6 raw,',
            'allow network inet,',
            'deny network udp, # example comment',
        )

        expected_raw = [
            '  network inet6 raw,',
            '  allow network inet,',
            '  deny network udp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny network udp, # example comment',
            '',
            '  allow network inet,',
            '  network inet6 raw,',
            '',
        ]

        for rule in rules:
            ruleset.add(NetworkRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))


class NetworkGlobTestAATest(AATest):
    def setUp(self):
        self.maxDiff = None
        self.ruleset = NetworkRuleset()

    def test_glob_1(self):
        self.assertEqual(self.ruleset.get_glob('network inet,'), 'network,')

    # not supported or used yet
    # def test_glob_2(self):
    #     self.assertEqual(self.ruleset.get_glob('network inet raw,'), 'network inet,')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for network rules
            self.ruleset.get_glob_ext('network inet raw,')


class NetworkDeleteTestAATest(AATest):
    pass


class NetworkRulesetReprTest(AATest):
    def test_network_ruleset_repr(self):
        obj = NetworkRuleset()
        obj.add(NetworkRule(NetworkRule.ALL, 'inet', 'stream', NetworkRule.ALL, NetworkRule.ALL))
        obj.add(NetworkRule.create_instance(' allow  network  inet  stream, # foo'))

        expected = '<NetworkRuleset>\n  network inet stream,\n  allow  network  inet  stream, # foo\n</NetworkRuleset>'
        self.assertEqual(str(obj), expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
