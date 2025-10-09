# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
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

import re

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.regex import RE_PROFILE_NETWORK, strip_parenthesis
from apparmor.rule import BaseRule, BaseRuleset, logprof_value_or_all, parse_modifiers, check_dict_keys, \
    check_and_split_list, initialize_cond_dict, print_dict_values, tuple_to_dict
from apparmor.translations import init_translation
from apparmor.rule.unix import unix_accesses as network_accesses
from apparmor.rule.unix import access_flags
import ipaddress

_ = init_translation()

network_domain_keywords = [
    'unspec', 'unix', 'inet', 'ax25', 'ipx', 'appletalk', 'netrom', 'bridge', 'atmpvc', 'x25', 'inet6',
    'rose', 'netbeui', 'security', 'key', 'netlink', 'packet', 'ash', 'econet', 'atmsvc', 'rds', 'sna',
    'irda', 'pppox', 'wanpipe', 'llc', 'ib', 'mpls', 'can', 'tipc', 'bluetooth', 'iucv', 'rxrpc', 'isdn',
    'phonet', 'ieee802154', 'caif', 'alg', 'nfc', 'vsock', 'kcm', 'qipcrtr', 'smc', 'xdp', 'mctp']

network_type_keywords = ['stream', 'dgram', 'seqpacket', 'rdm', 'raw', 'packet']
network_protocol_keywords = ['tcp', 'udp', 'icmp']

byte = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
network_ipv4 = fr'{byte}\.{byte}\.{byte}\.{byte}'

network_ipv6 = (
    r'('
    r'([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|'
    r'([0-9a-f]{1,4}:){1,7}:|'
    r'([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|'
    r'([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|'
    r'([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|'
    r'([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|'
    r'([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|'
    r'[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|'
    r':((:[0-9a-f]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9a-f]{0,4}){0,4}%%[0-9a-zA-Z]{1,}|'
    r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
    r'([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    r')(%%[0-9a-zA-Z]{1,})?'
)

network_port = r'(port\s*=\s*(?P<%s>\d+))[,\s]*'
ip_cond = fr'\s*ip\s*=\s*(?P<%s>(({network_ipv4})|({network_ipv6})|none))[,\s]*'

RE_LOCAL_EXPR = f'((({ip_cond % "ip"})|({network_port % "port"}))*)'
RE_PEER_EXPR = fr'(peer\s*=\s*\(\s*(({ip_cond % "ip_peer"})|({network_port % "port_peer"}))+\s*\))'


RE_NETWORK_DOMAIN = '(' + '|'.join(network_domain_keywords) + ')'
RE_NETWORK_TYPE = '(' + '|'.join(network_type_keywords) + ')'
RE_NETWORK_PROTOCOL = '(' + '|'.join(network_protocol_keywords) + ')'

RE_NETWORK_DETAILS = re.compile(
    r'^\s*'
    + r'(\s*' + network_accesses + r')?\s*'
    + '(?P<domain>' + RE_NETWORK_DOMAIN + r')?\s*'  # optional domain
    + r'(\s+(?P<type_or_protocol>' + RE_NETWORK_TYPE + '|' + RE_NETWORK_PROTOCOL + r'))?\s*'  # optional type or protocol
    + '(' + RE_LOCAL_EXPR + r')?\s*'
    + '(' + RE_PEER_EXPR + r')?\s*'
    + r'$')

non_peer_accesses = {'create', 'bind', 'listen', 'shutdown', 'getattr', 'setattr', 'getopt', 'setopt'}


class NetworkRule(BaseRule):
    """Class to handle and store a single network rule"""

    # Nothing external should reference this class, all external users
    # should reference the class field NetworkRule.ALL
    class __NetworkAll:
        pass

    ALL = __NetworkAll

    rule_name = 'network'
    _match_re = RE_PROFILE_NETWORK

    def __init__(self, accesses, domain, type_or_protocol, local_expr, peer_expr, audit=False, deny=False,
                 allow_keyword=False, comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        if type(local_expr) is tuple:
            if accesses is None:
                accesses = self.ALL
            else:
                accesses = accesses.split()
            local_expr = tuple_to_dict(local_expr, ['ip', 'port'])
            peer_expr = tuple_to_dict(peer_expr, ['ip', 'port'])

        self.accesses, self.all_accesses, unknown_items = check_and_split_list(accesses, access_flags, self.ALL,  type(self).__name__, 'accesses')

        if unknown_items:
            raise AppArmorException(f'Invalid access in Network rule: {unknown_items}')

        self.local_expr = check_dict_keys(local_expr, {'ip', 'port'}, self.ALL)
        self.peer_expr = check_dict_keys(peer_expr, {'ip', 'port'}, self.ALL)

        if self.local_expr != self.ALL and 'port' in self.local_expr and int(self.local_expr['port']) > 65535:
            raise AppArmorException(f'Invalid port: {self.local_expr["port"]}')
        if self.peer_expr != self.ALL and 'port' in self.peer_expr and int(self.peer_expr['port']) > 65535:
            raise AppArmorException(f'Invalid remote port: {self.peer_expr["port"]}')

        if self.local_expr != self.ALL and 'ip' in self.local_expr and not is_valid_ip(self.local_expr['ip']):
            raise AppArmorException(f'Invalid ip: {self.local_expr["ip"]}')
        if self.peer_expr != self.ALL and 'ip' in self.peer_expr and not is_valid_ip(self.peer_expr['ip']):
            raise AppArmorException(f'Invalid ip: {self.peer_expr["ip"]}')

        if not self.all_accesses and self.peer_expr != self.ALL and self.accesses & non_peer_accesses:
            raise AppArmorException('Cannot use a peer_expr and an access in the set (%s) simultaneously' % ', '.join(non_peer_accesses))

        self.domain = None
        self.all_domains = False
        if domain == self.ALL:
            self.all_domains = True
        elif isinstance(domain, str):
            if domain in network_domain_keywords:
                self.domain = domain

                if not self.domain.startswith('inet') and (self.local_expr != self.ALL or self.peer_expr != self.ALL):
                    raise AppArmorException('Cannot use a local expression or a peer expression for non-inet domains')
            else:
                raise AppArmorBug('Passed unknown domain to %s: %s' % (type(self).__name__, domain))
        else:
            raise AppArmorBug('Passed unknown object to %s: %s' % (type(self).__name__, str(domain)))

        self.type_or_protocol = None
        self.all_type_or_protocols = False
        if type_or_protocol == self.ALL:
            self.all_type_or_protocols = True
        elif isinstance(type_or_protocol, str):
            if type_or_protocol in network_protocol_keywords:
                self.type_or_protocol = type_or_protocol
            elif type_or_protocol in network_type_keywords:
                self.type_or_protocol = type_or_protocol
            else:
                raise AppArmorBug('Passed unknown type_or_protocol to %s: %s' % (type(self).__name__, type_or_protocol))
        else:
            raise AppArmorBug('Passed unknown object to %s: %s' % (type(self).__name__, str(type_or_protocol)))

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

        if rule_details:
            details = RE_NETWORK_DETAILS.search(rule_details)
            if not details:
                raise AppArmorException(_("Invalid or unknown keywords in 'network %s'" % rule_details))

            r = details.groupdict()

            domain = r['domain'] or cls.ALL
            type_or_protocol = r['type_or_protocol'] or cls.ALL

            if r['accesses']:
                accesses = strip_parenthesis(r['accesses']).replace(',', ' ').split()
            else:
                accesses = cls.ALL

            local_expr = initialize_cond_dict(r, ['ip', 'port'], '', cls.ALL)
            peer_expr = initialize_cond_dict(r, ['ip', 'port'], '_peer', cls.ALL)

        else:
            accesses = cls.ALL
            domain = cls.ALL
            type_or_protocol = cls.ALL
            local_expr = cls.ALL
            peer_expr = cls.ALL

        return cls(accesses, domain, type_or_protocol, local_expr, peer_expr,
                   audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment, priority=priority)

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        space = '  ' * depth

        accesses = ' (%s)' % (', '.join(sorted(self.accesses))) if not self.all_accesses else ''

        if self.all_domains:
            domain = ''
        elif self.domain:
            domain = ' %s' % self.domain
        else:
            raise AppArmorBug('Empty domain in network rule')

        if self.all_type_or_protocols:
            type_or_protocol = ''
        elif self.type_or_protocol:
            type_or_protocol = ' %s' % self.type_or_protocol
        else:
            raise AppArmorBug('Empty type or protocol in network rule')

        local_expr = print_dict_values(self.local_expr, self.ALL)
        peer_expr = print_dict_values(self.peer_expr, self.ALL, 'peer')

        return ('%s%snetwork%s%s%s%s%s,%s' % (space, self.modifiers_str(), accesses, domain, type_or_protocol, local_expr, peer_expr, self.comment))

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""

        if not self._is_covered_list(self.accesses, self.all_accesses, other_rule.accesses, other_rule.all_accesses, 'accesses'):
            return False

        if not self._is_covered_plain(self.domain, self.all_domains, other_rule.domain, other_rule.all_domains, 'domain'):
            return False

        if not self._is_covered_plain(self.type_or_protocol, self.all_type_or_protocols, other_rule.type_or_protocol, other_rule.all_type_or_protocols, 'type or protocol'):
            return False

        if not self._is_covered_dict(self.local_expr, other_rule.local_expr):
            return False
        if not self._is_covered_dict(self.peer_expr, other_rule.peer_expr):
            return False

        # still here? -> then it is covered
        return True

    def _is_covered_dict(self, d, other):

        if d is self.ALL:
            return True
        elif other is self.ALL:
            return False

        for it in other:
            if it not in d:
                continue  # No constraints on this item.
            else:
                if not self._is_covered_plain(d[it], False, other[it], False, it):
                    return False

        return True

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific variables are equal"""

        if self.accesses != other_rule.accesses:
            return False

        if (self.domain != other_rule.domain
                or self.all_domains != other_rule.all_domains):
            return False

        if (self.type_or_protocol != other_rule.type_or_protocol
                or self.all_type_or_protocols != other_rule.all_type_or_protocols):
            return False

        if self.local_expr != other_rule.local_expr:
            return False

        if self.peer_expr != other_rule.peer_expr:
            return False

        return True

    def _logprof_header_localvars(self):
        accesses = logprof_value_or_all(self.accesses, self.all_accesses)
        family    = logprof_value_or_all(self.domain,           self.all_domains)  # noqa: E221
        sock_type = logprof_value_or_all(self.type_or_protocol, self.all_type_or_protocols)

        local_expr = logprof_value_or_all(self.local_expr, self.local_expr == self.ALL)
        peer_expr = logprof_value_or_all(self.peer_expr, self.peer_expr == self.ALL)

        return (
            _('Accesses'), accesses,
            _('Network Family'), family,
            _('Socket Type'), sock_type,
            _('Local'), local_expr,
            _('Peer'), peer_expr,
        )

    @staticmethod
    def hashlog_from_event(hl, ev):
        local = (ev['addr'], ev['port'])
        peer = (ev['peer_addr'], ev['remote_port'])
        hl[ev['accesses']][ev['family']][ev['sock_type']][ev['protocol']][local][peer] = True

    @classmethod
    def from_hashlog(cls, hl):
        for access, family, sock_type, protocol, local_event, peer_event in BaseRule.generate_rules_from_hashlog(hl, 6):
            if access and set(access.split()) & non_peer_accesses:
                peer_event = (None, None)
            yield cls(access, family, sock_type, local_event, peer_event, log_event=True)


class NetworkRuleset(BaseRuleset):
    """Class to handle and store a collection of network rules"""

    def get_glob(self, path_or_rule):
        """Return the next possible glob. For network rules, that's "network DOMAIN," or "network," (all network)"""
        # XXX return 'network DOMAIN,' if 'network DOMAIN TYPE_OR_PROTOCOL' was given
        return 'network,'


def is_valid_ip(ip):
    if ip == 'none':
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
