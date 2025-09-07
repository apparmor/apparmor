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
import re

from apparmor.common import AppArmorException

from apparmor.regex import RE_PROFILE_UNIX, strip_parenthesis
from apparmor.rule import (BaseRule, BaseRuleset, parse_modifiers, logprof_value_or_all, check_and_split_list,
                           check_dict_keys, tuple_to_dict, print_dict_values, initialize_cond_dict, AARE)

from apparmor.translations import init_translation

_ = init_translation()

_aare = r'([][!/\\\,().*?@{}\w^-]+)'
_quoted_aare = r'"([][!/\\\,().*?@{}\w\s^-]+)"'
aare = rf'({_aare}|{_quoted_aare}|\(({_aare}|{_quoted_aare})\))'
aare_set = rf'({_aare}|{_quoted_aare}|\(({_aare}|{_quoted_aare})+\))'


def re_cond_set(x, y=None):
    return rf'\s*({x}\s*=\s*(?P<{y or x}_cond_set>{aare_set}))\s*'


def re_cond(x, y=None):
    return rf'\s*({x}\s*=\s*(?P<{y or x}_cond>{aare}))\s*'


access_flags = [
    'create', 'bind', 'listen', 'accept', 'connect', 'shutdown', 'getattr', 'setattr', 'getopt', 'setopt', 'send',
    'receive', 'r', 'w', 'rw'
]
join_access = r'(\s*(' + '|'.join(access_flags) + '))'
sep = r'\s*[\s,]\s*'

unix_accesses = rf'\s*(\s*(?P<accesses>\({join_access}({sep}{join_access})*\s*\)|{join_access}))?'
unix_rule_conds = rf'(\s*({re_cond_set("type")}|{re_cond_set("protocol")}))*'
unix_local_expr = rf'(\s*({re_cond("addr")}|{re_cond("label")}|{re_cond("attr")}|{re_cond("opt")}))*'
unix_peer_expr = rf'peer\s*=\s*\((\s*({re_cond("addr", "addr_peer")}|{re_cond("label", "label_peer")})(\s*,)?)*\)'

RE_UNIX_DETAILS = re.compile(rf'^(\s*{unix_accesses})?(\s*{unix_rule_conds})?(\s*{unix_local_expr})?(\s*{unix_peer_expr})?\s*$')


class UnixRule(BaseRule):
    '''Class to handle and store a single unix rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field UnixRule.ALL
    class __UnixAll(object):
        pass

    ALL = __UnixAll

    rule_name = 'unix'
    _match_re = RE_PROFILE_UNIX

    def __init__(self, accesses, rule_conds, local_expr, peer_expr, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event,
                         priority=priority)

        if type(rule_conds) is tuple:  # This comes from the logparser, we convert it to dicts
            accesses = strip_parenthesis(accesses).replace(',', ' ').split()
            rule_conds = tuple_to_dict(rule_conds, ['type', 'protocol'])
            local_expr = tuple_to_dict(local_expr, ['addr', 'label', 'attr', 'opt'])
            peer_expr = tuple_to_dict(peer_expr, ['addr', 'label'])

        self.accesses, self.all_accesses, unknown_items = check_and_split_list(accesses, access_flags, self.ALL,  type(self).__name__, 'accesses')

        if unknown_items:
            raise AppArmorException(f'Invalid access in Unix rule: {unknown_items}')

        self.rule_conds = check_dict_keys(rule_conds, {'type', 'protocol'}, self.ALL)
        self.local_expr = check_dict_keys(local_expr, {'addr', 'label', 'attr', 'opt'}, self.ALL)
        self.peer_expr = check_dict_keys(peer_expr, {'addr', 'label'}, self.ALL)

        if not self.all_accesses and self.peer_expr != self.ALL and self.accesses & {'create', 'bind', 'listen', 'shutdown', 'getattr', 'setattr', 'getopt', 'setopt'}:
            raise AppArmorException('Cannot use a peer_expr and an access in {create, bind, listen, shutdown, getattr, setattr, getopt, setopt} simultaneously')

        self.can_glob = not (self.accesses or self.rule_conds or self.local_expr or self.peer_expr)

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

            parsed = RE_UNIX_DETAILS.search(rule_details)

            if not parsed:
                raise AppArmorException('Cannot parse unix rule ' + raw_rule)

            r = parsed.groupdict()

            if r['accesses']:
                accesses = strip_parenthesis(r['accesses']).replace(',', ' ').split()
            else:
                accesses = cls.ALL

            rule_conds = initialize_cond_dict(r, ['type', 'protocol'], '_cond_set', cls.ALL)
            local_expr = initialize_cond_dict(r, ['addr', 'label', 'attr', 'opt'], '_cond', cls.ALL)
            peer_expr = initialize_cond_dict(r, ['addr', 'label'], '_peer_cond', cls.ALL)

        else:
            accesses = cls.ALL
            rule_conds = cls.ALL
            local_expr = cls.ALL
            peer_expr = cls.ALL

        return cls(accesses=accesses, rule_conds=rule_conds, local_expr=local_expr, peer_expr=peer_expr,
                   audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment, priority=priority)

    def get_clean(self, depth=0):
        space = '  ' * depth

        accesses = ' (%s)' % (', '.join(sorted(self.accesses))) if not self.all_accesses else ''
        rule_conds = print_dict_values(self.rule_conds, self.ALL)
        local_expr = print_dict_values(self.local_expr, self.ALL)
        peer_expr = print_dict_values(self.peer_expr, self.ALL, 'peer')
        return f'{space}{self.modifiers_str()}unix{accesses}{rule_conds}{local_expr}{peer_expr},{self.comment}'

    def _is_covered_localvars(self, other_rule):
        if not self._is_covered_list(self.accesses, self.all_accesses, other_rule.accesses, other_rule.all_accesses, 'accesses'):
            return False
        if not self._is_covered_dict(self.rule_conds, other_rule.rule_conds):
            return False
        if not self._is_covered_dict(self.local_expr, other_rule.local_expr):
            return False
        if not self._is_covered_dict(self.peer_expr, other_rule.peer_expr):
            return False
        return True

    def _is_equal_localvars(self, other_rule, strict):
        if self.accesses != other_rule.accesses:
            return False
        if self.rule_conds != other_rule.rule_conds:
            return False
        if self.local_expr != other_rule.local_expr:
            return False
        if self.peer_expr != other_rule.peer_expr:
            return False

        return True

    @staticmethod
    def hashlog_from_event(hl, e):
        rule = (e['sock_type'], None)  # Protocol is not supported yet.
        local = (e['addr'], None, e['attr'], None)
        peer = (e['peer_addr'], e['peer_profile'])

        hl[e['denied_mask']][rule][local][peer] = True

    @classmethod
    def from_hashlog(cls, hl):
        for denied_mask, rule, local, peer in BaseRule.generate_rules_from_hashlog(hl, 4):
            yield cls(denied_mask, rule, local, peer)

    def glob(self):
        '''Change path to next possible glob'''
        if self.peer_expr != self.ALL:
            self.peer_expr = self.ALL
        elif self.local_expr != self.ALL:
            self.local_expr = self.ALL
        elif self.rule_conds != self.ALL:
            self.rule_conds = self.ALL
        else:  # not self.all_accesses:
            self.accesses = None
            self.all_accesses = True

        self.raw_rule = None

    def _logprof_header_localvars(self):

        accesses = logprof_value_or_all(self.accesses, self.all_accesses)
        rule_conds = logprof_value_or_all(self.rule_conds, self.rule_conds == UnixRule.ALL)
        local_expr = logprof_value_or_all(self.local_expr, self.local_expr == UnixRule.ALL)
        peer_expr = logprof_value_or_all(self.peer_expr, self.peer_expr == UnixRule.ALL)
        return (
            _('Accesses'), accesses,
            _('Rule'), rule_conds,
            _('Local'), local_expr,
            _('Peer'), peer_expr,
        )

    def _is_covered_dict(self, d, other):

        if d is self.ALL:
            return True
        elif other is self.ALL:
            return False

        for it in other:
            if it not in d:
                continue  # No constraints on this item.
            else:
                if not self._is_covered_aare(AARE(d[it], False), False, AARE(other[it], False), False, it):
                    return False

        return True


class UnixRuleset(BaseRuleset):
    '''Class to handle and store a collection of Unix rules'''
