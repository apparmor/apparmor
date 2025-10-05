# ----------------------------------------------------------------------
#    Copyright (C) 2024 Christian Boltz
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

from apparmor.aare import AARE
from apparmor.regex import RE_PROFILE_PIVOT_ROOT, RE_PROFILE_NAME, RE_PROFILE_PATH_OR_VAR, strip_quotes
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers, logprof_value_or_all, quote_if_needed

from apparmor.translations import init_translation

_ = init_translation()

RE_PIVOT_ROOT_DETAILS = re.compile(
    r'^\s*'
    + r'(\s+oldroot=' + RE_PROFILE_PATH_OR_VAR % 'oldroot'  + r')?'  # noqa: E221
    + r'(\s+'         + RE_PROFILE_PATH_OR_VAR % 'newroot'  + r')?'  # noqa: E221
    + r'(\s+->\s+'    + RE_PROFILE_NAME % 'profile_name'    + r')?'  # noqa: E221
    + r'\s*$'
)


class PivotRootRule(BaseRule):
    '''Class to handle and store a single pivot_root rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field PivotRootRule.ALL
    class __PivotRootAll(object):
        pass

    ALL = __PivotRootAll

    rule_name = 'pivot_root'
    _match_re = RE_PROFILE_PIVOT_ROOT

#            PIVOT ROOT RULE = [ QUALIFIERS ] pivot_root [ oldroot=OLD PUT FILEGLOB ] [ NEW ROOT FILEGLOB ] [ ’->’ PROFILE NAME ]
    def __init__(self, oldroot, newroot, profile_name, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event, priority=priority)

        self.oldroot,      self.all_oldroots        = self._aare_or_all(oldroot,        'oldroot',        True,  log_event)  # noqa: E221
        self.newroot,      self.all_newroots        = self._aare_or_all(newroot,        'newroot',        True,  log_event)  # noqa: E221
        self.profile_name, self.all_profile_names   = self._aare_or_all(profile_name,   'profile_name',   False, log_event)  # noqa: E221

        self.can_glob = not self.all_newroots
        self.can_glob_ext = False
        self.can_edit = not self.all_newroots

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

            parsed = RE_PIVOT_ROOT_DETAILS.search(rule_details)

            if not parsed:
                raise AppArmorException('Cannot parse pivot_root rule ' + raw_rule)

            r = parsed.groupdict()

            if r['oldroot']:
                oldroot = strip_quotes(r['oldroot'])
            else:
                oldroot = cls.ALL

            if r['newroot']:
                newroot = strip_quotes(r['newroot'])
            else:
                newroot = cls.ALL

            if r['profile_name']:
                profile_name = strip_quotes(r['profile_name'])
            else:
                profile_name = cls.ALL

        else:
            oldroot = cls.ALL
            newroot = cls.ALL
            profile_name = cls.ALL

        return cls(oldroot=oldroot, newroot=newroot, profile_name=profile_name,
                   audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment, priority=priority)

    def get_clean(self, depth=0):
        space = '  ' * depth

        if self.all_oldroots:
            oldroot = ''
        elif self.oldroot:
            oldroot = ' oldroot=' + quote_if_needed(self.oldroot.regex)
        else:
            raise AppArmorBug('Empty oldroot in pivot_root rule')

        if self.all_newroots:
            newroot = ''
        elif self.newroot:
            newroot = ' ' + quote_if_needed(self.newroot.regex)
        else:
            raise AppArmorBug('Empty newroot in pivot_root rule')

        if self.all_profile_names:
            profile_name = ''
        elif self.profile_name:
            profile_name = ' -> ' + quote_if_needed(self.profile_name.regex)
        else:
            raise AppArmorBug('Empty profile_name in pivot_root rule')

        return f'{space}{self.modifiers_str()}pivot_root{oldroot}{newroot}{profile_name},{self.comment}'

    def _is_covered_localvars(self, other_rule):
        if not self._is_covered_aare(self.oldroot, self.all_oldroots, other_rule.oldroot, other_rule.all_oldroots, 'oldroot'):
            return False

        if not self._is_covered_aare(self.newroot, self.all_newroots, other_rule.newroot, other_rule.all_newroots, 'newroot'):
            return False

        if not self._is_covered_aare(self.profile_name, self.all_profile_names, other_rule.profile_name, other_rule.all_profile_names, 'profile_name'):
            return False

        # still here? -> then it is covered
        return True

    def _is_equal_localvars(self, other_rule, strict):
        if not self._is_equal_aare(self.oldroot, self.all_oldroots, other_rule.oldroot, other_rule.all_oldroots, 'oldroot'):
            return False

        if not self._is_equal_aare(self.newroot, self.all_newroots, other_rule.newroot, other_rule.all_newroots, 'newroot'):
            return False

        if not self._is_equal_aare(self.profile_name, self.all_profile_names, other_rule.profile_name, other_rule.all_profile_names, 'profile_name'):
            return False

        return True

    def glob(self):
        '''Change newroot path to next possible glob'''
        if self.all_newroots:
            return

        self.newroot = self.newroot.glob_path()
        self.raw_rule = None

    def edit_header(self):
        if self.all_newroots:
            raise AppArmorBug('Attemp to edit pivot_root rule without newroot limitations')

        return (_('Enter new newroot: '), self.newroot.regex)

    def validate_edit(self, newpath):
        if self.all_newroots:
            raise AppArmorBug('Attemp to edit pivot_root rule without newroot limitations')

        newpath = AARE(newpath, True)  # might raise AppArmorException if the new path doesn't start with / or a variable
        return newpath.match(self.newroot)

    def store_edit(self, newpath):
        if self.all_newroots:
            raise AppArmorBug('Attemp to edit pivot_root rule without newroot limitations')

        self.newroot = AARE(newpath, True)  # might raise AppArmorException if the new path doesn't start with / or a variable
        self.raw_rule = None

    def _logprof_header_localvars(self):

        oldroot = logprof_value_or_all(self.oldroot, self.all_oldroots)
        newroot = logprof_value_or_all(self.newroot, self.all_newroots)
        profile_name = logprof_value_or_all(self.profile_name, self.all_profile_names)

        return (
            _('Old root'), oldroot,
            _('New root'), newroot,
            _('Target profile'), profile_name,
        )

    @staticmethod
    def hashlog_from_event(hl, ev):
        # TODO: can the log contain the target profile?
        hl[ev['src_name']][ev['name']] = True

    @classmethod
    def from_hashlog(cls, hl):
        for oldroot, newroot in BaseRule.generate_rules_from_hashlog(hl, 2):
            yield cls(oldroot, newroot, cls.ALL, log_event=True)


class PivotRootRuleset(BaseRuleset):
    '''Class to handle and store a collection of pivot_root rules'''
