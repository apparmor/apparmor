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

import re

from apparmor.regex import RE_PROFILE_IO_URING, RE_PROFILE_NAME
from apparmor.common import AppArmorBug, AppArmorException
from apparmor.rule import BaseRule, BaseRuleset, check_and_split_list, logprof_value_or_all, parse_modifiers, quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


access_keywords = ['sqpoll', 'override_creds']

joint_access_keyword = r'\s*(' + '|'.join(access_keywords) + r')\s*'
RE_ACCESS_KEYWORDS = (joint_access_keyword  # one of the access_keyword or
                      + '|'                                           # or
                      + r'\(' + joint_access_keyword + '(' + r'(\s|,)+' + joint_access_keyword + ')*' + r'\)'  # one or more access_keyword in (...)
                      )
RE_IO_URING_DETAILS = re.compile(
    r'^'
    + r'(\s+(?P<access>' + RE_ACCESS_KEYWORDS + r'))?'  # optional access keyword(s)
    + r'(\s+(label\s*=\s*' + RE_PROFILE_NAME % 'label' + r'))?'  # optional label
    + r'\s*$')


class IOUringRule(BaseRule):
    '''Class to handle and store a single io_uring rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field IOUringRule.ALL
    class __IOUringAll(object):
        pass

    ALL = __IOUringAll

    rule_name = 'io_uring'
    _match_re = RE_PROFILE_IO_URING

    def __init__(self, access, label, audit=False, deny=False,
                 allow_keyword=False, comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event, priority=priority)

        self.access, self.all_access, unknown_items = check_and_split_list(access, access_keywords, self.ALL, type(self).__name__, 'access')
        if unknown_items:
            raise AppArmorException(_('Passed unknown access keyword to %s: %s') % (type(self).__name__, ' '.join(unknown_items)))

        self.label, self.all_labels = self._aare_or_all(label, 'label', is_path=False, log_event=log_event)

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

        if rule_details:
            details = RE_IO_URING_DETAILS.search(rule_details)
            if not details:
                raise AppArmorException(_("Invalid or unknown keywords in 'io_uring %s" % rule_details))

            if details.group('access'):
                access = details.group('access')
                if access.startswith('(') and access.endswith(')'):
                    access = access[1:-1]
                access = access.replace(',', ' ').split()  # split by ',' or whitespace
            else:
                access = cls.ALL

            if details.group('label'):
                label = details.group('label')
            else:
                label = cls.ALL
        else:
            access = cls.ALL
            label = cls.ALL

        return cls(access, label, audit=audit, deny=deny,
                   allow_keyword=allow_keyword, comment=comment, priority=priority)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        if self.all_access:
            access = ''
        elif len(self.access) == 1:
            access = ' %s' % ' '.join(self.access)
        elif self.access:
            access = ' (%s)' % ' '.join(sorted(self.access))
        else:
            raise AppArmorBug('Empty access in io_uring rule')

        if self.all_labels:
            label = ''
        elif self.label:
            label = ' label=%s' % quote_if_needed(self.label.regex)
        else:
            raise AppArmorBug('Empty label in io_uring rule')

        return '%s%sio_uring%s%s,%s' % (space, self.modifiers_str(), access, label, self.comment)

    def _is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not self._is_covered_list(self.access, self.all_access, other_rule.access, other_rule.all_access, 'access'):
            return False

        if not self._is_covered_aare(self.label, self.all_labels, other_rule.label, other_rule.all_labels, 'label'):
            return False

        # still here? -> then it is covered
        return True

    def _is_equal_localvars(self, other_rule, strict):
        '''compare if rule-specific variables are equal'''

        if (self.access != other_rule.access or self.all_access != other_rule.all_access):
            return False

        if not self._is_equal_aare(self.label, self.all_labels, other_rule.label, other_rule.all_labels, 'label'):
            return False

        return True

    def _logprof_header_localvars(self):
        access = logprof_value_or_all(self.access, self.all_access)
        label = logprof_value_or_all(self.label, self.all_labels)

        return (
            _('Access mode'), access,
            _('Label'), label,
        )

    @staticmethod
    def hashlog_from_event(hl, e):
        hl[e['denied_mask']][e['peer_profile']] = True

    @classmethod
    def from_hashlog(cls, hl):
        for access, label in BaseRule.generate_rules_from_hashlog(hl, 2):
            if not label:
                label = IOUringRule.ALL
            yield cls(access, label, log_event=True)


class IOUringRuleset(BaseRuleset):
    '''Class to handle and store a collection of io_uring rules'''

    def get_glob(self, path_or_rule):
        '''Return the next possible glob. For io_uring rules, that means removing access and label'''
        # XXX only remove one part, not all
        return 'io_uring,'
