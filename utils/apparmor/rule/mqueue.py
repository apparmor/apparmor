# ----------------------------------------------------------------------
#    Copyright (C) 2022 Canonical, Ltd.
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

from apparmor.regex import RE_PROFILE_MQUEUE, RE_PROFILE_NAME
from apparmor.common import AppArmorBug, AppArmorException
from apparmor.rule import BaseRule, BaseRuleset, check_and_split_list, logprof_value_or_all, parse_modifiers, quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


access_keywords_read = ['r', 'read']
access_keywords_write = ['w', 'write']
access_keywords_rw = ['rw', 'wr']
access_keywords_other = ['create', 'open', 'delete', 'getattr', 'setattr']
access_keywords = access_keywords_read + access_keywords_write + access_keywords_rw + access_keywords_other

joint_access_keyword = r'\s*(' + '|'.join(access_keywords) + r')\s*'
RE_ACCESS_KEYWORDS = (joint_access_keyword  # one of the access_keyword or
                      + '|'                                            # or
                      + r'\(' + joint_access_keyword + '(' + r'(\s|,)+' + joint_access_keyword + ')*' + r'\)'  # one or more access_keyword in (...)
                      )

RE_MQUEUE_NAME = r'(?P<%s>(/\S*|\d*))'  # / + string for posix, or digits for sys
RE_MQUEUE_TYPE = r'(?P<%s>(sysv|posix))'  # type can be sysv or posix

RE_MQUEUE_DETAILS = re.compile(
    '^'
    + r'(\s+(?P<access>' + RE_ACCESS_KEYWORDS + '))?'  # optional access keyword(s)
    + r'(\s+(type=' + RE_MQUEUE_TYPE % 'mqueue_type' + '))?'  # optional type
    + r'(\s+(label=' + RE_PROFILE_NAME % 'label' + '))?'  # optional label
    + r'(\s+(' + RE_MQUEUE_NAME % 'mqueue_name' + '))?'  # optional mqueue name
    + r'\s*$')


class MessageQueueRule(BaseRule):
    '''Class to handle and store a single mqueue rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field MessageQueueRule.ALL
    class __MessageQueueAll(object):
        pass

    ALL = __MessageQueueAll

    rule_name = 'mqueue'
    _match_re = RE_PROFILE_MQUEUE

    def __init__(self, access, mqueue_type, label, mqueue_name,
                 audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event,
                         priority=priority)

        self.access, self.all_access, unknown_items = check_and_split_list(access, access_keywords, self.ALL, type(self).__name__, 'access')
        if unknown_items:
            raise AppArmorException(_('Passed unknown access keyword to %s: %s') % (type(self).__name__, ' '.join(unknown_items)))

        self.label, self.all_labels = self._aare_or_all(label, 'label', is_path=False, log_event=log_event)
        self.mqueue_type, self.all_mqueue_types = self._aare_or_all(mqueue_type, 'type', is_path=False, log_event=log_event)
        if mqueue_name is not None:
            self.mqueue_name, self.all_mqueue_names = self._aare_or_all(mqueue_name, 'mqueue_name', is_path=False, log_event=log_event)
        else:
            self.mqueue_name, self.all_mqueue_names = None, self.ALL
        self.validate_mqueue_name()

    def validate_mqueue_name(self):
        # The regex checks if it starts with / or if it's numeric
        if self.all_mqueue_types or self.all_mqueue_names:
            return

        if self.mqueue_type.regex == 'sysv' and not self.mqueue_name.regex.isnumeric():
            raise AppArmorException(_('Queue name for SYSV must be a positive integer'))
        elif self.mqueue_type.regex == 'posix' and not self.mqueue_name.regex.startswith('/'):
            raise AppArmorException(_('Queue name for POSIX must begin with /'))

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

        if rule_details:
            details = RE_MQUEUE_DETAILS.search(rule_details)
            if not details:
                raise AppArmorException(_("Invalid or unknown keywords in 'mqueue %s" % rule_details))

            if details.group('access'):
                access = details.group('access')
                if access.startswith('(') and access.endswith(')'):
                    access = access[1:-1]
                access = access.replace(',', ' ').split()  # split by ',' or whitespace
            else:
                access = cls.ALL

            if details.group('mqueue_type'):
                mqueue_type = details.group('mqueue_type')
            else:
                mqueue_type = cls.ALL

            if details.group('label'):
                label = details.group('label')
            else:
                label = cls.ALL

            if details.group('mqueue_name'):
                mqueue_name = details.group('mqueue_name')
            else:
                mqueue_name = cls.ALL
        else:
            access = cls.ALL
            mqueue_type = cls.ALL
            label = cls.ALL
            mqueue_name = cls.ALL

        return cls(access, mqueue_type, label, mqueue_name,
                   audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment, priority=priority)

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
            raise AppArmorBug('Empty access in mqueue rule')

        if self.all_mqueue_types:
            mqueue_type = ''
        elif self.mqueue_type:
            mqueue_type = ' type=%s' % self.mqueue_type.regex
        else:
            raise AppArmorBug('Empty type in mqueue rule')

        if self.all_labels:
            label = ''
        elif self.label:
            label = ' label=%s' % quote_if_needed(self.label.regex)
        else:
            raise AppArmorBug('Empty label in mqueue rule')

        if self.all_mqueue_names:
            mqueue_name = ''
        elif self.mqueue_name:
            mqueue_name = ' %s' % self.mqueue_name.regex
        else:
            raise AppArmorBug('Empty mqueue_name in mqueue rule')

        return '%s%smqueue%s%s%s%s,%s' % (space, self.modifiers_str(), access, mqueue_type, label, mqueue_name, self.comment)

    def _is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not self._is_covered_list(self.access, self.all_access, other_rule.access, other_rule.all_access, 'access'):
            return False

        if not self._is_covered_aare(self.mqueue_type, self.all_mqueue_types, other_rule.mqueue_type, other_rule.all_mqueue_types, 'mqueue_type'):
            return False

        if not self._is_covered_aare(self.label, self.all_labels, other_rule.label, other_rule.all_labels, 'label'):
            return False

        if not self._is_covered_aare(self.mqueue_name, self.all_mqueue_names, other_rule.mqueue_name, other_rule.all_mqueue_names, 'mqueue_name'):
            return False

        # still here? -> then it is covered
        return True

    def _is_equal_localvars(self, other_rule, strict):
        '''compare if rule-specific variables are equal'''

        if (self.access != other_rule.access or self.all_access != other_rule.all_access):
            return False

        if not self._is_equal_aare(self.mqueue_type, self.all_mqueue_types, other_rule.mqueue_type, other_rule.all_mqueue_types, 'mqueue_type'):
            return False

        if not self._is_equal_aare(self.label, self.all_labels, other_rule.label, other_rule.all_labels, 'label'):
            return False

        if not self._is_equal_aare(self.mqueue_name, self.all_mqueue_names, other_rule.mqueue_name, other_rule.all_mqueue_names, 'mqueue_name'):
            return False

        return True

    def _logprof_header_localvars(self):
        access = logprof_value_or_all(self.access, self.all_access)
        mqueue_type = logprof_value_or_all(self.mqueue_type, self.all_mqueue_types)
        label = logprof_value_or_all(self.label, self.all_labels)
        mqueue_name = logprof_value_or_all(self.mqueue_name, self.all_mqueue_names)

        return (
            _('Access mode'), access,
            _('Type'), mqueue_type,
            _('Label'), label,
            _('Message queue name'), mqueue_name
        )

    @staticmethod
    def hashlog_from_event(hl, ev):
        mqueue_type = ev['class'].partition('_')[0]
        hl[ev['denied_mask']][mqueue_type][ev['name']] = True

    @classmethod
    def from_hashlog(cls, hl):
        for access, mqueue_type, mqueue_name in BaseRule.generate_rules_from_hashlog(hl, 3):
            yield cls(access, mqueue_type, MessageQueueRule.ALL, mqueue_name, log_event=True)


class MessageQueueRuleset(BaseRuleset):
    '''Class to handle and store a collection of mqueue rules'''

    def get_glob(self, path_or_rule):
        '''Return the next possible glob. For mqueue rules, that means removing access, label or mqueue_name'''
        # XXX only remove one part, not all
        return 'mqueue,'
