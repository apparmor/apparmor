# ----------------------------------------------------------------------
#    Copyright (C) 2023 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.regex import RE_PROFILE_ALL
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers
from apparmor.translations import init_translation

_ = init_translation()


class AllRule(BaseRule):
    """Class to handle and store a single all rule"""

    # This class doesn't have any localvars, therefore it doesn't need 'ALL'

    can_glob = False
    rule_name = 'all'
    _match_re = RE_PROFILE_ALL

    def __init__(self, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        # no localvars -> nothing more to do

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        return cls(audit=audit, deny=deny,
                   allow_keyword=allow_keyword,
                   comment=comment, priority=priority)

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        space = '  ' * depth

        return ('%s%sall,%s' % (space, self.modifiers_str(), self.comment))

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""

        # no localvars, so there can't be a difference
        return True

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific variables are equal"""

        # no localvars, so there can't be a difference
        return True

    def severity(self, sev_db):
        # allowing _everything_ is the worst thing you could do, therefore hardcode highest severity
        severity = 10

        return severity

    def _logprof_header_localvars(self):
        return _('All'), _('Allow everything')


class AllRuleset(BaseRuleset):
    """Class to handle and store a collection of all rules"""

    def get_glob(self, path_or_rule):
        # There's nothing to glob in all rules
        raise NotImplementedError
