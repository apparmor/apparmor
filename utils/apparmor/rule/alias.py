# ----------------------------------------------------------------------
#    Copyright (C) 2020 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.regex import RE_PROFILE_ALIAS, strip_quotes
from apparmor.rule import BaseRule, BaseRuleset, parse_comment, quote_if_needed
from apparmor.translations import init_translation

_ = init_translation()


class AliasRule(BaseRule):
    """Class to handle and store a single alias rule"""

    rule_name = 'alias'
    _match_re = RE_PROFILE_ALIAS

    def __init__(self, orig_path, target, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        # aliases don't support priority, allow keyword, audit or deny
        self.ensure_modifiers_not_supported()

        if not isinstance(orig_path, str):
            raise AppArmorBug('Passed unknown type for orig_path to %s: %s' % (self.__class__.__name__, orig_path))
        if not orig_path:
            raise AppArmorException('Passed empty orig_path to %s: %s' % (self.__class__.__name__, orig_path))
        if not orig_path.startswith('/'):
            raise AppArmorException("Alias path doesn't start with '/'")

        if not isinstance(target, str):
            raise AppArmorBug('Passed unknown type for target to %s: %s' % (self.__class__.__name__, target))
        if not target:
            raise AppArmorException('Passed empty target to %s: %s' % (self.__class__.__name__, target))
        if not target.startswith('/'):
            raise AppArmorException("Alias target doesn't start with '/'")

        self.orig_path = orig_path
        self.target = target

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        comment = parse_comment(matches)

        orig_path = strip_quotes(matches.group('orig_path').strip())
        target = strip_quotes(matches.group('target').strip())

        return cls(orig_path, target,
                   audit=False, deny=False, allow_keyword=False, comment=comment, priority=None)

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        space = '  ' * depth

        return '%salias %s -> %s,' % (space, quote_if_needed(self.orig_path), quote_if_needed(self.target))

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""

        # the only way aliases can be covered are exact duplicates
        return self._is_equal_localvars(other_rule, False)

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific aliases are equal"""

        if self.orig_path != other_rule.orig_path:
            return False

        if self.target != other_rule.target:
            return False

        return True

    def _logprof_header_localvars(self):
        return _('Alias'), '%s -> %s' % (self.orig_path, self.target)


class AliasRuleset(BaseRuleset):
    """Class to handle and store a collection of alias rules"""
