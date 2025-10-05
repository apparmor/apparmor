# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
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
from apparmor.regex import RE_PROFILE_BOOLEAN
from apparmor.rule import BaseRule, BaseRuleset, parse_comment
from apparmor.translations import init_translation

_ = init_translation()


class BooleanRule(BaseRule):
    """Class to handle and store a single variable rule"""

    rule_name = 'boolean'
    _match_re = RE_PROFILE_BOOLEAN

    def __init__(self, varname, value, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        # boolean variables don't support priority, allow keyword, audit or deny
        self.ensure_modifiers_not_supported()

        if not isinstance(varname, str):
            raise AppArmorBug('Passed unknown type for boolean variable to %s: %s' % (self.__class__.__name__, varname))
        if not varname.startswith('$'):
            raise AppArmorException("Passed invalid boolean to %s (doesn't start with '$'): %s" % (self.__class__.__name__, varname))

        if not isinstance(value, str):
            raise AppArmorBug('Passed unknown type for value to %s: %s' % (self.__class__.__name__, value))
        if not value:
            raise AppArmorException('Passed empty value to %s: %s' % (self.__class__.__name__, value))

        value = value.lower()
        if value not in ('true', 'false'):
            raise AppArmorException('Passed invalid value to %s: %s' % (self.__class__.__name__, value))

        self.varname = varname
        self.value = value

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        comment = parse_comment(matches)

        varname = matches.group('varname')
        value = matches.group('value')

        return cls(varname, value,
                   audit=False, deny=False, allow_keyword=False, comment=comment, priority=None)

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        space = '  ' * depth

        return '%s%s = %s' % (space, self.varname, self.value)

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""

        if self.varname != other_rule.varname:
            return False

        if not self._is_covered_list(self.value, None, set(other_rule.value), None, 'value'):
            return False

        # still here? -> then it is covered
        return True

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific variables are equal"""

        if self.varname != other_rule.varname:
            return False

        if self.value != other_rule.value:
            return False

        return True

    def _logprof_header_localvars(self):
        return _('Boolean Variable'), self.get_clean()


class BooleanRuleset(BaseRuleset):
    """Class to handle and store a collection of variable rules"""

    def add(self, rule, cleanup=False):
        """Add boolean variable rule object

           If the variable name is already known, raise an exception because re-defining a variable isn't allowed.
        """

        for knownrule in self.rules:
            if rule.varname == knownrule.varname:
                raise AppArmorException(_('Redefining existing variable %(variable)s: %(value)s')
                                        % {'variable': rule.varname, 'value': rule.value})

        super().add(rule, cleanup)
