#
# ----------------------------------------------------------------------
#    Copyright (C) 2026 Canonical, Ltd.
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

from copy import deepcopy

from apparmor.common import AppArmorException
from apparmor.regex import RE_PROFILE_BLOCK_OPEN
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers
from apparmor.rule.conditional import ConditionalBlock
from apparmor.translations import init_translation

_ = init_translation()


class BlockRule(BaseRule):
    """Class to handle and store a single rule block

       The qualifiers apply to every rule the block contains, and are kept on
       the block instead of being written onto those rules, so that a block
       survives a read/write cycle. Use iter_effective_rules() to get the
       contained rules with the qualifiers applied.
    """

    rule_name = 'block'
    _match_re = RE_PROFILE_BLOCK_OPEN

    # the rules inside a block decide which qualifiers it accepts
    supports_owner = True

    def __init__(self, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None, owner=False, prompt=False, other=False):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        if priority is not None:
            raise AppArmorException(_('priority is not allowed on rule blocks'))

        self.prompt = prompt
        self.owner = owner
        self.other = other

        self.profile_data = {}  # {profname: ProfileStorage}, filled by store_profile_data()

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        prompt = bool(matches.group('prompt'))
        owner = (matches.group('owner') or '').strip()  # 'owner', 'other' or ''

        rest = matches.group('rest').strip()
        if rest and rest != '}':  # the body is parsed by parse_rule_block(), not from text
            raise AppArmorException(
                _('The tools only support a rule block with its rules on separate lines: %s') % raw_rule)

        return cls(audit=audit, deny=deny, allow_keyword=allow_keyword, prompt=prompt,
                   owner=owner == 'owner', other=owner == 'other', comment=comment, priority=priority)

    @classmethod
    def create_instance(cls, raw_rule):
        """parse raw_rule and return an instance of this class"""

        rule_obj = super().create_instance(raw_rule)
        rule_obj.raw_rule = None  # a multi-line rule is always written in clean formatting

        return rule_obj

    def store_profile_data(self, profile_data):
        """store the rules of this block (as returned by parse_block())"""

        self.profile_data = profile_data

    def qualifiers_str(self):
        """return the qualifiers of this block as string, including whitespace"""

        # the parser only accepts them in this order
        qualifiers = self.modifiers_str()

        if self.prompt:
            qualifiers += 'prompt '

        if self.owner:
            qualifiers += 'owner '
        elif self.other:
            qualifiers += 'other '

        return qualifiers

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        return '\n'.join(self.get_clean_lines(depth))

    def get_clean_lines(self, depth=0):
        """return the lines of this block (in clean/default formatting)"""

        space = '  ' * depth

        data = ['%s%s{%s' % (space, self.qualifiers_str(), self.comment)]
        data += self.get_body_clean(depth + 1)
        data.append('%s}' % space)

        return data

    def get_body_clean(self, depth=0):
        """return the lines of the rules inside this block, without the braces"""

        data = []

        for profname in self.profile_data:
            data += self.profile_data[profname].get_rules_clean(depth)

        return data

    def iter_rules(self):
        """yield the rules inside this block, including the rules of nested blocks"""

        for prof_storage in self.profile_data.values():
            for ruleset in prof_storage.data.values():
                if not isinstance(ruleset, BaseRuleset):
                    continue

                for rule_obj in ruleset.rules:
                    if isinstance(rule_obj, ConditionalBlock):
                        continue  # the block qualifiers are not applied to its rules

                    yield rule_obj

                    if isinstance(rule_obj, BlockRule):
                        yield from rule_obj.iter_rules()

    def iter_effective_rules(self, wanted_ruletype):
        """yield (ruletype, rule) for the rules of wanted_ruletype inside this
           block, as copies carrying the qualifiers of the enclosing blocks"""

        # rules whose copy can't carry the qualifiers (prompt, other, or owner on anything
        # but a file rule) are left out, so that they never count as known
        if self.prompt or self.other:
            return

        for prof_storage in self.profile_data.values():
            for ruletype, ruleset in prof_storage.data.items():
                if not isinstance(ruleset, BaseRuleset):
                    continue

                if ruletype not in (wanted_ruletype, 'block'):
                    continue  # don't copy rules nobody asked for

                # a conditional is filtered out by its rule type ('cond_block')
                for rule_obj in ruleset.rules:
                    if isinstance(rule_obj, BlockRule):
                        for inner_type, inner_rule in rule_obj.iter_effective_rules(wanted_ruletype):
                            if not self.owner or hasattr(inner_rule, 'owner'):
                                yield inner_type, self.apply_qualifiers(inner_rule)
                    elif not self.owner or hasattr(rule_obj, 'owner'):
                        yield ruletype, self.apply_qualifiers(rule_obj)

    def apply_qualifiers(self, rule_obj):
        """return a copy of rule_obj with the qualifiers of this block applied"""

        rule_obj = deepcopy(rule_obj)

        if self.audit:
            rule_obj.audit = True

        if self.deny:
            rule_obj.deny = True
        elif self.allow_keyword:
            rule_obj.allow_keyword = True

        if self.owner:
            rule_obj.owner = True

        rule_obj.raw_rule = None  # the raw rule doesn't include the qualifiers

        return rule_obj

    def validate_body(self):
        """raise AppArmorException if the qualifiers don't fit the rules inside the block"""

        qualifiers = self.qualifiers_str()
        mode = (self.deny, self.allow_keyword, self.prompt)

        for rule_obj in self.iter_rules():
            if qualifiers and not rule_obj.supports_qualifiers:
                raise AppArmorException(
                    _('The qualifiers of a rule block are not allowed on the %s rules inside it') % rule_obj.rule_name)

            rule_mode = (rule_obj.deny, rule_obj.allow_keyword, getattr(rule_obj, 'prompt', False))
            if any(mode) and any(rule_mode) and mode != rule_mode:
                raise AppArmorException(
                    _('conflicting mode prefix on %s rule inside a rule block') % rule_obj.rule_name)

            if (self.owner or self.other) and not rule_obj.supports_owner:
                raise AppArmorException(
                    _('The %(qualifier)s qualifier of a rule block is not allowed on the %(rule)s rules inside it')
                    % {'qualifier': 'owner' if self.owner else 'other', 'rule': rule_obj.rule_name})

    def is_empty(self):
        """check if this block contains any rule"""

        for _rule_obj in self.iter_rules():
            return False

        return True

    def severity(self, sev_db):
        """return the highest severity of the rules inside this block"""

        severity = sev_db.NOT_IMPLEMENTED

        for rule_obj in self.iter_rules():
            rule_severity = rule_obj.severity(sev_db)

            if not isinstance(rule_severity, int):
                continue  # severity isn't implemented for this rule type

            if not isinstance(severity, int) or rule_severity > severity:
                severity = rule_severity

        return severity

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""

        # only an identical block is covered: never drop a block whose rules are covered elsewhere
        return self._is_equal_localvars(other_rule, False)

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific variables are equal"""

        if (self.prompt, self.owner, self.other) != (other_rule.prompt, other_rule.owner, other_rule.other):
            return False

        # compare the rules inside the block, not its rendered text
        return self.get_body_clean() == other_rule.get_body_clean()

    def _logprof_header_localvars(self):
        return _('Rule block'), self.get_clean()


class BlockRuleset(BaseRuleset):
    """Class to handle and store a collection of rule blocks"""
