# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014 Christian Boltz <apparmor@cboltz.de>
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

from abc import ABCMeta, abstractmethod

from apparmor.aare import AARE
from apparmor.common import AppArmorBug, AppArmorException, hasher
from apparmor.regex import strip_quotes
from apparmor.translations import init_translation

_ = init_translation()


class BaseRule(metaclass=ABCMeta):
    """Base class to handle and store a single rule"""

    # decides if the (G)lob and Glob w/ (E)xt options are displayed
    can_glob = False
    can_glob_ext = False

    # defines if the (N)ew option is displayed
    can_edit = False

    # defines if the '(O)wner permissions on/off' option is displayed
    can_owner = False

    rule_name = 'base'

    _match_re = None

    def __init__(self, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):
        """initialize variables needed by all rule types"""

        self._store_priority(priority)
        self.audit = audit
        self.deny = deny
        self.allow_keyword = allow_keyword
        self.comment = comment
        self.log_event = log_event

        # Set only in the parse() class method
        self.raw_rule = None

    def _store_priority(self, priority):
        if priority is None:  # default priority
            self.priority = None
            return

        try:
            ipriority = int(priority)
        except ValueError:
            raise AppArmorException("Invalid value for priority '%s'" % priority)

        if ipriority < -1000 or ipriority > 1000:
            raise AppArmorException('priority %d out of range' % (ipriority))

        self.priority = ipriority

    def _aare_or_all(self, rulepart, partname, is_path, log_event, empty_ok=False):
        """checks rulepart and returns
           - (AARE, False) if rulepart is a (non-empty) string
           - (None, True) if rulepart is all_obj (typically *Rule.ALL)
           - raises AppArmorBug if rulepart is an empty string or has a wrong type

           Parameters:
           - rulepart: the rule part to check (string or *Rule.ALL object)
           - partname: the name of the rulepart (for example 'peer', used for exception messages)
           - is_path (passed through to AARE)
           - log_event (passed through to AARE)
           """

        if rulepart == self.ALL:
            return None, True
        elif isinstance(rulepart, str):
            if not rulepart.strip() and not empty_ok:
                raise AppArmorBug(
                    'Passed empty %(partname)s to %(classname)s: %(rulepart)s'
                    % {'partname': partname, 'classname': self.__class__.__name__, 'rulepart': str(rulepart)})
            return AARE(rulepart, is_path=is_path, log_event=log_event), False
        else:
            raise AppArmorBug(
                'Passed unknown %(partname)s to %(classname)s: %(rulepart)s'
                % {'partname': partname, 'classname': self.__class__.__name__, 'rulepart': str(rulepart)})

    def __repr__(self):
        return '<%s> %s' % (self.__class__.__name__, self.get_raw())

    @classmethod
    def match(cls, raw_rule):
        """return True if raw_rule matches the class (main) regex, False otherwise
           Note: This function just provides an answer to "is this your job?".
                 It does not guarantee that the rule is completely valid."""
        return bool(cls._match(raw_rule))

    @classmethod
    def _match(cls, raw_rule):
        """parse raw_rule and return regex match object"""
        if cls._match_re is None:
            if cls is BaseRule:
                raise AppArmorBug("BaseRule class methods should not be called directly.")
            else:
                raise NotImplementedError("'%s' needs to implement _match(), but didn't" % (str(cls)))
        return cls._match_re.search(raw_rule)

    @classmethod
    def create_instance(cls, raw_rule):
        """parse raw_rule and return instance of this class"""
        matches = cls._match(raw_rule)
        if not matches:
            raise AppArmorException(_("Invalid %s rule '%s'") % (cls.rule_name, raw_rule))

        rule = cls._create_instance(raw_rule, matches)
        rule.raw_rule = raw_rule.strip()
        return rule

    @classmethod
    @abstractmethod
    def _create_instance(cls, raw_rule, matches):
        """returns a Rule object created from parsing the raw rule.
           required to be implemented by subclasses; raise exception if not"""
        raise NotImplementedError("'%s' needs to implement _create_instance(), but didn't" % (str(cls)))

    @staticmethod
    def generate_rules_from_hashlog(hashlog, nb_keys):
        """yields all key sequences from a hashlog of depth nb_keys"""
        stack = [(hashlog, [], nb_keys)]

        while stack:
            items, path, depth = stack.pop()

            if depth == 0:
                yield path
                continue

            for next_key in items:
                stack.append((items[next_key], path + [next_key], depth - 1))

    @classmethod
    def create_from_ev(cls, ev):
        """returns a rule that would allow an event"""
        hl = hasher()
        cls.hashlog_from_event(hl, ev)
        return next(cls.from_hashlog(hl))

    @staticmethod
    def hashlog_from_event(hl, ev):
        """stores an event in the hashlog"""
        raise NotImplementedError('hashlog_from_event should be called on a rule class and not directly on BaseRule.')

    @classmethod
    def from_hashlog(cls, hl):
        """constructs and yields all rules that would allow denials stored in a hashlog"""
        raise NotImplementedError("'%s' needs to implement from_hashlog(), but didn't" % (str(cls)))

    @abstractmethod
    def get_clean(self, depth=0):
        """return clean rule (with default formatting, and leading whitespace as specified in the depth parameter)"""

    def get_raw(self, depth=0):
        """return raw rule (with original formatting, and leading whitespace in the depth parameter)"""
        if self.raw_rule:
            return '%s%s' % ('  ' * depth, self.raw_rule)
        else:
            return self.get_clean(depth)

    def is_covered(self, other_rule, check_allow_deny=True, check_audit=False, check_priority=True):
        """check if other_rule is covered by this rule object"""

        if type(other_rule) is not type(self):
            raise AppArmorBug('Passes %s instead of %s' % (str(other_rule), self.__class__.__name__))

        if check_allow_deny and self.deny != other_rule.deny:
            return False

        if other_rule.deny and not self.deny:
            return False

        if check_audit and other_rule.audit != self.audit:
            return False

        if other_rule.audit and not self.audit:
            return False

        if check_priority and (self.priority or 0) > (other_rule.priority or 0):
            return False

        # still here? -> then the common part is covered, check rule-specific things now
        return self._is_covered_localvars(other_rule)

    @abstractmethod
    def _is_covered_localvars(self, other_rule):
        """check if the rule-specific parts of other_rule is covered by this rule object"""

    def _is_covered_plain(self, self_value, self_all, other_value, other_all, cond_name):
        """check if other_* is covered by self_* - for plain str, int etc."""

        if not other_value and not other_all:
            raise AppArmorBug('No %(cond_name)s specified in other %(rule_name)s rule' % {'cond_name': cond_name, 'rule_name': self.rule_name})

        if not self_all:
            if other_all:
                return False
            if self_value != other_value:
                return False

        # still here? -> then it is covered
        return True

    def _is_covered_list(self, self_value, self_all, other_value, other_all, cond_name, sanity_check=True):
        """check if other_* is covered by self_* - for lists"""

        if sanity_check and not other_value and not other_all:
            raise AppArmorBug('No %(cond_name)s specified in other %(rule_name)s rule' % {'cond_name': cond_name, 'rule_name': self.rule_name})

        if not self_all:
            if other_all:
                return False
            if not other_value.issubset(self_value):
                return False

        # still here? -> then it is covered
        return True

    def _is_covered_aare(self, self_value, self_all, other_value, other_all, cond_name):
        """check if other_* is covered by self_* - for AARE"""

        if not other_value and not other_all:
            raise AppArmorBug('No %(cond_name)s specified in other %(rule_name)s rule' % {'cond_name': cond_name, 'rule_name': self.rule_name})

        if not self_all:
            if other_all:
                return False
            if not self_value.match(other_value):
                return False

        # still here? -> then it is covered
        return True

    def is_equal(self, rule_obj, strict=False):
        """compare if rule_obj == self
           Calls _is_equal_localvars() to compare rule-specific variables"""

        if ((self.priority or 0) != (rule_obj.priority or 0)
                or self.audit != rule_obj.audit
                or self.deny != rule_obj.deny):
            return False

        if strict and (
            self.priority != rule_obj.priority
            or self.allow_keyword != rule_obj.allow_keyword
            or self.comment != rule_obj.comment
            or self.raw_rule != rule_obj.raw_rule
        ):
            return False

        if type(rule_obj) is not type(self):
            raise AppArmorBug('Passed non-{} rule: {}'.format(self.rule_name, rule_obj))

        return self._is_equal_localvars(rule_obj, strict)

    def _is_equal_aare(self, self_value, self_all, other_value, other_all, cond_name):
        """check if other_* is the same as self_* - for AARE"""

        if not other_value and not other_all:
            raise AppArmorBug('No %(cond_name)s specified in other %(rule_name)s rule' % {'cond_name': cond_name, 'rule_name': self.rule_name})

        if self_all != other_all:
            return False

        if self_value and not self_value.is_equal(other_value):
            return False

        # still here? -> then it is equal
        return True

    @abstractmethod
    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific variables are equal"""

    def severity(self, sev_db):
        """return severity of this rule, which can be:
           - a number between 0 and 10, where 0 means harmless and 10 means critical,
           - "unknown" (to be exact: the value specified for "unknown" as set when loading the severity database), or
           - sev_db.NOT_IMPLEMENTED if no severity check is implemented for this rule type.
           sev_db must be an apparmor.severity.Severity object."""
        return sev_db.NOT_IMPLEMENTED

    def logprof_header(self):
        """return the headers (human-readable version of the rule) to display in aa-logprof for this rule object
           returns {'label1': 'value1', 'label2': 'value2'}"""

        headers = []
        qualifier = []

        if self.priority:
            qualifier.append('priority=%s' % self.priority)

        if self.audit:
            qualifier.append('audit')

        if self.deny:
            qualifier.append('deny')
        elif self.allow_keyword:
            qualifier.append('allow')

        if qualifier:
            headers.extend((_('Qualifier'), ' '.join(qualifier)))

        headers.extend(self._logprof_header_localvars())

        return headers

    @abstractmethod
    def _logprof_header_localvars(self):
        """return the headers (human-readable version of the rule) to display in aa-logprof for this rule object
           returns {'label1': 'value1', 'label2': 'value2'}"""

    # NOTE: edit_header, validate_edit, and store_edit are not implemented by every subclass.
    def edit_header(self):
        """return the prompt for, and the path to edit when using '(N)ew'"""
        raise NotImplementedError("'%s' needs to implement edit_header(), but didn't" % (str(self)))

    def validate_edit(self, newpath):
        """validate the new path.
           Returns True if it covers the previous path, False if it doesn't."""
        raise NotImplementedError("'%s' needs to implement validate_edit(), but didn't" % (str(self)))

    def store_edit(self, newpath):
        """store the changed path.
           This is done even if the new path doesn't match the original one."""
        raise NotImplementedError("'%s' needs to implement store_edit(), but didn't" % (str(self)))

    def modifiers_str(self):
        """return priority, allow/deny, and audit keyword as string, including whitespace"""

        if self.priority is not None:
            prioritystr = 'priority=%s ' % self.priority
        else:
            prioritystr = ''

        if self.audit:
            auditstr = 'audit '
        else:
            auditstr = ''

        if self.deny:
            allowstr = 'deny '
        elif self.allow_keyword:
            allowstr = 'allow '
        else:
            allowstr = ''

        return '%s%s%s' % (prioritystr, auditstr, allowstr)

    def ensure_modifiers_not_supported(self):
        if self.audit:
            raise AppArmorBug('Attempt to initialize %s with audit flag' % self.__class__.__name__)
        if self.deny:
            raise AppArmorBug('Attempt to initialize %s with deny flag' % self.__class__.__name__)
        if self.allow_keyword:
            raise AppArmorBug('Attempt to initialize %s with allow keyword' % self.__class__.__name__)
        if self.priority is not None:
            raise AppArmorBug('Attempt to initialize %s with priority' % self.__class__.__name__)


class BaseRuleset:
    """Base class to handle and store a collection of rules"""

    # decides if the (G)lob and Glob w/ (E)xt options are displayed
    # XXX TODO: remove in all *Ruleset classes (moved to *Rule)
    can_glob = True
    can_glob_ext = False

    def __init__(self):
        """initialize variables needed by all ruleset types
           Do not override in child class unless really needed - override _init_vars() instead"""
        self.rules = []
        self._init_vars()

    def _init_vars(self):
        """called by __init__() and delete_all_rules() - override in child class to initialize more variables"""

    def __repr__(self):
        classname = self.__class__.__name__
        if self.rules:
            return '<%s>\n' % classname + '\n'.join(self.get_raw(1)) + '</%s>' % classname
        else:
            return '<%s (empty) />' % classname

    def add(self, rule, cleanup=False):
        """add a rule object
           if cleanup is specified, delete rules that are covered by the new rule
           (the difference to delete_duplicates() is: cleanup only deletes rules that
           are covered by the new rule, but keeps other, unrelated superfluous rules)
        """
        deleted = 0

        if cleanup:
            oldrules = self.rules
            self.rules = []

            for oldrule in oldrules:
                if not rule.is_covered(oldrule):
                    self.rules.append(oldrule)
                else:
                    deleted += 1

        self.rules.append(rule)

        return deleted

    def get_raw(self, depth=0):
        """return all raw rules (if possible/not modified in their original formatting).
           Returns an array of lines, with depth * leading whitespace"""

        data = []
        for rule in self.rules:
            data.append(rule.get_raw(depth))

        if data:
            data.append('')

        return data

    def get_clean(self, depth=0):
        """return all rules (in clean/default formatting)
           Returns an array of lines, with depth * leading whitespace"""

        allow_rules = []
        deny_rules = []

        for rule in self.rules:
            if rule.deny:
                deny_rules.append(rule.get_clean(depth))
            else:
                allow_rules.append(rule.get_clean(depth))

        allow_rules.sort()
        deny_rules.sort()

        cleandata = []

        if deny_rules:
            cleandata += deny_rules
            cleandata.append('')

        if allow_rules:
            cleandata += allow_rules
            cleandata.append('')

        return cleandata

    def get_clean_unsorted(self, depth=0):
        """return all rules (in clean/default formatting) in original order
           Returns an array of lines, with depth * leading whitespace"""

        all_rules = []

        for rule in self.rules:
            all_rules.append(rule.get_clean(depth))

        if all_rules:
            all_rules.append('')

        return all_rules

    def is_covered(self, rule, check_allow_deny=True, check_audit=False):
        """return True if rule is covered by existing rules, otherwise False"""

        for r in self.rules:
            if r.is_covered(rule, check_allow_deny, check_audit):
                return True

        return False

#    def is_log_covered(self, parsed_log_event, check_allow_deny=True, check_audit=False):
#        """return True if parsed_log_event is covered by existing rules, otherwise False"""
#
#        rule_obj = self.new_rule()
#        rule_obj.set_log(parsed_log_event)
#
#        return self.is_covered(rule_obj, check_allow_deny, check_audit)

    def delete(self, rule):
        """Delete rule from rules"""

        rule_to_delete = False
        i = 0
        for r in self.rules:
            if r.is_equal(rule):
                rule_to_delete = True
                break
            i = i + 1

        if rule_to_delete:
            self.rules.pop(i)
        else:
            raise AppArmorBug('Attempt to delete non-existing rule %s' % rule.get_raw(0))

    def delete_duplicates(self, include_rules):
        """Delete duplicate rules.
           include_rules must be a *_rules object or None"""

        deleted = 0

        # delete rules that are covered by include files
        if include_rules:
            oldrules = self.rules
            self.rules = []
            for rule in oldrules:
                if include_rules.is_covered(rule, True, False):
                    deleted += 1
                else:
                    self.rules.append(rule)

        # de-duplicate rules inside the profile
        deleted += self.delete_in_profile_duplicates()
        self.rules.reverse()
        deleted += self.delete_in_profile_duplicates()  # search again in reverse order - this will find the remaining duplicates
        self.rules.reverse()  # restore original order for raw output

        return deleted

    def delete_in_profile_duplicates(self):
        """Delete duplicate rules inside a profile"""

        deleted = 0
        oldrules = self.rules
        self.rules = []

        for rule in oldrules:
            if not self.is_covered(rule, True, False):
                self.rules.append(rule)
            else:
                deleted += 1

        return deleted

    def get_glob_ext(self, path_or_rule):
        """returns the next possible glob with extension (for file rules only).
           For all other rule types, raise an exception"""
        raise NotImplementedError("get_glob_ext is not available for this rule type!")


def check_and_split_list(lst, allowed_keywords, all_obj, classname, keyword_name, allow_empty_list=False):
    """check if lst is all_obj or contains only items listed in allowed_keywords"""

    if lst == all_obj:
        return None, True, None
    elif isinstance(lst, str):
        result_list = {lst}
    elif isinstance(lst, (list, tuple, set)) and (lst or allow_empty_list):
        result_list = set(lst)
    else:
        raise AppArmorBug(
            'Passed unknown %(type)s object to %(classname)s: %(unknown_object)s'
            % {'type': type(lst), 'classname': classname, 'unknown_object': str(lst)})

    unknown_items = set()
    for item in result_list:
        if not item.strip():
            raise AppArmorBug(
                'Passed empty %(keyword_name)s to %(classname)s'
                % {'keyword_name': keyword_name, 'classname': classname})
        if item not in allowed_keywords:
            unknown_items.add(item)

    return result_list, False, unknown_items


def logprof_value_or_all(value, all_values):
    """helper for logprof_header() to return 'all' (if all_values is True) or the specified value.
       For some types, the value is made more readable."""

    if all_values:
        return _('ALL')

    if isinstance(value, AARE):
        return value.regex
    elif isinstance(value, (set, list, tuple)):
        return ' '.join(sorted(value))
    else:
        return value


def parse_comment(matches):
    """returns the comment (with a leading space) from the matches object"""
    comment = ''
    if matches.group('comment'):
        # include a space so that we don't need to add it everywhere when writing the rule
        comment = ' %s' % matches.group('comment')
    return comment


def parse_modifiers(matches):
    """returns priority, audit, deny, allow_keyword and comment from the
    matches object
       - priority is a number or None
       - audit, deny and allow_keyword are True/False
       - comment is the comment with a leading space"""

    priority = None
    if matches.group('priority'):
        priority = int(matches.group('priority'))

    audit = False
    if matches.group('audit'):
        audit = True

    deny = False
    allow_keyword = False

    allowstr = matches.group('allow')
    if allowstr:
        if allowstr.strip() == 'allow':
            allow_keyword = True
        elif allowstr.strip() == 'deny':
            deny = True
        else:
            raise AppArmorBug("Invalid allow/deny keyword %s" % allowstr)

    comment = parse_comment(matches)

    return (priority, audit, deny, allow_keyword, comment)


def quote_if_needed(data):
    """quote data if it contains whitespace"""
    if ' ' in data:
        data = '"' + data + '"'
    return data


def check_dict_keys(d, possible_keys, type_all):
    """Check that all keys in dictionary are among possible keys"""
    if d == type_all or d == {}:
        return type_all
    if not possible_keys >= d.keys():
        raise AppArmorException(f'Incorrect key in dict {d}. Possible keys are {possible_keys},')
    return d


def initialize_cond_dict(d, keys, suffix, type_all):
    out = {
        key: strip_quotes(d[f'{key}{suffix}'])
        for key in keys
        if f'{key}{suffix}' in d and d[f'{key}{suffix}'] is not None
    }
    return out if out != {} else type_all


def tuple_to_dict(t, keys):
    d = {}
    for idx, k in enumerate(keys):
        if t[idx] is not None:
            d[k] = t[idx]
    return d


def print_dict_values(d, type_all, prefix=None):
    if d == type_all:
        return ''
    to_print = ' '.join(f'{k}={quote_if_needed(str(v))}' for k, v in d.items())
    if prefix:
        return f' {prefix}=({to_print})'
    else:
        return f' {to_print}'
