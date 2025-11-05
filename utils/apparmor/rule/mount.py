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

from apparmor.common import AppArmorBug, AppArmorException

from apparmor.regex import RE_PROFILE_MOUNT, RE_PROFILE_PATH_OR_VAR, strip_parenthesis, strip_quotes
from apparmor.rule import AARE
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers, logprof_value_or_all, check_and_split_list, quote_if_needed

from apparmor.translations import init_translation

_ = init_translation()

# TODO : Apparmor remount logs are displayed as mount (with remount flag). Profiles generated with aa-genprof are therefore mount rules. It could be interesting to make them remount rules.

flags_bind_mount = {'B', 'bind', 'R', 'rbind'}
flags_change_propagation = {
    'remount', 'unbindable', 'shared', 'private', 'slave', 'runbindable', 'rshared', 'rprivate', 'rslave',
    'make-unbindable', 'make-shared', 'make-private', 'make-slave', 'make-runbindable', 'make-rshared', 'make-rprivate',
    'make-rslave'
}
# keep in sync with parser/mount.cc mnt_opts_table!
flags_keywords = list(flags_bind_mount) + list(flags_change_propagation) + [
    'ro', 'r', 'read-only', 'rw', 'w', 'suid', 'nosuid', 'dev', 'nodev', 'exec', 'noexec', 'sync', 'async', 'mand',
    'nomand', 'dirsync', 'symfollow', 'nosymfollow', 'atime', 'noatime', 'diratime', 'nodiratime', 'move', 'M',
    'verbose', 'silent', 'loud', 'acl', 'noacl', 'relatime', 'norelatime', 'iversion', 'noiversion', 'strictatime',
    'nostrictatime', 'lazytime', 'nolazytime', 'user', 'nouser', '([A-Za-z0-9])',
]
join_valid_flags = '|'.join(flags_keywords)

sep = r'\s*[\s,]\s*'

# We aim to be a bit more restrictive than \S+ used in regex.py
FS_AARE = r'([][".*@{}\w^-]+)'

fs_type_pattern = r'\b(?P<fstype_or_vfstype>fstype|vfstype)\b\s*(?P<fstype_equals_or_in>=|in)\s*'\
    r'(?P<fstype>\(\s*(' + FS_AARE + r')(' + sep + r'(' + FS_AARE + r'))*\s*\)|'\
    r'\{\s*(' + FS_AARE + r')(' + sep + r'(' + FS_AARE + r'))*\s*\}|(\s*' + FS_AARE + r'))'\


option_pattern = r'\s*(\boption(s?)\b\s*(?P<options_equals_or_in>=|in)\s*'\
    r'(?P<options>\(\s*(' + join_valid_flags + r')(' + sep + r'(' + join_valid_flags + r'))*\s*\)|' \
    r'(\s*' + join_valid_flags + r')'\
    r'))?'

# allow any order of fstype and options
# Note: also matches if multiple fstype= or options= are given to keep the regex simpler
mount_condition_pattern = rf'({fs_type_pattern}\s*|{option_pattern}\s*)*'

# Source can either be
# - A path          : /foo
# - A globbed Path  : {,/usr}/lib{,32,64,x32}/modules/
# - A filesystem    : sysfs         (sudo mount -t tmpfs tmpfs /tmp/bar)
# - Any label       : mntlabel      (sudo mount -t tmpfs mntlabel /tmp/bar)
# Thus we cannot use directly RE_PROFILE_PATH_OR_VAR
# Destination can also be
# - A path          : /foo
# - A globbed Path  : **

glob_pattern = (
    r'(\s*(?P<%s>('
    + RE_PROFILE_PATH_OR_VAR % 'IGNOREDEV'  # path or variable
    + r'|\{\S*|"\{[^"]*"'  # alternation, optionally quoted (note: no leading "/" needed/enforced)
    + r'|\*\*\S*|\*\*[^"]*"'  # starting with "**"
    # Note: the closing ')))' needs to be added in the final regex
)

source_fileglob_pattern = (
    glob_pattern % 'source_file'
    + r'|""'  # empty source
    + r'|[\w-]+'  # any word including "-"
    + ')))'
)

dest_fileglob_pattern = (
    glob_pattern.replace('IGNOREDEV', 'IGNOREMP') % 'dest_file'
    + ')))'
)

RE_MOUNT_DETAILS = re.compile(r'^\s*' + mount_condition_pattern + rf'(\s+{source_fileglob_pattern})?' + rf'(\s+->\s+{dest_fileglob_pattern})?\s*' + r'$')
RE_UMOUNT_DETAILS = re.compile(r'^\s*' + mount_condition_pattern + rf'(\s+{dest_fileglob_pattern})?\s*' + r'$')

# check if a rule contains multiple 'options' or 'fstype'
# (not using option_pattern or fs_type_pattern here because a) it also matches an empty string, and b) using it twice would cause name conflicts)
multi_param_template = r'\sPARAM\s*(=|\sin).*\sPARAM\s*(=|\sin)'
RE_MOUNT_MULTIPLE_OPTIONS = re.compile(multi_param_template.replace('PARAM', 'options'))
RE_MOUNT_MULTIPLE_FS_TYPE = re.compile(multi_param_template.replace('PARAM', 'v?fstype'))


class MountRule(BaseRule):
    '''Class to handle and store a single mount rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field MountRule.ALL
    class __MountAll(object):
        pass

    ALL = __MountAll

    rule_name = 'mount'
    _match_re = RE_PROFILE_MOUNT

    def __init__(self, operation, fstype, options, source, dest,
                 audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event,
                         priority=priority)

        self.operation = operation

        if fstype == self.ALL or fstype[1] == self.ALL:
            self.all_fstype = True
            self.fstype = None
            self.is_fstype_equal = None
        else:
            self.all_fstype = False
            for it in fstype[1]:
                aare_len, unused = parse_aare(it, 0, 'fstype')
                if aare_len != len(it):
                    raise AppArmorException(f'Invalid aare : {it}')
            self.fstype = fstype[1]
            self.is_fstype_equal = fstype[0]

        self.options, self.all_options, unknown_items = check_and_split_list(options[1] if options != self.ALL else options, flags_keywords, self.ALL, type(self).__name__, 'options')
        if unknown_items:
            raise AppArmorException(_('Passed unknown options keyword to %s: %s') % (type(self).__name__, ' '.join(unknown_items)))
        self.is_options_equal = options[0] if not self.all_options else None

        self.source, self.all_source = self._aare_or_all(source, 'source', is_path=False, log_event=log_event, empty_ok=True)
        self.dest, self.all_dest = self._aare_or_all(dest, 'dest', is_path=False, log_event=log_event)

        if not self.all_fstype and self.is_fstype_equal not in ('=', 'in'):
            raise AppArmorBug(f'Invalid is_fstype_equal : {self.is_fstype_equal}')
        if not self.all_options and self.is_options_equal not in ('=', 'in'):
            raise AppArmorBug(f'Invalid is_options_equal : {self.is_options_equal}')
        if self.operation != 'mount' and not self.all_source:
            raise AppArmorException(f'Operation {self.operation} cannot have a source')

        if self.operation == 'mount' and not self.all_options and flags_change_propagation & self.options != set():
            if not (self.all_source or self.all_dest):
                raise AppArmorException(f'Operation {flags_change_propagation & self.options} cannot specify a source. Source = {self.source}')
            elif not self.all_fstype:
                raise AppArmorException(f'Operation {flags_change_propagation & self.options} cannot specify a fstype. Fstype = {self.fstype}')

        if self.operation == 'mount' and not self.all_options and flags_bind_mount & self.options != set() and not self.all_fstype:
            raise AppArmorException(f'Bind mount rules cannot specify a fstype. Fstype = {self.fstype}')

        self.can_glob = not self.all_source and not self.all_dest and not self.all_options

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        priority, audit, deny, allow_keyword, comment = parse_modifiers(matches)

        operation = matches.group('operation')

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

            if operation == 'mount':
                parsed = RE_MOUNT_DETAILS.search(rule_details)
            else:
                parsed = RE_UMOUNT_DETAILS.search(rule_details)

            r = parsed.groupdict() if parsed else None
            if not r:
                raise AppArmorException('Can\'t parse mount rule ' + raw_rule)

            if r['fstype'] is not None:
                # mount rules with multiple 'fstype' are not supported by the tools yet, and when writing them, only the last 'fstype' would survive.
                # Therefore raise an exception when parsing such a rule to prevent breaking the rule.
                if RE_MOUNT_MULTIPLE_FS_TYPE.search(raw_rule):
                    raise AppArmorException("mount rules with multiple 'fstype' are not supported by the tools")

                is_fstype_equal = r['fstype_equals_or_in']
                fstype = parse_aare_list(strip_parenthesis(r['fstype']), 'fstype')
            else:
                is_fstype_equal = None
                fstype = cls.ALL

            if r['options'] is not None:
                # mount rules with multiple 'options' are not supported by the tools yet, and when writing them, only the last 'options' would survive.
                # Therefore raise an exception when parsing such a rule to prevent breaking the rule.
                if RE_MOUNT_MULTIPLE_OPTIONS.search(raw_rule):
                    raise AppArmorException("mount rules with multiple 'options' are not supported by the tools")

                is_options_equal = r['options_equals_or_in']
                options = strip_parenthesis(r['options']).replace(',', ' ').split()
            else:
                is_options_equal = None
                options = cls.ALL

            if operation == 'mount' and r['source_file'] is not None:  # Umount cannot have a source
                source = strip_quotes(r['source_file'])
            else:
                source = cls.ALL

            if r['dest_file'] is not None:
                dest = strip_quotes(r['dest_file'])
            else:
                dest = cls.ALL

        else:
            is_fstype_equal = None
            is_options_equal = None
            fstype = cls.ALL
            options = cls.ALL
            source = cls.ALL
            dest = cls.ALL

        return cls(operation=operation, fstype=(is_fstype_equal, fstype), options=(is_options_equal, options),
                   source=source, dest=dest, audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment,
                   priority=priority)

    def get_clean(self, depth=0):
        space = '  ' * depth

        fstype = ' fstype%s(%s)' % (wrap_in_with_spaces(self.is_fstype_equal), ', '.join(sorted(self.fstype))) if not self.all_fstype else ''
        options = ' options%s(%s)' % (wrap_in_with_spaces(self.is_options_equal), ', '.join(sorted(self.options))) if not self.all_options else ''

        source = ''
        dest = ''

        if self.operation == 'mount':
            if not self.all_source:
                if self.source.regex == '':
                    source = ' ""'
                else:
                    source = ' ' + quote_if_needed(str(self.source.regex))

            if not self.all_dest:
                dest = ' -> ' + quote_if_needed(str(self.dest.regex))

        else:
            if not self.all_dest:
                dest = ' ' + str(self.dest.regex)

        return ('%s%s%s%s%s%s%s,%s' % (space,
                                       self.modifiers_str(),
                                       self.operation,
                                       fstype,
                                       options,
                                       source,
                                       dest,
                                       self.comment,
                                       ))

    def _is_covered_localvars(self, other_rule):
        if self.operation != other_rule.operation:
            return False
        if self.is_fstype_equal != other_rule.is_fstype_equal:
            return False
        if self.is_options_equal != other_rule.is_options_equal:
            return False

        for o_it in other_rule.fstype or []:
            found = False
            for s_it in self.fstype or []:
                if self._is_covered_aare(AARE(s_it, False), self.all_fstype, AARE(o_it, False), other_rule.all_fstype, 'fstype'):
                    found = True

            if not found:
                return False
        if not self._is_covered_list(self.options, self.all_options, other_rule.options, other_rule.all_options, 'options'):
            return False
        if not self._is_covered_aare(self.source, self.all_source, other_rule.source, other_rule.all_source, 'source'):
            return False
        if not self._is_covered_aare(self.dest, self.all_dest, other_rule.dest, other_rule.all_dest, 'dest'):
            return False

        return True

    def _is_equal_localvars(self, rule_obj, strict):
        if self.operation != rule_obj.operation:
            return False
        if self.is_fstype_equal != rule_obj.is_fstype_equal:
            return False
        if self.is_options_equal != rule_obj.is_options_equal:
            return False
        if self.fstype != rule_obj.fstype or self.options != rule_obj.options:
            return False
        if not self._is_equal_aare(self.source, self.all_source, rule_obj.source, rule_obj.all_source, 'source'):
            return False
        if not self._is_equal_aare(self.dest, self.all_dest, rule_obj.dest, rule_obj.all_dest, 'dest'):
            return False

        return True

    @staticmethod
    def hashlog_from_event(hl, e):
        if e['flags'] is not None:
            e['flags'] = ('=', e['flags'])
        if e['fs_type'] is not None:
            e['fs_type'] = ('=', e['fs_type'])
        if e['operation'] == 'mount':
            hl[e['operation']][e['flags']][e['fs_type']][e['name']][e['src_name']] = True
        else:  # Umount
            hl[e['operation']][e['flags']][e['fs_type']][e['name']][None] = True

    @classmethod
    def from_hashlog(cls, hl):
        for operation, options, fstype, dest, source in cls.generate_rules_from_hashlog(hl, 5):
            _options = (options[0], options[1].split(', ')) if options is not None else MountRule.ALL
            _fstype = (fstype[0], fstype[1].split(', ')) if fstype is not None else MountRule.ALL
            _source = source if source is not None else MountRule.ALL
            _dest = dest if dest is not None else MountRule.ALL
            yield cls(operation=operation, fstype=_fstype, options=_options, source=_source, dest=_dest)

    def glob(self):
        '''Change path to next possible glob'''
        if self.all_source and self.all_options:
            return

        if not self.all_dest:
            self.all_dest = True
            self.dest = self.ALL
        elif not self.all_source and type(self.source) is not str:
            self.source = self.source.glob_path()
            if self.source.is_equal('/**/'):
                self.all_source = True
                self.source = self.ALL

        else:
            self.options = self.ALL
            self.all_options = True
        self.raw_rule = None

    def _logprof_header_localvars(self):
        operation = self.operation
        fstype = logprof_value_or_all(self.fstype, self.all_fstype)
        options = logprof_value_or_all(self.options, self.all_options)
        source = logprof_value_or_all(self.source, self.all_source)
        dest = logprof_value_or_all(self.dest, self.all_dest)

        return (
            _('Operation'), operation,
            _('Fstype'), (self.is_fstype_equal, fstype) if fstype != 'ALL' else fstype,
            _('Options'), (self.is_options_equal, options) if options != 'ALL' else options,
            _('Source'), source,
            _('Destination'), dest,

        )


class MountRuleset(BaseRuleset):
    '''Class to handle and store a collection of Mount rules'''


def parse_aare(s, offset, param):
    parsed = ''
    brace_count = 0
    for i, c in enumerate(s[offset:], start=offset):
        if c in [' ', ',', '\t'] and brace_count == 0:
            break
        parsed += c
        if c == '{':
            brace_count += 1
        elif c == '}':
            brace_count -= 1
            if brace_count < 0:
                raise AppArmorException(f"Unmatched closing brace in {param}: {s[offset:]}")
        offset = i

    if brace_count != 0:
        raise AppArmorException(f"Unmatched opening brace in {param}: {s[offset:]}")

    return offset + 1, parsed


def parse_aare_list(s, param):
    res = []
    offset = 0
    while offset <= len(s):
        offset, part = parse_aare(s, offset, param)
        if part.translate(' ,\t') != '':
            res.append(part)
    return res


def wrap_in_with_spaces(value):
    ''' wrap 'in' keyword in spaces, and leave everything else unchanged '''

    if value == 'in':
        value = ' in '

    return value
