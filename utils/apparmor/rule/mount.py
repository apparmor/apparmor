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

from apparmor.regex import RE_PROFILE_MOUNT, RE_PROFILE_PATH_OR_VAR, strip_parenthesis, strip_quotes, strip_braces
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
    'nostrictatime', 'lazytime', 'nolazytime', 'user', 'nouser',
    '[A-Za-z0-9-]+',  # as long as the parser uses a hardcoded options list, this only helps to print a better error message on unknown mount options
]
join_valid_flags = '|'.join(flags_keywords)

sep = r'\s*[\s,]\s*'

# We aim to be a bit more restrictive than \S+ used in regex.py
FS_AARE = r'([][".*@{}\w^-]+)'

fs_type_pattern = r'\b(?P<fstype_or_vfstype>fstype|vfstype)\b\s*(?P<fstype_equals_or_in>=|in)\s*'\
    r'(?P<fstype>\(\s*(' + FS_AARE + r')(' + sep + r'(' + FS_AARE + r'))*\s*\)|'\
    r'\{\s*(' + FS_AARE + r')(' + sep + r'(' + FS_AARE + r'))*\s*\}|'\
    r'(\s*' + FS_AARE + r')(,' + FS_AARE + ')*)'


option_pattern = r'\s*(\boption(s?)\b\s*(?P<options_equals_or_in>=|in)\s*'\
    r'(?P<options>\(\s*(' + join_valid_flags + r')(' + sep + r'(' + join_valid_flags + r'))*\s*\)|' \
    r'(\s*' + join_valid_flags + r')(?=(\s|$))'\
    r'))'

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

# check if a rule contains multiple 'fstype'
# (not using fs_type_pattern here because a) it also matches an empty string, and b) using it twice would cause name conflicts)
multi_param_template = r'\sPARAM\s*(=|\sin).*\sPARAM\s*(=|\sin)'
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

        if not isinstance(fstype, list):
            fstype = [fstype]

        # self.all_fstype will only be true if no fstypes are
        # specified, so it's fine to set it inside the loop
        self.fstype = []
        for fst in fstype:
            if fst == self.ALL or fst[1] == self.ALL:
                self.all_fstype = True
                fstype_values = None
                is_fstype_equal = None
            else:
                self.all_fstype = False
                for it in fst[1]:
                    aare_len, unused = parse_aare(it, 0, 'fstype')
                    if aare_len != len(it):
                        raise AppArmorException(f'Invalid aare : {it}')
                fstype_values = fst[1]
                is_fstype_equal = fst[0]
            self.fstype.append(MountConditional('fstype', fstype_values, self.all_fstype, is_fstype_equal, 'aare'))

        if not isinstance(options, list):
            options = [options]

        # self.all_options will only be true if no options are
        # specified, so it's fine to set it inside the loop
        self.options = []
        for opts in options:
            opt_values, self.all_options, unknown_items = check_and_split_list(opts[1] if opts != self.ALL else opts, flags_keywords, self.ALL, type(self).__name__, 'options')
            if unknown_items:
                raise AppArmorException(_('Passed unknown options keyword to %s: %s') % (type(self).__name__, ' '.join(unknown_items)))
            is_options_equal = opts[0] if not self.all_options else None
            self.options.append(MountConditional('options', opt_values, self.all_options, is_options_equal, 'list'))

        self.source, self.all_source = self._aare_or_all(source, 'source', is_path=False, log_event=log_event, empty_ok=True)
        self.dest, self.all_dest = self._aare_or_all(dest, 'dest', is_path=False, log_event=log_event)

        if self.operation != 'mount' and not self.all_source:
            raise AppArmorException(f'Operation {self.operation} cannot have a source')

        for opt_cond in self.options:
            if self.operation == 'mount' and not self.all_options and flags_change_propagation & opt_cond.values != set():
                if not (self.all_source or self.all_dest):
                    raise AppArmorException(f'Operation {flags_change_propagation & opt_cond.values} cannot specify a source. Source = {self.source}')
                elif not self.all_fstype:
                    raise AppArmorException(f'Operation {flags_change_propagation & opt_cond.values} cannot specify a fstype. Fstype = {self.fstype}')

            if self.operation == 'mount' and not self.all_options and flags_bind_mount & opt_cond.values != set() and not self.all_fstype:
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

            fstype = (None, cls.ALL)
            if r['fstype'] is not None:
                fstype = []
                for m in re.finditer(fs_type_pattern, rule_details):
                    # apparmor_parser cannot handle items starting with '{' so '({ext3,ext4})' will fail -> Converting to (ext3,ext4)
                    fst = parse_aare_list(strip_braces(strip_parenthesis(m.group('fstype')).strip()), 'fstype')
                    fstype.append((m.group('fstype_equals_or_in'), fst))

            opts = (None, cls.ALL)
            if r['options'] is not None:
                opts = []
                for m in re.finditer(option_pattern, rule_details):
                    options = strip_parenthesis(m.group('options')).replace(',', ' ').split()
                    opts.append((m.group('options_equals_or_in'), options))

            if operation == 'mount' and r['source_file'] is not None:  # Umount cannot have a source
                source = strip_quotes(r['source_file'])
            else:
                source = cls.ALL

            if r['dest_file'] is not None:
                dest = strip_quotes(r['dest_file'])
            else:
                dest = cls.ALL

        else:
            opts = (None, cls.ALL)
            fstype = (None, cls.ALL)
            source = cls.ALL
            dest = cls.ALL

        return cls(operation=operation, fstype=fstype, options=opts,
                   source=source, dest=dest, audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment,
                   priority=priority)

    def get_clean(self, depth=0):
        space = '  ' * depth

        fstype = ''
        for fst in self.fstype:
            fstype += fst.get_clean()

        options = ''
        for opt in self.options:
            options += opt.get_clean()

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
                dest = ' ' + quote_if_needed(str(self.dest.regex))

        return ('%s%s%s%s%s%s%s,%s' % (space,
                                       self.modifiers_str(),
                                       self.operation,
                                       fstype,
                                       options,
                                       source,
                                       dest,
                                       self.comment,
                                       ))

    def _is_cond_list_covered(self, conds, other_conds):
        '''Checks if all conds in 'other_conds' are covered by at
        least one cond in 'conds'.'''
        return all(
            any(cond.is_covered(other_cond) for cond in conds)
            for other_cond in other_conds
        )

    def _is_covered_localvars(self, other_rule):
        if self.operation != other_rule.operation:
            return False
        if not self._is_cond_list_covered(self.fstype, other_rule.fstype):
            return False
        if not self._is_cond_list_covered(self.options, other_rule.options):
            return False
        if not self._is_covered_aare(self.source, self.all_source, other_rule.source, other_rule.all_source, 'source'):
            return False
        if not self._is_covered_aare(self.dest, self.all_dest, other_rule.dest, other_rule.all_dest, 'dest'):
            return False

        return True

    def _is_equal_localvars(self, other_rule, strict):
        if self.operation != other_rule.operation:
            return False
        if self.fstype != other_rule.fstype or self.options != other_rule.options:
            return False
        if not self._is_equal_aare(self.source, self.all_source, other_rule.source, other_rule.all_source, 'source'):
            return False
        if not self._is_equal_aare(self.dest, self.all_dest, other_rule.dest, other_rule.all_dest, 'dest'):
            return False

        return True

    @staticmethod
    def hashlog_from_event(hl, ev):
        if ev['flags'] is not None:
            ev['flags'] = ('=', ev['flags'])
        if ev['fs_type'] is not None:
            ev['fs_type'] = ('=', ev['fs_type'])
        if ev['operation'] == 'mount':
            hl[ev['operation']][ev['flags']][ev['fs_type']][ev['name']][ev['src_name']] = True
        else:  # Umount
            hl[ev['operation']][ev['flags']][ev['fs_type']][ev['name']][None] = True

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
            self.options = [MountConditional('options', self.ALL, True, None)]
            self.all_options = True
        self.raw_rule = None

    def _logprof_header_localvars(self):
        operation = self.operation

        fstype_output = ()
        for fst in self.fstype:
            fstype = logprof_value_or_all(fst.values, fst.all_values)
            fstype_output = fstype_output + (_('Fstype'), (fst.operator, fstype) if fstype != 'ALL' else fstype)

        opts_output = ()
        for opt in self.options:
            options = logprof_value_or_all(opt.values, opt.all_values)
            opts_output = opts_output + (_('Options'), (opt.operator, options) if options != 'ALL' else options)
        source = logprof_value_or_all(self.source, self.all_source)
        dest = logprof_value_or_all(self.dest, self.all_dest)

        return (
            _('Operation'), operation,
            *fstype_output,
            *opts_output,
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


class MountConditional(MountRule):
    '''Class to handle and store mount conditionals'''
    def __init__(self, name, values, all_values, operator, cond_type=None):
        self.name = name
        self.values = values
        self.all_values = all_values
        self.operator = operator
        self.cond_type = cond_type
        self.raw_rule = ''  # needed so __repr__ calls get_clean

        if not self.all_values and self.operator not in ('=', 'in'):
            raise AppArmorBug(f'Invalid operator for {self.name}: {self.operator}')

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MountConditional):
            return False

        if self.all_values != other.all_values:
            return False

        if self.cond_type != other.cond_type:
            return False

        if self.values != other.values:
            return False

        if self.operator != other.operator:
            return False

        return True

    def is_covered(self, other: object) -> bool:
        if not isinstance(other, MountConditional):
            return False

        if self.name != other.name:
            return False

        if self.all_values:
            return True

        if other.all_values:
            return False

        if self.cond_type == 'list':
            if not self._is_covered_list(self.values, self.all_values, other.values, other.all_values, self.name):
                return False
        elif self.cond_type == 'aare':  # list of aares - all values in other must be at least once in self.values
            if not all(any(self._is_covered_aare(AARE(value, False), self.all_values,
                                                 AARE(other_value, False), other.all_values, self.name)
                           for value in self.values)
                       for other_value in other.values):
                return False
        else:
            raise AppArmorBug('Type should only be empty if ALL is true')

        if self.operator == other.operator:
            return True

        return False

    def get_clean(self, depth=0) -> str:
        conditional = ''
        if not self.all_values:
            if self.name == 'fstype' and self.operator == "=":
                conditional += ' %s%s%s' % (self.name, wrap_in_with_spaces(self.operator), ','.join(sorted(self.values)))
            else:
                conditional += ' %s%s(%s)' % (self.name, wrap_in_with_spaces(self.operator), ', '.join(sorted(self.values)))

        return conditional
