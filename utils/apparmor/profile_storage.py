# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014-2024 Christian Boltz <apparmor@cboltz.de>
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

from types import NoneType

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.regex import parse_profile_start_line, re_print_dict
from apparmor.rule import quote_if_needed
from apparmor.rule.abi import AbiRule, AbiRuleset
from apparmor.rule.all import AllRule, AllRuleset
from apparmor.rule.capability import CapabilityRule, CapabilityRuleset
from apparmor.rule.change_profile import ChangeProfileRule, ChangeProfileRuleset
from apparmor.rule.dbus import DbusRule, DbusRuleset
from apparmor.rule.file import FileRule, FileRuleset
from apparmor.rule.include import IncludeRule, IncludeRuleset
from apparmor.rule.network import NetworkRule, NetworkRuleset
from apparmor.rule.ptrace import PtraceRule, PtraceRuleset
from apparmor.rule.rlimit import RlimitRule, RlimitRuleset
from apparmor.rule.signal import SignalRule, SignalRuleset
from apparmor.rule.userns import UserNamespaceRule, UserNamespaceRuleset
from apparmor.rule.mqueue import MessageQueueRule, MessageQueueRuleset
from apparmor.rule.io_uring import IOUringRule, IOUringRuleset
from apparmor.rule.mount import MountRule, MountRuleset
from apparmor.rule.pivot_root import PivotRootRule, PivotRootRuleset
from apparmor.rule.unix import UnixRule, UnixRuleset
from apparmor.rule.conditional import ConditionalBlock, ConditionalBlockset

from apparmor.translations import init_translation

_ = init_translation()

ruletypes = {
    'abi':            {'rule': AbiRule,           'ruleset': AbiRuleset},
    'inc_ie':         {'rule': IncludeRule,       'ruleset': IncludeRuleset},
    'all':            {'rule': AllRule,           'ruleset': AllRuleset},
    'capability':     {'rule': CapabilityRule,    'ruleset': CapabilityRuleset},
    'change_profile': {'rule': ChangeProfileRule, 'ruleset': ChangeProfileRuleset},
    'dbus':           {'rule': DbusRule,          'ruleset': DbusRuleset},
    'file':           {'rule': FileRule,          'ruleset': FileRuleset},
    'network':        {'rule': NetworkRule,       'ruleset': NetworkRuleset},
    'ptrace':         {'rule': PtraceRule,        'ruleset': PtraceRuleset},
    'rlimit':         {'rule': RlimitRule,        'ruleset': RlimitRuleset},
    'signal':         {'rule': SignalRule,        'ruleset': SignalRuleset},
    'userns':         {'rule': UserNamespaceRule, 'ruleset': UserNamespaceRuleset},
    'mqueue':         {'rule': MessageQueueRule,  'ruleset': MessageQueueRuleset},
    'io_uring':       {'rule': IOUringRule,       'ruleset': IOUringRuleset},
    'mount':          {'rule': MountRule,         'ruleset': MountRuleset},
    'pivot_root':     {'rule': PivotRootRule,     'ruleset': PivotRootRuleset},
    'unix':           {'rule': UnixRule,          'ruleset': UnixRuleset},
    'cond_block':     {'rule': ConditionalBlock,  'ruleset': ConditionalBlockset},
}


class ProfileStorage:
    """class to store the content (header, rules, comments) of a profilename

       Acts like a dict(), but has some additional checks.
    """

    def __init__(self, profilename, hat, calledby):
        data = dict()

        data['info'] = {'profile': profilename, 'hat': hat, 'calledby': calledby}

        for rule in ruletypes:
            data[rule] = ruletypes[rule]['ruleset']()

        data['filename'] = ''
        data['logprof_suggest'] = ''  # set in abstractions that should be suggested by aa-logprof
        data['parent'] = ''  # parent profile, or '' for top-level profiles and external hats
        data['name'] = ''
        data['attachment'] = ''
        data['xattrs'] = {}
        data['flags'] = ''
        data['external'] = False
        data['header_comment'] = ''  # comment in the profile/hat start line
        data['initial_comment'] = ''
        data['profile_keyword'] = False
        data['is_hat'] = False  # profile or hat?
        data['hat_keyword'] = False  # True for 'hat foo', False for '^foo'
        data['in_cond'] = False  # used for profiles created inside conditionals

        self.data = data

    def __getitem__(self, key):
        if key in self.data:
            return self.data[key]
        else:
            raise AppArmorBug('attempt to read unknown key %s' % key)

    def __setitem__(self, key, value):
        if key not in self.data:
            raise AppArmorBug('attempt to set unknown key %s' % key)

        allowed_types = {bool, str, dict, None, NoneType}
        old_type = type(self.data[key])
        if old_type in allowed_types:
            if key in {'flags', 'filename'} and type(value) in {str, NoneType}:
                self.data[key] = value
            elif isinstance(value, old_type):
                self.data[key] = value
            else:
                raise AppArmorBug('Attempt to change type of "%s" from %s to %s, value %s' % (key, old_type, type(value), value))
            self.data[key] = value
        else:
            raise AppArmorBug('Attempt to overwrite "%s" with %s, type %s' % (key, value, type(value)))

    def __repr__(self):
        classname = type(self).__name__
        header = '\n'.join(self.get_header(0, False))
        rules = '\n'.join(self.get_rules_clean(1))
        endprofile = '}'
        return f'\n<{classname}>\n{header}\n{rules}\n{endprofile}\n</{classname}>\n'

    def get(self, key, fallback=None):
        if key in self.data:
            return self.data.get(key, fallback)
        else:
            raise AppArmorBug('attempt to read unknown key %s' % key)

    def get_header(self, depth, embedded_hat):
        pre = ' ' * int(depth * 2)
        data = []
        unquoted_name = self.data['info']['profile']
        name = quote_if_needed(self.data['info']['profile'])

        attachment = ''
        if self.data['attachment']:
            attachment = ' %s' % quote_if_needed(self.data['attachment'])

        comment = ''
        if self.data['header_comment']:
            comment = ' %s' % self.data['header_comment']

        if self.data['external']:
            name = quote_if_needed(unquoted_name + '//' + self.data['info']['hat'])

        if not self.data['external'] and self.data['parent']:  # child profile
            name = quote_if_needed(self.data['info']['hat'])

        if self.data['is_hat']:
            if self.data['hat_keyword']:
                name = 'hat %s' % name
            else:
                name = '^%s' % name
        elif (not embedded_hat and not unquoted_name.startswith('/')) or (embedded_hat and not unquoted_name.startswith('^')) or self.data['attachment'] or self.data['profile_keyword']:
            name = 'profile %s%s' % (name, attachment)

        xattrs = ''
        if self.data['xattrs']:
            xattrs = ' xattrs=(%s)' % re_print_dict(self.data['xattrs'])

        flags = ''
        if self.data['flags']:
            flags = ' flags=(%s)' % self.data['flags']

        data.append('%s%s%s%s {%s' % (pre, name, xattrs, flags, comment))

        return data

    def get_rules_clean(self, depth):
        """return all clean rules of a profile (with default formatting, and leading whitespace as specified in the depth parameter)

           Note that the profile header and the closing "}" are _not_ included.
        """

        write_order = [
            'abi',
            'inc_ie',
            'rlimit',
            'capability',
            'cond_block',
            'network',
            'dbus',
            'mount',
            'mqueue',
            'signal',
            'ptrace',
            'pivot_root',
            'unix',
            'file',
            'change_profile',
            'userns',
            'io_uring',
        ]

        data = []

        for ruletype in write_order:
            data.extend(self.data[ruletype].get_clean(depth))

        return data

    def get_local_include(self):
        inc = None
        preferred_inc = self.data['name']
        if preferred_inc.startswith('/'):
            preferred_inc = preferred_inc[1:]
        preferred_inc = 'local/' + preferred_inc.replace('/', '.')

        # If a local profile already exists, we use it.
        for rule in self.data['inc_ie'].rules:
            if rule.path.startswith("local/"):
                inc = rule.path
                if rule.path == preferred_inc:  # Prefer includes that matches the profile name.
                    break
        return inc

    @classmethod
    def parse(cls, line, file, lineno, profile, hat):
        """parse a profile start line (using parse_profile_startline()) and convert it to an instance of this class"""

        matches = parse_profile_start_line(line, file)

        if profile:  # we are inside a profile, so we expect a child profile
            if not matches['profile_keyword']:
                raise AppArmorException(
                    _('%(profile)s profile in %(file)s contains syntax errors in line %(line)s: missing "profile" keyword.')
                    % {'profile': profile, 'file': file, 'line': lineno + 1})
            if hat is not None:
                # nesting limit reached - a child profile can't contain another child profile
                raise AppArmorException(
                    _('%(profile)s profile in %(file)s contains syntax errors in line %(line)s: a child profile inside another child profile is not allowed.')
                    % {'profile': profile, 'file': file, 'line': lineno + 1})

            parent = profile
            hat = matches['profile']
            prof_or_hat_name = hat
            pps_set_hat_external = False

        else:  # stand-alone profile
            parent = ''
            profile = matches['profile']
            prof_or_hat_name = profile
            if len(profile.split('//')) > 2:
                raise AppArmorException(
                    "Nested child profiles ('%(profile)s', found in %(file)s) are not supported by the AppArmor tools yet."
                    % {'profile': profile, 'file': file})
            elif len(profile.split('//')) == 2:
                profile, hat = profile.split('//')
                parent = profile
                pps_set_hat_external = True
            else:
                hat = profile
                pps_set_hat_external = False

        prof_storage = cls(profile, hat, cls.__name__ + '.parse()')

        prof_storage['parent'] = parent
        prof_storage['name'] = prof_or_hat_name
        prof_storage['filename'] = file
        prof_storage['external'] = pps_set_hat_external
        prof_storage['flags'] = matches['flags']
        prof_storage['header_comment'] = matches['comment'] or ''
        prof_storage['is_hat'] = matches['is_hat']

        if matches['is_hat']:
            prof_storage['hat_keyword'] = matches['hat_keyword']
        else:
            prof_storage['profile_keyword'] = matches['profile_keyword']
            prof_storage['attachment'] = matches['attachment'] or ''
            prof_storage['xattrs'] = matches['xattrs'] or {}

        return (profile, hat, prof_storage)


def split_flags(flags):
    """split the flags given as string into a sorted, de-duplicated list"""

    if flags is None:
        flags = ''

    # Flags may be whitespace and/or comma separated
    flags_list = flags.replace(',', ' ').split()
    # sort and remove duplicates
    return sorted(set(flags_list))


def add_or_remove_flag(flags, flags_to_change, set_flag):
    """add (if set_flag is True) or remove the given flags_to_change to flags"""

    if isinstance(flags, str) or flags is None:
        flags = split_flags(flags)

    if isinstance(flags_to_change, str) or flags_to_change is None:
        flags_to_change = split_flags(flags_to_change)

    if set_flag:
        for flag_to_change in flags_to_change:
            if flag_to_change not in flags:
                flags.append(flag_to_change)
    else:
        for flag_to_change in flags_to_change:
            if flag_to_change in flags:
                flags.remove(flag_to_change)

    return sorted(flags)


def var_transform(ref):
    data = []
    for value in sorted(ref):
        if not value:
            value = '""'
        data.append(quote_if_needed(value))
    return ' '.join(data)
