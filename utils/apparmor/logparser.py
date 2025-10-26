# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2015-2019 Christian Boltz <apparmor@cboltz.de>
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
import ctypes
import re
import sys
import time

import LibAppArmor
import apparmor.ui as aaui
from apparmor.common import AppArmorBug, AppArmorException, DebugLogger, hasher, open_file_read, split_name
from apparmor.rule.capability import CapabilityRule
from apparmor.rule.change_profile import ChangeProfileRule
from apparmor.rule.dbus import DbusRule
from apparmor.rule.file import FileRule
from apparmor.rule.io_uring import IOUringRule
from apparmor.rule.mount import MountRule
from apparmor.rule.mqueue import MessageQueueRule
from apparmor.rule.network import NetworkRule
from apparmor.rule.pivot_root import PivotRootRule
from apparmor.rule.ptrace import PtraceRule
from apparmor.rule.signal import SignalRule
from apparmor.rule.unix import UnixRule
from apparmor.rule.userns import UserNamespaceRule
from apparmor.translations import init_translation

_ = init_translation()


class ReadLog:

    # used to pre-filter log lines so that we hand over only relevant lines to LibAppArmor parsing
    RE_LOG_ALL = re.compile('apparmor=|operation=|type=AVC')

    ruletypes = {
        'capability': CapabilityRule,
        'change_profile': ChangeProfileRule,
        'dbus': DbusRule,
        'file': FileRule,
        'ptrace': PtraceRule,
        'signal': SignalRule,
        'userns': UserNamespaceRule,
        'mqueue': MessageQueueRule,
        'io_uring': IOUringRule,
        'mount': MountRule,
        'unix': UnixRule,
        'network': NetworkRule,
        'pivot_root': PivotRootRule,
    }

    def __init__(self, filename, active_profiles, profile_dir):
        self.filename = filename
        self.profile_dir = profile_dir
        self.active_profiles = active_profiles
        self.hashlog = {'PERMITTING': {}, 'REJECTING': {}}  # structure inside {}: {'profilename': init_hashlog(aamode, profilename), 'profilename2': init_hashlog(...), ...}
        self.debug_logger = DebugLogger(type(self).__name__)
        self.LOG = None
        self.logmark = ''
        self.seenmark = None
        self.next_log_entry = None

    def init_hashlog(self, aamode, profile):
        """initialize self.hashlog[aamode][profile] for all rule types"""

        if profile in self.hashlog[aamode].keys():
            return  # already initialized, don't overwrite existing data

        self.hashlog[aamode][profile] = {
            'final_name':   profile,  # might be changed for null-* profiles based on exec decisions
            'capability':   {},  # flat, no hasher needed
            'change_hat':   {},  # flat, no hasher needed
            'change_profile': {},  # flat, no hasher needed  (at least in logparser which doesn't support EXEC MODE and EXEC COND)
            'dbus':         hasher(),
            'exec':         hasher(),
            'file':         hasher(),
            'network':      hasher(),
            'pivot_root':   hasher(),
            'ptrace':       hasher(),
            'signal':       hasher(),
            'userns':       hasher(),
            'mqueue':       hasher(),
            'io_uring':     hasher(),
            'mount':        hasher(),
            'unix':         hasher(),
        }

    def prefetch_next_log_entry(self):
        if self.next_log_entry:
            sys.stderr.out('A log entry already present: %s' % self.next_log_entry)
        self.next_log_entry = self.LOG.readline()
        while not self.RE_LOG_ALL.search(self.next_log_entry) and not (self.logmark and self.logmark in self.next_log_entry):
            self.next_log_entry = self.LOG.readline()
            if not self.next_log_entry:
                break

    def get_next_log_entry(self):
        # If no next log entry fetch it
        if not self.next_log_entry:
            self.prefetch_next_log_entry()
        log_entry = self.next_log_entry
        self.next_log_entry = None
        return log_entry

    def get_event_type(self, e):

        if e['operation'] == 'exec':
            return 'file'
        elif e['class'] and e['class'] == 'namespace':
            if e['denied_mask'] and e['denied_mask'].startswith('userns_'):
                return 'userns'
            elif not e['denied_mask'] and e['request_mask'].startswith('userns_'):  # To support transition to special userns profiles
                return 'userns'
        elif e['class'] and e['class'].endswith('mqueue'):
            return 'mqueue'
        elif e['class'] and e['class'] == 'io_uring':
            return 'io_uring'
        elif e['class'] and e['class'] == 'mount' or e['operation'] == 'mount':
            return 'mount'
        elif e['operation'] and e['operation'] == 'pivotroot':
            return 'pivot_root'
        elif e['class'] and e['class'] == 'net' and e['family'] and e['family'] == 'unix':
            return 'unix'
        elif e['class'] == 'file' or self.op_type(e) == 'file':
            return 'file'
        elif e['operation'] == 'capable':
            return 'capability'
        elif self.op_type(e) == 'net':
            return 'network'
        elif e['operation'] == 'change_hat':
            return 'change_hat'
        elif e['operation'] == 'change_profile':
            return 'change_profile'
        elif e['operation'] == 'ptrace':
            return 'ptrace'
        elif e['operation'] == 'signal':
            return 'signal'
        elif e['operation'] and e['operation'].startswith('dbus_'):
            return 'dbus'

        else:
            self.debug_logger.debug('UNHANDLED: %s', e)

        return None

    def get_rule_type(self, r):
        for k, v in self.ruletypes.items():
            if v.match(r):
                return k, v
        return None

    def create_rule_from_ev(self, ev):
        event_type = self.get_event_type(ev)
        if not event_type:
            return None
        ruletype = self.ruletypes[event_type]

        try:
            return ruletype.create_from_ev(ev)
        except (AppArmorException, AppArmorBug):
            return None

    def parse_record(self, event):
        """Parse the record from LibAppArmor into key value pairs"""
        ev = dict()
        ev['resource'] = event.info
        ev['active_hat'] = event.active_hat
        ev['aamode'] = event.event
        ev['time'] = event.epoch
        ev['operation'] = event.operation
        ev['profile'] = event.profile
        ev['name'] = event.name
        ev['name2'] = event.name2
        ev['attr'] = event.attribute
        ev['parent'] = event.parent
        ev['pid'] = event.pid
        ev['task'] = event.task
        ev['info'] = event.info
        ev['error_code'] = event.error_code
        ev['denied_mask'] = event.denied_mask
        ev['request_mask'] = event.requested_mask
        ev['magic_token'] = event.magic_token
        ev['family'] = event.net_family
        ev['protocol'] = event.net_protocol
        ev['sock_type'] = event.net_sock_type
        ev['class'] = event._class

        if event.ouid != ctypes.c_ulong(-1).value:  # ULONG_MAX
            ev['fsuid'] = event.fsuid
            ev['ouid'] = event.ouid

        event_type = self.get_event_type(ev)
        if event_type == 'signal':
            ev['signal'] = event.signal
            ev['peer'] = event.peer
        elif event_type == 'ptrace':
            ev['peer'] = event.peer
        elif event_type == 'pivot_root':
            ev['src_name'] = event.src_name
        elif event_type == 'mount':
            ev['flags'] = event.flags
            ev['fs_type'] = event.fs_type
            if ev['operation'] and ev['operation'] == 'mount':
                ev['src_name'] = event.src_name  # mount can have a source but not umount.
        elif event_type == 'userns':
            ev['execpath'] = event.execpath
            ev['comm'] = event.comm
        elif event_type == 'network':
            ev['accesses'] = event.requested_mask
            ev['port'] = event.net_local_port or None
            ev['remote_port'] = event.net_foreign_port or None
            ev['addr'] = event.net_local_addr
            ev['peer_addr'] = event.net_foreign_addr
            ev['addr'] = event.net_local_addr
            ev['peer_addr'] = event.net_foreign_addr
        elif event_type == 'unix':
            ev['accesses'] = event.requested_mask
            ev['port'] = event.net_local_port or None
            ev['remote_port'] = event.net_foreign_port or None
            ev['addr'] = event.net_addr
            ev['peer_addr'] = event.peer_addr
            ev['peer'] = event.peer
            ev['peer_profile'] = event.peer_profile
        elif event_type == 'dbus':
            ev['peer_profile'] = event.peer_profile
            ev['bus'] = event.dbus_bus
            ev['path'] = event.dbus_path
            ev['interface'] = event.dbus_interface
            ev['member'] = event.dbus_member

        elif event_type == 'io_uring':
            ev['peer_profile'] = event.peer_profile
        elif event_type == 'capability':
            ev['comm'] = event.comm

        if not ev['time']:
            ev['time'] = int(time.time())

        if ev['aamode']:
            # Convert aamode values to their counter-parts
            mode_convertor = {0: 'UNKNOWN',
                              1: 'ERROR',
                              2: 'AUDIT',
                              3: 'PERMITTING',
                              4: 'REJECTING',
                              5: 'HINT',
                              6: 'STATUS'
                              }
            try:
                ev['aamode'] = mode_convertor[ev['aamode']]
            except KeyError:
                ev['aamode'] = None

        # "translate" disconnected paths to errors, which means the event will be ignored.
        # XXX Ideally we should propose to add the attach_disconnected flag to the profile
        if ev['error_code'] == 13 and ev['info'] == 'Failed name lookup - disconnected path':
            ev['aamode'] = 'ERROR'

        if ev['aamode']:
            return ev
        else:
            return None

    def parse_event(self, msg):
        """Parse the event from log into key value pairs"""
        msg = msg.strip()
        self.debug_logger.info('parse_event: %s', msg)
        try:
            event = LibAppArmor.parse_record(msg)
        except TypeError:
            aaui.UI_Important(_("WARNING: Cannot process log message, skipping entry. Make sure log is plaintext."))
            return None

        ev = self.parse_record(event)
        LibAppArmor.free_record(event)
        return ev

    def parse_event_for_tree(self, e):
        aamode = e.get('aamode', 'UNKNOWN')

        if aamode == 'UNKNOWN':
            raise AppArmorBug('aamode is UNKNOWN - %s' % e['type'])  # should never happen

        if aamode in ('AUDIT', 'STATUS', 'ERROR'):
            return

        # Skip if AUDIT event was issued due to a change_hat in unconfined mode
        if not e.get('profile', False):
            return

        full_profile = e['profile']  # full, nested profile name
        self.init_hashlog(aamode, full_profile)

        # Convert new null profiles to old single level null profile
        if '//null-' in e['profile']:
            e['profile'] = 'null-complain-profile'

        profile, hat = split_name(e['profile'])

        if profile != 'null-complain-profile' and not self.profile_exists(profile):
            return
        # TODO: replace all the if conditions with a loop over 'ruletypes'
        if e['operation'] == 'exec':
            FileRule.hashlog_from_event(self.hashlog[aamode][full_profile]['exec'], e)
            return

        elif e['class'] and e['class'] == 'namespace':
            if e['denied_mask'].startswith('userns_'):
                UserNamespaceRule.hashlog_from_event(self.hashlog[aamode][full_profile]['userns'], e)
            return

        elif e['class'] and e['class'].endswith('mqueue'):
            MessageQueueRule.hashlog_from_event(self.hashlog[aamode][full_profile]['mqueue'], e)
            return

        elif e['class'] and e['class'] == 'io_uring':
            IOUringRule.hashlog_from_event(self.hashlog[aamode][full_profile]['io_uring'], e)
            return

        elif e['class'] and e['class'] == 'mount' or e['operation'] == 'mount':
            MountRule.hashlog_from_event(self.hashlog[aamode][full_profile]['mount'], e)

        elif e['operation'] and e['operation'] == 'pivotroot':
            PivotRootRule.hashlog_from_event(self.hashlog[aamode][full_profile]['pivot_root'], e)

        elif e['class'] and e['class'] == 'net' and e['family'] and e['family'] == 'unix':
            if not e['denied_mask']:
                self.debug_logger.debug('ignored garbage unix event with empty denied_mask')
                return

            UnixRule.hashlog_from_event(self.hashlog[aamode][full_profile]['unix'], e)
            return

        elif e['class'] == 'file' or self.op_type(e) == 'file':
            FileRule.hashlog_from_event(self.hashlog[aamode][full_profile]['file'], e)

        elif e['operation'] == 'capable':
            CapabilityRule.hashlog_from_event(self.hashlog[aamode][full_profile]['capability'], e)
            return

        elif self.op_type(e) == 'net':
            NetworkRule.hashlog_from_event(self.hashlog[aamode][full_profile]['network'], e)
            return

        elif e['operation'] == 'change_hat':
            if e['error_code'] == 1 and e['info'] == 'unconfined can not change_hat':
                return

            self.hashlog[aamode][full_profile]['change_hat'][e['name2']] = True
            return

        elif e['operation'] == 'change_profile':
            ChangeProfileRule.hashlog_from_event(self.hashlog[aamode][full_profile]['change_profile'], e)
            return

        elif e['operation'] == 'ptrace':
            if not e['peer']:
                self.debug_logger.debug('ignored garbage ptrace event with empty peer')
                return
            if not e['denied_mask']:
                self.debug_logger.debug('ignored garbage ptrace event with empty denied_mask')
                return

            PtraceRule.hashlog_from_event(self.hashlog[aamode][full_profile]['ptrace'], e)
            return

        elif e['operation'] == 'signal':
            SignalRule.hashlog_from_event(self.hashlog[aamode][full_profile]['signal'], e)
            return

        elif e['operation'] and e['operation'].startswith('dbus_'):
            DbusRule.hashlog_from_event(self.hashlog[aamode][full_profile]['dbus'], e)
            return

        else:
            self.debug_logger.debug('UNHANDLED: %s', e)

    def read_log(self, logmark):
        self.logmark = logmark
        seenmark = True
        if self.logmark:
            seenmark = False
        try:
            self.LOG = open_file_read(self.filename)
        except IOError:
            raise AppArmorException('Can not read AppArmor logfile: ' + self.filename)
        with self.LOG:
            line = True
            while line:
                line = self.get_next_log_entry()
                if not line:
                    break
                line = line.strip()
                self.debug_logger.debug('read_log: %s', line)
                if self.logmark in line:
                    seenmark = True

                self.debug_logger.debug('read_log: seenmark = %s', seenmark)
                if not seenmark:
                    continue

                event = self.parse_event(line)
                if event:
                    try:
                        self.parse_event_for_tree(event)
                    except AppArmorException as e:
                        ex_msg = ('%(msg)s\n\nThis error was caused by the log line:\n%(logline)s'
                                  % {'msg': e.value, 'logline': line})
                        raise AppArmorBug(ex_msg) from None

        self.logmark = ''

        return self.hashlog

    # operation types that can be network or file operations
    # (used by op_type() which checks some event details to decide)
    OP_TYPE_FILE_OR_NET = {
        # Note: op_type() also uses some startswith() checks which are not listed here!
        'create',
        'post_create',
        'bind',
        'connect',
        'listen',
        'accept',
        'sendmsg',
        'recvmsg',
        'getsockname',
        'getpeername',
        'getsockopt',
        'setsockopt',
        'socket_create',
        'sock_shutdown',
        'open',
        'truncate',
        'mkdir',
        'mknod',
        'chmod',
        'chown',
        'rename_src',
        'rename_dest',
        'unlink',
        'rmdir',
        'symlink',
        'symlink_create',
        'link',
        'sysctl',
        'getattr',
        'setattr',
        'xattr',
    }

    def op_type(self, event):
        """Returns the operation type if known, unknown otherwise"""

        if event['operation'] and (event['operation'].startswith('file_')
                                   or event['operation'].startswith('inode_')
                                   or event['operation'] in self.OP_TYPE_FILE_OR_NET):
            # file or network event?
            if event['family'] and event['protocol'] and event['sock_type']:
                # 'unix' events also use keywords like 'connect', but protocol is 0 and should therefore be filtered out
                return 'net'
            elif event['denied_mask'] or event['operation'] == 'file_lock':
                return 'file'
            else:
                raise AppArmorException('unknown file or network event type')

        else:
            return 'unknown'

    def profile_exists(self, program):
        """Returns True if profile exists, False otherwise"""
        # Check cache of profiles
        if self.active_profiles.filename_from_profile_name(program):
            return True

        return False
