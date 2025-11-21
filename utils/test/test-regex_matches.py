#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2014 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest

import apparmor.aa as aa
from apparmor.common import AppArmorBug, AppArmorException
from apparmor.regex import (
    RE_PROFILE_CAP, RE_PROFILE_DBUS, RE_PROFILE_MOUNT, RE_PROFILE_PTRACE, RE_PROFILE_SIGNAL,
    RE_PROFILE_START, parse_profile_start_line, re_match_include, RE_PROFILE_UNIX,
    RE_PROFILE_PIVOT_ROOT,
    re_match_include_parse, strip_parenthesis, strip_quotes, resolve_variables, expand_braces,
    expand_var, expand_string, re_print_dict, re_parse_dict)
from common_test import AATest, setup_aa, setup_all_loops


class AARegexTest(AATest):
    def _run_test(self, params, expected):
        return _regex_test(self, params, expected)


class AANamedRegexTest(AATest):
    def _run_test(self, line, expected):
        """Run a line through self.regex.search() and verify the result

        Keyword arguments:
        line -- the line to search
        expected -- False if the search isn't expected to match or, if the search
                    is expected to match, a tuple of expected match groups.
        """
        matches = self.regex.search(line)
        if not expected:
            self.assertFalse(matches)
            return

        self.assertTrue(matches)

        for exp in expected:
            match = matches.group(exp)
            self.assertEqual(match, expected[exp], 'Group {} mismatch in rule {}'.format(exp, line))


class AARegexHasComma(AATest):
    """Tests for apparmor.aa.RE_RULE_HAS_COMMA"""

    def _check(self, line, expected=True):
        result = aa.RE_RULE_HAS_COMMA.search(line)
        if expected:
            self.assertTrue(result, 'Couldn\'t find a comma in "{}"'.format(line))
        else:
            self.assertEqual(None, result, 'Found an unexpected comma in "{}"'.format(line))


regex_has_comma_testcases = (
    ('dbus send%s', 'simple'),
    ('dbus (r, w, bind, eavesdrop)%s', 'embedded parens 01'),
    ('dbus (r, w,, bind, eavesdrop) %s', 'embedded parens 02'),
    ('dbus (r, w,, ) %s', 'embedded parens 03'),
    ('dbus () %s', 'empty parens'),
    ('member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName} %s ', 'embedded curly braces 01'),
    ('member={Hello,,,,,,AddMatch,,,NameHasOwner,StartServiceByName} %s ', 'embedded curly braces 02'),
    ('member={,Hello,,,,,,AddMatch,,,NameHasOwner,} %s ', 'embedded curly braces 03'),
    ('member={} %s ', 'empty curly braces'),
    ('dbus send%s# this is a comment', 'comment 01'),
    ('dbus send%s# this is a comment,', 'comment 02'),
    ('audit "/tmp/foo, bar" rw%s', 'quotes 01'),
    ('audit "/tmp/foo, bar" rw%s # comment', 'quotes 02'),
    ('audit "/tmp/foo, # bar" rw%s', 'comment embedded in quote 01'),
    ('audit "/tmp/foo, # bar" rw%s # comment', 'comment embedded in quote 02'),

    # lifted from parser/tst/simple_tests/vars/vars_alternation_3.sd
    ('/does/not/@{BAR},exist,notexist} r%s', 'partial alternation'),

    ('signal%s', 'bare signal'),
    ('signal receive%s', 'simple signal'),
    ('signal (send, receive)%s', 'embedded parens signal 01'),
    ('signal (send, receive) set=(hup, quit)%s', 'embedded parens signal 02'),

    ('ptrace%s', 'bare ptrace'),
    ('ptrace trace%s', 'simple ptrace'),
    ('ptrace (tracedby, readby)%s', 'embedded parens ptrace 01'),
    ('ptrace (trace) peer=/usr/bin/foo%s', 'embedded parens ptrace 02'),

    ('pivot_root%s', 'bare pivot_root'),
    ('pivot_root /old%s', 'pivot_root with old'),
    ('pivot_root /old new%s', 'pivot_root with new'),
    ('pivot_root /old /new -> child%s', 'pivot_root with child'),

    ('unix%s', 'bare unix'),
    ('unix create%s', 'simple unix'),
    ('peer=(addr=@abad1dea,label=a_profile) %s ', 'peer parens and comma'),
    ('type=stream%s', 'unix type'),
    ('unix (connect, receive, send)%s', 'unix perms'),

    # the following fail due to inadequacies in the regex
    # ('dbus (r, w, %s', 'incomplete dbus action'),
    # ('member="{Hello,AddMatch,RemoveMatch, %s', 'incomplete {} regex'),  # also invalid policy
    # ('member={Hello,AddMatch,RemoveMatch, %s', 'incomplete {} regex'),  # also invalid policy when trailing comma exists

    # the following passes the tests, but variable declarations are
    # odd in that they *don't* allow trailing commas; commas at the end
    # of the line need to be quoted.
    # ('@{BAR}={bar,baz,blort %s', 'tricksy variable declaration')
    # ('@{BAR}="{bar,baz,blort," %s', 'tricksy variable declaration')
    # The following fails the no comma test, but is invalid
    # ('@{BAR}={bar,baz,blort, %s', 'tricksy variable declaration')
    # The following fails the comma test, because it's really a no comma situation
    # ('@{BAR}="{bar,baz,blort%s" ', 'tricksy variable declaration')
)


def setup_has_comma_testcases():
    i = 0
    for (test_string, description) in regex_has_comma_testcases:
        i += 1

        def stub_test_comma(self, test_string=test_string):
            self._check(test_string % ',')

        def stub_test_no_comma(self, test_string=test_string):
            self._check(test_string % ' ', False)

        stub_test_comma.__doc__ = "test {} (w/comma)".format(description)
        stub_test_no_comma.__doc__ = "test {} (no comma)".format(description)
        setattr(AARegexHasComma, 'test_comma_{}'.format(i), stub_test_comma)
        setattr(AARegexHasComma, 'test_no_comma_{}'.format(i), stub_test_no_comma)


class AARegexSplitComment(AATest):
    """Tests for RE_HAS_COMMENT_SPLIT"""

    def _check(self, line, expected, comment=None, not_comment=None):
        result = aa.RE_HAS_COMMENT_SPLIT.search(line)
        if expected:
            self.assertTrue(result, 'Couldn\'t find a comment in "{}"'.format(line))
            self.assertEqual(
                result.group('comment'), comment,
                'Expected comment "{}", got "{}"'.format(comment, result.group('comment')))
            self.assertEqual(
                result.group('not_comment'), not_comment,
                'Expected not comment "{}", got "{}"'.format(not_comment, result.group('not_comment')))
        else:
            self.assertEqual(None, result, 'Found an unexpected comment "{}" in "{}"'.format(
                "" if result is None else result.group('comment'), line))


# Tuples of (string, expected result), where expected result is False if
# the string should not be considered as having a comment, or a second
# tuple of the not comment and comment sections split apart
regex_split_comment_testcases = (
    ('dbus send # this is a comment', ('dbus send ', '# this is a comment')),
    ('dbus send member=no_comment', False),
    ('dbus send member=no_comment, ', False),
    ('audit "/tmp/foo, # bar" rw', False),
    ('audit "/tmp/foo, # bar" rw # comment', ('audit "/tmp/foo, # bar" rw ', '# comment')),
    ('file,', False),
    ('file, # bare', ('file, ', '# bare')),
    ('file /tmp/foo rw, # read-write', ('file /tmp/foo rw, ', '# read-write')),
    ('signal, # comment', ('signal, ', '# comment')),
    ('signal receive set=(usr1 usr2) peer=foo,', False),
    ('ptrace, # comment', ('ptrace, ', '# comment')),
    ('ptrace (trace read) peer=/usr/bin/foo,', False),
    ('pivot_root, # comment', ('pivot_root, ', '# comment')),
    ('pivot_root /old /new -> child,', False),
)


def setup_split_comment_testcases():
    i = 0
    for (test_string, result) in regex_split_comment_testcases:
        i += 1

        def stub_test(self, test_string=test_string, result=result):
            if result is False:
                self._check(test_string, False)
            else:
                self._check(test_string, True, not_comment=result[0], comment=result[1])

        stub_test.__doc__ = "test '{}'".format(test_string)
        setattr(AARegexSplitComment, 'test_split_comment_{}'.format(i), stub_test)


def _regex_test(self, line, expected):
    """Run a line through self.regex.search() and verify the result

    Keyword arguments:
    line -- the line to search
    expected -- False if the search isn't expected to match or, if the search
                is expected to match, a tuple of expected match groups with all
                of the strings stripped
    """
    result = self.regex.search(line)
    if not expected:
        self.assertFalse(result)
        return

    self.assertTrue(result)

    groups = result.groups()
    self.assertEqual(len(groups), len(expected))
    for (i, group) in enumerate(groups):
        if group:
            group = group.strip()
        self.assertEqual(group, expected[i], 'Group {} mismatch in rule {}'.format(i, line))


class AARegexCapability(AARegexTest):
    """Tests for RE_PROFILE_CAP"""

    def AASetup(self):
        self.regex = RE_PROFILE_CAP

    tests = (
        ('   capability net_raw,', (None, None, None, None, 'net_raw', 'net_raw', None)),
        ('capability     net_raw   ,  ', (None, None, None, None, 'net_raw', 'net_raw', None)),
        ('   capability,', (None, None, None, None, None, None, None)),
        ('   capability   ,  ', (None, None, None, None, None, None, None)),
        ('   capabilitynet_raw,', False),
        ('   priority=1 capability net_raw,', ('priority=1', '1', None, None, 'net_raw', 'net_raw', None)),
        ('priority=1 capability     net_raw   ,  ', ('priority=1', '1', None, None, 'net_raw', 'net_raw', None)),
        ('   priority=1 capability,', ('priority=1', '1', None, None, None, None, None)),
        ('   priority=1 capability   ,  ', ('priority=1', '1', None, None, None, None, None)),
        ('   priority=1 capabilitynet_raw,', False),
    )


class AARegexDbus(AARegexTest):
    """Tests for RE_PROFILE_DBUS"""

    def AASetup(self):
        self.regex = RE_PROFILE_DBUS

    tests = (
        ('   dbus,',                                  (None, None, None,    None, 'dbus,',                        None,                     None)),
        ('   audit dbus,',                            (None, None, 'audit', None, 'dbus,',                        None,                     None)),
        ('   dbus send member=no_comment,',           (None, None, None,    None, 'dbus send member=no_comment,', 'send member=no_comment', None)),
        ('   dbus send member=no_comment, # comment', (None, None, None,    None, 'dbus send member=no_comment,', 'send member=no_comment', '# comment')),

        ('   priority=-11 dbus,',                                  ('priority=-11', '-11', None,    None, 'dbus,',                        None,                     None)),
        ('   priority=-11 audit dbus,',                            ('priority=-11', '-11', 'audit', None, 'dbus,',                        None,                     None)),
        ('   priority=-11 dbus send member=no_comment,',           ('priority=-11', '-11', None,    None, 'dbus send member=no_comment,', 'send member=no_comment', None)),
        ('   priority=-11 dbus send member=no_comment, # comment', ('priority=-11', '-11', None,    None, 'dbus send member=no_comment,', 'send member=no_comment', '# comment')),

        ('   dbusdriver,', False),
        ('   audit dbusdriver,', False),
        ('   priority=-11 audit dbusdriver,', False),
    )


class AARegexMount(AARegexTest):
    """Tests for RE_PROFILE_MOUNT"""

    def AASetup(self):
        self.regex = RE_PROFILE_MOUNT

    tests = (
        ('   mount,',           (None, None, None,    None,   'mount,',   'mount',   None, None)),
        ('   audit mount,',     (None, None, 'audit', None,   'mount,',   'mount',   None, None)),
        ('   umount,',          (None, None, None,    None,   'umount,',  'umount',  None, None)),
        ('   audit umount,',    (None, None, 'audit', None,   'umount,',  'umount',  None, None)),
        ('   unmount,',         (None, None, None,    None,   'unmount,', 'unmount', None, None)),
        ('   audit unmount,',   (None, None, 'audit', None,   'unmount,', 'unmount', None, None)),
        ('   remount,',         (None, None, None,    None,   'remount,', 'remount', None, None)),
        ('   deny remount,',    (None, None, None,    'deny', 'remount,', 'remount', None, None)),

        ('   priority = 0 mount,',           ('priority = 0', '0', None,    None,   'mount,',   'mount',   None, None)),
        ('   priority = 0 audit mount,',     ('priority = 0', '0', 'audit', None,   'mount,',   'mount',   None, None)),
        ('   priority = 0 umount,',          ('priority = 0', '0', None,    None,   'umount,',  'umount',  None, None)),
        ('   priority = 0 audit umount,',    ('priority = 0', '0', 'audit', None,   'umount,',  'umount',  None, None)),
        ('   priority = 0 unmount,',         ('priority = 0', '0', None,    None,   'unmount,', 'unmount', None, None)),
        ('   priority = 0 audit unmount,',   ('priority = 0', '0', 'audit', None,   'unmount,', 'unmount', None, None)),
        ('   priority = 0 remount,',         ('priority = 0', '0', None,    None,   'remount,', 'remount', None, None)),
        ('   priority = 0 deny remount,',    ('priority = 0', '0', None,    'deny', 'remount,', 'remount', None, None)),

        ('   mount, # comment', (None, None, None,    None,   'mount,',   'mount',   None, '# comment')),
        ('   priority = 0 mount, # comment', ('priority = 0', '0', None,    None,   'mount,',   'mount',   None, '# comment')),

        ('   mountain,', False),
        ('   audit mountain,', False),
        ('   priority = 0 audit mountain,', False),
    )


class AARegexSignal(AARegexTest):
    """Tests for RE_PROFILE_SIGNAL"""

    def AASetup(self):
        self.regex = RE_PROFILE_SIGNAL

    tests = (
        ('   signal,',                                            (None, None, None,    None, 'signal,',                                            None,                                         None)),
        ('   audit signal,',                                      (None, None, 'audit', None, 'signal,',                                            None,                                         None)),
        ('   signal receive,',                                    (None, None, None,    None, 'signal receive,',                                    'receive',                                    None)),
        ('   signal (send, receive),',                            (None, None, None,    None, 'signal (send, receive),',                            '(send, receive)',                            None)),
        ('   audit signal (receive),',                            (None, None, 'audit', None, 'signal (receive),',                                  '(receive)',                                  None)),
        ('   signal (send, receive) set=(usr1 usr2),',            (None, None, None,    None, 'signal (send, receive) set=(usr1 usr2),',            '(send, receive) set=(usr1 usr2)',            None)),
        ('   signal send set=(hup, quit) peer=/usr/sbin/daemon,', (None, None, None,    None, 'signal send set=(hup, quit) peer=/usr/sbin/daemon,', 'send set=(hup, quit) peer=/usr/sbin/daemon', None)),

        ('   priority = -1 signal,',                                            ('priority = -1', '-1', None,    None, 'signal,',                                            None,                                         None)),
        ('   priority = -1 audit signal,',                                      ('priority = -1', '-1', 'audit', None, 'signal,',                                            None,                                         None)),
        ('   priority = -1 signal receive,',                                    ('priority = -1', '-1', None,    None, 'signal receive,',                                    'receive',                                    None)),
        ('   priority = -1 signal (send, receive),',                            ('priority = -1', '-1', None,    None, 'signal (send, receive),',                            '(send, receive)',                            None)),
        ('   priority = -1 audit signal (receive),',                            ('priority = -1', '-1', 'audit', None, 'signal (receive),',                                  '(receive)',                                  None)),
        ('   priority = -1 signal (send, receive) set=(usr1 usr2),',            ('priority = -1', '-1', None,    None, 'signal (send, receive) set=(usr1 usr2),',            '(send, receive) set=(usr1 usr2)',            None)),
        ('   priority = -1 signal send set=(hup, quit) peer=/usr/sbin/daemon,', ('priority = -1', '-1', None,    None, 'signal send set=(hup, quit) peer=/usr/sbin/daemon,', 'send set=(hup, quit) peer=/usr/sbin/daemon', None)),

        ('   signalling,', False),
        ('   audit signalling,', False),
        ('   priority = -1 audit signalling,', False),
        ('   signalling receive,', False),
    )


class AARegexPtrace(AARegexTest):
    """Tests for RE_PROFILE_PTRACE"""

    def AASetup(self):
        self.regex = RE_PROFILE_PTRACE

    tests = (
        #                                            priority    audit    allow  rule                                  rule details                   comment
        ('   ptrace,',                              (None, None, None,    None, 'ptrace,',                             None,                          None)),
        ('   audit ptrace,',                        (None, None, 'audit', None, 'ptrace,',                             None,                          None)),
        ('   ptrace trace,',                        (None, None, None,    None, 'ptrace trace,',                       'trace',                       None)),
        ('   ptrace (tracedby, readby),',           (None, None, None,    None, 'ptrace (tracedby, readby),',          '(tracedby, readby)',          None)),
        ('   audit ptrace (read),',                 (None, None, 'audit', None, 'ptrace (read),',                      '(read)',                      None)),
        ('   ptrace trace peer=/usr/sbin/daemon,',  (None, None, None,    None, 'ptrace trace peer=/usr/sbin/daemon,', 'trace peer=/usr/sbin/daemon', None)),

        ('   priority=100 ptrace,',                              ('priority=100', '100', None,    None, 'ptrace,',                             None,                          None)),
        ('   priority=100 audit ptrace,',                        ('priority=100', '100', 'audit', None, 'ptrace,',                             None,                          None)),
        ('   priority=100 ptrace trace,',                        ('priority=100', '100', None,    None, 'ptrace trace,',                       'trace',                       None)),
        ('   priority=100 ptrace (tracedby, readby),',           ('priority=100', '100', None,    None, 'ptrace (tracedby, readby),',          '(tracedby, readby)',          None)),
        ('   priority=100 audit ptrace (read),',                 ('priority=100', '100', 'audit', None, 'ptrace (read),',                      '(read)',                      None)),
        ('   priority=100 ptrace trace peer=/usr/sbin/daemon,',  ('priority=100', '100', None,    None, 'ptrace trace peer=/usr/sbin/daemon,', 'trace peer=/usr/sbin/daemon', None)),

        ('   ptraceback,', False),
        ('   audit ptraceback,', False),
        ('   priority=100 audit ptraceback,', False),
        ('   ptraceback trace,', False),
    )


class AARegexPivotRoot(AARegexTest):
    """Tests for RE_PROFILE_PIVOT_ROOT"""

    def AASetup(self):
        self.regex = RE_PROFILE_PIVOT_ROOT

    tests = (
        ('   pivot_root,',                                      (None, None, None,    None, 'pivot_root,',                                None,                                 None)),
        ('   audit pivot_root,',                                (None, None, 'audit', None, 'pivot_root,',                                None,                                 None)),
        ('   pivot_root oldroot=/new/old,',                     (None, None, None,    None, 'pivot_root oldroot=/new/old,',               'oldroot=/new/old',                   None)),
        ('   pivot_root oldroot=/new/old /new,',                (None, None, None,    None, 'pivot_root oldroot=/new/old /new,',          'oldroot=/new/old /new',              None)),
        ('   pivot_root oldroot=/new/old /new -> child,',       (None, None, None,    None, 'pivot_root oldroot=/new/old /new -> child,', 'oldroot=/new/old /new -> child',     None)),
        ('   audit pivot_root oldroot=/new/old /new -> child,', (None, None, 'audit', None, 'pivot_root oldroot=/new/old /new -> child,', 'oldroot=/new/old /new -> child',     None)),

        ('   priority=-100 pivot_root,',                                      ('priority=-100', '-100', None,    None, 'pivot_root,',                                None,                                 None)),
        ('   priority=-100 audit pivot_root,',                                ('priority=-100', '-100', 'audit', None, 'pivot_root,',                                None,                                 None)),
        ('   priority=-100 pivot_root oldroot=/new/old,',                     ('priority=-100', '-100', None,    None, 'pivot_root oldroot=/new/old,',               'oldroot=/new/old',                   None)),
        ('   priority=-100 pivot_root oldroot=/new/old /new,',                ('priority=-100', '-100', None,    None, 'pivot_root oldroot=/new/old /new,',          'oldroot=/new/old /new',              None)),
        ('   priority=-100 pivot_root oldroot=/new/old /new -> child,',       ('priority=-100', '-100', None,    None, 'pivot_root oldroot=/new/old /new -> child,', 'oldroot=/new/old /new -> child',     None)),
        ('   priority=-100 audit pivot_root oldroot=/new/old /new -> child,', ('priority=-100', '-100', 'audit', None, 'pivot_root oldroot=/new/old /new -> child,', 'oldroot=/new/old /new -> child',     None)),

        ('pivot_root', False),  # comma missing

        ('pivot_rootbeer,', False),
        ('pivot_rootbeer    ,  ', False),
        ('pivot_rootbeer, # comment', False),
        ('pivot_rootbeer /new,  ', False),
        ('pivot_rootbeer /new, # comment', False),
        ('priority=-100 pivot_rootbeer /new, # comment', False),
    )


class AARegexUnix(AARegexTest):
    """Tests for RE_PROFILE_UNIX"""

    def AASetup(self):
        self.regex = RE_PROFILE_UNIX

    tests = (
        ('   unix,',                                                                               (None, None, None,    None,    'unix,',                                      None,                                   None)),
        ('   audit unix,',                                                                         (None, None, 'audit', None,    'unix,',                                      None,                                   None)),
        ('   unix accept,',                                                                        (None, None, None,    None,    'unix accept,',                               'accept',                               None)),
        ('   allow unix connect,',                                                                 (None, None, None,    'allow', 'unix connect,',                              'connect',                              None)),
        ('   audit allow unix bind,',                                                              (None, None, 'audit', 'allow', 'unix bind,',                                 'bind',                                 None)),
        ('   deny unix bind,',                                                                     (None, None, None,    'deny',  'unix bind,',                                 'bind',                                 None)),
        ('unix peer=(label=@{profile_name}),',                                                     (None, None, None,    None,    'unix peer=(label=@{profile_name}),',         'peer=(label=@{profile_name})',         None)),
        ('unix (receive) peer=(label=unconfined),',                                                (None, None, None,    None,    'unix (receive) peer=(label=unconfined),',    '(receive) peer=(label=unconfined)',    None)),
        (' unix (getattr, shutdown) peer=(addr=none),',                                            (None, None, None,    None,    'unix (getattr, shutdown) peer=(addr=none),', '(getattr, shutdown) peer=(addr=none)', None)),
        ('unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),', (None, None, None,    None,    'unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),',
                                                                                                                                                                    '(connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*")',  # noqa: E127
                                                                                                                                                                                                            None)),  # noqa: E127

        ('   priority=1 unix,',                                                                               ('priority=1', '1', None,    None,    'unix,',                                      None,                                   None)),
        ('   priority=1 audit unix,',                                                                         ('priority=1', '1', 'audit', None,    'unix,',                                      None,                                   None)),
        ('   priority=1 unix accept,',                                                                        ('priority=1', '1', None,    None,    'unix accept,',                               'accept',                               None)),
        ('   priority=1 allow unix connect,',                                                                 ('priority=1', '1', None,    'allow', 'unix connect,',                              'connect',                              None)),
        ('   priority=1 audit allow unix bind,',                                                              ('priority=1', '1', 'audit', 'allow', 'unix bind,',                                 'bind',                                 None)),
        ('   priority=1 deny unix bind,',                                                                     ('priority=1', '1', None,    'deny',  'unix bind,',                                 'bind',                                 None)),
        ('priority=1 unix peer=(label=@{profile_name}),',                                                     ('priority=1', '1', None,    None,    'unix peer=(label=@{profile_name}),',         'peer=(label=@{profile_name})',         None)),
        ('priority=1 unix (receive) peer=(label=unconfined),',                                                ('priority=1', '1', None,    None,    'unix (receive) peer=(label=unconfined),',    '(receive) peer=(label=unconfined)',    None)),
        (' priority=1 unix (getattr, shutdown) peer=(addr=none),',                                            ('priority=1', '1', None,    None,    'unix (getattr, shutdown) peer=(addr=none),', '(getattr, shutdown) peer=(addr=none)', None)),
        ('priority=1 unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),', ('priority=1', '1', None,    None,    'unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),',
                                                                                                                                                                    '(connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*")',  # noqa: E127
                                                                                                                                                                                                            None)),  # noqa: E127

        ('unixlike', False),
        ('deny unixlike,', False),
        ('priority=1 deny unixlike,', False),
    )


class AANamedRegexProfileStart_2(AANamedRegexTest):
    """Tests for RE_PROFILE_START"""

    def AASetup(self):
        self.regex = RE_PROFILE_START

    tests = (
        ('/bin/foo ', False),  # no '{'
        ('/bin/foo /bin/bar', False),  # missing 'profile' keyword
        ('profile {', False),  # no attachment
        ('   profile foo bar /foo {', False),  # missing quotes around "foo bar"
        ('bin/foo {', False),  # not starting with '/'
        ('"bin/foo" {', False),  # not starting with '/', quoted version

        ('   /foo {',                      {'plainprofile': '/foo',   'namedprofile': None,        'attachment': None,     'flags': None,         'comment': None}),
        ('   "/foo" {',                    {'plainprofile': '"/foo"', 'namedprofile': None,        'attachment': None,     'flags': None,         'comment': None}),
        ('   profile /foo {',              {'plainprofile': None,     'namedprofile': '/foo',      'attachment': None,     'flags': None,         'comment': None}),
        ('   profile "/foo" {',            {'plainprofile': None,     'namedprofile': '"/foo"',    'attachment': None,     'flags': None,         'comment': None}),
        ('   profile foo /foo {',          {'plainprofile': None,     'namedprofile': 'foo',       'attachment': '/foo',   'flags': None,         'comment': None}),
        ('   profile foo /foo (audit) {',  {'plainprofile': None,     'namedprofile': 'foo',       'attachment': '/foo',   'flags': 'audit',      'comment': None}),
        ('   profile "foo" "/foo" {',      {'plainprofile': None,     'namedprofile': '"foo"',     'attachment': '"/foo"', 'flags': None,         'comment': None}),
        ('   profile "foo bar" /foo {',    {'plainprofile': None,     'namedprofile': '"foo bar"', 'attachment': '/foo',   'flags': None,         'comment': None}),
        ('   /foo (complain) {',           {'plainprofile': '/foo',   'namedprofile': None,        'attachment': None,     'flags': 'complain',   'comment': None}),
        ('   /foo flags=(complain) {',     {'plainprofile': '/foo',   'namedprofile': None,        'attachment': None,     'flags': 'complain',   'comment': None}),
        ('   /foo (complain) { # x',       {'plainprofile': '/foo',   'namedprofile': None,        'attachment': None,     'flags': 'complain',   'comment': '# x'}),
        ('   /foo flags = ( complain ){#', {'plainprofile': '/foo',   'namedprofile': None,        'attachment': None,     'flags': ' complain ', 'comment': '#'}),
        ('  @{foo} {',                     {'plainprofile': '@{foo}', 'namedprofile': None,        'attachment': None,     'flags': None,         'comment': None}),
        ('  profile @{foo} {',             {'plainprofile': None,     'namedprofile': '@{foo}',    'attachment': None,     'flags': None,         'comment': None}),
        ('  profile @{foo} /bar {',        {'plainprofile': None,     'namedprofile': '@{foo}',    'attachment': '/bar',   'flags': None,         'comment': None}),
        ('  profile foo @{bar} {',         {'plainprofile': None,     'namedprofile': 'foo',       'attachment': '@{bar}', 'flags': None,         'comment': None}),
        ('  profile @{foo} @{bar} {',      {'plainprofile': None,     'namedprofile': '@{foo}',    'attachment': '@{bar}', 'flags': None,         'comment': None}),

        ('   /foo {',                      {'plainprofile': '/foo',   'namedprofile': None,  'leadingspace': '   '}),
        ('/foo {',                         {'plainprofile': '/foo',   'namedprofile': None,  'leadingspace': ''}),
        ('   profile foo {',               {'plainprofile': None,     'namedprofile': 'foo', 'leadingspace': '   '}),
        ('profile foo {',                  {'plainprofile': None,     'namedprofile': 'foo', 'leadingspace': ''}),
    )


class Test_parse_profile_start_line(AATest):
    tests = (
        ('   /foo {',                     {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': None,         'comment': None}),
        ('   "/foo" {',                   {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': None,         'comment': None}),
        ('   profile /foo {',             {'profile': '/foo',    'profile_keyword': True,  'plainprofile': None,     'namedprofile': '/foo',    'attachment': None,     'flags': None,         'comment': None}),
        ('   profile "/foo" {',           {'profile': '/foo',    'profile_keyword': True,  'plainprofile': None,     'namedprofile': '/foo',    'attachment': None,     'flags': None,         'comment': None}),
        ('   profile foo /foo {',         {'profile': 'foo',     'profile_keyword': True,  'plainprofile': None,     'namedprofile': 'foo',     'attachment': '/foo',   'flags': None,         'comment': None}),
        ('   profile foo /foo (audit) {', {'profile': 'foo',     'profile_keyword': True,  'plainprofile': None,     'namedprofile': 'foo',     'attachment': '/foo',   'flags': 'audit',      'comment': None}),
        ('   profile "foo" "/foo" {',     {'profile': 'foo',     'profile_keyword': True,  'plainprofile': None,     'namedprofile': 'foo',     'attachment': '/foo',   'flags': None,         'comment': None}),
        ('   profile "foo bar" /foo {',   {'profile': 'foo bar', 'profile_keyword': True,  'plainprofile': None,     'namedprofile': 'foo bar', 'attachment': '/foo',   'flags': None,         'comment': None}),
        ('   /foo (complain) {',          {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': 'complain',   'comment': None}),
        ('   /foo flags=(complain) {',    {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': 'complain',   'comment': None}),
        ('   /foo flags = ( complain ){', {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': ' complain ', 'comment': None}),
        ('   /foo (complain) { # x',      {'profile': '/foo',    'profile_keyword': False, 'plainprofile': '/foo',   'namedprofile': None,      'attachment': None,     'flags': 'complain',   'comment': '# x'}),

        ('   /foo {',                     {'profile': '/foo',  'leadingspace': '   ',      'plainprofile': '/foo',   'namedprofile': None}),
        ('/foo {',                        {'profile': '/foo',  'leadingspace': None,       'plainprofile': '/foo',   'namedprofile': None}),
        ('   profile foo {',              {'profile': 'foo',   'leadingspace': '   ',      'plainprofile': None,     'namedprofile': 'foo'}),
        ('profile foo {',                 {'profile': 'foo',   'leadingspace': None,       'plainprofile': None,     'namedprofile': 'foo'}),
        ('  @{foo} {',                    {'profile': '@{foo}',                            'plainprofile': '@{foo}', 'namedprofile': None,      'attachment': None,     'flags': None,         'comment': None}),
        ('  profile @{foo} {',            {'profile': '@{foo}',                            'plainprofile': None,     'namedprofile': '@{foo}',  'attachment': None,     'flags': None,         'comment': None}),
        ('  profile @{foo} /bar {',       {'profile': '@{foo}',                            'plainprofile': None,     'namedprofile': '@{foo}',  'attachment': '/bar',   'flags': None,         'comment': None}),
        ('  profile foo @{bar} {',        {'profile': 'foo',                               'plainprofile': None,     'namedprofile': 'foo',     'attachment': '@{bar}', 'flags': None,         'comment': None}),
        ('  profile @{foo} @{bar} {',     {'profile': '@{foo}',                            'plainprofile': None,     'namedprofile': '@{foo}',  'attachment': '@{bar}', 'flags': None,         'comment': None}),
    )

    def _run_test(self, line, expected):
        matches = parse_profile_start_line(line, 'somefile')

        self.assertTrue(matches)

        for exp in expected:
            self.assertEqual(
                matches[exp], expected[exp],
                'Group {} mismatch in rule {}'.format(exp, line))


class TestInvalid_parse_profile_start_line(AATest):
    tests = (
        ('/bin/foo ', False),  # no '{'
        ('/bin/foo /bin/bar', False),  # missing 'profile' keyword
        ('profile {', False),  # no attachment
        ('   profile foo bar /foo {', False),  # missing quotes around "foo bar"
    )

    def _run_test(self, line, expected):
        with self.assertRaises(AppArmorBug):
            parse_profile_start_line(line, 'somefile')


class Test_re_match_include(AATest):
    tests = (
        # #include
        ('#include <abstractions/base>',            'abstractions/base'),  # magic path
        ('#include <abstractions/base> # comment',  'abstractions/base'),
        ('#include<abstractions/base>#comment',     'abstractions/base'),
        ('   #include    <abstractions/base>  ',    'abstractions/base'),
        ('#include "/foo/bar"',                     '/foo/bar'),  # absolute path
        ('#include "/foo/bar" # comment',           '/foo/bar'),
        ('#include "/foo/bar"#comment',             '/foo/bar'),
        ('   #include "/foo/bar"  ',                '/foo/bar'),
        # include (without #)
        ('include <abstractions/base>',            'abstractions/base'),  # magic path
        ('include <abstractions/base> # comment',  'abstractions/base'),
        ('include<abstractions/base>#comment',     'abstractions/base'),
        ('   include    <abstractions/base>  ',    'abstractions/base'),
        ('include "/foo/bar"',                     '/foo/bar'),  # absolute path
        ('include "/foo/bar" # comment',           '/foo/bar'),
        ('include "/foo/bar"#comment',             '/foo/bar'),
        ('   include "/foo/bar"  ',                '/foo/bar'),

        (' some #include <abstractions/base>',      None),  # non-matching
        ('  /etc/fstab r,',                         None),
        ('/usr/include r,',                         None),
        ('/include r,',                             None),
        (' #include if exists <abstractions/base>', None),  # include if exists
        (' #include if exists "/foo/bar"',          None),
    )

    def _run_test(self, params, expected):
        self.assertEqual(re_match_include(params), expected)


class TestInvalid_re_match_include(AATest):
    tests = (
        ('#include <>',                  AppArmorException),  # '#include'
        ('#include <  >',                AppArmorException),
        ('#include ""',                  AppArmorException),
        ('#include "  "',                AppArmorException),
        ('#include',                     AppArmorException),
        ('#include  ',                   AppArmorException),
        ('#include "foo"',               AppArmorException),  # LP: 1738880 (relative)
        ('#include "foo" # comment',     AppArmorException),
        ('#include "foo"#comment',       AppArmorException),
        ('   #include "foo"  ',          AppArmorException),
        ('#include "foo/bar"',           AppArmorException),
        ('#include "foo/bar" # comment', AppArmorException),
        ('#include "foo/bar"#comment',   AppArmorException),
        ('   #include "foo/bar"  ',      AppArmorException),
        ('#include foo',                 AppArmorException),  # LP: 1738879 (no quotes)
        ('#include foo/bar',             AppArmorException),
        ('#include /foo/bar',            AppArmorException),
        ('#include foo bar',             AppArmorException),  # LP: 1738877 (space in name)
        ('#include foo bar/baz',         AppArmorException),
        ('#include "foo bar"',           AppArmorException),
        ('#include /foo bar',            AppArmorException),
        ('#include "/foo bar"',          AppArmorException),
        ('#include "foo bar/baz"',       AppArmorException),

        ('include <>',                   AppArmorException),  # 'include'
        ('include <  >',                 AppArmorException),
        ('include ""',                   AppArmorException),
        ('include "  "',                 AppArmorException),
        ('include',                      AppArmorException),
        ('include  ',                    AppArmorException),
        ('include "foo"',                AppArmorException),  # LP: 1738880 (relative)
        ('include "foo" # comment',      AppArmorException),
        ('include "foo"#comment',        AppArmorException),
        ('   include "foo"  ',           AppArmorException),
        ('include "foo/bar"',            AppArmorException),
        ('include "foo/bar" # comment',  AppArmorException),
        ('include "foo/bar"#comment',    AppArmorException),
        ('   include "foo/bar"  ',       AppArmorException),
        ('include foo',                  AppArmorException),  # LP: 1738879 (no quotes)
        ('include foo/bar',              AppArmorException),
        ('include /foo/bar',             AppArmorException),
        ('include foo bar',              AppArmorException),  # LP: 1738877 (space in name)
        ('include foo bar/baz',          AppArmorException),
        ('include "foo bar"',            AppArmorException),
        ('include /foo bar',             AppArmorException),
        ('include "/foo bar"',           AppArmorException),
        ('include "foo bar/baz"',        AppArmorException),
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            re_match_include(params)


class Test_re_match_include_parse(AATest):
    tests = (
        #                                                       path            if exists  magic path
        # #include
        ('#include <abstractions/base>',                      ('abstractions/base', False, True)),  # magic path
        ('#include <abstractions/base> # comment',            ('abstractions/base', False, True)),
        ('#include<abstractions/base>#comment',               ('abstractions/base', False, True)),
        ('   #include     <abstractions/base>  ',             ('abstractions/base', False, True)),
        ('#include "/foo/bar"',                               ('/foo/bar',          False, False)),  # absolute path
        ('#include "/foo/bar" # comment',                     ('/foo/bar',          False, False)),
        ('#include "/foo/bar"#comment',                       ('/foo/bar',          False, False)),
        ('   #include "/foo/bar"  ',                          ('/foo/bar',          False, False)),
        # include (without #)
        ('include <abstractions/base>',                       ('abstractions/base', False, True)),  # magic path
        ('include <abstractions/base> # comment',             ('abstractions/base', False, True)),
        ('include<abstractions/base>#comment',                ('abstractions/base', False, True)),
        ('   include     <abstractions/base>  ',              ('abstractions/base', False, True)),
        ('include "/foo/bar"',                                ('/foo/bar',          False, False)),  # absolute path
        ('include "/foo/bar" # comment',                      ('/foo/bar',          False, False)),
        ('include "/foo/bar"#comment',                        ('/foo/bar',          False, False)),
        ('   include "/foo/bar"  ',                           ('/foo/bar',          False, False)),
        # #include if exists
        ('#include if exists <abstractions/base>',            ('abstractions/base', True,  True)),  # magic path
        ('#include if exists <abstractions/base> # comment',  ('abstractions/base', True,  True)),
        ('#include if exists<abstractions/base>#comment',     ('abstractions/base', True,  True)),
        ('   #include    if     exists<abstractions/base>  ', ('abstractions/base', True,  True)),
        ('#include if exists "/foo/bar"',                     ('/foo/bar',          True,  False)),  # absolute path
        ('#include if exists "/foo/bar" # comment',           ('/foo/bar',          True,  False)),
        ('#include if exists "/foo/bar"#comment',             ('/foo/bar',          True,  False)),
        ('   #include if exists "/foo/bar"  ',                ('/foo/bar',          True,  False)),
        # include if exists (without #)
        ('include if exists <abstractions/base>',             ('abstractions/base', True,  True)),  # magic path
        ('include if exists <abstractions/base> # comment',   ('abstractions/base', True,  True)),
        ('include if exists<abstractions/base>#comment',      ('abstractions/base', True,  True)),
        ('   include    if     exists<abstractions/base>  ',  ('abstractions/base', True,  True)),
        ('include if exists "/foo/bar"',                      ('/foo/bar',          True,  False)),  # absolute path
        ('include if exists "/foo/bar" # comment',            ('/foo/bar',          True,  False)),
        ('include if exists "/foo/bar"#comment',              ('/foo/bar',          True,  False)),
        ('   include if exists "/foo/bar"  ',                 ('/foo/bar',          True,  False)),

        (' some #include if exists <abstractions/base>',      (None,                None,  None)),  # non-matching
        ('  /etc/fstab r,',                                   (None,                None,  None)),
        ('/usr/include r,',                                   (None,                None,  None)),
        ('/include r,',                                       (None,                None,  None)),
        ('abi <abi/4.19>,',                                   (None,                None,  None)),  # abi rule
    )

    def _run_test(self, params, expected):
        self.assertEqual(re_match_include_parse(params, 'include'), expected)


class Test_re_match_include_parse_abi(AATest):
    tests = (
        #                                                   path     if exists  magic path
        ('abi <abi/4.19>,',                                ('abi/4.19',  False, True)),  # magic path
        ('abi <abi/4.19>, # comment',                      ('abi/4.19',  False, True)),
        ('   abi    <abi/4.19>   ,    #    comment',       ('abi/4.19',  False, True)),
        ('abi "/abi/4.19" ,',                              ('/abi/4.19', False, False)),  # quoted path starting with /
        ('abi "/abi/4.19",     #  comment',                ('/abi/4.19', False, False)),
        ('  abi     "/abi/4.19"    ,    #      comment  ', ('/abi/4.19', False, False)),
        ('  abi     "abi/4.19"    ,    #      comment  ',  ('abi/4.19',  False, False)),  # quoted path, no leading /
        ('abi abi/4.19,',                                  ('abi/4.19',  False, False)),  # without quotes
        ('some abi <abi/4.19>,',                           (None,        None,  None)),  # non-matching
        ('  /etc/fstab r,',                                (None,        None,  None)),
        ('/usr/abi r,',                                    (None,        None,  None)),
        ('/abi r,',                                        (None,        None,  None)),
        ('#include <abstractions/base>',                   (None,        None,  None)),  # include rule path
    )

    def _run_test(self, params, expected):
        self.assertEqual(re_match_include_parse(params, 'abi'), expected)


class Test_re_match_include_parse_errors(AATest):
    tests = (
        (('include <>', 'include'), AppArmorException),  # various rules with empty filename
        (('include ""', 'include'), AppArmorException),
        (('include   ', 'include'), AppArmorException),
        (('abi <>,',    'abi'),     AppArmorException),
        (('abi "",',    'abi'),     AppArmorException),
        (('abi   ,',    'abi'),     AppArmorException),
        (('abi <foo>,', 'invalid'), AppArmorBug),  # invalid rule name
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            rule, rule_name = params
            re_match_include_parse(rule, rule_name)


class TestStripParenthesis(AATest):
    tests = (
        ('foo',      'foo'),
        ('(foo)',    'foo'),
        ('(  foo )', 'foo'),
        ('(foo',     '(foo'),
        ('foo  )',   'foo  )'),
        ('foo ()',   'foo ()'),
        ('()',       ''),
        ('(  )',     ''),
        ('(())',     '()'),
        (' (foo)',   '(foo)'),  # parenthesis not first char, whitespace stripped nevertheless
        ('(foo) ',   '(foo)'),  # parenthesis not last char, whitespace stripped nevertheless
    )

    def _run_test(self, params, expected):
        self.assertEqual(strip_parenthesis(params), expected)


class TestStripQuotes(AATest):
    tests = (
        ('foo',             'foo'),
        ('"foo"',           'foo'),
        ('"foo',            '"foo'),
        ('foo"',            'foo"'),
        ('""',              ''),
        ('foo"bar',         'foo"bar'),
        ('"foo"bar"',       'foo"bar'),
        ('""""foo"bar""""', '"""foo"bar"""'),
        ('',                ''),
        ('/',               '/'),
        ('"',               '"'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(strip_quotes(params), expected)


class TestExpandBraces(AATest):
    tests = (
        ('foo',                     ['foo']),
        ('/{,foo}',                 ['/', '/foo']),
        ('/{,foo,bar}',             ['/', '/foo', '/bar']),
        ('/{bin,sbin}/runc',        ['/bin/runc', '/sbin/runc']),
        ('/{,usr/}{,s}bin/runc',    ['/bin/runc', '/sbin/runc', '/usr/bin/runc', '/usr/sbin/runc']),
        ('/{,usr/{,s}}bin/runc',    ['/bin/runc', '/usr/bin/runc', '/usr/sbin/runc']),
        ('{{a,b},{c,{d,e}},f}',     ['a', 'b', 'c', 'd', 'e', 'f']),
        ('{,b}{d,e}',               ['d', 'e', 'bd', 'be']),
        ('{aa,b}{d,e}',             ['aad', 'aae', 'bd', 'be']),
        ('{{foo,bar},{baz,qux}}',   ['foo', 'bar', 'baz', 'qux']),
    )

    def _run_test(self, params, expected):
        self.assertEqual(expand_braces(params), expected)


class TestInvalidExpandBraces(AATest):
    tests = (
        # Malformed expressions
        ('/{',              AppArmorException),
        ('/{}}{',           AppArmorException),
        ('/}',              AppArmorException),
        ('/{foo,bar}}',     AppArmorException),
        ('/{a,b},{c,d}}',   AppArmorException),
        # Braces should always provide at least 2 alternatives
        ('{foo}',           AppArmorException),
        ('/{foo}/',         AppArmorException),
        ('/{,foo}{bar}',    AppArmorException),

    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            expand_braces(params)


var_dict = {
    # Normal variables
    '@{a}': ['AAA'],
    '@{b}': ['BBB'],
    # Multiple values variables
    '@{c}': ['CC', 'CCC'],
    '@{d}': ['DD', 'DDD', 'DDDD'],
    # Variable relying on other variables
    '@{e}': ['@{a}'],
    '@{f}': ['@{e}@{b}', '@{c}'],
    '@{g}': ['/bin/@{f}/{foo,bar}'],
    # Invalid variables
    '@{h}': ['@{h}'],  # Self reference
    '@{i}': ['@{j}'],  # Circular reference with i and j
    '@{j}': ['@{i}'],
}


class TestResolveVariables(AATest):
    tests = (
        ('@{a}',        ['AAA']),
        ('/@{a}/@{b}/', ['/AAA/BBB/']),
        ('/@{a}/@{c}/', ['/AAA/CC/', '/AAA/CCC/']),
        ('/@{a}/@{d}/', ['/AAA/DD/', '/AAA/DDD/', '/AAA/DDDD/']),
        ('/@{c}/@{d}/', ['/CC/DD/', '/CC/DDD/', '/CC/DDDD/', '/CCC/DD/', '/CCC/DDD/', '/CCC/DDDD/']),
        ('/@{e}/',      ['/AAA/']),
        ('/@{f}/',      ['/AAABBB/', '/CC/', '/CCC/']),
        ('@{g}',        ['/bin/AAABBB/{foo,bar}', '/bin/CC/{foo,bar}', '/bin/CCC/{foo,bar}']),
        ('@nota{var}',  ['@nota{var}']),  # not a variable to be expanded
        ('@{foo,bar}',  ['@{foo,bar}']),  # @ followed by alternation, not a variable to be expanded
    )

    def _run_test(self, params, expected):
        self.assertEqual(resolve_variables(params, var_dict), expected)


class TestInvalidResolveVariables(AATest):
    tests = (
        ('@{h}', AppArmorException),
        ('@{i}', AppArmorException),
        ('@{z}', AppArmorException),  # @{z} doesn't exist
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            resolve_variables(params, var_dict)


class TestExpandVar(AATest):
    tests = (
        (('@{a}', set()), ['AAA']),
        (('@{d}', set()), ['DD', 'DDD', 'DDDD']),
        (('@{f}', set()), ['AAABBB', 'CC', 'CCC']),
    )

    def _run_test(self, params, expected):
        var, seen_vars = params
        self.assertEqual(expand_var(var, var_dict, seen_vars), expected)


class TestInvalidExpandVar(AATest):
    tests = (
        (('@{h}',   set()),     AppArmorException),  # Circular dependency
        (('@{a}',   {'@{a}'}),  AppArmorException),  # Circular dependency
        (('@{z}',   set()),     AppArmorException),  # Invalid variable (not in var_dict)
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            var, seen_vars = params
            expand_var(var, var_dict, seen_vars)


class TestExpandString(AATest):
    tests = (
        ('@{g}/@{a}', ['/bin/AAABBB/{foo,bar}/AAA', '/bin/CC/{foo,bar}/AAA', '/bin/CCC/{foo,bar}/AAA']),
        ('@{g}/@{c}', ['/bin/AAABBB/{foo,bar}/CC', '/bin/AAABBB/{foo,bar}/CCC', '/bin/CC/{foo,bar}/CC', '/bin/CC/{foo,bar}/CCC', '/bin/CCC/{foo,bar}/CC', '/bin/CCC/{foo,bar}/CCC']),
    )

    def _run_test(self, params, expected):
        self.assertEqual(expand_string(params, var_dict, set()), expected)


class TestInvalidExpandString(AATest):
    tests = (
        (('@{h}',   set()),     AppArmorException),  # Circular dependency
        (('@{a}',   {'@{a}'}),  AppArmorException),  # Circular dependency
        (('@{z}',   set()),     AppArmorException),  # Invalid variable (not in var_dict)
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            var, seen_vars = params
            expand_string(var, var_dict, seen_vars)


class TestRePrintDict(AATest):
    tests = (
        ({'a': 'b'},            'a=b'),
        ({'a': 'b', 'bb': 'cc'}, 'a=b bb=cc'),
        ({'z': 'c', 'y': 'b', 'x': 'a'}, 'x=a y=b z=c'),
    )

    def _run_test(self, params, expected):
        self.assertEqual(re_print_dict(params), expected)


class TestReParseDict(AATest):
    tests = (
        ('a=b', {'a': 'b'}),
        ('  a=bbb  bb=cc', {'a': 'bbb', 'bb': 'cc'}),
    )

    def _run_test(self, params, expected):
        self.assertEqual(re_parse_dict(params), expected)


setup_aa(aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    # these two are not converted to a tests[] loop yet
    setup_has_comma_testcases()
    setup_split_comment_testcases()

    unittest.main(verbosity=1)
