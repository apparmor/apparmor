# ----------------------------------------------------------------------
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.common import convert_regexp, AppArmorBug, AppArmorException


path_entry = r"(/[^\n,]*|(@{[^\n,}]*}[^\n,]*))"
# XXX Matching using this regex is not perfect but should be enough for practical scenarios. Limitations are:
#  - We do not look recursively '{', therefore some weird-but-valid string such as {{/foo,/bar},{/baz,/qux}} are denied
#  - Variables are not replaced: we have to accept "@{" regardless of whether it contains an actual path
AARE_PATH_REGEX = re.compile(
    r"^" + path_entry
    + r"|{" + path_entry + "," + path_entry + "*}$"
)


class AARE:
    """AARE (AppArmor Regular Expression) wrapper class"""

    def __init__(self, regex, is_path, log_event=None):
        """Initialize instance for the given AppArmor regex.
        If is_path is true, the regex is expected to be a path and therefore must start with / or a variable."""
        # using the specified variables when matching.

        if is_path and not AARE_PATH_REGEX.match(regex):
            raise AppArmorException("Path doesn't start with / or variable: %s" % regex)

        if log_event:
            self.orig_regex = regex
            self.regex = convert_expression_to_aare(regex)
        else:
            self.orig_regex = None
            self.regex = regex

        self._regex_compiled = None  # done on first use in match() - that saves us some re.compile() calls
        # self.variables = variables  # XXX

    def __repr__(self):
        """returns a "printable" representation of object"""
        return type(self).__name__ + "('%s')" % self.regex

    def __eq__(self, other):
        """check if the given object is equal
           Note that the == check is more strict than is_equal() - it doesn't accept if other is a string instead of AARE"""

        if isinstance(other, type(self)):
            return self.regex == other.regex

        return False

    # check if a regex is a plain path (not containing variables, alternations or wildcards)
    # some special characters are probably not covered by the plain_path regex (if in doubt, better error out on the safe side)
    plain_path = re.compile('^[0-9a-zA-Z/._-]+$')

    def match(self, expression):
        """check if the given expression (string or instance of this class) matches the regex"""

        if isinstance(expression, type(self)):
            if expression.orig_regex:
                expression = expression.orig_regex
            elif self.plain_path.match(expression.regex):
                # regex doesn't contain variables or wildcards, therefore handle it as plain path
                expression = expression.regex
            else:
                return self.is_equal(expression)  # better safe than sorry
        elif not isinstance(expression, str):
            raise AppArmorBug('match() called with unknown object: %s' % str(expression))

        if self._regex_compiled is None:
            self._regex_compiled = re.compile(convert_regexp(self.regex))

        return bool(self._regex_compiled.match(expression))

    def is_equal(self, expression):
        """check if the given expression is equal"""

        if isinstance(expression, type(self)):
            return self.regex == expression.regex
        elif isinstance(expression, str):
            return self.regex == expression
        else:
            raise AppArmorBug('is_equal() called with unknown object: %s' % str(expression))

    def glob_path(self):
        """Glob the given file or directory path"""
        if self.regex.endswith('/'):
            if self.regex.endswith(('/**/', '/*/')):
                # /foo/**/ and /foo/*/ => /**/
                newpath = re.sub(r'/[^/]+/\*{1,2}/$', '/**/', self.regex)
            elif re.search(r'/[^/]+\*\*[^/]*/$', self.regex):
                # /foo**/ and /foo**bar/ => /**/
                newpath = re.sub(r'/[^/]+\*\*[^/]*/$', '/**/', self.regex)
            elif re.search(r'/\*\*[^/]+/$', self.regex):
                # /**bar/ => /**/
                newpath = re.sub(r'/\*\*[^/]+/$', '/**/', self.regex)
            else:
                newpath = re.sub('/[^/]+/$', '/*/', self.regex)
        else:
            if self.regex.endswith(('/**', '/*')):
                # /foo/** and /foo/* => /**
                newpath = re.sub(r'/[^/]+/\*{1,2}$', '/**', self.regex)
            elif re.search(r'/[^/]*\*\*[^/]+$', self.regex):
                # /**foo and /foor**bar => /**
                newpath = re.sub(r'/[^/]*\*\*[^/]+$', '/**', self.regex)
            elif re.search(r'/[^/]+\*\*$', self.regex):
                # /foo** => /**
                newpath = re.sub(r'/[^/]+\*\*$', '/**', self.regex)
            else:
                newpath = re.sub('/[^/]+$', '/*', self.regex)
        return type(self)(newpath, False)

    def glob_path_withext(self):
        """Glob given file path with extension
           Files without extensions and directories won't be changed"""
        # match /**.ext and /*.ext
        match = re.search(r'/\*{1,2}(\.[^/]+)$', self.regex)
        if match:
            # /foo/**.ext and /foo/*.ext => /**.ext
            newpath = re.sub(r'/[^/]+/\*{1,2}\.[^/]+$', '/**' + match.groups()[0], self.regex)
        elif re.search(r'/[^/]+\*\*[^/]*\.[^/]+$', self.regex):
            # /foo**.ext and /foo**bar.ext => /**.ext
            match = re.search(r'/[^/]+\*\*[^/]*(\.[^/]+)$', self.regex)
            newpath = re.sub(r'/[^/]+\*\*[^/]*\.[^/]+$', '/**' + match.groups()[0], self.regex)
        elif re.search(r'/\*\*[^/]+\.[^/]+$', self.regex):
            # /**foo.ext => /**.ext
            match = re.search(r'/\*\*[^/]+(\.[^/]+)$', self.regex)
            newpath = re.sub(r'/\*\*[^/]+\.[^/]+$', '/**' + match.groups()[0], self.regex)
        else:
            newpath = self.regex
            match = re.search(r'(\.[^/]+)$', self.regex)
            if match:
                newpath = re.sub(r'/[^/]+(\.[^/]+)$', '/*' + match.groups()[0], self.regex)
        return type(self)(newpath, False)


def convert_expression_to_aare(expression):
    """convert an expression (taken from audit.log) to an AARE string"""

    aare_escape_chars = ['\\', '?', '*', '[', ']', '{', '}', '"', '!']
    for char in aare_escape_chars:
        expression = expression.replace(char, '\\' + char)

    return expression
