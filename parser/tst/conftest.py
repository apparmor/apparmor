#!/usr/bin/env python3
# ------------------------------------------------------------------
#
#   Copyright (C) 2026 Canonical Ltd.
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

# pytest configuration for parser/tst.
#
# Registers a --parser option so that the apparmor_parser binary path can be
# passed on the command line (mirroring the -p / --parser flag used by the
# standalone ./caching.py invocation).  The value is written to the
# APPARMOR_PARSER environment variable so that pytest-xdist worker processes
# inherit it automatically.

import os

import testlib


def pytest_addoption(parser):
    parser.addoption(
        '--parser',
        default=testlib.DEFAULT_PARSER,
        action='store',
        dest='parser',
        help='path to the apparmor_parser binary under test',
    )


def pytest_configure(config):
    parser_bin = config.option.parser
    os.environ['APPARMOR_PARSER'] = parser_bin
