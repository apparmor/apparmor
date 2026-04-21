#!/usr/bin/env python3
import sys
import subprocess
import re
import os


VERBOSE = bool(os.environ.get('VERBOSE'))

NAME_RE     = re.compile(r'^Name:\s*(\S+)')
PERMS_ALL   = re.compile(r'^Perms:.*r.*:.*:.*\(/\{?,?\*\*,?}?\)')
ATTACH_RE   = re.compile(r'^Attachment:\s*(.+)')

RED = '\033[0;31m'
GREEN = '\033[0;32m'
NORMAL = '\033[0m'

def die(msg):
    print(RED + msg + NORMAL, file=sys.stderr)
    sys.exit(1)

def check_profile(name, prof_file, skip, attachment, lines):
    if skip:
        if VERBOSE:
            print('Profile "{}" skipped: {}'.format(name, skip))
        return

    pat = re.compile(r'^Perms:.*r.*:.*:.*\({}\)'.format(re.escape(attachment)))
    for l in lines:
        if pat.match(l):
            if VERBOSE:
                print(GREEN + 'Profile {} ({}): OK "{}" found'.format(prof_file, name, attachment) + NORMAL)
            return

    die('Profile {} ({}): ERROR: no Perms rule for "{}".'.format(prof_file, name, attachment))

def process_profile(profile, extra_args):
    cmd = ['../parser/apparmor_parser'] + extra_args + ['-d', profile]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        die('ERROR: Failed to parse "{}": {}'.format(profile, proc.stdout.strip()))

    lines = proc.stdout.splitlines()
    curr_name = ''
    attachment = ''
    skip = None
    in_entries = False
    block = []

    for line in lines:
        m = NAME_RE.match(line)
        if m:
            if curr_name:
                # check previously found profile
                check_profile(curr_name, profile, skip, attachment, block)

            # remember newly found profile
            curr_name = m.group(1)
            attachment = ''
            skip = None
            in_entries = False
            block = []
            continue

        if PERMS_ALL.match(line):
            skip = 'All files available'
            continue

        m = ATTACH_RE.match(line)
        if m:
            attachment = m.group(1)
            if attachment == '<NULL>':
                skip = 'no attachment'
            continue

        if line.strip() == '--- Entries ---':
            in_entries = True
            continue

        if in_entries:
            block.append(line)

    if not block:
        skip = 'no rules'
    # Last profile
    check_profile(curr_name, profile, skip, attachment, block)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {0} <profile-file> [parser_extra_args]'.format(sys.argv[0]))
        sys.exit(1)
    process_profile(sys.argv[1], sys.argv[2:])
