#!/usr/bin/python3

import os
import subprocess
import sys

# pkexec scrubs PYTHONPATH; Python's default sys.path puts this file's own
# dir (the apparmor package) on it, not the parent. Prepend the parent so
# `import apparmor.*` resolves to the co-located checkout, not whatever's
# installed system-wide.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apparmor import aa  # noqa: E402
from apparmor.logparser import ReadLog  # noqa: E402

from apparmor.translations import init_translation  # noqa: E402

_ = init_translation()


def create_userns(template_path, name, bin_path, profile_path, decision):
    with open(template_path, 'r') as f:
        profile_template = f.read()

    rule = 'userns create' if decision == 'allow' else 'audit deny userns create'
    profile = profile_template.format(rule=rule, name=name, path=bin_path)

    with open(profile_path, 'w') as file:
        file.write(profile)

    try:
        subprocess.run(['apparmor_parser', '-r', profile_path], check=True)
    except subprocess.CalledProcessError:
        exit(_('Cannot reload updated profile'))


def add_to_profile(rule, profile_name):
    aa.init_aa()
    aa.read_profiles()

    rule_type, rule_class = ReadLog('', '', '').get_rule_type(rule)

    rule_obj = rule_class.create_instance(rule)

    if profile_name not in aa.aa or profile_name not in aa.aa[profile_name]:
        exit(_('Cannot find {} in profiles').format(profile_name))
    aa.aa[profile_name][profile_name][rule_type].add(rule_obj, cleanup=True)

    # Save changes
    aa.write_profile_ui_feedback(profile_name)
    aa.reload_base(profile_name)


def usage(is_help):
    print('This tool is a low level tool - do not use it directly')
    print('{} create_userns <template_path> <name> <bin_path> <profile_path> <decision>'.format(sys.argv[0]))
    print('{} add_rule <rule> <profile_name>'.format(sys.argv[0]))

    if is_help:
        exit(0)
    else:
        exit(1)


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = None  # Handle the case where no command is provided

    if command == 'create_userns':
        if not len(sys.argv) == 7:
            usage(False)
        create_userns(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif command == 'add_rule':
        if not len(sys.argv) == 4:
            usage(False)
        add_to_profile(sys.argv[2], sys.argv[3])
    elif command == 'help':
        usage(True)
    else:
        usage(False)


if __name__ == '__main__':
    main()
