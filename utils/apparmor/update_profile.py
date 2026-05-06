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

is_aa_inited = False


def init_if_needed():
    global is_aa_inited
    if not is_aa_inited:
        aa.init_aa()
        aa.read_profiles()
        is_aa_inited = True


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


def add_to_profile(rule_obj, profile_name):
    aa.active_profiles[profile_name][rule_obj.rule_name].add(rule_obj, cleanup=True)

    # Save changes
    aa.write_profile_ui_feedback(profile_name)


def add_to_local_profile(rule_obj, profile_name):
    inc_file = aa.create_local_profile_if_needed(profile_name)

    aa.include[inc_file][inc_file].data[rule_obj.rule_name].add(rule_obj, cleanup=True)
    aa.write_include_ui_feedback(aa.include[inc_file][inc_file], inc_file)


def add_rule(mode, rule, profile_name):
    init_if_needed()

    if not aa.active_profiles.profile_exists(profile_name):
        exit(_('Cannot find {} in profiles').format(profile_name))

    rule_type, rule_class = ReadLog('', '', '').get_rule_type(rule)
    rule_obj = rule_class.create_instance(rule)

    if mode == 'yes':
        add_to_local_profile(rule_obj, profile_name)
    elif mode == 'no':
        add_to_profile(rule_obj, profile_name)
    elif mode == 'auto':
        if aa.active_profiles[profile_name].get_local_include():
            add_to_local_profile(rule_obj, profile_name)
        else:
            add_to_profile(rule_obj, profile_name)
    else:
        usage(False)

    aa.reload_base(profile_name)


def usage(is_help):
    print('This tool is a low level tool - do not use it directly')
    print('{} create_userns <template_path> <name> <bin_path> <profile_path> <decision>'.format(sys.argv[0]))
    print('{} add_rule <mode=yes|no|auto> <rule> <profile_name>'.format(sys.argv[0]))
    print('{} from_file <file>'.format(sys.argv[0]))
    if is_help:
        exit(0)
    else:
        exit(1)


def create_from_file(file_path):
    with open(file_path) as file:
        for line in file:
            args = line[:-1].split('\t')
            if len(args) > 1:
                command = args[0]
            else:
                command = None  # Handle the case where no command is provided
            do_command(command, args)


def do_command(command, args):
    if command == 'from_file':
        if not len(args) == 2:
            usage(False)
        create_from_file(args[1])
    elif command == 'create_userns':
        if not len(args) == 6:
            usage(False)
        create_userns(args[1], args[2], args[3], args[4], args[5])
    elif command == 'add_rule':
        if not len(args) == 4:
            usage(False)
        add_rule(args[1], args[2], args[3])
    elif command == 'help':
        usage(True)
    else:
        usage(False)


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = None  # Handle the case where no command is provided

    do_command(command, sys.argv[1:])


if __name__ == '__main__':
    main()
