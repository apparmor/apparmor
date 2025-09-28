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
# No old version logs, only 2.6 + supported
import atexit
import os
import re
import shutil
import sys
import time
import traceback
from copy import deepcopy
from shutil import which
from tempfile import NamedTemporaryFile

import apparmor.config
import apparmor.logparser
import apparmor.severity
import apparmor.ui as aaui
from apparmor.aare import AARE
from apparmor.common import (
    AppArmorBug, AppArmorException, DebugLogger, cmd, combine_profname, hasher,
    is_skippable_file, open_file_read, open_file_write, split_name, valid_path)
from apparmor.profile_list import ProfileList, preamble_ruletypes
from apparmor.profile_storage import ProfileStorage, add_or_remove_flag, ruletypes
from apparmor.regex import (
    RE_HAS_COMMENT_SPLIT, RE_PROFILE_CHANGE_HAT, RE_PROFILE_CONDITIONAL,
    RE_PROFILE_CONDITIONAL_BOOLEAN, RE_PROFILE_CONDITIONAL_VARIABLE, RE_PROFILE_END,
    RE_PROFILE_HAT_DEF, RE_PROFILE_START, RE_METADATA_LOGPROF_SUGGEST,
    RE_RULE_HAS_COMMA, parse_profile_start_line, re_match_include)
from apparmor.rule.abi import AbiRule
from apparmor.rule.file import FileRule
from apparmor.rule.include import IncludeRule
from apparmor.logparser import ReadLog
from apparmor.translations import init_translation

_ = init_translation()

# Setup logging in case debugging is enabled
debug_logger = DebugLogger('aa')

# The database for severity
sev_db = None
# The file to read log messages from
logfile = None

CONFDIR = None
conf = None
cfg = None

parser = None
profile_dir = None
extra_profile_dir = None

use_abstractions = True

# To keep track of previously included profile fragments
include = dict()

active_profiles = ProfileList()
original_profiles = ProfileList()
extra_profiles = ProfileList()

# To store the globs entered by users so they can be provided again
# format: user_globs['/foo*'] = AARE('/foo*')
user_globs = {}

# let ask_addhat() remember answers for already-seen change_hat events
transitions = {}

changed = dict()
created = []
helpers = dict()  # Preserve this between passes # was our


def reset_aa():
    """Reset the most important global variables

       Used by aa-mergeprof and some tests.
    """

    global include, active_profiles, original_profiles

    include = dict()
    active_profiles = ProfileList()
    original_profiles = ProfileList()


def on_exit():
    """Shutdowns the logger and records exit if debugging enabled"""
    debug_logger.debug('Exiting..')
    debug_logger.shutdown()


# Register the on_exit method with atexit
atexit.register(on_exit)


def check_for_LD_XXX(file):
    """Returns True if specified program contains references to LD_PRELOAD or
    LD_LIBRARY_PATH to give the Px/Ux code better suggestions"""
    if not os.path.isfile(file):
        return False
    size = os.stat(file).st_size
    # Limit to checking files under 100k for the sake of speed
    if size > 100000:
        return False
    with open(file, 'rb') as f_in:
        for line in f_in:
            if b'LD_PRELOAD' in line or b'LD_LIBRARY_PATH' in line:
                return True
    return False


def fatal_error(message):
    # Get the traceback to the message
    tb_stack = traceback.format_list(traceback.extract_stack())
    tb_stack = ''.join(tb_stack)
    # Add the traceback to message
    message = tb_stack + '\n\n' + message
    debug_logger.error(message)

    # Else tell user what happened
    aaui.UI_Important(message)
    sys.exit(1)


def check_for_apparmor(filesystem='/proc/filesystems', mounts='/proc/mounts'):
    """Finds and returns the mountpoint for apparmor None otherwise"""
    support_securityfs = False
    aa_mountpoint = None
    if valid_path(filesystem):
        with open_file_read(filesystem) as f_in:
            for line in f_in:
                if 'securityfs' in line:
                    support_securityfs = True
                    break
    if valid_path(mounts) and support_securityfs:
        with open_file_read(mounts) as f_in:
            for line in f_in:
                split = line.split()
                if len(split) > 2 and split[2] == 'securityfs':
                    mountpoint = split[1] + '/apparmor'
                    # Check if apparmor is actually mounted there
                    # XXX valid_path() only checks the syntax, but not if the directory exists!
                    if valid_path(mountpoint) and valid_path(mountpoint + '/profiles'):
                        aa_mountpoint = mountpoint
                        break
    return aa_mountpoint


def get_full_path(original_path):
    """Return the full path after resolving any symlinks"""
    path = original_path
    link_count = 0
    if not path.startswith('/'):
        path = os.path.join(os.getcwd(), path)
    while os.path.islink(path):
        link_count += 1
        if link_count > 64:
            fatal_error(_("Followed too many links while resolving %s") % (original_path))
        direc, file = os.path.split(path)
        link = os.readlink(path)
        # If the link an absolute path
        if link.startswith('/'):
            path = link
        else:
            # Link is relative path
            path = os.path.join(direc, link)
    return os.path.realpath(path)


def find_executable(bin_path):
    """Returns the full executable path for the given executable, None otherwise"""
    full_bin = None
    if os.path.exists(bin_path):
        full_bin = get_full_path(bin_path)
    else:
        if '/' not in bin_path:
            env_bin = which(bin_path)
            if env_bin:
                full_bin = get_full_path(env_bin)
    if full_bin and os.path.exists(full_bin):
        return full_bin
    return None


def get_profile_filename_from_profile_name(profile, get_new=False):
    """Returns the full profile name for the given profile name"""

    filename = active_profiles.filename_from_profile_name(profile)
    if filename:
        return filename

    if get_new:
        return get_new_profile_filename(profile)


def get_profile_filename_from_attachment(profile, get_new=False):
    """Returns the full profile name for the given attachment"""

    filename = active_profiles.filename_from_attachment(profile)
    if filename:
        return filename

    if get_new:
        return get_new_profile_filename(profile)


def get_new_profile_filename(profile):
    """Compose filename for a new profile"""
    if profile.startswith('/'):
        # Remove leading /
        filename = profile[1:]
    else:
        filename = profile
    filename = filename.replace('/', '.')
    filename = os.path.join(profile_dir, filename)
    return filename


def name_to_prof_filename(prof_filename):
    """Returns the profile"""
    if prof_filename.startswith(profile_dir):
        profile = prof_filename.split(profile_dir, 1)[1]
        return (prof_filename, profile)
    else:
        bin_path = find_executable(prof_filename)
        if bin_path:
            prof_filename = get_profile_filename_from_attachment(bin_path, True)
            if os.path.isfile(prof_filename):
                return (prof_filename, bin_path)

    return None, None


def complain(path):
    """Sets the profile to complain mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename:
        fatal_error(_("Can't find %s") % path)
    set_complain(prof_filename, name)


def enforce(path):
    """Sets the profile to enforce mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename:
        fatal_error(_("Can't find %s") % path)
    set_enforce(prof_filename, name)


def set_complain(filename, program):
    """Sets the profile to complain mode"""
    aaui.UI_Info(_('Setting %s to complain mode.') % (filename if program is None else program))
    # a force-complain symlink is more packaging-friendly, but breaks caching
    # create_symlink('force-complain', filename)
    delete_symlink('disable', filename)
    change_profile_flags(filename, program, ['enforce', 'kill', 'unconfined', 'prompt', 'default_allow'], False)  # remove conflicting mode flags
    change_profile_flags(filename, program, 'complain', True)


def set_enforce(filename, program):
    """Sets the profile to enforce mode"""
    aaui.UI_Info(_('Setting %s to enforce mode.') % (filename if program is None else program))
    delete_symlink('force-complain', filename)
    delete_symlink('disable', filename)
    change_profile_flags(filename, program, ['complain', 'kill', 'unconfined', 'prompt', 'default_allow'], False)  # remove conflicting and complain mode flags


def disable_abstractions():
    global use_abstractions
    use_abstractions = False


def delete_symlink(subdir, filename):
    path = filename
    link = re.sub('^%s' % profile_dir, '%s/%s' % (profile_dir, subdir), path)
    if link != path and os.path.islink(link):
        os.remove(link)


def create_symlink(subdir, filename):
    path = filename
    bname = os.path.basename(filename)
    if not bname:
        raise AppArmorException(_('Unable to find basename for %s.') % filename)
    # print(filename)
    link = re.sub('^%s' % profile_dir, '%s/%s' % (profile_dir, subdir), path)
    # print(link)
    # link = link + '/%s'%bname
    # print(link)
    symlink_dir = os.path.dirname(link)
    if not os.path.exists(symlink_dir):
        # If the symlink directory does not exist create it
        os.makedirs(symlink_dir)

    if not os.path.exists(link):
        try:
            os.symlink(filename, link)
        except OSError:
            raise AppArmorException(
                _('Could not create %(link)s symlink to %(file)s.')
                % {'link': link, 'file': filename})


def head(file):
    """Returns the first/head line of the file"""
    if os.path.isfile(file):
        with open_file_read(file) as f_in:
            try:
                first = f_in.readline().rstrip()
            except UnicodeDecodeError:
                first = ''
            return first
    else:
        raise AppArmorException(_('Unable to read first line from %s: File Not Found') % file)


def check_output_dir(output_dir):
    if os.path.isdir(output_dir):
        return True
    elif os.path.exists(output_dir):
        raise AppArmorException(_("%(dir) exists and is not a directory") % {'dir': output_dir})
    try:
        os.mkdir(output_dir, mode=0o700)
    except OSError as e:
        raise AppArmorException(
            _("Unable to create output directory %(dir)s\n\t%(error)s")
            % {'dir': output_dir, 'error': str(e)}
        )


def get_interpreter_and_abstraction(exec_target):
    """Check if exec_target is a script.
       If a hashbang is found, check if we have an abstraction for it.

       Returns (interpreter_path, abstraction)
       - interpreter_path is none if exec_target is not a script or doesn't have a hashbang line
       - abstraction is None if no matching abstraction exists"""

    if not os.path.exists(exec_target):
        aaui.UI_Important(_('Execute target %s does not exist!') % exec_target)
        return None, None

    if not os.path.isfile(exec_target):
        aaui.UI_Important(_('Execute target %s is not a file!') % exec_target)
        return None, None

    hashbang = head(exec_target)
    if not hashbang.startswith('#!'):
        return None, None

    # get the interpreter (without parameters)
    interpreter = hashbang[2:].strip().split()[0]
    interpreter_path = get_full_path(interpreter)
    interpreter = re.sub('^(/usr)?/bin/', '', interpreter_path)

    if interpreter in ('bash', 'dash', 'sh'):
        abstraction = 'abstractions/bash'
    elif interpreter == 'perl':
        abstraction = 'abstractions/perl'
    elif re.search(r'^python([23]|[23]\.[0-9]+)?$', interpreter):
        abstraction = 'abstractions/python'
    elif re.search(r'^ruby([0-9]+(\.[0-9]+)*)?$', interpreter):
        abstraction = 'abstractions/ruby'
    else:
        abstraction = None

    return interpreter_path, abstraction


def create_new_profile(localfile, is_stub=False):
    local_profile = {}
    local_profile[localfile] = ProfileStorage(localfile, localfile, 'create_new_profile()')
    local_profile[localfile]['flags'] = 'complain'

    if os.path.join(profile_dir, 'abstractions/base') in include:
        local_profile[localfile]['inc_ie'].add(IncludeRule('abstractions/base', False, True))
    else:
        aaui.UI_Important(_("WARNING: Can't find %s, therefore not adding it to the new profile.") % 'abstractions/base')

    if os.path.exists(localfile) and os.path.isfile(localfile):
        interpreter_path, abstraction = get_interpreter_and_abstraction(localfile)

        if interpreter_path:
            local_profile[localfile]['file'].add(FileRule(localfile,        'r',  None, FileRule.ALL, owner=False))
            local_profile[localfile]['file'].add(FileRule(interpreter_path, None, 'ix', FileRule.ALL, owner=False))

            if abstraction:
                if os.path.join(profile_dir, abstraction) in include:
                    local_profile[localfile]['inc_ie'].add(IncludeRule(abstraction, False, True))
                else:
                    aaui.UI_Important(_("WARNING: Can't find %s, therefore not adding it to the new profile.") % abstraction)

        else:
            local_profile[localfile]['file'].add(FileRule(localfile,        'mr', None, FileRule.ALL, owner=False))

    # Add required hats to the profile if they match the localfile
    for hatglob in cfg['required_hats'].keys():
        if re.search(hatglob, localfile):
            for hat in sorted(cfg['required_hats'][hatglob].split()):
                full_hat = combine_profname((localfile, hat))
                if not local_profile.get(full_hat, False):
                    local_profile[full_hat] = ProfileStorage(localfile, hat, 'create_new_profile() required_hats')
                    local_profile[full_hat]['parent'] = localfile
                    local_profile[full_hat]['is_hat'] = True
                local_profile[full_hat]['flags'] = 'complain'

    if not is_stub:
        created.append(localfile)
        changed[localfile] = True

    debug_logger.debug("Profile for %s:\n\t%s", localfile, local_profile)
    return local_profile


def get_profile(prof_name):
    """search for inactive/extra profile, and ask if it should be used"""

    if not extra_profiles.profile_exists(prof_name):
        return None  # no inactive profile found

    # TODO: search based on the attachment, not (only?) based on the profile name
    #       (Note: in theory, multiple inactive profiles (with different profile names) could exist for a binary.)
    inactive_profile = deepcopy(extra_profiles.get_profile_and_childs(prof_name))

    orig_filename = inactive_profile[prof_name]['filename']  # needed for CMD_VIEW_PROFILE

    for prof in inactive_profile:
        inactive_profile[prof]['flags'] = 'complain'  # TODO: preserve other flags, if any
        inactive_profile[prof]['filename'] = ''

    # ensure active_profiles has the /etc/apparmor.d/ filename initialized
    # TODO: ideally serialize_profile() shouldn't always use active_profiles
    prof_filename = get_new_profile_filename(prof_name)
    if not active_profiles.files.get(prof_filename):
        active_profiles.init_file(prof_filename)

    uname = 'Inactive local profile for %s' % prof_name
    profile_hash = {
        uname: {
            'profile': serialize_profile(inactive_profile, prof_name, {}),
            'profile_data': inactive_profile,
        }
    }

    options = [uname]

    q = aaui.PromptQuestion()
    q.headers = ['Profile', prof_name]
    q.functions = ['CMD_VIEW_PROFILE', 'CMD_USE_PROFILE', 'CMD_CREATE_PROFILE', 'CMD_ABORT']
    q.default = "CMD_VIEW_PROFILE"
    q.options = options
    q.selected = 0

    ans = ''
    while 'CMD_USE_PROFILE' not in ans and 'CMD_CREATE_PROFILE' not in ans:
        ans, arg = q.promptUser()
        p = profile_hash[options[arg]]
        q.selected = options.index(options[arg])
        if ans == 'CMD_VIEW_PROFILE':
            aaui.UI_ShowFile(uname, orig_filename)
        elif ans == 'CMD_USE_PROFILE':
            created.append(prof_name)
            return p['profile_data']

    return None  # CMD_CREATE_PROFILE chosen


def autodep(bin_name, pname=''):
    bin_full = None
    if bin_name:
        bin_full = find_executable(bin_name)
        # if not bin_full:
        #    bin_full = bin_name
        # if not bin_full.startswith('/'):
        #     return
        # Return if executable path not found
        if not bin_full:
            return
    else:
        bin_full = pname  # for named profiles

    pname = bin_full
    read_inactive_profiles()
    profile_data = get_profile(pname)
    # Create a new profile if no existing profile
    if not profile_data:
        profile_data = create_new_profile(pname)
    file = get_profile_filename_from_profile_name(pname, True)
    profile_data[pname]['filename'] = file  # change filename from extra_profile_dir to /etc/apparmor.d/

    for p in profile_data.keys():
        original_profiles.add_profile(file, p, profile_data[p]['attachment'], deepcopy(profile_data[p]))

    attachment = profile_data[pname]['attachment']
    if not attachment and pname.startswith('/'):
        attachment = pname  # use name as name and attachment

    active_profiles.add_profile(file, pname, attachment, profile_data[pname])

    if os.path.isfile(profile_dir + '/abi/4.0'):
        active_profiles.add_abi(file, AbiRule('abi/4.0', False, True))
    if os.path.isfile(profile_dir + '/tunables/global'):
        active_profiles.add_inc_ie(file, IncludeRule('tunables/global', False, True))
    write_profile_ui_feedback(pname)


def get_profile_flags(filename, program):
    # To-Do
    # XXX If more than one profile in a file then second one is being ignored XXX
    # Do we return flags for both or
    flags = ''
    with open_file_read(filename) as f_in:
        for line in f_in:
            if RE_PROFILE_START.search(line):
                matches = parse_profile_start_line(line, filename)
                if (matches['attachment'] is not None):
                    profile_glob = AARE(matches['attachment'], True)
                else:
                    profile_glob = AARE(matches['profile'], True)
                flags = matches['flags']
                if ((program is not None and profile_glob.match(program))
                        or program is None or program == matches['profile']):
                    return flags

    raise AppArmorException(_('%s contains no profile') % filename)


def change_profile_flags(prof_filename, program, flag, set_flag):
    """Reads the old profile file and updates the flags accordingly"""
    # TODO: count the number of matching lines (separated by profile and hat?) and return it
    #       so that code calling this function can make sure to only report success if there was a match
    # TODO: change child profile flags even if program is specified

    found = False
    depth = -1

    if not flag or (isinstance(flag, str) and not flag.strip()):
        raise AppArmorBug('New flag for %s is empty' % prof_filename)

    with open_file_read(prof_filename) as f_in:
        temp_file = NamedTemporaryFile('w', prefix=prof_filename, suffix='~', delete=False, dir=profile_dir)
        temp_file.close()
        shutil.copymode(prof_filename, temp_file.name)
        with open_file_write(temp_file.name) as f_out:
            for lineno, line in enumerate(f_in):
                if RE_PROFILE_START.search(line):
                    depth += 1
                    # TODO: hand over profile and hat (= parent profile)
                    #       (and find out why it breaks test-aa.py with several "a child profile inside another child profile is not allowed" errors when doing so)
                    (profile, hat, prof_storage) = ProfileStorage.parse(line, prof_filename, lineno, '', '')
                    old_flags = prof_storage['flags']
                    newflags = ', '.join(add_or_remove_flag(old_flags, flag, set_flag))

                    if (prof_storage['attachment']):
                        profile_glob = AARE(prof_storage['attachment'], True)
                    else:
                        profile_glob = AARE(prof_storage['name'], False)  # named profiles can come without an attachment path specified ("profile foo {...}")

                    if (program is not None and profile_glob.match(program)) or program is None or program == prof_storage['name']:
                        found = True
                        if program is not None and program != profile:
                            aaui.UI_Info(_('Warning: profile %s represents multiple programs') % profile)

                        prof_storage['flags'] = newflags

                        line = prof_storage.get_header(depth, False)
                        line = '%s\n' % line[0]
                elif RE_PROFILE_HAT_DEF.search(line):
                    depth += 1
                    # TODO: hand over profile and hat (= parent profile)
                    (profile, hat, prof_storage) = ProfileStorage.parse(line, prof_filename, lineno, '', '')
                    old_flags = prof_storage['flags']
                    newflags = ', '.join(add_or_remove_flag(old_flags, flag, set_flag))
                    prof_storage['flags'] = newflags

                    line = prof_storage.get_header(depth, False)
                    line = '%s\n' % line[0]
                elif RE_PROFILE_END.search(line):
                    depth -= 1
                    # TODO: restore 'profile' and 'hat' to previous values (not really needed/used for aa-complain etc., but can't hurt)

                f_out.write(line)
    os.rename(temp_file.name, prof_filename)

    if not found:
        if program is None:
            raise AppArmorException("%(file)s doesn't contain a valid profile (syntax error?)" % {'file': prof_filename})
        else:
            raise AppArmorException("%(file)s doesn't contain a valid profile for %(profile)s (syntax error?)" % {'file': prof_filename, 'profile': program})


def build_x_functions(default, options, exec_toggle):
    ret_list = []
    fallback_toggle = False
    if exec_toggle:
        if 'i' in options:
            ret_list.append('CMD_ix')
            if 'p' in options:
                ret_list.append('CMD_pix')
                fallback_toggle = True
            if 'c' in options:
                ret_list.append('CMD_cix')
                fallback_toggle = True
            if 'n' in options:
                ret_list.append('CMD_nix')
                fallback_toggle = True
            if fallback_toggle:
                ret_list.append('CMD_EXEC_IX_OFF')
        if 'u' in options:
            ret_list.append('CMD_ux')

    else:
        if 'i' in options:
            ret_list.append('CMD_ix')
        if 'c' in options:
            ret_list.append('CMD_cx')
            fallback_toggle = True
        if 'p' in options:
            ret_list.append('CMD_px')
            fallback_toggle = True
        if 'n' in options:
            ret_list.append('CMD_nx')
            fallback_toggle = True
        if 'u' in options:
            ret_list.append('CMD_ux')

        if fallback_toggle:
            ret_list.append('CMD_EXEC_IX_ON')

    ret_list.extend(('CMD_DENY', 'CMD_ABORT', 'CMD_IGNORE_ENTRY', 'CMD_FINISHED'))
    return ret_list


def ask_addhat(hashlog):
    """ask the user about change_hat events (requests to add a hat)"""

    for aamode in hashlog:
        for profile in hashlog[aamode]:
            if '//' in hashlog[aamode][profile]['final_name'] and hashlog[aamode][profile]['change_hat'].keys():
                aaui.UI_Important('Ignoring change_hat event for %s, nested profiles are not supported yet.' % profile)
                continue

            for full_hat in hashlog[aamode][profile]['change_hat']:
                hat = full_hat.split('//')[-1]

                if active_profiles.profile_exists(full_hat):
                    continue  # no need to ask if the hat already exists

                default_hat = None
                for hatglob in cfg.options('defaulthat'):
                    if re.search(hatglob, profile):
                        default_hat = cfg['defaulthat'][hatglob]

                context = profile + ' -> ^%s' % hat
                ans = transitions.get(context, 'XXXINVALIDXXX')

                while ans not in ('CMD_ADDHAT', 'CMD_USEDEFAULT', 'CMD_DENY'):
                    q = aaui.PromptQuestion()
                    q.headers.extend((_('Profile'), profile))

                    if default_hat:
                        q.headers.extend((_('Default Hat'), default_hat))

                    q.headers.extend((_('Requested Hat'), hat))

                    q.functions.append('CMD_ADDHAT')
                    if default_hat:
                        q.functions.append('CMD_USEDEFAULT')
                    q.functions.extend(('CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED'))

                    q.default = 'CMD_DENY'
                    if aamode == 'PERMITTING':
                        q.default = 'CMD_ADDHAT'

                    ans = q.promptUser()[0]

                    if ans == 'CMD_FINISHED':
                        save_profiles()
                        return

                transitions[context] = ans

                filename = active_profiles.filename_from_profile_name(profile)  # filename of parent profile, will be used for new hats

                if ans == 'CMD_ADDHAT':
                    hat_obj = ProfileStorage(profile, hat, 'ask_addhat addhat')
                    hat_obj['parent'] = profile
                    hat_obj['flags'] = active_profiles[profile]['flags']
                    new_full_hat = combine_profname([profile, hat])
                    active_profiles.add_profile(filename, new_full_hat, hat, hat_obj)
                    hashlog[aamode][full_hat]['final_name'] = new_full_hat
                    changed[profile] = True
                elif ans == 'CMD_USEDEFAULT':
                    hat = default_hat
                    new_full_hat = combine_profname([profile, hat])
                    hashlog[aamode][full_hat]['final_name'] = new_full_hat
                    if not active_profiles.profile_exists(full_hat):
                        # create default hat if it doesn't exist yet
                        hat_obj = ProfileStorage(profile, hat, 'ask_addhat default hat')
                        hat_obj['parent'] = profile
                        hat_obj['flags'] = active_profiles[profile]['flags']
                        active_profiles.add_profile(filename, new_full_hat, hat, hat_obj)
                        changed[profile] = True
                elif ans == 'CMD_DENY':
                    # As unknown hat is denied no entry for it should be made
                    hashlog[aamode][full_hat]['final_name'] = ''
                    continue


def ask_exec(hashlog, default_ans=''):
    """ask the user about exec events (requests to execute another program) and which exec mode to use"""

    for aamode in hashlog:
        for full_profile in hashlog[aamode]:
            profile, hat = split_name(full_profile)  # XXX temporary solution to avoid breaking the existing code

            for exec_target in hashlog[aamode][full_profile]['exec']:
                for target_profile in hashlog[aamode][full_profile]['exec'][exec_target]:
                    to_name = ''

                    if os.path.isdir(exec_target):
                        raise AppArmorBug(
                            'exec permissions requested for directory %s (profile %s). This should not happen - please open a bugreport!' % (exec_target, full_profile))

                    if not active_profiles.profile_exists(profile):
                        continue  # ignore log entries for non-existing profiles

                    if not active_profiles.profile_exists(full_profile):
                        continue  # ignore log entries for non-existing hats

                    exec_event = FileRule(exec_target, None, FileRule.ANY_EXEC, FileRule.ALL, owner=False, log_event=True)
                    if is_known_rule(active_profiles[full_profile], 'file', exec_event):
                        continue

                    # nx is not used in profiles but in log files.
                    # Log parsing methods will convert it to its profile form
                    # nx is internally cx/px/cix/pix + to_name
                    exec_mode = False
                    file_perm = None

                    options = cfg['qualifiers'].get(exec_target, 'ipcnu')

                    # If profiled program executes itself only 'ix' option
                    # if exec_target == profile:
                    #     options = 'i'

                    # Don't allow hats to cx (nested profiles not supported by aa-logprof yet)
                    if '//' in hashlog[aamode][full_profile]['final_name'] and hashlog[aamode][full_profile]['exec'].keys():
                        options = options.replace('c', '')

                    # Add deny to options
                    options += 'd'
                    # Define the default option
                    default = None
                    if 'p' in options and os.path.exists(get_profile_filename_from_attachment(exec_target, True)):
                        default = 'CMD_px'
                        sys.stdout.write(_('Target profile exists: %s\n') % get_profile_filename_from_attachment(exec_target, True))
                    elif 'i' in options:
                        default = 'CMD_ix'
                    elif 'c' in options:
                        default = 'CMD_cx'
                    elif 'n' in options:
                        default = 'CMD_nx'
                    else:
                        default = 'DENY'

                    #
                    parent_uses_ld_xxx = check_for_LD_XXX(profile)

                    prof_filename = get_profile_filename_from_profile_name(profile)
                    if prof_filename and active_profiles.files.get(prof_filename):
                        sev_db.set_variables(active_profiles.get_all_merged_variables(
                                             prof_filename,
                                             include_list_recursive(active_profiles.files[prof_filename], True)))
                    else:
                        sev_db.set_variables({})

                    severity = sev_db.rank_path(exec_target, 'x')

                    # Prompt portion starts
                    q = aaui.PromptQuestion()

                    q.headers.extend((
                        _('Profile'), combine_name(profile, hat),

                        # to_name should not exist here since, transitioning is already handled
                        _('Execute'), exec_target,
                        _('Severity'), severity,
                    ))

                    exec_toggle = False
                    q.functions.extend(build_x_functions(default, options, exec_toggle))
                    q.already_have_profile = get_profile_filename_from_attachment(exec_target)

                    # ask user about the exec mode to use
                    ans = ''
                    while ans not in ('CMD_ix', 'CMD_px', 'CMD_cx', 'CMD_nx', 'CMD_pix', 'CMD_cix', 'CMD_nix', 'CMD_ux', 'CMD_DENY', 'CMD_IGNORE_ENTRY'):
                        if default_ans:
                            ans = default_ans
                        else:
                            ans = q.promptUser()[0]

                        if ans.startswith('CMD_EXEC_IX_'):
                            exec_toggle = not exec_toggle
                            q.functions = build_x_functions(default, options, exec_toggle)
                            ans = ''
                            continue

                        if ans == 'CMD_FINISHED':
                            save_profiles()
                            return

                        if ans == 'CMD_nx' or ans == 'CMD_nix':
                            arg = exec_target
                            ynans = 'n'
                            if profile == hat:
                                ynans = aaui.UI_YesNo(_('Are you specifying a transition to a local profile?'), 'n')
                            if ynans == 'y':
                                if ans == 'CMD_nx':
                                    ans = 'CMD_cx'
                                else:
                                    ans = 'CMD_cix'
                            else:
                                if ans == 'CMD_nx':
                                    ans = 'CMD_px'
                                else:
                                    ans = 'CMD_pix'

                            to_name = aaui.UI_GetString(_('Enter profile name to transition to: '), arg)

                        if ans == 'CMD_ix':
                            exec_mode = 'ix'
                        elif ans in ('CMD_px', 'CMD_cx', 'CMD_pix', 'CMD_cix'):
                            exec_mode = ans.replace('CMD_', '')
                            px_msg = _(
                                "Should AppArmor enable secure-execution mode\n"
                                "when switching profiles?\n"
                                "\n"
                                "Doing so is more secure, but some applications\n"
                                "depend on the presence of LD_PRELOAD or\n"
                                "LD_LIBRARY_PATH, which would be sanitized by\n"
                                "enabling secure-execution mode.")
                            if parent_uses_ld_xxx:
                                px_msg = _(
                                    "Should AppArmor enable secure-execution mode\n"
                                    "when switching profiles?\n"
                                    "\n"
                                    "Doing so is more secure,\n"
                                    "but this application appears to be using LD_PRELOAD\n"
                                    "or LD_LIBRARY_PATH, and sanitising those environment\n"
                                    "variables by enabling secure-execution mode\n"
                                    "could cause functionality problems.")

                            ynans = aaui.UI_YesNo(px_msg, 'y')
                            if ynans == 'y':
                                # Disable the unsafe mode
                                exec_mode = exec_mode.capitalize()
                        elif ans == 'CMD_ux':
                            exec_mode = 'ux'
                            ynans = aaui.UI_YesNo(_(
                                "Launching processes in an unconfined state is a very\n"
                                "dangerous operation and can cause serious security holes.\n"
                                "\n"
                                "Are you absolutely certain you wish to remove all\n"
                                "AppArmor protection when executing %s ?") % exec_target, 'n')
                            if ynans == 'y':
                                ynans = aaui.UI_YesNo(_(
                                    "Should AppArmor sanitise the environment when\n"
                                    "running this program unconfined?\n"
                                    "\n"
                                    "Not sanitising the environment when unconfining\n"
                                    "a program opens up significant security holes\n"
                                    "and should be avoided if at all possible."), 'y')
                                if ynans == 'y':
                                    # Disable the unsafe mode
                                    exec_mode = exec_mode.capitalize()
                            else:
                                ans = 'INVALID'

                    if ans == 'CMD_IGNORE_ENTRY':
                        continue

                    if exec_mode and 'i' in exec_mode:
                        # For inherit we need mr
                        file_perm = 'mr'
                    else:
                        if ans == 'CMD_DENY':
                            add_rule_ui_feedback(active_profiles[full_profile]['file'], full_profile,
                                                 FileRule(exec_target, None, 'x', FileRule.ALL, owner=False, log_event=True, deny=True))
                            changed[profile] = True
                            if target_profile and hashlog[aamode].get(target_profile):
                                hashlog[aamode][target_profile]['final_name'] = ''
                            # Skip remaining events if they ask to deny exec
                            continue

                    if ans != 'CMD_DENY':
                        if to_name:
                            rule_to_name = to_name
                        else:
                            rule_to_name = FileRule.ALL
                        add_rule_ui_feedback(active_profiles[full_profile]['file'], full_profile,
                                             FileRule(exec_target, file_perm, exec_mode, rule_to_name, owner=False, log_event=True))

                        changed[profile] = True

                        if 'i' in exec_mode:
                            interpreter_path, abstraction = get_interpreter_and_abstraction(exec_target)

                            if interpreter_path:
                                exec_target_rule = FileRule(exec_target,      'r',  None, FileRule.ALL, owner=False)
                                interpreter_rule = FileRule(interpreter_path, None, 'ix', FileRule.ALL, owner=False)

                                if not is_known_rule(active_profiles[full_profile], 'file', exec_target_rule):
                                    add_rule_ui_feedback(active_profiles[full_profile]['file'], full_profile, exec_target_rule)
                                if not is_known_rule(active_profiles[full_profile], 'file', interpreter_rule):
                                    add_rule_ui_feedback(active_profiles[full_profile]['file'], full_profile, interpreter_rule)

                                if abstraction:
                                    abstraction_rule = IncludeRule(abstraction, False, True)

                                    if not active_profiles[full_profile]['inc_ie'].is_covered(abstraction_rule):
                                        add_rule_ui_feedback(active_profiles[full_profile]['inc_ie'], full_profile, abstraction_rule)

                    # Update tracking info based on kind of change

                    if ans == 'CMD_ix':
                        if target_profile and hashlog[aamode].get(target_profile):
                            hashlog[aamode][target_profile]['final_name'] = profile

                    elif ans.startswith('CMD_px') or ans.startswith('CMD_pix'):
                        if to_name:
                            exec_target = to_name

                        if target_profile and hashlog[aamode].get(target_profile):
                            hashlog[aamode][target_profile]['final_name'] = exec_target

                        # Check profile exists for px
                        if exec_target.startswith(('/', '@', '{')):
                            prof_filename = get_profile_filename_from_attachment(exec_target, True)
                        else:  # named exec
                            prof_filename = get_profile_filename_from_profile_name(exec_target, True)

                        if not os.path.exists(prof_filename):
                            ynans = 'y'
                            if 'i' in exec_mode:
                                ynans = aaui.UI_YesNo(_('A profile for %s does not exist.\nDo you want to create one?') % exec_target, 'n')
                            if ynans == 'y':
                                helpers[exec_target] = 'enforce'
                                if to_name:
                                    autodep('', exec_target)
                                else:
                                    autodep(exec_target, '')
                                reload_base(exec_target)
                            else:
                                if target_profile and hashlog[aamode].get(target_profile):
                                    hashlog[aamode][target_profile]['final_name'] = profile  # not creating the target profile effectively results in ix mode

                    elif ans.startswith('CMD_cx') or ans.startswith('CMD_cix'):
                        if to_name:
                            exec_target = to_name

                        full_exec_target = combine_profname([profile, exec_target])
                        if not active_profiles.profile_exists(full_exec_target):
                            ynans = 'y'
                            if 'i' in exec_mode:
                                ynans = aaui.UI_YesNo(_('A profile for %s does not exist.\nDo you want to create one?') % exec_target, 'n')
                            if ynans == 'y':
                                if not active_profiles.profile_exists(full_exec_target):
                                    stub_profile = create_new_profile(exec_target, True)
                                    for p in stub_profile:
                                        active_profiles.add_profile(prof_filename, p, stub_profile[p]['attachment'], stub_profile[p])

                                if profile != exec_target:
                                    active_profiles[full_exec_target]['flags'] = active_profiles[profile]['flags']

                                active_profiles[full_exec_target]['flags'] = 'complain'

                                if target_profile and hashlog[aamode].get(target_profile):
                                    hashlog[aamode][target_profile]['final_name'] = '%s//%s' % (profile, exec_target)

                            else:
                                if target_profile and hashlog[aamode].get(target_profile):
                                    hashlog[aamode][target_profile]['final_name'] = profile  # not creating the target profile effectively results in ix mode

                    elif ans.startswith('CMD_ux'):
                        continue

                    else:
                        raise AppArmorBug('Unhandled ans %s, please open a bugreport!' % ans)


def order_globs(globs, original_path):
    """Returns the globs in sorted order, more specific behind"""
    # To-Do
    # ATM its lexicographic, should be done to allow better matches later

    globs = sorted(globs)

    # make sure the original path is always the last option
    if original_path in globs:
        globs.remove(original_path)
    globs.append(original_path)

    return globs


def ask_the_questions(log_dict):
    for aamode in sorted(log_dict.keys()):
        # Describe the type of changes
        if aamode == 'PERMITTING':
            aaui.UI_Info(_('Complain-mode changes:'))
        elif aamode == 'REJECTING':
            aaui.UI_Info(_('Enforce-mode changes:'))
        elif aamode == 'merge':
            pass  # aa-mergeprof
        else:
            raise AppArmorBug(_('Invalid mode found: %s') % aamode)

        for full_profile in sorted(log_dict[aamode].keys()):
            profile, hat = split_name(full_profile)  # XXX limited to two levels to avoid an Exception on nested child profiles or nested null-*

            # TODO: honor full profile name as soon as child profiles are listed in active_profiles
            prof_filename = get_profile_filename_from_profile_name(profile)
            if prof_filename and active_profiles.files.get(prof_filename):
                sev_db.set_variables(active_profiles.get_all_merged_variables(prof_filename, include_list_recursive(active_profiles.files[prof_filename], True)))
            else:
                sev_db.set_variables({})

            if active_profiles.profile_exists(profile):  # only continue/ask if the parent profile exists  # XXX check direct parent or top-level? Also, get rid of using "profile" here!
                if not active_profiles.profile_exists(full_profile):
                    if aamode != 'merge':
                        # Ignore log events for a non-existing profile or child profile. Such events can occur
                        # after deleting a profile or hat manually, or when processing a foreign log.
                        # (Checking for 'file' is a simplified way to check if it's a ProfileStorage.)
                        debug_logger.debug("Ignoring events for non-existing profile %s", full_profile)
                        continue

                    ans = ''
                    while ans not in ('CMD_ADDHAT', 'CMD_ADDSUBPROFILE', 'CMD_DENY'):
                        q = aaui.PromptQuestion()
                        q.headers.extend((_('Profile'), profile))

                        if log_dict[aamode][full_profile]['is_hat']:
                            q.headers.extend((_('Requested Hat'), hat))
                            q.functions.append('CMD_ADDHAT')
                        else:
                            q.headers.extend((_('Requested Subprofile'), hat))
                            q.functions.append('CMD_ADDSUBPROFILE')

                        q.functions.extend(('CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED'))

                        q.default = 'CMD_DENY'

                        ans = q.promptUser()[0]

                        if ans == 'CMD_FINISHED':
                            return

                    if ans == 'CMD_DENY':
                        continue  # don't ask about individual rules if the user doesn't want the additional subprofile/hat

                    if log_dict[aamode][full_profile]['is_hat']:
                        prof_obj = ProfileStorage(profile, hat, 'mergeprof ask_the_questions() - missing hat')
                        prof_obj['is_hat'] = True
                    else:
                        prof_obj = ProfileStorage(profile, hat, 'mergeprof ask_the_questions() - missing subprofile')
                        prof_obj['is_hat'] = False

                    prof_obj['parent'] = profile
                    active_profiles.add_profile(prof_filename, full_profile, hat, prof_obj)

                # check for and ask about conflicting exec modes
                ask_conflict_mode(active_profiles[full_profile], log_dict[aamode][full_profile])

                prof_changed, end_profiling = ask_rule_questions(
                    log_dict[aamode][full_profile], full_profile,
                    active_profiles[full_profile], ruletypes)
                if prof_changed:
                    changed[profile] = True
                if end_profiling:
                    return  # end profiling loop


def add_rule_ui_feedback(prof, prof_name, rule, deleted=0):
    prof.add(rule)
    ui_feedback(prof_name, rule.get_clean(), deleted=deleted)


def ui_feedback(prof_name, rule_str, deleted=False):
    if aaui.UI_mode == 'allow_all':
        aaui.UI_Info(_('Adding %s to profile %s.') % (rule_str, prof_name))
    else:
        aaui.UI_Info(_('Adding %s to profile.') % rule_str)
    if deleted:
        aaui.UI_Info(_('Deleted %s previous matching profile entries.') % deleted)


def ask_rule_questions(prof_events, profile_name, the_profile, r_types):
    """ask questions about rules to add to a single profile/hat

       parameter       typical value
       prof_events     log_dict[aamode][full_profile]
       profile_name    profile name (possible profile//hat)
       the_profile     active_profiles[full_profile] -- will be modified
       r_types         ruletypes

       returns:
       changed         True if the profile was changed
       end_profiling   True if the user wants to end profiling
    """

    changed = False

    for ruletype in r_types:
        for rule_obj in prof_events[ruletype].rules:

            if is_known_rule(the_profile, ruletype, rule_obj):
                continue

            default_option = 1
            options = []
            newincludes = match_includes(the_profile, ruletype, rule_obj)
            q = aaui.PromptQuestion()
            if newincludes:
                if use_abstractions:
                    options.extend(map(lambda inc: 'include <%s>' % inc, sorted(set(newincludes))))

            if ruletype == 'file' and rule_obj.path:
                options += propose_file_rules(the_profile, rule_obj)
            else:
                options.append(rule_obj.get_clean())

            done = False
            while not done:
                q.options = options
                q.selected = default_option - 1
                q.headers = [_('Profile'), profile_name]
                q.headers.extend(rule_obj.logprof_header())

                # Load variables into sev_db? Not needed/used for capabilities and network rules.
                severity = rule_obj.severity(sev_db)
                if severity != sev_db.NOT_IMPLEMENTED:
                    q.headers.extend((_('Severity'), severity))

                q.functions = available_buttons(rule_obj)

                # In complain mode: events default to allow
                # In enforce mode: events default to deny
                # XXX does this behaviour really make sense, except for "historical reasons"[tm]?
                q.default = 'CMD_DENY'
                if rule_obj.log_event == 'PERMITTING':
                    q.default = 'CMD_ALLOW'

                ans, selected = q.promptUser()
                selection = options[selected]

                if ans == 'CMD_IGNORE_ENTRY':
                    done = True
                    break

                elif ans == 'CMD_FINISHED':
                    return changed, True

                elif ans.startswith('CMD_AUDIT'):
                    if ans == 'CMD_AUDIT_NEW':
                        rule_obj.audit = True
                        rule_obj.raw_rule = None
                    else:
                        rule_obj.audit = False
                        rule_obj.raw_rule = None

                    options = set_options_audit_mode(rule_obj, options)

                elif ans.startswith('CMD_USER_'):
                    if ans == 'CMD_USER_ON':
                        rule_obj.owner = True
                        rule_obj.raw_rule = None
                    else:
                        rule_obj.owner = False
                        rule_obj.raw_rule = None

                    options = set_options_owner_mode(rule_obj, options)

                elif ans == 'CMD_ALLOW':
                    done = True
                    changed = True

                    inc = re_match_include(selection)
                    if inc:
                        deleted = delete_all_duplicates(the_profile, inc, r_types)

                        the_profile['inc_ie'].add(IncludeRule.create_instance(selection))

                        ui_feedback(profile_name, selection, deleted)

                    else:
                        rule_obj = rule_obj.create_instance(selection)
                        deleted = the_profile[ruletype].add(rule_obj, cleanup=True)

                        ui_feedback(profile_name, rule_obj.get_clean(), deleted)

                elif ans == 'CMD_DENY':
                    if re_match_include(selection):
                        aaui.UI_Important("Denying via an include file isn't supported by the AppArmor tools")

                    else:
                        done = True
                        changed = True

                        rule_obj = rule_obj.create_instance(selection)
                        rule_obj.deny = True
                        rule_obj.raw_rule = None  # reset raw rule after manually modifying rule_obj
                        deleted = the_profile[ruletype].add(rule_obj, cleanup=True)
                        aaui.UI_Info(_('Adding %s to profile.') % rule_obj.get_clean())
                        if deleted:
                            aaui.UI_Info(_('Deleted %s previous matching profile entries.') % deleted)

                elif ans == 'CMD_GLOB':
                    if not re_match_include(selection):
                        globbed_rule_obj = rule_obj.create_instance(selection)
                        globbed_rule_obj.glob()
                        options, default_option = add_to_options(options, globbed_rule_obj.get_raw())

                elif ans == 'CMD_GLOBEXT':
                    if not re_match_include(selection):
                        globbed_rule_obj = rule_obj.create_instance(selection)
                        globbed_rule_obj.glob_ext()
                        options, default_option = add_to_options(options, globbed_rule_obj.get_raw())

                elif ans == 'CMD_NEW':
                    if not re_match_include(selection):
                        edit_rule_obj = rule_obj.create_instance(selection)
                        prompt, oldpath = edit_rule_obj.edit_header()

                        newpath = aaui.UI_GetString(prompt, oldpath)
                        if newpath:
                            try:
                                input_matches_path = rule_obj.validate_edit(newpath)  # note that we check against the original rule_obj here, not edit_rule_obj (which might be based on a globbed path)
                            except AppArmorException:
                                aaui.UI_Important(_('The path you entered is invalid (not starting with / or a variable)!'))
                                continue

                            if not input_matches_path:
                                ynprompt = (
                                    _('The specified path does not match this log entry:\n'
                                      '\n'
                                      '  Log Entry: %(path)s\n'
                                      '  Entered Path:  %(ans)s\n'
                                      'Do you really want to use this path?')
                                    % {'path': oldpath, 'ans': newpath})
                                key = aaui.UI_YesNo(ynprompt, 'n')
                                if key == 'n':
                                    continue

                            edit_rule_obj.store_edit(newpath)
                            options, default_option = add_to_options(options, edit_rule_obj.get_raw())
                            user_globs[newpath] = AARE(newpath, True)

                else:
                    done = False

    return changed, False


def set_options_audit_mode(rule_obj, options):
    """change audit state in options (proposed rules) to audit state in rule_obj.
       #include options will be kept unchanged
    """
    return set_options_mode(rule_obj, options, 'audit')


def set_options_owner_mode(rule_obj, options):
    """change owner state in options (proposed rules) to owner state in rule_obj.
       #include options will be kept unchanged
    """
    return set_options_mode(rule_obj, options, 'owner')


def set_options_mode(rule_obj, options, what):
    """helper function for set_options_audit_mode() and set_options_owner_mode"""
    new_options = []

    for rule in options:
        if re_match_include(rule):
            new_options.append(rule)
        else:
            parsed_rule = rule_obj.create_instance(rule)
            if what == 'audit':
                parsed_rule.audit = rule_obj.audit
            elif what == 'owner':
                parsed_rule.owner = rule_obj.owner
            else:
                raise AppArmorBug('Unknown "what" value given to set_options_mode: %s' % what)

            parsed_rule.raw_rule = None
            new_options.append(parsed_rule.get_raw())

    return new_options


def available_buttons(rule_obj):
    buttons = []

    if not rule_obj.deny:
        buttons.append('CMD_ALLOW')

    buttons.extend(('CMD_DENY', 'CMD_IGNORE_ENTRY'))

    if rule_obj.can_glob:
        buttons.append('CMD_GLOB')

    if rule_obj.can_glob_ext:
        buttons.append('CMD_GLOBEXT')

    if rule_obj.can_edit:
        buttons.append('CMD_NEW')

    if rule_obj.audit:
        buttons.append('CMD_AUDIT_OFF')
    else:
        buttons.append('CMD_AUDIT_NEW')

    if rule_obj.can_owner:
        if rule_obj.owner:
            buttons.append('CMD_USER_OFF')
        else:
            buttons.append('CMD_USER_ON')

    buttons.extend(('CMD_ABORT', 'CMD_FINISHED'))

    return buttons


def add_to_options(options, newpath):
    if newpath not in options:
        options.append(newpath)

    default_option = options.index(newpath) + 1
    return (options, default_option)


def delete_all_duplicates(profile, incname, r_types):
    deleted = 0
    # Allow rules covered by denied rules shouldn't be deleted
    # only a subset allow rules may actually be denied

    if include.get(incname, False):
        for rule_type in r_types:
            deleted += profile[rule_type].delete_duplicates(include[incname][incname][rule_type])

    return deleted


def ask_conflict_mode(old_profile, merge_profile):
    """ask user about conflicting exec rules"""
    for oldrule in old_profile['file'].rules:
        conflictingrules = merge_profile['file'].get_exec_conflict_rules(oldrule)

        if conflictingrules.rules:
            q = aaui.PromptQuestion()
            q.headers = [
                _('Path'), oldrule.path.regex,
                _('Select the appropriate mode'), '',
            ]
            options = [oldrule.get_clean()]
            for rule in conflictingrules.rules:
                options.append(rule.get_clean())
            q.options = options
            q.functions = ['CMD_ALLOW', 'CMD_ABORT']
            done = False
            while not done:
                ans, selected = q.promptUser()
                if ans == 'CMD_ALLOW':
                    if selected == 0:
                        pass  # just keep the existing rule
                    elif selected > 0:
                        # replace existing rule with merged one
                        old_profile['file'].delete(oldrule)
                        old_profile['file'].add(conflictingrules.rules[selected - 1])
                    else:
                        raise AppArmorException(_('Unknown selection'))

                    for rule in conflictingrules.rules:
                        merge_profile['file'].delete(rule)  # make sure aa-mergeprof doesn't ask to add conflicting rules later

                    done = True


def match_includes(profile, rule_type, rule_obj):
    """propose abstractions that allow the given rule_obj

       Note: This function will return relative paths for includes inside profile_dir
    """

    newincludes = []
    for incname in include.keys():
        rel_incname = incname.replace(profile_dir + '/', '')

        # TODO: improve/fix logic to honor magic vs. quoted include paths
        if rel_incname.startswith('/'):
            is_magic = False
        else:
            is_magic = True

        # never propose includes that are already in the profile (shouldn't happen because of is_known_rule())
        if profile and profile['inc_ie'].is_covered(IncludeRule(rel_incname, False, is_magic)):
            continue

        # never propose a local/ include (they are meant to be included in exactly one profile)
        if rel_incname.startswith('local/'):
            continue

        # XXX type check should go away once we init all profiles correctly
        if valid_include(incname) and include[incname][incname][rule_type].is_covered(rule_obj):
            sug = include[incname][incname]['logprof_suggest'].split()
            if sug == []:
                newincludes.append(rel_incname)
            elif sug[0] == 'no':
                continue
            else:
                for s in sug:
                    try:
                        if re.match(s, profile.data['name']):
                            newincludes.append(rel_incname)
                            break
                    except re.error as err:
                        aaui.UI_Important(_('WARNING: Invalid regex \'%s\' in abstraction %s: %s.'
                                            % (s, rel_incname, err)))

    return newincludes


def valid_include(incname):
    """check if the given include file exists or is whitelisted in custom_includes"""
    if cfg['settings']['custom_includes']:
        for incm in cfg['settings']['custom_includes'].split():
            if incm == incname:
                return True

    if incname.startswith('abstractions/') and os.path.isfile(os.path.join(profile_dir, incname)):
        return True
    elif incname.startswith('/') and os.path.isfile(incname):
        return True

    return False


def set_logfile(filename):
    """set logfile to a) the specified filename or b) if not given, the first existing logfile from logprof.conf"""

    global logfile

    if filename:
        logfile = filename
    elif 'logfiles' in cfg['settings']:
        # This line can only run if the 'logfile' exists in settings, otherwise
        # it will yield a Python KeyError
        logfile = conf.find_first_file(cfg['settings']['logfiles']) or '/var/log/syslog'
    else:
        logfile = '/var/log/syslog'

    if not os.path.exists(logfile):
        if filename:
            raise AppArmorException(_('The logfile %s does not exist. Please check the path.') % logfile)
        else:
            raise AppArmorException('Can\'t find system log "%s". Please check permissions.' % (logfile))
    elif os.path.isdir(logfile):
        raise AppArmorException(_('%s is a directory. Please specify a file as logfile') % logfile)


def do_logprof_pass(logmark='', out_dir=None):
    aaui.UI_Info(_('Reading log entries from %s.') % logfile)

    load_sev_db()

    log_reader = apparmor.logparser.ReadLog(logfile, active_profiles, profile_dir)
    hashlog = log_reader.read_log(logmark)

    ask_exec(hashlog)
    ask_addhat(hashlog)

    log_dict = collapse_log(hashlog)

    ask_the_questions(log_dict)

    save_profiles(out_dir=out_dir)


def save_profiles(is_mergeprof=False, out_dir=None):
    # Ensure the changed profiles are actual active profiles
    for prof_name in changed.keys():
        if not active_profiles.profile_exists(prof_name):
            print("*** save_profiles(): removing %s" % prof_name)
            print('*** This should not happen. Please open a bugreport!')
            changed.pop(prof_name)

    changed_list = sorted(changed.keys())

    if changed_list:
        q = aaui.PromptQuestion()
        q.title = 'Changed Local Profiles'
        q.explanation = _('The following local profiles were changed. Would you like to save them?')
        q.functions = ['CMD_SAVE_CHANGES', 'CMD_SAVE_SELECTED', 'CMD_VIEW_CHANGES', 'CMD_VIEW_CHANGES_CLEAN', 'CMD_ABORT']
        if is_mergeprof:
            q.functions = ['CMD_SAVE_CHANGES', 'CMD_VIEW_CHANGES', 'CMD_ABORT', 'CMD_IGNORE_ENTRY']
        q.default = 'CMD_VIEW_CHANGES'
        q.selected = 0
        ans = ''
        arg = None
        while ans != 'CMD_SAVE_CHANGES':
            if not changed:
                return

            options = sorted(changed.keys())
            q.options = options

            ans, arg = q.promptUser()

            q.selected = arg  # remember selection
            profile_name = options[arg]

            if ans == 'CMD_SAVE_SELECTED':
                write_profile_ui_feedback(profile_name, out_dir=out_dir)
                reload_base(profile_name)
                q.selected = 0  # saving the selected profile removes it from the list, therefore reset selection

            elif ans == 'CMD_VIEW_CHANGES':
                oldprofile = None
                if active_profiles[profile_name].get('filename', False):
                    oldprofile = active_profiles[profile_name]['filename']
                else:
                    oldprofile = get_profile_filename_from_attachment(profile_name, True)

                serialize_options = {'METADATA': True}
                newprofile = serialize_profile(active_profiles, profile_name, serialize_options)

                aaui.UI_Changes(oldprofile, newprofile, comments=True)

            elif ans == 'CMD_VIEW_CHANGES_CLEAN':
                oldprofile = serialize_profile(original_profiles, profile_name, {})
                newprofile = serialize_profile(active_profiles, profile_name, {})

                aaui.UI_Changes(oldprofile, newprofile)

            elif ans == 'CMD_IGNORE_ENTRY':
                changed.pop(options[arg])

        for profile_name in sorted(changed.keys()):
            write_profile_ui_feedback(profile_name, out_dir=out_dir)
            reload_base(profile_name)


def collapse_log(hashlog, ignore_null_profiles=True):
    log_dict = {}

    for aamode in hashlog.keys():
        log_dict[aamode] = {}

        for full_profile in hashlog[aamode].keys():
            final_name = hashlog[aamode][full_profile]['final_name']

            if final_name == '':
                continue  # user chose "deny" or "unconfined" for this target, therefore ignore log events

            if '//null-' in final_name and ignore_null_profiles:
                # ignore null-* profiles (probably nested childs)
                # otherwise we'd accidentally create a null-* hat in the profile which is worse
                # XXX drop this once we support nested childs
                continue

            profile, hat = split_name(final_name)  # XXX limited to two levels to avoid an Exception on nested child profiles or nested null-*
            # TODO: support nested child profiles

            # used to avoid calling is_known_rule() on events for a non-existing profile
            hat_exists = False
            if active_profiles.profile_exists(profile) and active_profiles.profile_exists(final_name):  # we need to check for the target profile here
                hat_exists = True

            if not log_dict[aamode].get(final_name):
                # with execs in ix mode, we already have ProfileStorage initialized and should keep the content it already has
                log_dict[aamode][final_name] = ProfileStorage(profile, hat, 'collapse_log()')

            for ev_type, ev_class in ReadLog.ruletypes.items():
                for rule in ev_class.from_hashlog(hashlog[aamode][full_profile][ev_type]):
                    if not hat_exists or not is_known_rule(active_profiles[full_profile], ev_type, rule):
                        log_dict[aamode][final_name][ev_type].add(rule)

    return log_dict


def update_profiles(ui_msg=False, skip_profiles=()):
    reset_aa()
    try:
        read_profiles(ui_msg, skip_profiles)
    except AppArmorException as e:
        print(_("Error while loading profiles: {}").format(e))


def read_profiles(ui_msg=False, skip_profiles=(), skip_disabled=True, skip_perm_error=False):
    # we'll read all profiles from disk, so reset the storage first (autodep() might have created/stored
    # a profile already, which would cause a 'Conflicting profile' error in attach_profile_data())
    #
    # The skip_profiles parameter should only be specified by tests.

    global original_profiles
    original_profiles = ProfileList()

    if ui_msg:
        aaui.UI_Info(_('Updating AppArmor profiles in %s.') % profile_dir)

    try:
        os.listdir(profile_dir)
    except (OSError, TypeError):
        if skip_perm_error:
            aaui.UI_Info(_("WARNING: Can't read AppArmor profiles in %s") % profile_dir)
            return
        fatal_error(_("Can't read AppArmor profiles in %s") % profile_dir)

    for file in os.listdir(profile_dir):
        full_file = os.path.join(profile_dir, file)
        if os.path.isfile(full_file):
            if is_skippable_file(file):
                continue
            elif skip_disabled and os.path.exists(f'{profile_dir}/disable/{file}'):
                debug_logger.debug("skipping disabled profile %s", file)
                continue
            elif file in skip_profiles:
                aaui.UI_Info("skipping profile %s" % full_file)
                continue
            else:
                try:
                    read_profile(full_file, True)
                except AppArmorException as e:
                    aaui.UI_Info("skipping unparseable profile %s (%s)" % (full_file, e.value))


def read_inactive_profiles(skip_profiles=()):
    # The skip_profiles parameter should only be specified by tests.

    if hasattr(read_inactive_profiles, 'already_read'):
        # each autodep() run calls read_inactive_profiles, but that's a) superfluous and b) triggers a conflict because the inactive profiles are already loaded
        # therefore don't do anything if the inactive profiles were already loaded
        return

    read_inactive_profiles.already_read = True

    if not os.path.exists(extra_profile_dir):
        return
    try:
        os.listdir(profile_dir)
    except (OSError, TypeError):
        fatal_error(_("Can't read AppArmor profiles in %s") % extra_profile_dir)

    for file in os.listdir(extra_profile_dir):
        full_file = os.path.join(extra_profile_dir, file)
        if os.path.isfile(full_file):
            if is_skippable_file(file):
                continue
            elif file in skip_profiles:
                aaui.UI_Info("skipping profile %s" % full_file)
                continue
            else:
                read_profile(full_file, False)


def read_profile(file, is_active_profile, read_error_fatal=False):
    data = None
    try:
        with open_file_read(file) as f_in:
            data = f_in.readlines()
    except IOError as e:
        aaui.UI_Important('WARNING: Error reading file %s, skipping.\n    %s' % (file, e))
        debug_logger.debug("read_profile: can't read %s - skipping", file)
        if read_error_fatal:
            raise (e)
        else:
            return

    profile_data = parse_profile_data(data, file, 0, True)

    if not profile_data:
        return

    for profile in profile_data:
        attachment = profile_data[profile]['attachment']
        filename = profile_data[profile]['filename']

        if not attachment and profile.startswith('/'):
            attachment = profile  # use profile as name and attachment

        if is_active_profile:
            active_profiles.add_profile(filename, profile, attachment, profile_data[profile])
            original_profiles.add_profile(filename, profile, attachment, deepcopy(profile_data[profile]))
        else:
            extra_profiles.add_profile(filename, profile, attachment, profile_data[profile])


# TODO: Split profiles' creating and saving.
def create_local_profile_if_needed(profile_name):
    base_profile = profile_name
    while True:
        parent = active_profiles[base_profile].data.get('parent')
        if parent == '':
            break
        base_profile = parent

    local_include = active_profiles[profile_name].get_local_include()

    # Not found: we add a mention of the local profile in the main profile
    if not local_include:
        local_include = "local/" + profile_name.replace('/', '.')
        active_profiles[profile_name]['inc_ie'].add(IncludeRule(local_include, True, True))
        write_profile_ui_feedback(base_profile)

    inc_file = profile_dir + '/' + local_include

    # Create the include if needed
    if not include.get(inc_file, {}).get(inc_file, False):
        include[inc_file] = dict()
        include[inc_file][inc_file] = ProfileStorage(inc_file, inc_file, "create_local_profile_if_needed")

    return inc_file


def serialize_include(prof_storage, include_metadata=True):
    lines = []
    if include_metadata:
        lines.append('# Last Modified: %s' % time.asctime())

    if prof_storage.get('initial_comment'):
        lines.append(prof_storage['initial_comment'].rstrip())

    lines.extend(prof_storage.get_rules_clean(0))

    return '\n'.join(lines) + '\n'


def write_include_ui_feedback(include_data, incfile, out_dir=None, include_metadata=True):
    aaui.UI_Info(_('Writing updated include file %s') % incfile)
    write_include(include_data, incfile, out_dir, include_metadata)


def write_include(include_data, incfile, out_dir=None, include_metadata=True):
    target_file = incfile if incfile.startswith('/') else os.path.join(profile_dir, incfile)
    if out_dir:
        target_file = os.path.join(out_dir, os.path.basename(target_file))

    include_string = serialize_include(include_data, include_metadata=include_metadata)

    with NamedTemporaryFile('w', suffix='~', delete=False, dir=profile_dir + "/local") as tmp:
        if os.path.exists(target_file):
            shutil.copymode(target_file, tmp.name)
        else:
            pass  # 0o600 (NamedTemporaryFile default)
        tmp.write(include_string)

    try:
        shutil.move(tmp.name, target_file)
    except PermissionError:
        aaui.UI_Important(_('WARNING: Can\'t write to %s. Please run this script with elevated privileges') % target_file)


def attach_profile_data(profiles, profile_data):
    profile_data = merged_to_split(profile_data)
    # Make deep copy of data to avoid changes to
    # arising due to mutables
    for p in profile_data.keys():
        if profiles.get(p, False):
            for hat in profile_data[p].keys():
                if profiles[p].get(hat, False):
                    raise AppArmorException(
                        _("Conflicting profiles for %s defined in two files:\n- %s\n- %s")
                        % (combine_name(p, hat), profiles[p][hat]['filename'], profile_data[p][hat]['filename']))

        profiles[p] = deepcopy(profile_data[p])


def parse_profile_data(data, file, do_include, in_preamble):
    profile_data = {}
    profile = None
    hat = None
    profname = None
    in_contained_hat = None
    parsed_profiles = []
    initial_comment = ''
    lastline = None

    active_profiles.init_file(file)

    if do_include:
        profile = file
        hat = None
        profname = combine_profname((profile, hat))
        profile_data[profname] = ProfileStorage(profile, hat, 'parse_profile_data() do_include')
        profile_data[profname]['filename'] = file

    for lineno, line in enumerate(data):
        line = line.strip()
        if not line:
            continue
        # we're dealing with a multiline statement
        if lastline:
            line = '%s %s' % (lastline, line)
            lastline = None

        # is line handled by a *Rule class?
        (rule_name, rule_obj) = match_line_against_rule_classes(line, profile, file, lineno, in_preamble)
        if rule_name:
            if in_preamble:
                active_profiles.add_rule(file, rule_name, rule_obj)
            else:
                profile_data[profname][rule_name].add(rule_obj)

            if rule_name == 'inc_ie':
                for incname in rule_obj.get_full_paths(profile_dir):
                    if incname == file:
                        # warn about endless loop, and don't call load_include() (again) for this file
                        aaui.UI_Important(_('WARNING: endless loop detected: file %s includes itself' % incname))
                    else:
                        load_include(incname, in_preamble)

        elif RE_PROFILE_START.search(line) or RE_PROFILE_HAT_DEF.search(line):  # Starting line of a profile/hat
            # in_contained_hat is needed to know if we are already in a profile or not. Simply checking if we are in a hat doesn't work,
            # because something like "profile foo//bar" will set profile and hat at once, and later (wrongfully) expect another "}".
            # The logic is simple and resembles a "poor man's stack" (with limited/hardcoded height).
            if profile:
                in_contained_hat = True
            else:
                in_contained_hat = False

            in_preamble = False

            (profile, hat, prof_storage) = ProfileStorage.parse(line, file, lineno, profile, hat)

            if profile == hat:
                hat = None
            profname = combine_profname((profile, hat))

            if profile_data.get(profname, False):
                raise AppArmorException(
                    'Profile %(profile)s defined twice in %(file)s, last found in line %(line)s'
                    % {'file': file, 'line': lineno + 1, 'profile': combine_name(profile, hat)})

            profile_data[profname] = prof_storage

            # Save the initial comment
            if initial_comment:
                profile_data[profname]['initial_comment'] = initial_comment

            initial_comment = ''

        elif RE_PROFILE_END.search(line):
            # If profile ends and we're not in one
            if not profile:
                raise AppArmorException(
                    _('Syntax Error: Unexpected End of Profile reached in file: %(file)s line: %(line)s')
                    % {'file': file, 'line': lineno + 1})

            if in_contained_hat:
                hat = None
                in_contained_hat = False
                profname = combine_profname((profile, hat))
            else:
                parsed_profiles.append(profile)
                profile = None
                profname = None
                in_preamble = True

            initial_comment = ''

        elif RE_PROFILE_CONDITIONAL.search(line):
            # Conditional Boolean
            pass

        elif RE_PROFILE_CONDITIONAL_VARIABLE.search(line):
            # Conditional Variable defines
            pass

        elif RE_PROFILE_CONDITIONAL_BOOLEAN.search(line):
            # Conditional Boolean defined
            pass

        elif RE_PROFILE_CHANGE_HAT.search(line):
            matches = RE_PROFILE_CHANGE_HAT.search(line).groups()

            if not profile:
                raise AppArmorException(_('Syntax Error: Unexpected change hat declaration found in file: %(file)s line: %(line)s')
                                        % {'file': file, 'line': lineno + 1})

            aaui.UI_Important(_('Ignoring no longer supported change hat declaration "^%(hat)s," found in file: %(file)s line: %(line)s')
                              % {'hat': matches[0], 'file': file, 'line': lineno + 1})

        elif line.startswith('#'):
            # Handle initial comments
            if not profile:
                if line.startswith('# Last Modified:'):
                    continue
                else:
                    initial_comment = initial_comment + line + '\n'

            if RE_METADATA_LOGPROF_SUGGEST.search(line):
                # - logprof_suggest is a set of space-separated regexes
                # - If this metadata is present, the abstraction is only proposed to logprof if at least one regex is matched
                # - If this abstraction should not be proposed to any profile, it is possible to tell #LOGPROF-SUGGEST: no
                profile_data[profname]['logprof_suggest'] = RE_METADATA_LOGPROF_SUGGEST.search(line).group('suggest')

                # keep line as part of initial_comment (if we ever support writing abstractions, we should update serialize_profile())
                initial_comment = initial_comment + line + '\n'

        elif not RE_RULE_HAS_COMMA.search(line):
            # Bah, line continues on to the next line
            if RE_HAS_COMMENT_SPLIT.search(line):
                # filter trailing comments
                lastline = RE_HAS_COMMENT_SPLIT.search(line).group('not_comment')
            else:
                lastline = line
        else:
            raise AppArmorException(
                _('Syntax Error: Unknown line found in file %(file)s line %(lineno)s:\n    %(line)s')
                % {'file': file, 'lineno': lineno + 1, 'line': line})

    if lastline:
        # lastline gets merged into line (and reset to None) when reading the next line.
        # If it isn't empty, this means there's something unparsable at the end of the profile
        raise AppArmorException(
            _('Syntax Error: Unknown line found in file %(file)s line %(lineno)s:\n    %(line)s')
            % {'file': file, 'lineno': lineno + 1, 'line': lastline})

    # Below is not required I'd say
    if not do_include:
        for hatglob in cfg['required_hats'].keys():
            for parsed_prof in sorted(parsed_profiles):
                if re.search(hatglob, parsed_prof):
                    for hat in cfg['required_hats'][hatglob].split():
                        profname = combine_profname((parsed_prof, hat))
                        if not profile_data.get(profname, False):
                            profile_data[profname] = ProfileStorage(parsed_prof, hat, 'parse_profile_data() required_hats')
                            profile_data[profname]['parent'] = parsed_prof
                            profile_data[profname]['is_hat'] = True

    # End of file reached but we're stuck in a profile
    if profile and not do_include:
        raise AppArmorException(
            _("Syntax Error: Missing '}' or ','. Reached end of file %(file)s while inside profile %(profile)s")
            % {'file': file, 'profile': profile})

    return profile_data


def match_line_against_rule_classes(line, profile, file, lineno, in_preamble):
    """handle all lines handled by *Rule classes"""

    for rule_name in (
            'abi',
            'all',
            'alias',
            'boolean',
            'variable',
            'inc_ie',
            'capability',
            'change_profile',
            'dbus',
            'file',  # file rules need to be parsed after variable rules
            'network',
            'ptrace',
            'rlimit',
            'signal',
            'userns',
            'mqueue',
            'io_uring',
            'mount',
            'pivot_root',
            'unix',
    ):

        if rule_name in ruletypes:
            rule_class = ruletypes[rule_name]['rule']
        else:
            rule_class = preamble_ruletypes[rule_name]['rule']

        if rule_class.match(line):
            if not in_preamble and rule_name not in ruletypes:
                raise AppArmorException(
                    _('Syntax Error: Unexpected %(rule)s definition found inside profile in file: %(file)s line: %(line)s')
                    % {'file': file, 'line': lineno + 1, 'rule': rule_name})

            if in_preamble and rule_name not in preamble_ruletypes:
                raise AppArmorException(
                    _('Syntax Error: Unexpected %(rule)s entry found in file: %(file)s line: %(line)s')
                    % {'file': file, 'line': lineno + 1, 'rule': rule_name})

            rule_obj = rule_class.create_instance(line)
            return (rule_name, rule_obj)

    return (None, None)


def merged_to_split(profile_data):
    """(temporary) helper function to convert a list of profile['foo//bar'] profiles into compat['foo']['bar']"""
    compat = hasher()
    for prof in profile_data:
        profile, hat = split_name(prof)  # XXX limited to two levels to avoid an Exception on nested child profiles or nested null-*
        compat[profile][hat] = profile_data[prof]

    return compat


def write_piece(profile_data, depth, name, nhat):
    pre = '  ' * depth
    data = []
    inhat = False
    if name != nhat:
        name = nhat
        inhat = True
    data += profile_data[name].get_header(depth, False)
    data += profile_data[name].get_rules_clean(depth + 1)

    pre2 = '  ' * (depth + 1)

    if not inhat:
        # Embedded hats
        all_childs = []
        for child in sorted(profile_data.keys()):
            if child.startswith('%s//' % name):
                all_childs.append(child)

        for hat in all_childs:
            profile, only_hat = split_name(hat)

            if not profile_data[hat]['external']:
                data.append('')

                data += profile_data[hat].get_header(depth + 1, True)

                data += profile_data[hat].get_rules_clean(depth + 2)

                data.append('%s}' % pre2)

        data.append('%s}' % pre)

        # External hats
        for hat in all_childs:
            if name == nhat and profile_data[hat].get('external', False):
                data.append('')
                data.extend(map(lambda x: '%s%s' % (pre, x), write_piece(profile_data, depth, name, hat)))
                data.append('%s}' % pre)

    return data


def serialize_profile(profile_data, name, options):
    ''' combine the preamble and profiles in a file to a string (to be written to the profile file) '''

    data = []

    if not isinstance(options, dict):
        raise AppArmorBug('serialize_profile(): options is not a dict: %s' % options)

    include_metadata = options.get('METADATA', False)

    if include_metadata:
        data.extend(['# Last Modified: %s' % time.asctime()])

#     if profile_data[name].get('initial_comment', False):
#         comment = profile_data[name]['initial_comment']
#         data.append(comment)

    if options.get('is_attachment'):
        prof_filename = get_profile_filename_from_attachment(name, True)
    else:
        prof_filename = get_profile_filename_from_profile_name(name, True)

    data.extend(active_profiles.get_clean(prof_filename, 0))

    # Here should be all the profiles from the files added write after global/common stuff
    for prof in sorted(active_profiles.profiles_in_file(prof_filename)):
        parent = active_profiles.profiles[prof]['parent']
        if parent and parent in active_profiles.profiles:
            continue  # child profile or hat, already part of its parent profile if parent is defined

        # aa-logprof asks to save each file separately. Therefore only update the given profile, and keep the original version of other profiles in the file
        if prof != name:
            if original_profiles.profile_exists(prof) and original_profiles[prof].get('initial_comment'):
                comment = original_profiles[prof]['initial_comment']
                data.extend([comment, ''])

            data.extend(write_piece(original_profiles.get_profile_and_childs(prof), 0, prof, prof))

        else:
            if profile_data[name].get('initial_comment', False):
                comment = profile_data[name]['initial_comment']
                data.extend([comment, ''])

            # write_piece() expects a dict, not a ProfileList - TODO: change write_piece()?
            if type(profile_data) is dict:
                data.extend(write_piece(profile_data, 0, name, name))
            else:
                data.extend(write_piece(profile_data.get_profile_and_childs(name), 0, name, name))

    return '\n'.join(data) + '\n'


def write_profile_ui_feedback(profile, is_attachment=False, out_dir=None):
    aaui.UI_Info(_('Writing updated profile for %s.') % profile)
    write_profile(profile, is_attachment, out_dir=out_dir)


def write_profile(profile, is_attachment=False, out_dir=None):
    if active_profiles[profile]['filename']:
        prof_filename = active_profiles[profile]['filename']
    elif is_attachment:
        prof_filename = get_profile_filename_from_attachment(profile, True)
    else:
        prof_filename = get_profile_filename_from_profile_name(profile, True)

    serialize_options = {'METADATA': True, 'is_attachment': is_attachment}
    profile_string = serialize_profile(active_profiles, profile, serialize_options)

    try:
        with NamedTemporaryFile('w', suffix='~', delete=False, dir=out_dir or profile_dir) as newprof:
            if os.path.exists(prof_filename):
                shutil.copymode(prof_filename, newprof.name)
            else:
                # permission_600 = stat.S_IRUSR | stat.S_IWUSR    # Owner read and write
                # os.chmod(newprof.name, permission_600)
                pass
            newprof.write(profile_string)
    except PermissionError as e:
        raise AppArmorException(e)

    if out_dir is None:
        os.rename(newprof.name, prof_filename)
    else:
        out_filename = out_dir + "/" + prof_filename.split('/')[-1]
        os.rename(newprof.name, out_filename)

    if profile in changed:
        changed.pop(profile)
    else:
        debug_logger.info("Unchanged profile written: %s (not listed in 'changed' list)", profile)

    for full_profile in active_profiles.get_profile_and_childs(profile):
        if profile == full_profile or active_profiles[full_profile]['parent']:  # copy main profile and childs, but skip external hats
            original_profiles.replace_profile(full_profile, deepcopy(active_profiles[full_profile]))


def include_list_recursive(profile, in_preamble=False):
    """get a list of all includes in a profile and its included files"""

    includelist = profile['inc_ie'].get_all_full_paths(profile_dir)
    full_list = []

    while includelist:
        incname = includelist.pop(0)

        if incname in full_list:
            continue
        full_list.append(incname)

        if in_preamble:
            look_at = active_profiles.files[incname]
        else:
            look_at = include[incname][incname]

        for childinc in look_at['inc_ie'].rules:
            for childinc_file in childinc.get_full_paths(profile_dir):
                if childinc_file not in full_list:
                    includelist.append(childinc_file)

    return full_list


def is_known_rule(profile, rule_type, rule_obj):
    if profile[rule_type].is_covered(rule_obj, False):
        return True

    includelist = include_list_recursive(profile)

    for incname in includelist:
        if include[incname][incname][rule_type].is_covered(rule_obj, False):
            return True

    return False


def get_file_perms(profile, path, audit, deny):
    """get the current permissions for the given path"""

    perms = profile['file'].get_perms_for_path(path, audit, deny)

    includelist = include_list_recursive(profile)

    for incname in includelist:
        incperms = include[incname][incname]['file'].get_perms_for_path(path, audit, deny)

        for allow_or_deny in ('allow', 'deny'):
            for owner_or_all in ('all', 'owner'):
                for perm in incperms[allow_or_deny][owner_or_all]:
                    perms[allow_or_deny][owner_or_all].add(perm)

                if 'a' in perms[allow_or_deny][owner_or_all] and 'w' in perms[allow_or_deny][owner_or_all]:
                    perms[allow_or_deny][owner_or_all].remove('a')  # a is a subset of w, so remove it

        for incpath in incperms['paths']:
            perms['paths'].add(incpath)

    return perms


def propose_file_rules(profile_obj, rule_obj):
    """Propose merged file rules based on the existing profile and the log events
       - permissions get merged
       - matching paths from existing rules, common_glob() and user_globs get proposed
       - IMPORTANT: modifies rule_obj.original_perms and rule_obj.perms"""
    options = []
    original_path = rule_obj.path.regex

    merged_rule_obj = deepcopy(rule_obj)   # make sure not to modify the original rule object (with exceptions, see end of this function)

    existing_perms = get_file_perms(profile_obj, rule_obj.path, False, False)
    for perm in existing_perms['allow']['all']:  # XXX also handle owner-only perms
        merged_rule_obj.perms.add(perm)
        merged_rule_obj.raw_rule = None

    if 'a' in merged_rule_obj.perms and 'w' in merged_rule_obj.perms:
        merged_rule_obj.perms.remove('a')  # a is a subset of w, so remove it

    pathlist = {original_path} | existing_perms['paths'] | set(glob_common(original_path))

    for user_glob in user_globs:
        if user_globs[user_glob].match(original_path):
            pathlist.add(user_glob)

    pathlist = order_globs(pathlist, original_path)

    # paths in existing rules that match the original path
    for path in pathlist:
        merged_rule_obj.store_edit(path)
        merged_rule_obj.raw_rule = None
        options.append(merged_rule_obj.get_clean())

    merged_rule_obj.exec_perms = None

    rule_obj.original_perms = existing_perms
    if rule_obj.perms != merged_rule_obj.perms:
        rule_obj.perms = merged_rule_obj.perms
        rule_obj.raw_rule = None

    return options


def reload_base(bin_path):
    if not check_for_apparmor():
        return

    prof_filename = get_profile_filename_from_profile_name(bin_path, True)

    reload_profile(prof_filename)


def reload_profile(prof_filename, raise_exc=False):
    """run apparmor_parser to reload the given profile file"""

    ret, out = cmd((parser, '-I%s' % profile_dir, '--base', profile_dir, '-r', prof_filename))

    if ret != 0:
        if raise_exc:
            raise AppArmorException(out)
        else:
            print(out)


def reload(bin_path):
    bin_path = find_executable(bin_path)
    if bin_path:
        reload_base(bin_path)


def get_include_data(filename):
    data = []
    if not filename.startswith('/'):
        filename = os.path.join(profile_dir, filename)
    if os.path.exists(filename):
        with open_file_read(filename) as f_in:
            data = f_in.readlines()
    else:
        raise AppArmorException(_('File Not Found: %s') % filename)
    return data


def include_dir_filelist(include_name):
    """returns a list of files in the given include_name directory,
       except skippable files.
    """

    if not include_name.startswith('/'):
        raise AppArmorBug('incfile %s not starting with /' % include_name)

    files = []
    for path in os.listdir(include_name):
        path = path.strip()
        if is_skippable_file(path):
            continue
        file_name = os.path.join(include_name, path)
        if os.path.isfile(file_name):
            files.append(file_name)

    return files


def load_include(incname, in_preamble=False):
    load_includeslist = [incname]
    while load_includeslist:
        incfile = load_includeslist.pop(0)
        if not incfile.startswith('/'):
            raise AppArmorBug('incfile %s not starting with /' % incfile)

        if include.get(incfile, {}).get(incfile, False):
            pass  # already read, do nothing
        elif os.path.isfile(incfile):
            data = get_include_data(incfile)
            incdata = parse_profile_data(data, incfile, True, in_preamble)
            attach_profile_data(include, incdata)
        # If the include is a directory means include all subfiles
        elif os.path.isdir(incfile):
            load_includeslist += include_dir_filelist(incfile)
        else:
            raise AppArmorException("Include file %s not found" % (incfile))

    return 0


def check_qualifiers(program):
    if cfg['qualifiers'].get(program, False):
        if cfg['qualifiers'][program] != 'p':
            fatal_error(
                _("%s is currently marked as a program that should not have its own\n"
                  "profile.  Usually, programs are marked this way if creating a profile for \n"
                  "them is likely to break the rest of the system.  If you know what you're\n"
                  "doing and are certain you want to create a profile for this program, edit\n"
                  "the corresponding entry in the [qualifiers] section in /etc/apparmor/logprof.conf.")
                % program)
    return False


def get_subdirectories(current_dir):
    """Returns a list of all directories directly inside given directory"""
    return next(os.walk(current_dir))[1]


def loadincludes():
    loadincludes_dir('tunables', True)
    loadincludes_dir('abstractions', False)


def loadincludes_dir(subdir, in_preamble):
    idir = os.path.join(profile_dir, subdir)

    if os.path.isdir(idir):  # if directory doesn't exist, silently skip loading it
        for dirpath, dirname, files in os.walk(idir):
            for fi in files:
                if is_skippable_file(fi):
                    continue
                else:
                    fi = os.path.join(dirpath, fi)
                    load_include(fi, in_preamble)


def glob_common(path):
    globs = []

    if re.search(r'[\d.]+\.so$', path) or re.search(r'\.so\.[\d.]+$', path):
        libpath = path
        libpath = re.sub(r'[\d.]+\.so$', '*.so', libpath)
        libpath = re.sub(r'\.so\.[\d.]+$', '.so.*', libpath)
        if libpath != path:
            globs.append(libpath)

    for glob in cfg['globs']:
        if re.search(glob, path):
            globbedpath = path
            globbedpath = re.sub(glob, cfg['globs'][glob], path)
            if globbedpath != path:
                globs.append(globbedpath)

    return sorted(set(globs))


def combine_name(name1, name2):
    if name1 == name2:
        return name1
    else:
        return '%s^%s' % (name1, name2)


def logger_path():
    logger = conf.find_first_file(cfg['settings']['logger']) or '/bin/logger'
    if not os.path.isfile(logger) or not os.access(logger, os.EX_OK):
        raise AppArmorException("Can't find logger!\nPlease make sure %s exists, or update the 'logger' path in logprof.conf." % logger)
    return logger


# ------ Initialisations ------ #

def init_aa(confdir=None, profiledir=None):
    global CONFDIR
    global conf
    global cfg
    global profile_dir
    global extra_profile_dir
    global parser

    if CONFDIR:
        return  # config already initialized (and possibly changed afterwards), so don't overwrite the config variables

    if not confdir:
        confdir = "/etc/apparmor"

    CONFDIR = confdir
    conf = apparmor.config.Config('ini', CONFDIR)
    cfg = conf.read_config('logprof.conf')

    # prevent various failures if logprof.conf doesn't exist
    if not cfg.sections():
        cfg.add_section('settings')
        cfg.add_section('required_hats')

    if cfg['settings'].get('default_owner_prompt', False):
        cfg['settings']['default_owner_prompt'] = ''

    if profiledir:
        profile_dir = profiledir
    else:
        profile_dir = conf.find_first_dir(cfg['settings'].get('profiledir')) or '/etc/apparmor.d'
    profile_dir = os.path.abspath(profile_dir)
    if not os.path.isdir(profile_dir):
        raise AppArmorException("Can't find AppArmor profiles in %s" % (profile_dir))

    extra_profile_dir = conf.find_first_dir(cfg['settings'].get('inactive_profiledir')) or '/usr/share/apparmor/extra-profiles/'

    parser = conf.find_first_file(cfg['settings'].get('parser')) or '/sbin/apparmor_parser'
    if not os.path.isfile(parser) or not os.access(parser, os.EX_OK):
        raise AppArmorException("Can't find apparmor_parser at %s" % (parser))


def load_sev_db():
    global sev_db

    if not sev_db:
        sev_db = apparmor.severity.Severity(CONFDIR + '/severity.db', _('unknown'))
