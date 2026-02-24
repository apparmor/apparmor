#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2016 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import gettext
import os
import subprocess
import unittest

from apparmor.ui import CMDS, get_translated_hotkey
from common_test import AATest, setup_all_loops


class TestHotkeyConflicts(AATest):
    # check if there are any hotkey conflicts in one of the apparmor-utils translations
    tests = (
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_OFF', 'CMD_ABORT', 'CMD_FINISHED'),                 True),  # aa.py available_buttons() with CMD_AUDIT_OFF
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_NEW', 'CMD_ABORT', 'CMD_FINISHED'),                 True),  # aa.py available_buttons() with CMD_AUDIT_NEW
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_OFF', 'CMD_USER_ON',  'CMD_ABORT', 'CMD_FINISHED'), True),  # aa.py available_buttons() with CMD_AUDIT_OFF and CMD_USER_ON
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_OFF', 'CMD_USER_OFF', 'CMD_ABORT', 'CMD_FINISHED'), True),  # aa.py available_buttons() with CMD_AUDIT_OFF and CMD_USER_OFF
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_NEW', 'CMD_USER_ON',  'CMD_ABORT', 'CMD_FINISHED'), True),  # aa.py available_buttons() with CMD_AUDIT_NEW and CMD_USER_ON
        (('CMD_ALLOW', 'CMD_DENY', 'CMD_IGNORE_ENTRY', 'CMD_GLOB', 'CMD_GLOBEXT', 'CMD_NEW', 'CMD_AUDIT_NEW', 'CMD_USER_OFF', 'CMD_ABORT', 'CMD_FINISHED'), True),  # aa.py available_buttons() with CMD_AUDIT_NEW and CMD_USER_OFF
        (('CMD_SAVE_CHANGES', 'CMD_SAVE_SELECTED', 'CMD_VIEW_CHANGES', 'CMD_VIEW_CHANGES_CLEAN', 'CMD_ABORT'),                                              True),  # aa.py save_profiles()
        (('CMD_VIEW_PROFILE', 'CMD_USE_PROFILE', 'CMD_CREATE_PROFILE', 'CMD_ABORT'),                                                                        True),  # aa.py get_profile()
        (('CMD_ix', 'CMD_pix', 'CMD_cix', 'CMD_nix', 'CMD_EXEC_IX_OFF', 'CMD_ux', 'CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED', 'CMD_IGNORE_ENTRY'),             True),  # aa.py build_x_functions() with exec_toggle
        (('CMD_ix', 'CMD_cx', 'CMD_px', 'CMD_nx', 'CMD_ux', 'CMD_EXEC_IX_ON', 'CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED', 'CMD_IGNORE_ENTRY'),                 True),  # aa.py build_x_functions() without exec_toggle
        (('CMD_ADDHAT', 'CMD_USEDEFAULT', 'CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED'),                                                                         True),  # aa.py ask_addhat()
        (('CMD_YES', 'CMD_NO', 'CMD_CANCEL'),                                                                                                               True),  # ui.py UI_YesNo() and UI_YesNoCancel
        (('CMD_SAVE_CHANGES', 'CMD_VIEW_CHANGES', 'CMD_ABORT', 'CMD_IGNORE_ENTRY'),                                                                         True),  # aa-mergeprof act()
        (('CMD_ALLOW', 'CMD_ABORT'),                                                                                                                        True),  # aa-mergeprof conflict_mode()
        (('CMD_ADDSUBPROFILE', 'CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED'),                                                                                    True),  # aa-mergeprof ask_the_questions() - new subprofile
        (('CMD_ADDHAT', 'CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED'),                                                                                           True),  # aa-mergeprof ask_the_questions() - new hat
    )

    def _run_test(self, params, expected):
        self.createTmpdir()

        subprocess.run(['make', '-C', '../po'], stdout=subprocess.DEVNULL, check=True)
        subprocess.run(
            ['make', '-C', '../po', 'install', 'DESTDIR={}'.format(self.tmpdir), 'NAME=apparmor-utils'],
            stdout=subprocess.DEVNULL, check=True,
        )

        self.localedir = '{}/usr/share/locale'.format(self.tmpdir)

        self.languages = os.listdir(self.localedir)

        # make sure we found all translations
        if len(self.languages) < 15:
            raise Exception('None or not all languages found, only {}'.format(self.languages))

        # we also want to detect hotkey conflicts in the untranslated english strings
        self.languages.append('C')

        conflicts = []

        for language in self.languages:
            with self.subTest(language=language):
                t = gettext.translation(
                    'apparmor-utils', fallback=True,
                    localedir=self.localedir, languages=(language,),
                )

                keys = {}
                all_keys = []
                found_conflict = ''

                for key in params:
                    text = t.gettext(CMDS[key])
                    all_keys.append(text)
                    hotkey = get_translated_hotkey(text)

                    if keys.get(hotkey):
                        found_conflict = "Hotkey conflict for {}: '{}' and '{}'".format(language, keys[hotkey], text)
                    else:
                        keys[hotkey] = text

                if found_conflict:
                    conflicts.append("{}\n    {}'".format(found_conflict, '  '.join(all_keys)))

        if conflicts:
            raise Exception('\n'.join(conflicts))


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
