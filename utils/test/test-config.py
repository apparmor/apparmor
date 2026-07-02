# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
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
import unittest

import apparmor.config as config


class Test(unittest.TestCase):

    def test_IniConfig(self):
        ini_config = config.Config('ini')
        ini_config.CONF_DIR = '.'
        conf = ini_config.read_config('logprof.conf')
        logprof_sections = ['settings', 'qualifiers', 'required_hats', 'defaulthat', 'globs']
        logprof_sections_options = [
            'profiledir', 'inactive_profiledir', 'logfiles', 'parser',
            'logger', 'default_owner_prompt', 'custom_includes', 'json_log']
        logprof_settings_parser = '../../parser/apparmor_parser ../parser/apparmor_parser'

        self.assertEqual(conf.sections(), logprof_sections)
        self.assertEqual(conf.options('settings'), logprof_sections_options)
        self.assertEqual(conf['settings']['parser'], logprof_settings_parser)

    def test_ShellConfig(self):
        shell_config = config.Config('shell')
        shell_config.CONF_DIR = '.'
        conf = shell_config.read_config('easyprof.conf')
        easyprof_sections = ['POLICYGROUPS_DIR', 'TEMPLATES_DIR']
        easyprof_policygroup = './policygroups'
        easyprof_templates = './templates'

        self.assertEqual(sorted(conf[''].keys()), easyprof_sections)
        self.assertEqual(conf['']['POLICYGROUPS_DIR'], easyprof_policygroup)
        self.assertEqual(conf['']['TEMPLATES_DIR'], easyprof_templates)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testConfig']
    unittest.main()
