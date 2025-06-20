#!/usr/bin/python3
#
#   Copyright (c) 2025 Canonical, Ltd. (All rights reserved)
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, contact Canonical Ltd.
#

from testlib import write_file

def gen_file(test, xres, op, lhs, rhs, add_else):
    global count

    content = ''
    content += '#\n'
    content += '#=DESCRIPTION {}\n'.format(test)
    content += '#=EXRESULT {}\n'.format(xres)
    content += '#\n'
    if lhs['def'] and lhs != rhs:
        content += '{} = {}\n'.format(lhs['varname'], lhs['def'])
    if rhs['def']:
        content += '{} = {}\n'.format(rhs['varname'], rhs['def'])
    content += '/usr/bin/foo {\n'
    content += '  if {} {} {} {{\n'.format(lhs['varname'], op, rhs['varname'])
    content += '    /bin/true rix,\n'
    content += '  }'
    if add_else:
        content += ' else {\n'
        content += '    mount,\n'
        content += '  }\n'
    else:
        content += '\n'

    content += '}\n'

    write_file('simple_tests/generated_conditional', '{}{}-{}.sd'.format(test, '-else' if add_else else '', count), content)

    count += 1

ops = {'==': 'equals', '!=': 'notequals', 'in': 'in', '>': 'greater', '>=': 'greaterequals', '<': 'lesser', '<=': 'lesserequals'}

test_vars = [
    {'varname': '@{VAR_EMPTY}', 'def': '""', 'desc': 'empty', 'number': False},  # empty var
    {'varname': '@{VAR_ONE_STRING}', 'def': '/path/foo/', 'desc': 'var_one_string', 'number': False},  # one string in var
    {'varname': '@{VAR_ONE_NUMBER}', 'def': '10', 'desc': 'var_one_number', 'number': True},  # one number in var
    {'varname': '@{VAR_MULT_STRING}', 'def': '/path/foo/ /path/bar/', 'desc': 'var_mult_string', 'number': False},  # multiple strings in var
    {'varname': '@{VAR_MULT_NUMBER}', 'def': '10 2 3.1', 'desc': 'var_mult_number', 'number': False},  # multiple numbers in var
    {'varname': '@{VAR_MIXED}', 'def': '3 /foo 1 /bar/ 10 /path/foo/', 'desc': 'var_mixed', 'number': False},  # mixed var contents
    {'varname': '10', 'def': '', 'desc': 'number1', 'number': True},  # number directly
    {'varname': '9', 'def': '', 'desc': 'number2', 'number': True},  # number directly
    {'varname': '/path/foo/', 'def': '', 'desc': 'string1', 'number': False},  # string directly
    {'varname': '/path/baz/', 'def': '', 'desc': 'string2', 'number': False},  # string directly
]

def gen_files():
    for op in ops:
        for lhs in test_vars:
            for rhs in test_vars:
                for add_else in [True, False]:
                    test_description = lhs['desc'] + '-' + ops[op]  + '-' + rhs['desc']
                    xres = 'PASS' if lhs['number'] == rhs['number'] or op in ['in', '==', '!='] else 'FAIL'
                    gen_file(test_description, xres, op, lhs, rhs, add_else)

count = 0
gen_files()
print('Generated {} conditional tests'.format(count))
