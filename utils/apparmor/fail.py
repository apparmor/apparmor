# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

try:
    import cgitb
except ImportError:
    cgitb = None
    pass
import sys
import traceback
from tempfile import NamedTemporaryFile

from apparmor.common import error


#
# Exception handling
#
def handle_exception(*exc_info):
    """Used as exception handler in the aa-* tools.
       For AppArmorException (used for profile syntax errors etc.), print only the exceptions
       value because a backtrace is superfluous and would confuse users.
       For other exceptions, print backtrace and save detailed information in a file in /tmp/
       (including variable content etc.) to make debugging easier.
    """
    (ex_cls, ex, tb) = exc_info

    if ex_cls.__name__ == 'AppArmorException':  # I didn't find a way to get this working with isinstance() :-/
        print('', file=sys.stderr)
        error(ex.value)
    else:
        if cgitb:
            with NamedTemporaryFile('w', prefix='apparmor-bugreport-', suffix='.txt', delete=False) as file:
                cgitb_hook = cgitb.Hook(display=1, file=file, format='text', context=10)
                cgitb_hook.handle(exc_info)
                file.write('Please consider reporting a bug at https://gitlab.com/apparmor/apparmor/-/issues\n')
                file.write('and attach this file.\n')

        print(''.join(traceback.format_exception(*exc_info)), file=sys.stderr)
        print('An unexpected error occurred!', file=sys.stderr)
        print('', file=sys.stderr)
        if cgitb:
            print('For details, see %s' % file.name, file=sys.stderr)
        print('Please consider reporting a bug at https://gitlab.com/apparmor/apparmor/-/issues', file=sys.stderr)
        if cgitb:
            print('and attach this file.', file=sys.stderr)


def enable_aa_exception_handler():
    """Setup handle_exception() as exception handler"""
    sys.excepthook = handle_exception
