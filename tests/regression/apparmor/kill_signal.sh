#! /bin/bash
#	Copyright (C) 2026 Canonical, Ltd
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME kill_signal
#=DESCRIPTION
# Verifies that the kill.signal profile flag changes the signal that is
# delivered to a task confined by a profile in kill mode when it is denied
# access. Without kill.signal the task should receive SIGKILL.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

requires_kernel_features domain/kill.signal

settest open

file=$tmpdir/file
okperm=rw
badperm=r

# Avoid writing core files for the core-dumping signals (eg. SIGABRT)
ulimit -c 0

sigkill=`kill -l KILL`
sigabrt=`kill -l ABRT`
sigusr1=`kill -l USR1`
sigterm=`kill -l TERM`

touch $file

# Sanity checks: allowed access in kill mode must not signal the task
genprofile flag:kill $file:$okperm
runchecktest "KILL_SIGNAL kill mode, allowed" pass $file

genprofile flag:kill flag:kill.signal=abrt $file:$okperm
runchecktest "KILL_SIGNAL kill.signal=abrt, allowed" pass $file

# Default kill mode delivers SIGKILL
genprofile flag:kill $file:$badperm
runchecktest "KILL_SIGNAL kill mode, denied (default SIGKILL)" signal${sigkill} $file

# kill.signal must override the default signal
genprofile flag:kill flag:kill.signal=kill $file:$badperm
runchecktest "KILL_SIGNAL kill.signal=kill, denied" signal${sigkill} $file

genprofile flag:kill flag:kill.signal=abrt $file:$badperm
runchecktest "KILL_SIGNAL kill.signal=abrt, denied" signal${sigabrt} $file

genprofile flag:kill flag:kill.signal=usr1 $file:$badperm
runchecktest "KILL_SIGNAL kill.signal=usr1, denied" signal${sigusr1} $file

genprofile flag:kill flag:kill.signal=term $file:$badperm
runchecktest "KILL_SIGNAL kill.signal=term, denied" signal${sigterm} $file

# Flag order in the profile must not matter
genprofile flag:kill.signal=abrt flag:kill $file:$badperm
runchecktest "KILL_SIGNAL kill.signal=abrt (reversed flag order), denied" signal${sigabrt} $file
