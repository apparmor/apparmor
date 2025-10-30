#! /bin/bash
#Copyright (C) 2025 Canonical, Ltd.
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License as
#published by the Free Software Foundation, version 2 of the
#License.

#=NAME exec_namespace
#=DESCRIPTION
# Verifies permissions and labels for exec transitions to namespaced profiles
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

requires_namespace_interface
settest transition

file=$tmpdir/file
otherfile=$tmpdir/file2
thirdfile=$tmpdir/file3
sharedfile=$tmpdir/file.shared
okperm=rw

touch $file $otherfile $sharedfile $thirdfile

ns="ns"
prof="$test"
nstest=":${ns}:${prof}"
nsunconfined=":${ns}:unconfined"

# Verify file access and contexts by an unconfined process
runchecktest "EXEC (unconfined - file)" pass -f $file
runchecktest "EXEC (unconfined - otherfile)" pass -f $otherfile
runchecktest "EXEC (unconfined - thirdfile)" pass -f $thirdfile
runchecktest "EXEC (unconfined - sharedfile)" pass -f $sharedfile

runchecktest "EXEC (unconfined - okcon)" pass -l unconfined -m '(null)'
runchecktest "EXEC (unconfined - bad label)" fail -l "$prof" -m '(null)'
runchecktest "EXEC (unconfined - bad mode)" fail -l unconfined -m enforce

# yikes...
aa_exec_test="-- $aa_exec -p $nsunconfined -- $bin/transition -- $bin/transition"

# Verify file access and contexts by a namespaced profile
genprofile image=$nstest --stdin <<EOF
$nstest {
  file,
  audit deny $otherfile $okperm,
  audit deny $thirdfile $okperm,
}
EOF

runchecktest "EXEC (namespaced - file)" pass $aa_exec_test -f $file
runchecktest_errno EACCES "EXEC (namespaced - otherfile)" fail $aa_exec_test -f $otherfile
runchecktest_errno EACCES "EXEC (namespaced - thirdfile)" fail $aa_exec_test -f $thirdfile
runchecktest "EXEC (namespaced - sharedfile)" pass $aa_exec_test -f $sharedfile

runchecktest "EXEC (namespaced - okcon)" pass $aa_exec_test -l "$prof" -m enforce
runchecktest "EXEC (namespaced - bad label)" fail $aa_exec_test -l "${prof}XXX" -m enforce
runchecktest "EXEC (namespaced - bad mode)" fail $aa_exec_test -l "$prof" -m complain

# Verify file access and contexts by transitioning to a namespaced profile
genprofile image=$test --stdin <<EOF
$test {
  file,
  audit deny $otherfile $okperm,
  audit deny $thirdfile $okperm,
  $test Px -> $nstest,
}
EOF

genprofile --append image=$nstest --stdin <<EOF
$nstest {
  file,
  audit deny $file $okperm,
  audit deny $thirdfile $okperm,
}
EOF

runchecktest_errno EACCES "EXEC (exec to namespaced profile - file)" fail -- $test -f $file
runchecktest "EXEC (exec to namespaced profile - otherfile)" pass -- $test -f $otherfile
runchecktest_errno EACCES "EXEC (exec to namespaced profile - thirdfile)" fail -- $test -f $thirdfile
runchecktest "EXEC (exec to namespaced profile - sharedfile)" pass -- $test -f $sharedfile

runchecktest "EXEC (exec to namespaced profile - okcon)" pass -- $test -l "$prof" -m enforce
runchecktest "EXEC (exec to namespaced profile - bad label)" fail -- $test -l "unconfined" -m enforce
runchecktest "EXEC (exec to namespaced profile - bad mode)" fail -- $test -l "$prof" -m complain


# Verify file access and contexts by transitioning to namespaced unconfined
genprofile image=$test --stdin <<EOF
$test {
  file,
  audit deny $file $okperm,
  audit deny $otherfile $okperm,
  audit deny $thirdfile $okperm,
  audit deny $sharedfile $okperm,
  $test Px -> $nsunconfined,
}
EOF

runchecktest "EXEC (exec to unconfined - file)" pass -- $test -f $file
runchecktest "EXEC (exec to unconfined - otherfile)" pass -- $test -f $otherfile
runchecktest "EXEC (exec to unconfined - thirdfile)" pass -- $test -f $thirdfile
runchecktest "EXEC (exec to unconfined - sharedfile)" pass -- $test -f $sharedfile

runchecktest "EXEC (exec to unconfined - okcon)" pass -- $test -l unconfined -m '(null)'
runchecktest "EXEC (exec to unconfined - bad label)" fail -- $test -l "$prof" -m '(null)'
runchecktest "EXEC (exec to unconfined - bad mode)" fail -- $test -l unconfined -m enforce

# TODO: add tests that check if the namespace is correct
