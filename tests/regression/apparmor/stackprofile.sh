#! /bin/bash
#	Copyright (C) 2016 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME stackprofile
#=DESCRIPTION
# Verifies basic file access permission checks for a parent profile and a
# stacked subprofile
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

requires_kernel_features domain/stack
settest transition

file=$tmpdir/file
otherfile=$tmpdir/file2
thirdfile=$tmpdir/file3
sharedfile=$tmpdir/file.shared
okperm=rw

fileok="${file}:${okperm}"
otherok="${otherfile}:${okperm}"
thirdok="${thirdfile}:${okperm}"
sharedok="${sharedfile}:${okperm}"

getcon="/proc/*/attr/current:r /proc/*/attr/apparmor/current:r"

othertest="$pwd/rename"
thirdtest="$pwd/exec"

stackotherok="change_profile->:&$othertest"
stackthirdok="change_profile->:&$thirdtest"

touch $file $otherfile $sharedfile $thirdfile

for iface in "" "-B" ; do
# Verify file access and contexts by an unconfined process
runchecktest "STACKPROFILE iface='$iface' (unconfined - file)" pass $iface -f $file
runchecktest "STACKPROFILE iface='$iface' (unconfined - otherfile)" pass $iface -f $otherfile
runchecktest "STACKPROFILE iface='$iface' (unconfined - thirdfile)" pass $iface -f $thirdfile
runchecktest "STACKPROFILE iface='$iface' (unconfined - sharedfile)" pass $iface -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (unconfined - okcon)" pass $iface -l unconfined -m '(null)'
runchecktest "STACKPROFILE iface='$iface' (unconfined - bad label)" fail $iface -l "$test" -m '(null)'
runchecktest "STACKPROFILE iface='$iface' (unconfined - bad mode)" fail $iface -l unconfined -m enforce

# Verify file access and contexts by a non-stacked profile
genprofile $fileok $sharedok $getcon
runchecktest "STACKPROFILE iface='$iface' (not stacked - file)" pass $iface -f $file
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (not stacked - otherfile)" fail $iface -f $otherfile
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (not stacked - thirdfile)" fail $iface -f $thirdfile
runchecktest "STACKPROFILE iface='$iface' (not stacked - sharedfile)" pass $iface -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (not stacked - okcon)" pass $iface -l "$test" -m enforce
runchecktest "STACKPROFILE iface='$iface' (not stacked - bad label)" fail $iface -l "${test}XXX" -m enforce
runchecktest "STACKPROFILE iface='$iface' (not stacked - bad mode)" fail $iface -l "$test" -m complain

# Verify file access and contexts by a profile stacked with unconfined
genprofile image=$othertest $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (stacked with unconfined - file)" fail $iface -p $othertest -f $file
runchecktest "STACKPROFILE iface='$iface' (stacked with unconfined - otherfile)" pass $iface -p $othertest -f $otherfile
runchecktest "STACKPROFILE iface='$iface' (stacked with unconfined - sharedfile)" pass $iface -p $othertest -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (stacked with unconfined - okcon)" pass $iface -p $othertest -l "unconfined//&${othertest}" -m enforce
runchecktest "STACKPROFILE iface='$iface' (stacked with unconfined - bad label)" fail $iface -p $othertest -l "${test}//&${othertest}" -m enforce
runchecktest "STACKPROFILE iface='$iface' (stacked with unconfined - bad mode)" fail $iface -p $othertest -l "unconfined//&${othertest}" -m '(null)'

removeprofile
# Verify that stacking a nonexistent file is properly handled
runchecktest_errno ENOENT "STACKPROFILE iface='$iface' (unconfined - stack nonexistent profile)" fail $iface -p $othertest -f $file

# Verify file access and contexts by 2 stacked profiles
genprofile $fileok $sharedok $getcon $stackotherok -- \
	image=$othertest $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (2 stacked - file)" fail $iface -p $othertest -f $file
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (2 stacked - otherfile)" fail $iface -p $othertest -f $otherfile
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (2 stacked - thirdfile)" fail $iface -p $othertest -f $thirdfile
runchecktest "STACKPROFILE iface='$iface' (2 stacked - sharedfile)" pass -p $othertest $iface -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (2 stacked - okcon)" pass $iface -p $othertest -l "${test}//&${othertest}" -m enforce
runchecktest "STACKPROFILE iface='$iface' (2 stacked - bad label)" fail $iface -p $othertest -l "${test}//&${test}" -m enforce
runchecktest "STACKPROFILE iface='$iface' (2 stacked - bad mode)" fail $iface -p $othertest -l "${test}//&${test}" -m '(null)'

# Verify that a change_profile rule is required to aa_stack_profile())
genprofile $fileok $sharedok $getcon -- \
	image=$othertest $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (2 stacked - no change_profile)" fail $iface -p $othertest -l "${test}//&${othertest}" -m enforce

# Verify file access and contexts by 3 stacked profiles
genprofile $fileok $sharedok $getcon $stackotherok $stackthirdok -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon $stackthirdok -- \
	image=$thirdtest $thirdok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (3 stacked - file)" fail $iface -p $othertest -- $test -p $thirdtest -f $file
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (3 stacked - otherfile)" fail $iface -p $othertest -- $test -p $thirdtest -f $otherfile
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (3 stacked - thirdfile)" fail $iface -p $othertest -- $test -p $thirdtest -f $thirdfile
runchecktest "STACKPROFILE iface='$iface' (3 stacked - sharedfile)" pass $iface -p $othertest -- $test -p $thirdtest -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (3 stacked - okcon)" pass $iface -p $othertest -- $test -p $thirdtest -l "${thirdtest}//&${test}//&${othertest}" -m enforce

genprofile $fileok $sharedok $getcon $stackotherok -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon $stackthirdok -- \
	image=$thirdtest $thirdok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (3 stacked - sharedfile - no change_profile)" fail $iface -p $othertest -- $test -p $thirdtest -f $sharedfile

ns="ns"
prof="stackprofile"
nstest=":${ns}:${prof}"
# Verify file access and contexts by stacking a profile with a namespaced profile
genprofile image=$test --stdin <<EOF
$test {
  file,
  audit deny $otherfile $okperm,
  change_profile -> &$nstest,
}
EOF

genprofile --append image=$nstest --stdin <<EOF
$nstest {
  $otherfile $okperm,
  $sharedfile $okperm,
  /proc/*/attr/{apparmor/,}current r,
}
EOF
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (stacked with namespaced profile - file)" fail $iface -p $nstest -f $file
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (stacked with namespaced profile - otherfile)" fail $iface -p $nstest -f $otherfile
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (stacked with namespaced profile - thirdfile)" fail $iface -p $nstest -f $thirdfile
runchecktest "STACKPROFILE iface='$iface' (stacked with namespaced profile - sharedfile)" pass $iface -p $nstest -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (stacked with namespaced profile - okcon)" pass $iface -p $nstest -l $prof -m enforce

# Verify file access and contexts in mixed mode
genprofile $fileok $sharedok $getcon $stackotherok -- \
	image=$othertest flag:complain $otherok $sharedok $getcon
runchecktest "STACKPROFILE iface='$iface' (mixed mode - file)" pass $iface -p $othertest -f $file
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (mixed mode - otherfile)" fail -p $othertest -f $otherfile
runchecktest "STACKPROFILE iface='$iface' (mixed mode - sharedfile)" pass $iface -p $othertest -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (mixed mode - okcon)" pass $iface -p $othertest -l "${othertest}//&${test}" -m mixed

genprofile $fileok $sharedok $getcon -- \
	image=$othertest flag:complain $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (mixed mode - okcon - no change_profile)" fail $iface -p $othertest -l "${othertest}//&${test}" -m mixed

genprofile flag:complain $fileok $sharedok $getcon $stackotherok -- \
	image=$othertest $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKPROFILE iface='$iface' (mixed mode 2 - file)" fail $iface -p $othertest -f $file
runchecktest "STACKPROFILE iface='$iface' (mixed mode 2 - otherfile)" pass $iface -p $othertest -f $otherfile
runchecktest "STACKPROFILE iface='$iface' (mixed mode 2 - sharedfile)" pass $iface -p $othertest -f $sharedfile

runchecktest "STACKPROFILE iface='$iface' (mixed mode 2 - okcon)" pass $iface -p $othertest -l "${othertest}//&${test}" -m mixed

genprofile flag:complain $fileok $sharedok $getcon -- \
	image=$othertest $otherok $sharedok $getcon
runchecktest "STACKPROFILE iface='$iface' (mixed mode 2 - okcon - no change_profile)" pass $iface -p $othertest -l "${othertest}//&${test}" -m mixed

# Verify file access and contexts in complain mode
genprofile flag:complain $getcon -- image=$othertest flag:complain $getcon
runchecktest "STACKPROFILE iface='$iface' (complain mode - file)" pass $iface -p $othertest -f $file

runchecktest "STACKPROFILE iface='$iface' (complain mode - okcon)" pass $iface -p $othertest -l "${test}//&${othertest}" -m complain

# Verify that stacking with a bare namespace is handled
genprofile image=$test --stdin <<EOF
$test { file, change_profile, }
EOF
genprofile --append image=$nstest --stdin <<EOF
$nstest { }
EOF
runchecktest "STACKPROFILE iface='$iface' (bare :ns:)" pass $iface -p ":${ns}:"
runchecktest "STACKPROFILE iface='$iface' (bare :ns://)" pass $iface -p ":${ns}://"
runchecktest "STACKPROFILE iface='$iface' (bare :ns)" pass $iface -p ":${ns}"
removeprofile
done # for iface
