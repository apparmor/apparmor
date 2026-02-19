#! /bin/bash
#	Copyright (C) 2016 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME stackonexec
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

getcon="/proc/*/attr/{apparmor/,}current:r"
onexec="/proc/*/attr/{apparmor/,}exec:w"

othertest="$pwd/rename"
thirdtest="$pwd/exec"

stackotherok="change_profile->:&$othertest"
stackthirdok="change_profile->:&$thirdtest"

touch $file $otherfile $sharedfile $thirdfile

for iface in "" "-B" ; do
# Verify file access and contexts by an unconfined process
runchecktest "STACKONEXEC iface='$iface' (unconfined - file)" pass $iface -f $file
runchecktest "STACKONEXEC iface='$iface' (unconfined - otherfile)" pass $iface -f $otherfile
runchecktest "STACKONEXEC iface='$iface' (unconfined - thirdfile)" pass $iface -f $thirdfile
runchecktest "STACKONEXEC iface='$iface' (unconfined - sharedfile)" pass $iface -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (unconfined - okcon)" pass $iface -l unconfined -m '(null)'
runchecktest "STACKONEXEC iface='$iface' (unconfined - bad label)" fail $iface -l "$test" -m '(null)'
runchecktest "STACKONEXEC iface='$iface' (unconfined - bad mode)" fail $iface -l unconfined -m enforce

# Verify file access and contexts by a non-stacked profile
genprofile $fileok $sharedok $getcon
runchecktest "STACKONEXEC (not stacked - file)" pass $iface -f $file
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (not stacked - otherfile)" fail $iface -f $otherfile
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (not stacked - thirdfile)" fail $iface -f $thirdfile
runchecktest "STACKONEXEC iface='$iface' (not stacked - sharedfile)" pass $iface -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (not stacked - okcon)" pass $iface -l "$test" -m enforce
runchecktest "STACKONEXEC iface='$iface' (not stacked - bad label)" fail $iface -l "${test}XXX" -m enforce
runchecktest "STACKONEXEC iface='$iface' (not stacked - bad mode)" fail $iface -l "$test" -m complain

# Verify file access and contexts by a profile stacked with unconfined
genprofile image=$othertest addimage:$test $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (stacked with unconfined - file)" fail $iface -o $othertest -- $test -f $file
runchecktest "STACKONEXEC iface='$iface' (stacked with unconfined - otherfile)" pass $iface -o $othertest -- $test -f $otherfile
runchecktest "STACKONEXEC iface='$iface' (stacked with unconfined - sharedfile)" pass $iface -o $othertest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (stacked with unconfined - okcon)" pass $iface -o $othertest -- $test -l "unconfined//&${othertest}" -m enforce
runchecktest "STACKONEXEC iface='$iface' (stacked with unconfined - bad label)" fail $iface -o $othertest -- $test -l "${test}//&${othertest}" -m enforce
runchecktest "STACKONEXEC iface='$iface' (stacked with unconfined - bad mode)" fail $iface -o $othertest -- $test -l "unconfined//&${othertest}" -m "(null)"

removeprofile
# Verify that stacking a nonexistent file is properly handled
runchecktest_errno ENOENT "STACKONEXEC iface='$iface' (unconfined - stack nonexistent profile)" fail $iface -o $othertest -- $test -f $file

# Verify file access and contexts by 2 stacked profiles
genprofile $fileok $sharedok $getcon $onexec $stackotherok -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (2 stacked - file)" fail $iface -o $othertest -- $test -f $file
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (2 stacked - otherfile)" fail $iface -o $othertest -- $test -f $otherfile
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (2 stacked - thirdfile)" fail $iface -o $othertest -- $test -f $thirdfile
runchecktest "STACKONEXEC iface='$iface' (2 stacked - sharedfile)" pass $iface -o $othertest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (2 stacked - okcon)" pass $iface -o $othertest -- $test -l "${test}//&${othertest}" -m enforce
runchecktest "STACKONEXEC iface='$iface' (2 stacked - bad label)" fail $iface -o $othertest -- $test -l "${test}//&${test}" -m enforce
runchecktest "STACKONEXEC iface='$iface' (2 stacked - bad mode)" fail $iface -o $othertest -- $test -l "${test}//&${test}" -m '(null)'

# Verify that a change_profile rule is required to aa_stack_onexec()
genprofile $fileok $sharedok $getcon $onexec -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (2 stacked - no change_profile)" fail $iface -o $othertest -- $test -l "${test}//&${othertest}" -m enforce

# Verify file access and contexts by 3 stacked profiles
genprofile $fileok $sharedok $getcon $onexec $stackotherok $stackthirdok -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon $onexec $stackthirdok -- \
	image=$thirdtest addimage:$test $thirdok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (3 stacked - file)" fail $iface -o $othertest -- $test -o $thirdtest -- $test -f $file
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (3 stacked - otherfile)" fail $iface -o $othertest -- $test -o $thirdtest -- $test -f $otherfile
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (3 stacked - thirdfile)" fail $iface -o $othertest -- $test -o $thirdtest -- $test -f $thirdfile
runchecktest "STACKONEXEC iface='$iface' (3 stacked - sharedfile)" pass $iface -o $othertest -- $test -o $thirdtest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (3 stacked - okcon)" pass $iface -o $othertest -- $test -o $thirdtest -- $test -l "${thirdtest}//&${test}//&${othertest}" -m enforce

genprofile $fileok $sharedok $getcon $onexec $stackotherok -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon $onexec $stackthirdok -- \
	image=$thirdtest addimage:$test $thirdok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (3 stacked - sharedfile - no change_profile)" fail $iface -o $othertest -- $test -o $thirdtest -- $test -f $sharedfile

ns="ns"
prof="stackonexec"
nstest=":${ns}:${prof}"
# Verify file access and contexts by stacking a profile with a namespaced profile
genprofile image=$test --stdin <<EOF
$test {
  file,
  audit deny $otherfile $okperm,
  audit deny $thirdfile $okperm,
  change_profile -> &$nstest,
}
EOF

genprofile --append image=$nstest --stdin <<EOF
$nstest {
  file,
  audit deny $file $okperm,
  audit deny $thirdfile $okperm,
}
EOF
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (stacked with namespaced profile - file)" fail $iface -o $nstest -- $test -f $file
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (stacked with namespaced profile - otherfile)" fail $iface -o $nstest -- $test -f $otherfile
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (stacked with namespaced profile - thirdfile)" fail $iface -o $nstest -- $test -f $thirdfile
runchecktest "STACKONEXEC iface='$iface' (stacked with namespaced profile - sharedfile)" pass -o $nstest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (stacked with namespaced profile - okcon)" pass $iface -o $nstest -- $test -l $prof -m enforce

# Verify file access and contexts in mixed mode
genprofile $fileok $sharedok $getcon $onexec $stackotherok -- \
	image=$othertest flag:complain addimage:$test $otherok $sharedok $getcon
runchecktest "STACKONEXEC iface='$iface' (mixed mode - file)" pass $iface -o $othertest -- $test -f $file
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (mixed mode - otherfile)" fail -o $othertest -- $test -f $otherfile
runchecktest "STACKONEXEC iface='$iface' (mixed mode - sharedfile)" pass $iface -o $othertest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (mixed mode - okcon)" pass $iface -o $othertest -- $test -l "${othertest}//&${test}" -m mixed

genprofile $fileok $sharedok $getcon $onexec -- \
	image=$othertest flag:complain addimage:$test $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (mixed mode - okcon - no change_profile)" fail $iface -o $othertest -- $test -l "${othertest}//&${test}" -m mixed

genprofile flag:complain $fileok $sharedok $getcon $onexec -- \
	image=$othertest addimage:$test $otherok $sharedok $getcon
runchecktest_errno EACCES "STACKONEXEC iface='$iface' (mixed mode 2 - file)" fail -o $othertest -- $test -f $file
runchecktest "STACKONEXEC iface='$iface' (mixed mode 2 - otherfile)" pass $iface -o $othertest -- $test -f $otherfile
runchecktest "STACKONEXEC iface='$iface' (mixed mode 2 - sharedfile)" pass $iface -o $othertest -- $test -f $sharedfile

runchecktest "STACKONEXEC iface='$iface' (mixed mode 2 - okcon)" pass $iface -o $othertest -- $test -l "${othertest}//&${test}" -m mixed

# Verify file access and contexts in complain mode
genprofile flag:complain $getcon -- image=$othertest addimage:$test flag:complain $getcon
runchecktest "STACKONEXEC iface='$iface' (complain mode - file)" pass $iface -o $othertest -- $test -f $file

runchecktest "STACKONEXEC iface='$iface' (complain mode - okcon)" pass $iface -o $othertest -- $test -l "${test}//&${othertest}" -m complain

# Verify that stacking with a bare namespace is handled. The process is placed
# into the default profile of the namespace, which is unconfined.
genprofile image=$test --stdin <<EOF
$test { file, change_profile, }
EOF
genprofile --append image=$nstest --stdin <<EOF
$nstest { }
EOF
runchecktest "STACKONEXEC iface='$iface' (bare :ns:)" pass $iface -o ":${ns}:" -- $test -l unconfined -m "(null)"
runchecktest "STACKONEXEC iface='$iface' (bare :ns://)" pass $iface -o ":${ns}://" -- $test -l unconfined -m "(null)"
runchecktest "STACKONEXEC iface='$iface' (bare :ns)" pass $iface -o ":${ns}" -- $test -l unconfined -m "(null)"
removeprofile
done # for iface
