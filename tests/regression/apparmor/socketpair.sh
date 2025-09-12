#! /bin/bash
#	Copyright (C) 2014 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME socketpair
#=DESCRIPTION
# This test verifies that the fds returned from the socketpair syscall are
# correctly labeled
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"
. "$bin/net_supports.inc"

requires_any_of_kernel_features network/af_unix network_v9/af_unix
requires_parser_support "unix,"


do_test()
{
	local desc="SOCKETPAIR ($1)"
	shift

	runchecktest "$desc" "$@"
}

exec="/proc/*/attr/exec:w"
np1="new_profile_1"
np2="new_profile_2"
af_unix_create=""
af_unix_create_label=""
af_unix_inherit=""
aa_enabled="/sys/module/apparmor/parameters/enabled:r"

# AppArmor requires that the process inheriting the sock file
# descriptors have send,receive perms in its profile
af_unix_create="unix:(create,getopt)"
af_unix_create_label="unix:(send,receive)"
af_unix_inherit="unix:(getopt,send,receive)"

if [ "$(kernel_features network_v9/af_unix)" = "true" -a \
     "$(parser_supports 'unix,')" = "true" ] ; then
	# can get a stack from socket being passed to new confinement
	if [ "$(parser_supports_v9_unix_encode)" != "true" ] ; then
		# NOP ATM, this doesn't change what the kernel is doing
		# as this part of v9 is a break with v7/8
		echo -n "    parser does not support v9, encoding v7/8 "
	fi
	np1_result="$test//&$np1"
	np1_np2_result="$test//&$np1//&$np2"
        mixed_enforce="mixed"
        mixed_complain="mixed"
	echo "... using v9 af_unix kernel semantics"
elif [ "$(kernel_features network_v8/af_unix)" = "true" -o \
       "$(kernel_features network/af_unix)" = "true" -a \
       "$(parser_supports 'unix,')" = "true" ] ; then
	# old abi did not update the label to new task confinements using it
	np1_result="$test"
	np1_np2_result="$test"
        mixed_enforce="enforce"
        mixed_complain="complain"
	if [ "$(kernel_features network_v9/af_unix)" = "true" ] ; then
		echo -n "    kernel supports v9 unix should not be here"
		exit 1
	fi
	echo "... using v7 af_unix kernel"
else
	echo "    kernel does not support unix rules, broken requires should not be here"
	exit 1
fi

# Ensure everything works as expected when unconfined
do_test "unconfined" pass "unconfined" "(null)"

# Test the test
do_test "unconfined bad con" fail "uncon" "(null)"
do_test "unconfined bad mode" fail "unconfined" "(null)XXX"

# Ensure correct labeling under confinement
genprofile $af_unix_create $aa_enabled
do_test "confined" pass "$test" "enforce"

# Test the test
do_test "confined bad con" fail "/bad${test}" "enforce"
do_test "confined bad mode" fail "$test" "inforce"

# Ensure correct mode when using the complain flag
genprofile flag:complain $af_unix_create $aa_enabled
do_test "complain" pass "$test" "complain"

# Test the test
genprofile flag:complain $af_unix_create $aa_enabled
do_test "complain bad mode" fail "$test" "enforce"

# Ensure correct mode when using the audit flag
genprofile flag:audit $af_unix_create $aa_enabled
do_test "complain" pass "$test" "enforce"

# Ensure correct labeling after passing fd pair across exec
# NOTE: due to label crosscheck, parent needs 'rw' access
genprofile $af_unix_create ${af_unix_create_label} $aa_enabled $exec 'change_profile->':$np1 -- \
           image=$np1 addimage:$test $af_unix_inherit $aa_enabled
do_test "confined exec transition" pass "$test" "enforce" "$np1" "$np1_result" "enforce"

# af_unix_create is set to non-null at the top of the test script if
# the kernel advertises supporting unix sockets
if [ -n "${af_unix_create}" ] ; then
	# Ensure label crosscheck still requires parent needs' rw' access
	# after passing fd pair across exec
	genprofile $af_unix_create $exec $aa_enabled 'change_profile->':$np1 -- \
	           image=$np1 addimage:$test $af_unix_inherit $aa_enabled
	do_test "confined exec transition, crosscheck rejection" fail "$test" "enforce" "$np1"
fi

# Ensure correct labeling after passing fd pair across a no-transition exec
# NOTE: The test still calls aa_change_onexec(), so change_profile -> $test
#       is still needed
genprofile $af_unix_create $exec $aa_enabled 'change_profile->':$test
do_test "confined exec no transition" pass "$test" "enforce" "$test" "$test" "enforce"

# Ensure correct complain mode after passing fd pair across exec
genprofile flag:complain $af_unix_create $aa_enabled $exec 'change_profile->':$np1 -- \
	   image=$np1 addimage:$test $af_unix_inherit $aa_enabled
do_test "confined exec transition from complain" pass "$test" "complain" "$np1" "$np1_result" "$mixed_complain"

# Ensure correct complain mode after passing fd pair across exec
genprofile flag:complain $af_unix_create $aa_enabled $exec 'change_profile->':$np1 -- \
	   image=$np1 flag:complain addimage:$test $af_unix_inherit $aa_enabled
do_test "confined exec transition from complain" pass "$test" "complain" "$np1" "$np1_result" "complain"

# Ensure correct enforce mode after passing fd pair across exec
genprofile $af_unix_create ${af_unix_create_label} $aa_enabled $exec 'change_profile->':$np1 -- \
	   image=$np1 addimage:$test flag:complain $af_unix_inherit $aa_enabled
do_test "confined exec transition to complain" pass "$test" "enforce" "$np1" "$np1_result" "$mixed_enforce"

genprofile $af_unix_create ${af_unix_create_label} $aa_enabled $exec 'change_profile->':$np1 -- \
	   image=$np1 addimage:$test $af_unix_inherit $aa_enabled
do_test "confined exec transition to complain" pass "$test" "enforce" "$np1" "$np1_result" "enforce"


# af_unix_create is set to non-null at the top of the test script if
# the kernel advertises supporting unix sockets
if [ -n "${af_unix_create}" ] ; then
	# Ensure label crosscheck enforced in complain mode after passing fd pair across exec
	genprofile $af_unix_create $aa_enabled $exec 'change_profile->':$np1 -- \
		   image=$np1 addimage:$test flag:complain $af_unix_inherit $aa_enabled
	do_test "confined exec transition to complain, crosscheck rejection" fail "$test" "enforce" "$np1" "$np1_result" "enforce"
fi

# Ensure correct labeling after passing fd pair across 2 execs
gp_args="$af_unix_create ${af_unix_create_label} $aa_enabled $exec change_profile->:$np1 -- \
	 image=$np1 addimage:$test $af_unix_inherit $aa_enabled $exec change_profile->:$np2 -- \
	 image=$np2 addimage:$test $af_unix_inherit $aa_enabled"
genprofile $gp_args
do_test "confined 2 exec transitions" pass "$test" "enforce" "$np1" "$np1_result" "enforce" "$np2" "$np1_np2_result" "enforce"

# Test the test
do_test "confined 2 exec transitions bad con" fail "$test" "enforce" "$np1" "$test//&$np1" "enforce" "$np1" "$test//&$np1//&$np2" "enforce"
do_test "confined 2 exec transitions bad mode" fail "$test" "complain" "$np1" "$np1_result" "enforce" "$np2" "$np1_np2_result" "enforce"

# Ensure correct labeling after passing fd pair across exec to unconfined
genprofile $af_unix_create $aa_enabled $exec 'change_profile->':unconfined
do_test "confined exec transition to unconfined" pass "$test" "enforce" "unconfined" "$test" "enforce"

# Ensure correct labeling after passing fd pair across exec from unconfined
# doesn't change because of unconfined delegation
genprofile image=$np1 addimage:$test $af_unix_inherit $aa_enabled
do_test "unconfined exec transition to confined" pass "unconfined" "(null)" "$np1" "unconfined" "(null)"
