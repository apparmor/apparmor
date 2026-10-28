#! /bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Jérémy Jean <Jeremy.Jean@oss.cyber.gouv.fr>

#=NAME net_inet_sctp
#=DESCRIPTION
# SCTP association creation must require connect permission, including
# implicit connections through sendto/sendmsg and the CONNECTX socket options.
#=END

bin=$(cd "$(dirname "$0")" && pwd)
. "$bin/prologue.inc"

requires_any_of_kernel_features network/af_mask network_v8/af_mask network_v9

result=fail
if ! any_of_kernel_features network/sctp network_v8/sctp network_v9/sctp ; then
    result=xfail
fi

# Probe the same ABI that genprofile selects with "abi <kernel>".
requires_parser_support --policy-features=/sys/kernel/security/apparmor/features \
	--warn=rule-downgraded --Werror=rule-downgraded \
	--warn=rule-not-enforced --Werror=rule-not-enforced -- \
	"network (create,bind,listen,send,receive,setopt,getopt,getattr) inet seqpacket," \
	"deny network connect inet seqpacket,"

run_modes()
{
	local description=$1 expected=$2 error=$3 mode

	for mode in connect sendto sendmsg connectx_old connectx connectx3; do
		runchecktest_errno "$error" "SCTP $family $mode ($description)" \
			"$expected" "$family" "$mode"
	done
}

for family in inet inet6; do
	# Probe without a profile so policy denials cannot cause a skip.
	probe_rc=0
	"$test" "$family" probe || probe_rc=$?
	if [ "$probe_rc" -eq 77 ]; then
		echo "    SCTP $family not available. Skipping tests ..."
		continue
	fi
	[ "$probe_rc" -eq 0 ] || fatalerror "SCTP $family probe failed"

	run_modes unconfined pass 0

	genprofile "network;$family;seqpacket"
	run_modes "connect allowed" pass 0

	# Grant all the other permissions used by the client and listener.
	genprofile "network;(create,bind,listen,send,receive,setopt,getopt,getattr);$family;seqpacket"
	run_modes "connect omitted" $result EACCES

	genprofile "network;$family;seqpacket" \
		"qual=deny:network;connect;$family;seqpacket"
	run_modes "connect denied" $result EACCES

	removeprofile
done
