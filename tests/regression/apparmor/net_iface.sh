#! /bin/bash
#Copyright (C) 2022 Canonical, Ltd.
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License as
#published by the Free Software Foundation, version 2 of the
#License.

#=NAME net_iface
#=DESCRIPTION
# This test verifies if network interface mediation is working
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

requires_kernel_features network_v9_skb/iface
requires_parser_support "network interface=eth0,"

skb_enabled_path="/proc/sys/kernel/apparmor_packet_mediation"
if [ ! -e $skb_enabled_path ]; then
	echo "$skb_enabled_path not available. Skipping tests ..."
	exit 0
else
	skb_enabled=$(cat $skb_enabled_path)
	if [ $skb_enabled -eq 0 ]; then
		echo "$skb_enabled_path disabled. Skipping tests ..."
		exit 0
	fi
fi

settest net_inet_rcv

sender="$bin/net_inet_snd"
receiver="$bin/net_inet_rcv"

ipv6_subnet=2001:db8:acad::1/64
bind_ipv6=2001:db8:acad::cf32
remote_ipv6=2001:db8:acad::a0f9

bind_ipv4=203.0.113.10
remote_ipv4=203.0.113.200

iface=tapaatest0
iface_policy=lo # workaround: tap interfaces show up as loopback in the kernel

ip tuntap add dev $iface mode tap
sysctl -w net.ipv6.conf.$iface.accept_dad=0 >/dev/null # prevent ipv6 from being tentative
ip addr add $bind_ipv4/24 dev $iface
ip addr add $remote_ipv4/24 dev $iface
ip -6 addr add $bind_ipv6/64 dev $iface
ip -6 addr add $remote_ipv6/64 dev $iface
ip link set $iface up

cleanup()
{
	ip tuntap del dev $iface mode tap
	ip link show $iface 2>/dev/null
	if [ $? -eq 0 ]; then
	    echo "Failure removing tap interface $iface"
	fi
}

do_onexit="cleanup"

do_test()
{
	local desc="NETWORK IFACE ($1)"
	shift
	runchecktest "$desc" "$@"
}


do_tests()
{
	local prefix="$1"
	local expect_rcv=$2
	local expect_snd=$3
	local bind_ip=$4
	local bind_port=$5
	local remote_ip=$6
	local remote_port=$7
	local protocol=$8
	local iface=$9
	local generate_profile=${10}

	settest net_inet_rcv
	$generate_profile
	do_test "$prefix - root" $expect_rcv --bind_ip $bind_ip --bind_port $bind_port --remote_ip $remote_ip --remote_port $remote_port --protocol $protocol --interface $iface --timeout 2 --sender "$sender"

	settest -u "foo" net_inet_rcv
	$generate_profile
	do_test "$prefix - user" $expect_rcv --bind_ip $bind_ip --bind_port $bind_port --remote_ip $remote_ip --remote_port $remote_port --protocol $protocol --interface $iface --timeout 2 --sender "$sender"


}

bind_port=3456
while lsof -i:$bind_port >/dev/null; do
	let bind_port=$bind_port+1
done

let remote_port=$bind_port+50
while lsof -i:$remote_port >/dev/null; do
	let remote_port=$remote_port+1
done

for prot in tcp udp; do
	generate_profile=""
	do_tests "ipv4 $prot $iface unconfined" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

        # showing denial when it shouldnt for tcp 
        generate_profile="genprofile flag:debug network:inet:interface=lo $sender:px -- image=$sender network:inet:interface=lo flag:debug"
        do_tests "ipv4 $prot specific interface" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

        generate_profile="genprofile flag:debug network:inet:interface=invalid $sender:px -- image=$sender network:inet:interface=lo flag:debug"
        do_tests "ipv4 $prot specific interface" fail fail $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	generate_profile="genprofile network:inet qual=deny:network;interface=invalid $sender:px -- image=$sender network:inet qual=deny:network;interface=invalid"
	do_tests "ipv4 $prot invalid iface, full net perms" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	
	generate_profile="genprofile network:inet qual=deny:network;interface=$iface_policy $sender:px -- image=$sender network:inet qual=deny:network;interface=$iface_policy"
	do_tests "ipv4 $prot valid $iface, full net perms" fail fail $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"


	generate_profile="genprofile network $sender:px -- image=$sender network"
	do_tests "ipv4 $prot $iface no conds" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	generate_profile="genprofile network;interface=$iface_policy $sender:px -- image=$sender network;interface=$iface_policy"
	do_tests "ipv4 $prot $iface no conds" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	#=
	setsockopt_rules="network;(setopt,getopt);ip=0.0.0.0;port=0;interface=$iface_policy" # INADDR_ANY
	rcv_rules="network;ip=$bind_ipv4;interface=$iface_policy;peer=(ip=none)"
	inv_rcv_rules="network;ip=$bind_ipv4;interface=invalid;peer=(ip=none)"
	snd_rules="network;ip=$remote_ipv4;interface=$iface_policy;peer=(ip=none)"
	inv_snd_rules="network;ip=$remote_ipv4;interface=invalid;peer=(ip=none)"

	# port range tests
	let invalid1=$bind_port-1
	let end_range=$bind_port+2
	let invalid2=$bind_port+3

	for test_port in $(seq $bind_port $end_range); do
	    generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port-$end_range;interface=$iface_policy $setsockopt_rules $sender:px -- image=$sender network $setsockopt_rules $snd_rules"
	    do_tests "ipv4 $prot $iface port range $test_port generic perms" pass pass $bind_ipv4 $test_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	    generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port-$end_range;interface=invalid $setsockopt_rules $sender:px -- image=$sender network $setsockopt_rules $inv_snd_rules"
	    do_tests "ipv4 $prot invalid port range $test_port generic perms" fail fail $bind_ipv4 $test_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	done

	generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port-$end_range;interface=$iface_policy $setsockopt_rules $sender:px -- image=$sender network $setsockopt_rules $snd_rules"
	do_tests "ipv4 $prot port range $invalid1 generic perms" fail fail $bind_ipv4 $invalid1 $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port-$end_range;interface=$iface_policy $setsockopt_rules $sender:px -- image=$sender network $setsockopt_rules $snd_rules"
	do_tests "ipv4 $prot port range $invalid2 generic perms" fail fail $bind_ipv4 $invalid2 $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	# end of port range tests

	generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port;interface=$iface_policy;peer=(ip=$remote_ipv4,port=$remote_port) $setsockopt_rules $rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv4;port=$remote_port;peer=(ip=$bind_ipv4,port=$bind_port) $setsockopt_rules $snd_rules"
	do_tests "ipv4 $prot $iface generic perms" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	generate_profile="genprofile network;ip=$bind_ipv4;port=$bind_port;interface=invalid;peer=(ip=$remote_ipv4,port=$remote_port) $setsockopt_rules $inv_rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv4;port=$remote_port;peer=(ip=$bind_ipv4,port=$bind_port) $setsockopt_rules $inv_snd_rules"
	do_tests "ipv4 $prot invalid generic perms" fail fail $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	generate_profile="genprofile network;(connect,receive,send);ip=$bind_ipv4;port=$bind_port;interface=$iface_policy;peer=(ip=$remote_ipv4,port=$remote_port) $setsockopt_rules $rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv4;port=$remote_port;peer=(ip=$bind_ipv4,port=$bind_port) $setsockopt_rules $snd_rules"
	do_tests "ipv4 $prot $iface specific perms" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"
	generate_profile="genprofile network;(connect,receive,send);ip=$bind_ipv4;port=$bind_port;interface=invalid;peer=(ip=$remote_ipv4,port=$remote_port) $setsockopt_rules $inv_rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv4;port=$remote_port;peer=(ip=$bind_ipv4,port=$bind_port) $setsockopt_rules $inv_snd_rules"
	do_tests "ipv4 $prot invalid specific perms" fail fail $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"


	removeprofile

	# ipv6 tests
	generate_profile=""
	do_tests "ipv6 $prot $iface unconfined" pass pass $bind_ipv6 $bind_port $remote_ipv6 $remote_port $prot $iface "$generate_profile"

	generate_profile="genprofile network $sender:px -- image=$sender network"
	do_tests "ipv6 $prot $iface no conds" pass pass $bind_ipv6 $bind_port $remote_ipv6 $remote_port $prot $iface "$generate_profile"

	setsockopt_rules="network;(setopt,getopt);ip=::0;port=0;interface=$iface_policy" # IN6ADDR_ANY_INIT
	rcv_rules="network;ip=$bind_ipv6;interface=$iface_policy;peer=(ip=none)"
	inv_rcv_rules="network;ip=$bind_ipv6;interface=invalid;peer=(ip=none)"
	snd_rules="network;ip=$remote_ipv6;interface=$iface_policy;peer=(ip=none)"
	inv_snd_rules="network;ip=$remote_ipv6;interface=invalid;peer=(ip=none)"

	generate_profile="genprofile network;ip=$bind_ipv6;port=$bind_port;interface=$iface_policy;peer=(ip=$remote_ipv6,port=$remote_port) $setsockopt_rules $rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv6;port=$remote_port;interface=$iface_policy;peer=(ip=$bind_ipv6,port=$bind_port) $setsockopt_rules $snd_rules"
	do_tests "ipv6 $prot $iface generic perms" pass pass $bind_ipv6 $bind_port $remote_ipv6 $remote_port $prot $iface "$generate_profile"
	generate_profile="genprofile network;ip=$bind_ipv6;port=$bind_port;interface=invalid;peer=(ip=$remote_ipv6,port=$remote_port) $setsockopt_rules $inv_rcv_rules $sender:px -- image=$sender network;ip=$remote_ipv6;port=$remote_port;interface=invalid;peer=(ip=$bind_ipv6,port=$bind_port) $setsockopt_rules $inv_snd_rules"
	do_tests "ipv6 $prot invalid generic perms" fail fail $bind_ipv6 $bind_port $remote_ipv6 $remote_port $prot $iface "$generate_profile"


	if [ "$(parser_supports 'all,')" = "true" ]; then
	    generate_profile="genprofile all -- image=$sender all"
	    do_tests "ipv4 $prot allow all" pass pass $bind_ipv4 $bind_port $remote_ipv4 $remote_port $prot $iface "$generate_profile"

	    generate_profile="genprofile all -- image=$sender all"
	    do_tests "ipv6 $prot allow all" pass pass $bind_ipv6 $bind_port $remote_ipv6 $remote_port $prot $iface "$generate_profile"
	fi

	# needs to be done for the next loop iteration
	removeprofile
done
