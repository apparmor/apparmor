#! /bin/bash
#Copyright (C) 2022 Canonical, Ltd.
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License as
#published by the Free Software Foundation, version 2 of the
#License.

#=NAME net_iface_veth
#=DESCRIPTION
# This test verifies if network interface mediation is working with veth interfaces
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

# Test based on snapd tests for veth ifaces

# Host-side veth interface names
VETH0=veth0
VETH1=veth1
# Peer interface names (live inside network namespaces)
VETH0_PEER=veth0-peer
VETH1_PEER=veth1-peer
# Network namespaces hosting the client processes
NS_CLIENT0=ns-netif-client0
NS_CLIENT1=ns-netif-client1
# Host-side IPs assigned to the host ends of the veth pairs
HOST_IP_IFACE0="10.10.0.100"
HOST_IP_IFACE1="10.20.0.100"
# Client IPs assigned inside each namespace
CLIENT_IP_IFACE0="10.10.0.1"
CLIENT_IP_IFACE1="10.20.0.1"
PORT=8081
REQUEST_FILE="$tmpdir/request.txt"

ip netns add "$NS_CLIENT0"
ip netns add "$NS_CLIENT1"

ip link add "$VETH0" type veth peer name "$VETH0_PEER"
ip link add "$VETH1" type veth peer name "$VETH1_PEER"

ip link set "$VETH0_PEER" netns "$NS_CLIENT0"
ip link set "$VETH1_PEER" netns "$NS_CLIENT1"

ip addr add "${HOST_IP_IFACE0}/24" dev "$VETH0"
ip addr add "${HOST_IP_IFACE1}/24" dev "$VETH1"

ip netns exec "$NS_CLIENT0" ip addr add "${CLIENT_IP_IFACE0}/24" dev "$VETH0_PEER"
ip netns exec "$NS_CLIENT1" ip addr add "${CLIENT_IP_IFACE1}/24" dev "$VETH1_PEER"

ip link set "$VETH0" up
ip link set "$VETH1" up
ip netns exec "$NS_CLIENT0" ip link set "$VETH0_PEER" up
ip netns exec "$NS_CLIENT1" ip link set "$VETH1_PEER" up

wait_listen_port(){
    PORT="$1"
    NETNS="${2:-}"

    for _ in $(seq 120); do
        if ${NETNS:+ip netns exec "$NETNS"} ss -lnt | grep -Pq "LISTEN.*?:$PORT +.*?\\n*"; then
            break
        fi
        sleep 0.5
    done

    # Ensure we really have the listen port, this will fail with an
    # exit code if the port is not available.
    ${NETNS:+ip netns exec "$NETNS"} ss -lnt | grep -Pq "LISTEN.*?:$PORT +.*?\\n*"
}

cat > "$REQUEST_FILE" <<EOF
GET / HTTP/1.0
EOF

killtestbg()
{
	if ps -p $_pid > /dev/null 2>&1
	then
	    kill $_pid
	fi
}

cleanup()
{
	killtestbg
	ip link delete "$VETH0"
	ip link delete "$VETH1"
	ip netns delete "$NS_CLIENT0"
	ip netns delete "$NS_CLIENT1"
}

do_onexit="cleanup"

settest consumer

do_test()
{
	local desc="NETWORK IFACE ($1)"
	shift
	runtestbg "$desc" "$@"
}

update_test()
{
	_testdesc="NETWORK IFACE ($1)"
	_pfmode=$2
}


do_check()
{
	checktestfg
	echo -n "" > $outfile
}

default_perms="file, signal"

do_test "unconfined $NS_CLIENT0" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "unconfined $NS_CLIENT1" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

# IMPORTANT NOTE: if the server, while still running, goes from
# unconfined to confined, the kernel does NOT start mediating new
# actions, therefore the following tests will still pass even if we
# add a deny rule for the interfaces. Mediation starts if/when the
# server restarts or execs itself. This could change in the future.

genprofile $default_perms network qual=deny:network:interface=${VETH0} qual=deny:network:interface=${VETH1}

update_test "unconfined->confined $NS_CLIENT0" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "unconfined->confined $NS_CLIENT1" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

# killing the test so we can start testing profile changes without
# restarting the server
killtestbg

genprofile $default_perms network

do_test "full net perms $NS_CLIENT0" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "full net perms $NS_CLIENT1" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

genprofile $default_perms qual=deny:network

update_test "deny full net perms $NS_CLIENT0" fail
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "deny full net perms $NS_CLIENT1" fail
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

genprofile $default_perms network:interface=${VETH0}

update_test "iface ${VETH0} $NS_CLIENT0" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "iface ${VETH0} $NS_CLIENT1" fail
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

genprofile $default_perms network qual=deny:network:interface=${VETH0}

update_test "deny iface ${VETH0} $NS_CLIENT0" fail
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT0" "${HOST_IP_IFACE0}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check

update_test "deny iface ${VETH0} $NS_CLIENT1" pass
wait_listen_port "$PORT"
$bin/client.sh "$NS_CLIENT1" "${HOST_IP_IFACE1}" "${PORT}" "$REQUEST_FILE" >> $outfile
do_check
