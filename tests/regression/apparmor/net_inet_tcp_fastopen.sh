#! /bin/bash
#	Copyright (C) 2026 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME net_inet_tcp_fastopen
#=DESCRIPTION
# Regression test for the TCP Fast Open connect-mediation bypass. Under a
# profile that grants inet/inet6 stream "send" but DENIES "connect", a plain
# connect(2) is refused, and sendto(..., MSG_FASTOPEN, ...) (which performs an
# implicit connect) MUST also be refused -- for both plain TCP and MPTCP. Pre-fix
# the TFO path checked only the send permission (AA_NET_SEND 0x02) and skipped
# connect (AA_NET_CONNECT 0x40).
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

# Need fine-grained inet mediation (connect/send are separable only there).
requires_any_of_kernel_features network_v8/af_inet network_v9/af_inet
requires_parser_support "network (send) ip=::1,"

settest net_inet_tcp_fastopen

tfo_sysctl=/proc/sys/net/ipv4/tcp_fastopen
tfo_saved=""

cleanup()
{
	# restore the original tcp_fastopen value if we changed it
	if [ -n "$tfo_saved" ]; then
		echo "$tfo_saved" > "$tfo_sysctl" 2>/dev/null || true
	fi
}
do_onexit="cleanup"

# The sendto(MSG_FASTOPEN) client path needs the TCP Fast Open client bit
# (0x1). Enable it for the run; if it is unavailable (no sysctl, or it cannot
# be enabled) the bug cannot be exercised at all, so skip rather than report a
# spurious failure.
if [ ! -w "$tfo_sysctl" ]; then
	echo "    TCP Fast Open sysctl ($tfo_sysctl) not available. Skipping tests ..."
	exit 0
fi
tfo_saved=`cat "$tfo_sysctl"`
echo $((tfo_saved | 1)) > "$tfo_sysctl" 2>/dev/null || true
if [ $(($(cat "$tfo_sysctl") & 1)) -ne 1 ]; then
	echo "    Could not enable the TCP Fast Open client bit. Skipping tests ..."
	exit 0
fi

# add ::1 if not already present (loopback usually has it)
ip -6 addr add ::1/128 dev lo 2>/dev/null || true

# pick a free port for the listener this binary creates
port=4321
while lsof -i:$port >/dev/null 2>&1; do
	let port=$port+1
done

# Profile: allow stream send/receive + the perms needed to stand up the
# in-process listener (bind/listen/accept), allow setopt/getopt for TFO
# sockopts, but explicitly DENY connect on both inet and inet6.
gen_send_no_connect()
{
	genprofile \
	  "network;(send,receive,accept,listen,bind);ip=127.0.0.1;port=$port" \
	  "network;(send,receive,accept,listen,bind);ip=::1;port=$port" \
	  "network;(send,receive);peer=(ip=127.0.0.1)" \
	  "network;(send,receive);peer=(ip=::1)" \
	  "network;(setopt,getopt);ip=0.0.0.0;port=0" \
	  "network;(setopt,getopt);ip=::0;port=0" \
	  "qual=deny:network;(connect);ip=127.0.0.1" \
	  "qual=deny:network;(connect);ip=::1"
}

# ---- inet (IPv4) ----
gen_send_no_connect
# baseline: a normal connect(2) must be denied -> binary prints PASS (denied),
# expected outcome 'pass'
runchecktest "TFO inet - connect(2) denied" pass connect inet $port
# the bug: sendto(MSG_FASTOPEN) must ALSO be denied post-fix
runchecktest "TFO inet - sendto(MSG_FASTOPEN) denied" pass fastopen inet $port

# ---- inet6 (IPv6) ----
gen_send_no_connect
runchecktest "TFO inet6 - connect(2) denied" pass connect inet6 $port
runchecktest "TFO inet6 - sendto(MSG_FASTOPEN) denied" pass fastopen inet6 $port

# ---- MPTCP: the second producer the fix guards (IPPROTO_MPTCP) ----
# The deny-connect rule is family/type based, so it covers MPTCP (inet/inet6
# stream) too. Only run when MPTCP is enabled.
if [ "`cat /proc/sys/net/mptcp/enabled 2>/dev/null`" = "1" ]; then
	gen_send_no_connect
	runchecktest "TFO MPTCP inet - connect(2) denied" pass connect minet $port
	runchecktest "TFO MPTCP inet - sendto(MSG_FASTOPEN) denied" pass fastopen minet $port
	gen_send_no_connect
	runchecktest "TFO MPTCP inet6 - connect(2) denied" pass connect minet6 $port
	runchecktest "TFO MPTCP inet6 - sendto(MSG_FASTOPEN) denied" pass fastopen minet6 $port
fi

# ---- positive control: when connect IS allowed, both succeed (no false deny) ----
genprofile \
  "network;(connect,send,receive,accept,listen,bind);ip=127.0.0.1;port=$port" \
  "network;(connect,send,receive);peer=(ip=127.0.0.1)" \
  "network;(setopt,getopt);ip=0.0.0.0;port=0"
# Here the binary's "denied" assertion is FALSE (op allowed), so it prints
# FAIL; we expect that, i.e. expected outcome 'fail'.
runchecktest "TFO inet - connect allowed (control)" fail connect inet $port
runchecktest "TFO inet - fastopen allowed (control)" fail fastopen inet $port

exit 0
