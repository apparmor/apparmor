#! /bin/bash
#	Copyright (c) 2026 Canonical Ltd. (All rights reserved)
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of version 2 of the GNU General Public
#	License published by the Free Software Foundation.

#=NAME signal_identity
#=DESCRIPTION
# Verify identity-based signal access control.
# Test uses two separated binaries "victim" and "killer" ensuring that
# separate profiles can be attached.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

# Require kernel identity support
requires_kernel_features "domain/identity"

# Prepare binaries in tmpdir
victim_bin=${tmpdir}/victim
killer_bin=${tmpdir}/killer

cp -pL $bin/signal_identity_victim $victim_bin
cp -pL $bin/signal_identity_killer $killer_bin
chmod 755 $victim_bin
chmod 755 $killer_bin

# Helper to run the test
# $1 = test description
# $2 = expected result (pass/fail)
# $3 = killer identity (or "none" for no identity)
# Unified test runner
# $1 = test description
# $2 = expected result (pass/fail)
# $3 = victim identity
# $4 = killer identity (or "none")
# $5 = killer peer target (e.g. "killable" or "unconfined", or "none" to skip rule)
run_test() {
	local desc=$1
	local expected=$2
	local victim_identity=$3
	local killer_identity=$4
	local killer_peer=$5
	local victim_pid
	local killer_id_arg=""
	if [ "$killer_identity" != "none" ]; then
		killer_id_arg="identities=($killer_identity)"
	fi
	local killer_sig_arg=""
	if [ "$killer_peer" != "none" ]; then
		killer_sig_arg="signal send set=term peer=$killer_peer"
	fi

	# Note: peer=unconfined is needed for cleanup
	genprofile image=$victim_bin \
		"identities=($victim_identity)" \
		"$victim_bin mrix" \
		"signal receive peer=can_kill" \
		"signal receive peer=unconfined" \
		-- \
		image=$killer_bin \
		${killer_id_arg:+"$killer_id_arg"} \
		"$killer_bin rix" \
		${killer_sig_arg:+"$killer_sig_arg"}

	$victim_bin &
	victim_pid=$!
	sleep 0.1

	testexec=$killer_bin

	runchecktest "$desc" "$expected" $victim_pid

	# Cleanup victim if it is still alive
	if kill -0 $victim_pid 2>/dev/null; then
		kill -9 $victim_pid 2>/dev/null || true
		wait $victim_pid 2>/dev/null || true
	fi
}

# Test 1: Killer matches identity (can_kill) -> PASS
run_test "Test 1: Killer(can_kill) -> Victim(killable)" pass "killable" "can_kill" "killable"

# Test 2: Killer has wrong identity (other) -> FAIL
run_test "Test 2: Killer(other) -> Victim(killable)" fail "killable" "other" "killable"

# Test 3: Killer has NO identity -> FAIL
# Note: explicitly passing "none" for peer target to match original behavior (no signal rule)
run_test "Test 3: Killer(none) -> Victim(killable)" fail "killable" "none" "none"

# Test 4: Killer(peer=unconfined) -> Victim(identities=foo) -> FAIL
run_test "Test 4: Killer(peer=unconfined) -> Victim(foo)" fail "foo" "can_kill" "unconfined"

# Test 5: Killer(peer=unconfined) -> Victim(identities=unconfined) -> PASS
run_test "Test 5: Killer(peer=unconfined) -> Victim(unconfined)" pass "unconfined" "can_kill" "unconfined"
