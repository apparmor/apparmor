#! /bin/bash
#	Copyright (C) 2016 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME at_secure
#=DESCRIPTION
# Verifies the AT_SECURE flag in the auxiliary vector after an exec transition
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

settest transition
at_secure=$pwd/at_secure
test_prof=at_secure
stacking_supported="$(kernel_features domain/stack || true)"

onexec_default=1
if [ "$stacking_supported" != "true" ]; then
	# Pre-stacking kernels default to insecure exec transitions with
	# change_profile rules that have an exec condition but don't have an
	# "(un)safe" modifier.
	onexec_default=0
fi

for iface in "" "-B" ; do

# Verify AT_SECURE after unconfined -> unconfined transition
runchecktest "AT_SECURE iface='$iface' (unconfined -> unconfined - change_onexec)" \
	pass $iface -O unconfined -- $at_secure 0
runchecktest "AT_SECURE  iface='$iface' (unconfined -> unconfined - change_onexec) [NEGATIVE]" \
	fail $iface -O unconfined -- $at_secure 1

# Verify AT_SECURE after unconfined -> confined transition
genprofile image=$test_prof addimage:$at_secure
runchecktest "AT_SECURE  iface='$iface' (unconfined -> confined - change_onexec)" \
	pass $iface -O $test_prof -- $at_secure 0
runchecktest "AT_SECURE (unconfined -> confined - change_onexec) [NEGATIVE]" \
	fail $iface -O $test_prof -- $at_secure 1

genprofile image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (unconfined -> confined - binary attachment)" \
	pass $iface -- $at_secure 0
runchecktest "AT_SECURE (unconfined -> confined - binary attachment) [NEGATIVE]" \
	fail $iface -- $at_secure 1

# Verify AT_SECURE after confined -> unconfined transition
genprofile "change_profile:unconfined"
runchecktest "AT_SECURE  iface='$iface' (confined -> unconfined - change_onexec)" \
	pass $iface -O unconfined -- $at_secure $onexec_default

genprofile $at_secure:ux
runchecktest "AT_SECURE iface='$iface' (confined -> unconfined - ux)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:Ux
runchecktest "AT_SECURE  iface='$iface' (confined -> unconfined - Ux)" \
	pass $iface -- $at_secure 1

genprofile $at_secure:pux
runchecktest "AT_SECURE  iface='$iface' (confined -> unconfined - pux fallback)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:PUx
runchecktest "AT_SECURE iface='$iface' (confined -> unconfined - PUx fallback)" \
	pass $iface -- $at_secure 1

genprofile $at_secure:cux
runchecktest "AT_SECURE iface='$iface' (confined -> unconfined - cux fallback)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:CUx
runchecktest "AT_SECURE  iface='$iface' (confined -> unconfined - CUx fallback)" \
	pass $iface -- $at_secure 1

# Verify AT_SECURE after confined -> confined transition
genprofile "change_profile:$test_prof" -- image=$test_prof addimage:$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - change_onexec)" \
	pass $iface -O $test_prof -- $at_secure $onexec_default

genprofile $at_secure:px -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - px)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:Px -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - Px)" \
	pass $iface -- $at_secure 1

genprofile $at_secure:pux -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - pux)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:PUx -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - PUx)" \
	pass $iface -- $at_secure 1

genprofile $at_secure:ix -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - ix)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:pix -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - pix)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:Pix -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - Pix)" \
	pass $iface -- $at_secure 1

genprofile $at_secure:cix -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - cix fallback)" \
	pass $iface -- $at_secure 0

genprofile $at_secure:Cix -- image=$at_secure
runchecktest "AT_SECURE  iface='$iface' (confined -> confined - Cix fallback)" \
	pass $iface -- $at_secure 0

# TODO: Adjust mkprofile.pl to allow child profiles so that cx and Cx can be
# tested as well as the non-fallback cix and Cix cases

if [ "$stacking_supported" != "true" ]; then
	echo "Warning: kernel doesn't support stacking. Skipping tests..."
else
	removeprofile

	# Verify AT_SECURE after unconfined -> &unconfined stacking transition
	runchecktest "AT_SECURE  iface='$iface' (unconfined -> &unconfined - stack_onexec)" \
		pass $iface -o unconfined -- $at_secure 0
	runchecktest "AT_SECURE  iface='$iface' (unconfined -> &unconfined - stack_onexec) [NEGATIVE]" \
		fail $iface -o unconfined -- $at_secure 1

	# Verify AT_SECURE after unconfined -> &confined stacking transition
	genprofile image=$test_prof addimage:$at_secure
	runchecktest "AT_SECURE  iface='$iface' (unconfined -> &confined - stack_onexec)" \
		pass $iface -o $test_prof -- $at_secure 0
	runchecktest "AT_SECURE (unconfined -> &confined - stack_onexec) [NEGATIVE]" \
		fail $iface -o $test_prof -- $at_secure 1

	# Verify AT_SECURE after confined -> &unconfined stacking transition
	genprofile "change_profile:&unconfined"
	runchecktest "AT_SECURE iface='$iface' (confined -> &unconfined - stack_onexec)" \
		pass $iface -o unconfined -- $at_secure $onexec_default

	# Verify AT_SECURE after confined -> &confined stacking transition
	genprofile "change_profile:&$test_prof" -- image=$test_prof addimage:$at_secure
	runchecktest "AT_SECURE iface='$iface' (confined -> &confined - stack_onexec)" \
		pass $iface -o $test_prof -- $at_secure $onexec_default
fi

if [ "$(parser_supports 'change_profile safe /a -> /b,')" != "true" ]; then
	echo "Warning: parser doesn't support change_profile (un)safe rules. Skipping tests..."
else
	safe_at_secure=1
	if [ "$stacking_supported" != "true" ]; then
		# Pre-stacking kernels can't properly support the
		# change_profile safe modifier:
		#  change_profile safe /a -> /b,
		#
		# The parser downgrades 'safe' to 'unsafe' in this situation.
		safe_at_secure=0
	fi

	# Verify AT_SECURE after (un)safe confined -> unconfined transition
	genprofile "change_profile:unsafe:$at_secure:unconfined"
	runchecktest "AT_SECURE iface='$iface' (confined -> unconfined - unsafe change_onexec)" \
		pass $iface -O unconfined -- $at_secure 0

	genprofile "change_profile:safe:$at_secure:unconfined"
	runchecktest "AT_SECURE iface='$iface' (confined -> unconfined - safe change_onexec)" \
		pass $iface -O unconfined -- $at_secure $safe_at_secure

	# Verify AT_SECURE after (un)safe confined -> confined transition
	genprofile "change_profile:unsafe:$at_secure:$test_prof" -- image=$test_prof addimage:$at_secure
	runchecktest "AT_SECURE iface='$iface' (confined -> confined - unsafe change_onexec)" \
		pass $iface -O $test_prof -- $at_secure 0

	genprofile "change_profile:safe:$at_secure:$test_prof" -- image=$test_prof addimage:$at_secure
	runchecktest "AT_SECURE iface='$iface' (confined -> confined - safe change_onexec)" \
		pass $iface -O $test_prof -- $at_secure $safe_at_secure

	if [ "$stacking_supported" != "true" ]; then
		# We've already warned the user that we're skipping stacking tests
		:
	else
		# Verify AT_SECURE after (un)safe confined -> &unconfined stacking transition
		genprofile "change_profile:unsafe:$at_secure:&unconfined"
		runchecktest "AT_SECURE iface='$iface' (confined -> &unconfined - unsafe stack_onexec)" \
			pass $iface -o unconfined -- $at_secure 0

		genprofile "change_profile:safe:$at_secure:&unconfined"
		runchecktest "AT_SECURE iface='$iface' (confined -> &unconfined - safe stack_onexec)" \
			pass $iface -o unconfined -- $at_secure 1

		# Verify AT_SECURE after (un)safe confined -> &confined stacking transition
		genprofile "change_profile:unsafe:$at_secure:&$test_prof" -- image=$test_prof addimage:$at_secure
		runchecktest "AT_SECURE iface='$iface' (confined -> &confined - unsafe stack_onexec)" \
			pass $iface -o $test_prof -- $at_secure 0

		genprofile "change_profile:safe:$at_secure:&$test_prof" -- image=$test_prof addimage:$at_secure
		runchecktest "AT_SECURE iface='$iface' (confined -> &confined - safe stack_onexec)" \
			pass $iface -o $test_prof -- $at_secure 1
	fi
fi

removeprofile
done # for iface
