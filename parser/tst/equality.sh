#!/bin/bash
#
#   Copyright (c) 2013
#   Canonical, Ltd. (All rights reserved)
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, contact Canonical Ltd.
#

# Tests for post-parser equality among multiple profiles. These tests are
# useful to verify that keyword aliases, formatting differences, etc., all
# result in the same parser output.

set -o pipefail

_SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}" )

APPARMOR_PARSER="${APPARMOR_PARSER:-${_SCRIPTDIR}/../apparmor_parser}"
fails=0
errors=0
verbose="${VERBOSE:-}"
default_features_file="features.all"
features_file=$default_features_file
retain=0
dumpdfa=0
testtype=""
description="Manually run test"
tmpdir=$(mktemp -d /tmp/eq.$$-XXXXXX)
chmod 755 ${tmpdir}
export tmpdir

map_priority()
{
    if [ -z "$1" -o "$1" == "priority=0" ] ; then
	echo "0";
    elif [ "$1" == "priority=-1" ] ; then
	echo "-1"
    elif [ "$1" == "priority=1" ] ;then
	echo "1"
    else
	echo "unknown priority '$1'"
	exit 1
    fi
}

priority_eq()
{
	local p1=$(map_priority "$1")
	local p2=$(map_priority "$2")

	if [ $p1 -eq $p2 ] ; then
		return 0
	fi

	return 1
}

priority_lt()
{
	local p1=$(map_priority "$1")
	local p2=$(map_priority "$2")

	if [ $p1 -lt $p2 ] ; then
		return 0
	fi

	return 1
}

priority_gt()
{
	local p1=$(map_priority "$1")
	local p2=$(map_priority "$2")

	if [ $p1 -gt $p2 ] ; then
		return 0
	fi

	return 1
}

hash_binary_policy()
{
	local hash="parser_failure"
	local dump="/dev/null"
	local flags="-QKSq"
	local rc=0

	if [ $dumpdfa -ne 0 ] ; then
		flags="$flags -D rule-exprs -D dfa-states"
		dump="${tmpdir}/$1.state"
	fi

	printf %s "$2" | ${APPARMOR_PARSER} --features-file "${_SCRIPTDIR}/features_files/$features_file" ${flags} > "$tmpdir/$1.bin" 2>"$dump"
	rc=$?
	if [ $rc -eq 0 ] ; then
		hash=$(sha256sum "${tmpdir}/$1.bin" | cut -d ' ' -f 1)
		rc=$?
	fi

	printf %s $hash
	if [ $retain -eq 0 -a $rc -ne 0 ] ; then
		rm ${tmpdir}/*
	else
		mv "${tmpdir}/$1.bin" "${tmpdir}/$1.bin.$hash"
		if [ $dumpdfa -ne 0 ] ; then
			mv "${tmpdir}/$1.state" "$tmpdir/$1.state.$hash"
		fi
	fi

	return $rc
}

check_retain()
{
	if [ ${retain} -ne 0 ] ; then
		printf "  files retained in \"%s/\"\n" ${tmpdir} 1>&2
		exit $ret
	fi
}

# verify_binary - compares the binary policy of multiple profiles
# $1: Test type (equality or inequality)
# $2: A short description of the test
# $3: The known-good profile
# $4..$n: The profiles to compare against $3
#
# Upon failure/error, prints out the test description and profiles that failed
# and increments $fails or $errors for each failure and error, respectively
verify_binary()
{
	local t=$1
	local desc=$2
	local good_profile=$3
	local good_hash
	local ret=0

	shift
	shift
	shift

	if [ "$t" != "equality" ] && [ "$t" != "inequality" ] && \
	       [ "$t" != "xequality" ] && [ "$t" != "xinequality" ]
	then
		printf "\nERROR: Unknown test mode:\n%s\n\n" "$t" 1>&2
		((errors++))
		return $((ret + 1))
	fi
	rm -f $tmpdir/*

	if [ -n "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
	if ! good_hash=$(hash_binary_policy "known" "$good_profile") ; then
		if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
		printf "\nERROR: Error hashing the following \"known-good\" profile:\n%s\n\n" \
		       "$good_profile" 1>&2
		((errors++))
		rm -f ${tmpdir}/*
		return $((ret + 1))
	fi

	for profile in "$@"
	do
		if ! hash=$(hash_binary_policy "test" "$profile")
		then
			if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
			printf "\nERROR: Error hashing the following profile:\n%s\n\n" \
			       "$profile" 1>&2
			((errors++))
			((ret++))
		elif [ "$t" == "equality" ] && [ "$hash" != "$good_hash" ]
		then
			if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
			printf "\nFAIL: Hash values do not match\n" 1>&2
			printf "parser: %s -QKSq --features-file=%s\n" "${APPARMOR_PARSER}" "${_SCRIPTDIR}/features_files/$features_file" 1>&2
			printf "known-good (%s) != profile-under-test (%s) for the following profiles:\nknown-good         %s\nprofile-under-test %s\n\n" \
				"$good_hash" "$hash" "$good_profile" "$profile" 1>&2
			((fails++))
			((ret++))
			check_retain
		elif [ "$t" == "xequality" ] && [ "$hash" == "$good_hash" ]
		then
			if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
			printf "\nunexpected PASS: equality test with known problem, Hash values match\n" 1>&2
			printf "parser: %s -QKSq --features-file=%s\n" "${APPARMOR_PARSER}" "${_SCRIPTDIR}/features_files/$features_file" 1>&2
			printf "known-good (%s) == profile-under-test (%s) for the following profile:\nknown-good         %s\nprofile-under-test %s\n\n" \
				"$good_hash" "$hash" "$good_profile" "$profile" 1>&2
			((fails++))
			((ret++))
			check_retain
		elif [ "$t" == "xequality" ] && [ "$hash" != "$good_hash" ]
		then
		    printf "\nknown problem %s %s: unchanged" "$t" "$desc" 1>&2
		elif [ "$t" == "inequality" ] && [ "$hash" == "$good_hash" ]
		then
			if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
			printf "\nFAIL: Hash values match\n" 1>&2
			printf "parser: %s -QKSq --features-file=%s\n" "${APPARMOR_PARSER}" "${_SCRIPTDIR}/features_files/$features_file" 1>&2
			printf "known-good (%s) == profile-under-test (%s) for the following profiles:\nknown-good         %s\nprofile-under-test %s\n\n" \
				"$good_hash" "$hash" "$good_profile" "$profile" 1>&2
			((fails++))
			((ret++))
			check_retain
		elif [ "$t" == "xinequality" ] && [ "$hash" != "$good_hash" ]
		then
			if [ -z "$verbose" ] ; then printf "Binary %s %s" "$t" "$desc" ; fi
			printf "\nunexpected PASS: inequality test with known problem, Hash values do not match\n" 1>&2
			printf "parser: %s -QKSq --features-file %s\n" "${APPARMOR_PARSER}" "${_SCRIPTDIR}/features_files/$features_file" 1>&2
			printf "known-good (%s) != profile-under-test (%s) for the following profile:\nknown-good         %s\nprofile-under-test %s\n\n" \
				"$good_hash" "$hash" "$good_profile" "$profile" 1>&2
			((fails++))
			((ret++))
			check_retain
		elif [ "$t" == "xinequality" ] && [ "$hash" == "$good_hash" ]
		then
			printf "\nknown problem %s %s: unchanged" "$t" "$desc" 1>&2
			printf "parser: %s -QKSq --features-file=%s\n" "${APPARMOR_PARSER}" "${_SCRIPTDIR}/features_files/$features_file"  1>&2
		fi
		rm -f ${tmpdir}/test*
	done

	if [ $ret -eq 0 ]
	then
		if [ -z "$verbose" ] ; then
			printf "."
		else
			printf " ok\n"

		fi
	fi
	return $ret
}

verify_binary_equality()
{
	verify_binary "equality" "$@"
}

# test we want to be equal but is currently a known problem
verify_binary_xequality()
{
	verify_binary "xequality" "$@"
}

verify_binary_inequality()
{
	verify_binary "inequality" "$@"
}

# test we want to be not equal but is currently a know problem
verify_binary_xinequality()
{
	verify_binary "xinequality" "$@"
}

# kernel_features - test whether path(s) are present
# $@: feature path(s) to test
# Returns: 0 and outputs "true" if all paths exist
#          1 and error message if features dir is not available
#          2 and error message if path does not exist
kernel_features()
{
	features_dir="/sys/kernel/security/apparmor/features/"
	if [ ! -e "$features_dir" ] ; then
		echo "Kernel feature masks not supported."
		return 1;
	fi

	for f in $@ ; do
		if [ ! -e "$features_dir/$f" ] ; then
			# check if feature is in file
			feature=$(basename "$features_dir/$f")
			file=$(dirname "$features_dir/$f")
			if [ -f $file ]; then
				if ! grep -q $feature $file; then
					echo "Required feature '$f' not available."
					return 2;
				fi
			else
				echo "Required feature '$f' not available."
				return 3;
			fi
		fi
	done

	echo "true"
	return 0;
}

##########################################################################
### wrapper fn, should be indented but isn't to reduce wrap
verify_set()
{
    local p1="$1"
    local p2="$2"
    [ -n "${verbose}" ] && echo -e "\n   equality $e of '$p1' vs '$p2'\n"

verify_binary_equality "'$p1'x'$p2' dbus send" \
	"/t { $p1 dbus send, }" \
	"/t { $p2 dbus write, }" \
	"/t { $p2 dbus w, }"

verify_binary_equality "'$p1'x'$p2' dbus receive" \
	"/t { $p1 dbus receive, }" \
	"/t { $p2 dbus read, }" \
	"/t { $p2 dbus r, }"

verify_binary_equality "'$p1'x'$p2' dbus send + receive" \
	"/t { $p1 dbus (send, receive), }" \
	"/t { $p2 dbus (read, write), }" \
	"/t { $p2 dbus (r, w), }" \
	"/t { $p2 dbus (rw), }" \
	"/t { $p2 dbus rw, }" \

verify_binary_equality "'$p1'x'$p2' dbus all accesses" \
	"/t { $p1 dbus (send, receive, bind, eavesdrop), }" \
	"/t { $p2 dbus (read, write, bind, eavesdrop), }" \
	"/t { $p2 dbus (r, w, bind, eavesdrop), }" \
	"/t { $p2 dbus (rw, bind, eavesdrop), }" \
	"/t { $p2 dbus (), }" \
	"/t { $p2 dbus, }" \

verify_binary_equality "'$p1'x'$p2' dbus implied accesses with a bus conditional" \
	"/t { $p1 dbus (send, receive, bind, eavesdrop) bus=session, }" \
	"/t { $p2 dbus (read, write, bind, eavesdrop) bus=session, }" \
	"/t { $p2 dbus (r, w, bind, eavesdrop) bus=session, }" \
	"/t { $p2 dbus (rw, bind, eavesdrop) bus=session, }" \
	"/t { $p2 dbus () bus=session, }" \
	"/t { $p2 dbus bus=session, }" \

verify_binary_equality "'$p1'x'$p2' dbus implied accesses for services" \
	"/t { $p1 dbus bind name=com.foo, }" \
	"/t { $p2 dbus name=com.foo, }"

verify_binary_equality "'$p1'x'$p2' dbus implied accesses for messages" \
	"/t { $p1 dbus (send, receive) path=/com/foo interface=org.foo, }" \
	"/t { $p2 dbus path=/com/foo interface=org.foo, }"

verify_binary_equality "'$p1'x'$p2' dbus implied accesses for messages with peer names" \
	"/t { $p1 dbus (send, receive) path=/com/foo interface=org.foo peer=(name=com.foo), }" \
	"/t { $p2 dbus path=/com/foo interface=org.foo peer=(name=com.foo), }" \
	"/t { $p2 dbus (send, receive) path=/com/foo interface=org.foo peer=(name=(com.foo)), }" \
	"/t { $p2 dbus path=/com/foo interface=org.foo peer=(name=(com.foo)), }"

verify_binary_equality "'$p1'x'$p2' dbus implied accesses for messages with peer labels" \
	"/t { $p1 dbus (send, receive) path=/com/foo interface=org.foo peer=(label=/usr/bin/app), }" \
	"/t { $p2 dbus path=/com/foo interface=org.foo peer=(label=/usr/bin/app), }"

verify_binary_equality "'$p1'x'$p2' dbus element parsing" \
	"/t { $p1 dbus bus=b path=/ interface=i member=m peer=(name=n label=l), }" \
	"/t { $p2 dbus bus=\"b\" path=\"/\" interface=\"i\" member=\"m\" peer=(name=\"n\" label=\"l\"), }" \
	"/t { $p2 dbus bus=(b) path=(/) interface=(i) member=(m) peer=(name=(n) label=(l)), }" \
	"/t { $p2 dbus bus=(\"b\") path=(\"/\") interface=(\"i\") member=(\"m\") peer=(name=(\"n\") label=(\"l\")), }" \
	"/t { $p2 dbus bus =b path =/ interface =i member =m peer =(name =n label =l), }" \
	"/t { $p2 dbus bus= b path= / interface= i member= m peer= (name= n label= l), }" \
	"/t { $p2 dbus bus = b path = / interface = i member = m peer = ( name = n label = l ), }"

verify_binary_equality "'$p1'x'$p2' dbus access parsing" \
	"/t { $p1 dbus, }" \
	"/t { $p2 dbus (), }" \
	"/t { $p2 dbus (send, receive, bind, eavesdrop), }" \
	"/t { $p2 dbus (send receive bind eavesdrop), }" \
	"/t { $p2 dbus (send,	receive                  bind,  eavesdrop), }" \
	"/t { $p2 dbus (send,receive,bind,eavesdrop), }" \
	"/t { $p2 dbus (send,receive,,,,,,,,,,,,,,,,bind,eavesdrop), }" \
	"/t { $p2 dbus (send,send,send,send send receive,bind	eavesdrop), }" \

verify_binary_equality "'$p1'x'$p2' dbus variable expansion" \
	"/t { $p1 dbus (send, receive) path=/com/foo member=spork interface=org.foo peer=(name=com.foo label=/com/foo), }" \
	"@{FOO}=foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO} member=spork interface=org.@{FOO} peer=(name=com.@{FOO} label=/com/@{FOO}), }" \
	"@{FOO}=foo
	 @{SPORK}=spork
	    /t { $p2 dbus (send, receive) path=/com/@{FOO} member=@{SPORK} interface=org.@{FOO} peer=(name=com.@{FOO} label=/com/@{FOO}), }" \
	"@{FOO}=/com/foo
            /t { $p2 dbus (send, receive) path=@{FOO} member=spork interface=org.foo peer=(name=com.foo label=@{FOO}), }" \
	"@{FOO}=com
            /t { $p2 dbus (send, receive) path=/@{FOO}/foo member=spork interface=org.foo peer=(name=@{FOO}.foo label=/@{FOO}/foo), }"

verify_binary_equality "'$p1'x'$p2' dbus variable expansion, multiple values/rules" \
	"/t { $p1 dbus (send, receive) path=/com/foo, $p1 dbus (send, receive) path=/com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com/{foo,bar}, }" \
	"/t { $p2 dbus (send, receive) path={/com/foo,/com/bar}, }" \
	"@{FOO}=foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=foo bar
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=bar foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}={bar,foo}
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=foo
	 @{BAR}=bar
	    /t { $p2 dbus (send, receive) path=/com/{@{FOO},@{BAR}}, }" \

verify_binary_equality "'$p1'x'$p2' dbus variable expansion, ensure rule de-duping occurs" \
	"/t { $p1 dbus (send, receive) path=/com/foo, $p1 dbus (send, receive) path=/com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com/foo, $p2 dbus (send, receive) path=/com/bar, dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=bar foo bar foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=bar foo bar foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com/@{FOO}, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with all perms" \
	"/t { $p1 dbus, }" \
	"/t { $p2 dbus bus=session, $p2 dbus, }" \
	"/t { $p2 dbus (send, receive, bind, eavesdrop), $p2 dbus, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with bind" \
	"/t { $p1 dbus bind, }" \
	"/t { $p2 dbus bind bus=session, $p2 dbus bind, }" \
	"/t { $p2 dbus bind bus=system name=com.foo, $p2 dbus bind, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with send and a bus conditional" \
	"/t { $p1 dbus send bus=system, }" \
	"/t { $p2 dbus send bus=system path=/com/foo interface=com.foo member=bar, dbus send bus=system, }" \
	"/t { $p2 dbus send bus=system peer=(label=/usr/bin/foo), $p2 dbus send bus=system, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with an audit modifier" \
	"/t { $p1 audit dbus eavesdrop, }" \
	"/t { $p2 audit dbus eavesdrop bus=session, $p2 audit dbus eavesdrop, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with a deny modifier" \
	"/t { $p1 deny dbus send bus=system peer=(name=com.foo), }" \
	"/t { $p2 deny dbus send bus=system peer=(name=com.foo label=/usr/bin/foo), $p2 deny dbus send bus=system peer=(name=com.foo), }" \

verify_binary_equality "'$p1'x'$p2' dbus minimization found in dbus abstractions" \
	"/t { $p1 dbus send bus=session, }" \
	"/t { $p2 dbus send
                   bus=session
                   path=/org/freedesktop/DBus
                   interface=org.freedesktop.DBus
                   member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}
                   peer=(name=org.freedesktop.DBus),
	      $p2 dbus send bus=session, }"

# verify slash filtering for dbus paths.
verify_binary_equality "'$p1'x'$p2' dbus slash filtering for paths" \
	"/t { $p1 dbus (send, receive) path=/com/foo, $p1 dbus (send, receive) path=/com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com///foo, $p2 dbus (send, receive) path=///com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com//{foo,bar}, }" \
	"/t { $p2 dbus (send, receive) path={//com/foo,/com//bar}, }" \
	"@{FOO}=/foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=/foo /bar
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=/bar //foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=//{bar,foo}
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=/foo
	 @{BAR}=bar
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com//@{BAR}, }"

# Rules compatible with audit, deny, and audit deny
# note: change_profile does not support audit/allow/deny atm
for rule in "capability" "capability mac_admin" \
	"mount" "mount /a" "mount /a -> /b" "mount options in (ro) /a -> b" \
	"remount" "remount /a" \
	"umount" "umount /a" \
	"pivot_root" "pivot_root /a" "pivot_root oldroot=/" \
	 "pivot_root oldroot=/ /a" "pivot_root oldroot=/ /a -> foo" \
	"ptrace" "ptrace trace" "ptrace (readby,tracedby) peer=unconfined" \
	"signal" "signal (send,receive)" "signal peer=unconfined" \
	 "signal receive set=(kill)" \
	"dbus" "dbus send" "dbus bus=system" "dbus bind name=foo" \
	 "dbus peer=(label=foo)" "dbus eavesdrop" \
	"unix" "unix (create, listen, accept)" "unix addr=@*" "unix addr=none" \
	 "unix peer=(label=foo)" \
	"/f r" "/f w" "/f rwmlk" "/** r" "/**/ w" \
	"file /f r" "file /f w" "file /f rwmlk" \
	"link /a -> /b" "link subset /a -> /b" \
	"l /a -> /b" "l subset /a -> /b" \
	"file l /a -> /b" "l subset /a -> /b"
do
	verify_binary_equality "'$p1'x'$p2' allow modifier for \"${rule}\"" \
		"/t { $p1 ${rule}, }" \
		"/t { $p2 allow ${rule}, }"

	verify_binary_equality "'$p1'x'$p2' audit allow modifier for \"${rule}\"" \
		"/t { $p1 audit ${rule}, }" \
		"/t { $p2 audit allow ${rule}, }"

	verify_binary_inequality "'$p1'x'$p2' audit, deny, and audit deny modifiers for \"${rule}\"" \
		"/t { $p1 ${rule}, }" \
		"/t { $p2 audit ${rule}, }" \
		"/t { $p2 audit allow ${rule}, }" \
		"/t { $p2 deny ${rule}, }" \
		"/t { $p2 audit deny ${rule}, }"

	verify_binary_inequality "'$p1'x'$p2' audit vs deny and audit deny modifiers for \"${rule}\"" \
		"/t { $p1 audit ${rule}, }" \
		"/t { $p2 deny ${rule}, }" \
		"/t { $p2 audit deny ${rule}, }"

	verify_binary_inequality "'$p1'x'$p2' deny and audit deny modifiers for \"${rule}\"" \
		"/t { $p1 deny ${rule}, }" \
		"/t { $p2 audit deny ${rule}, }"
done

####### special case for network  TODO: for network above  when network
####### rules fixed
for rule in "network" "network tcp" "network inet6 tcp"
do
	verify_binary_equality "allow modifier for \"${rule}\"" \
		"/t { ${rule}, }" \
		"/t { allow ${rule}, }"

	verify_binary_equality "audit allow modifier for \"${rule}\"" \
		"/t { audit ${rule}, }" \
		"/t { audit allow ${rule}, }"

	verify_binary_inequality "audit, deny, and audit deny modifiers for \"${rule}\"" \
		"/t { ${rule}, }" \
		"/t { audit ${rule}, }" \
		"/t { audit allow ${rule}, }" \
		"/t { deny ${rule}, }" \
		"/t { audit deny ${rule}, }"

	verify_binary_inequality "audit vs deny and audit deny modifiers for \"${rule}\"" \
		"/t { audit ${rule}, }" \
		"/t { deny ${rule}, }" \
		"/t { audit deny ${rule}, }"

	verify_binary_inequality "deny and audit deny modifiers for \"${rule}\"" \
		"/t { deny ${rule}, }" \
		"/t { audit deny ${rule}, }"
done

# Rules that need special treatment for the deny modifier
for rule in "/f ux" "/f Ux" "/f px" "/f Px" "/f cx" "/f Cx" "/f ix" \
            "/f pux" "/f Pux" "/f pix" "/f Pix" \
            "/f cux" "/f Cux" "/f cix" "/f Cix" \
            "/* ux" "/* Ux" "/* px" "/* Px" "/* cx" "/* Cx" "/* ix" \
            "/* pux" "/* Pux" "/* pix" "/* Pix" \
            "/* cux" "/* Cux" "/* cix" "/* Cix" \
	    "/f px -> b " "/f Px -> b" "/f cx -> b" "/f Cx -> b" \
            "/f pux -> b" "/f Pux -> b" "/f pix -> b" "/f Pix -> b" \
            "/f cux -> b" "/f Cux -> b" "/f cix -> b" "/f Cix -> b" \
            "/* px -> b" "/* Px -> b" "/* cx -> b" "/* Cx -> b" \
            "/* pux -> b" "/* Pux -> b" "/* pix -> b" "/* Pix -> b" \
            "/* cux -> b" "/* Cux -> b" "/* cix -> b" "/* Cix -> b" \
	    "file /f ux" "file /f Ux" "file /f px" "file /f Px" \
            "file /f cx" "file /f Cx" "file /f ix" \
            "file /f pux" "file /f Pux" "file /f pix" "file /f Pix" \
            "/f cux" "/f Cux" "/f cix" "/f Cix" \
            "file /* ux" "file /* Ux" "file /* px" "file /* Px" \
            "file /* cx" "file /* Cx" "file /* ix" \
            "file /* pux" "file /* Pux" "file /* pix" "file /* Pix" \
            "file /* cux" "file /* Cux" "file /* cix" "file /* Cix" \
	    "file /f px -> b " "file /f Px -> b" "file /f cx -> b" "file /f Cx -> b" \
            "file /f pux -> b" "file /f Pux -> b" "file /f pix -> b" "file /f Pix -> b" \
            "file /f cux -> b" "file /f Cux -> b" "file /f cix -> b" "file /f Cix -> b" \
            "file /* px -> b" "file /* Px -> b" "file /* cx -> b" "file /* Cx -> b" \
            "file /* pux -> b" "file /* Pux -> b" "file /* pix -> b" "file /* Pix -> b" \
            "file /* cux -> b" "file /* Cux -> b" "file /* cix -> b" "file /* Cix -> b"

do
	verify_binary_equality "'$p1'x'$p2' allow modifier for \"${rule}\"" \
		"/t { $p1 ${rule}, }" \
		"/t { $p2 allow ${rule}, }"

	verify_binary_equality "'$p1'x'$p2' audit allow modifier for \"${rule}\"" \
		"/t { $p1 audit ${rule}, }" \
		"/t { $p2 audit allow ${rule}, }"

	# skip rules that don't end with x perm
	if [ -n "${rule##*x}" ] ; then continue ; fi

	verify_binary_inequality "'$p1'x'$p2' deny, audit deny modifier for \"${rule}\"" \
		"/t { $p1 ${rule}, }" \
		"/t { $p2 audit ${rule}, }" \
		"/t { $p2 audit allow ${rule}, }" \
		"/t { $p2 deny ${rule% *} x, }" \
		"/t { $p2 audit deny ${rule% *} x, }"

	verify_binary_inequality "'$p1'x'$p2' audit vs deny and audit deny modifiers for \"${rule}\"" \
		"/t { $p1 audit ${rule}, }" \
		"/t { $p2 deny ${rule% *} x, }" \
		"/t { $p2 audit deny ${rule% *} x, }"

done

# verify deny and audit deny differ for x perms
for prefix in "/f" "/*" "file /f" "file /*" ; do
	verify_binary_inequality "'$p1'x'$p2' deny and audit deny x modifiers for \"${prefix}\"" \
		"/t { $p1 deny ${prefix} x, }" \
		"/t { $p2 audit deny ${prefix} x, }"
done

#Test equality of leading and trailing file permissions
for audit in "" "audit" ; do
	for allow in "" "allow" "deny" ; do
		for owner in "" "owner" ; do
			for f in "" "file" ; do
				prefix="$audit $allow $owner $f"
				for perm in "r" "w" "a" "l" "k" "m" "rw" "ra" \
					    "rl" "rk" "rm" "wl" "wk" "wm" \
					    "rwl" "rwk" "rwm" "ral" "rak" \
					    "ram" "rlk" "rlm" "rkm" "wlk" \
					    "wlm" "wkm" "alk" "alm" "akm" \
					    "lkm" "rwlk" "rwlm" "rwkm" \
					    "ralk" "ralm" "wlkm" "alkm" \
					    "rwlkm" "ralkm" ; do
					verify_binary_equality "'$p1'x'$p2' leading and trailing perms for \"${perm}\"" \
						"/t { $p1 ${prefix} /f ${perm}, }" \
						"/t { $p2 ${prefix} ${perm} /f, }"
				done
				if [ "$allow" == "deny" ] ; then continue ; fi
				for perm in "ux" "Ux" "px" "Px" "cx" "Cx" \
					    "ix" "pux" "Pux" "pix" "Pix" \
					    "cux" "Cux" "cix" "Cix"
				do
					verify_binary_equality "'$p1'x'$p2' leading and trailing perms for \"${perm}\"" \
						"/t { $p1 ${prefix} /f ${perm}, }" \
						"/t { $p2 ${prefix} ${perm} /f, }"
				done
				for perm in "px" "Px" "cx" "Cx" \
					    "pux" "Pux" "pix" "Pix" \
					    "cux" "Cux" "cix" "Cix"
				do
					verify_binary_equality "'$p1'x'$p2' leading and trailing perms for x-transition \"${perm}\"" \
						"/t { $p1 ${prefix} /f ${perm} -> b, }" \
						"/t { $p2 ${prefix} ${perm} /f -> b, }"
				done
			done
		done
	done
done

#Test rule overlap for x most specific match
for perm1 in "ux" "Ux" "px" "Px" "cx" "Cx" "ix" "pux" "Pux" \
	     "pix" "Pix" "cux" "Cux" "cix" "Cix" "px -> b" \
	     "Px -> b" "cx -> b" "Cx -> b" "pux -> b" "Pux ->b" \
	     "pix -> b" "Pix -> b" "cux -> b" "Cux -> b" \
	     "cix -> b" "Cix -> b"
do
	for perm2 in "ux" "Ux" "px" "Px" "cx" "Cx" "ix" "pux" "Pux" \
		     "pix" "Pix" "cux" "Cux" "cix" "Cix" "px -> b" \
	             "Px -> b" "cx -> b" "Cx -> b" "pux -> b" "Pux ->b" \
	             "pix -> b" "Pix -> b" "cux -> b" "Cux -> b" \
	             "cix -> b" "Cix -> b"
	do
		# Fixme: have to do special handling for -> b, as this
		# creates an entry in the transition table. However
		# priority rules can make it so the reference to the
		# transition table is removed, but the parser still keeps
		# the tranition. This can lead to a situation where the
		# test dfa with a "-> b" transition is functionally equivalent
		# but will fail equality comparison.
		# fix this by adding two none overlapping x rules to add
		# xtable entries
		# /c -> /t//b, for cx rules being converted to px -> /t//b
		# /a -> b, for px rules
		# the rules must come last guarantee xtable order
		if [ "$perm1" == "$perm2" ] || priority_gt "$p1" "" ; then
			verify_binary_equality "'$p1'x'$p2' Exec perm \"${perm1}\" - most specific match: same as glob" \
				"/t { $p1 /f* ${perm1}, /f ${perm2}, /a px -> b, /c px -> /t//b, }" \
				"/t { $p2 /f* ${perm1}, /a px -> b, /c px -> /t//b, }"
		else
			verify_binary_inequality "'$p1'x'$p2' Exec \"${perm1}\" vs \"${perm2}\" - most specific match: different from glob" \
				"/t { $p1 /f* ${perm1}, /f ${perm2}, /a px -> b, /c px -> /t//b, }" \
				"/t { $p2 /f* ${perm1}, /a px -> b, /c px -> /t//b, }"
		fi
	done
	if priority_gt "$p1" "" ; then
		# priority stops permission carve out
		verify_binary_equality "'$p1'x'$p2' Exec \"${perm1}\" vs deny x - most specific match: different from glob" \
			"/t { $p1 /* ${perm1}, audit deny /f x, }" \
			"/t { $p2 /* ${perm1}, }"
	else
		# deny rule carves out some of the match
		verify_binary_inequality "'$p1'x'$p2' Exec \"${perm1}\" vs deny x - most specific match: different from glob" \
			"/t { $p1 /* ${perm1}, audit deny /f x, }" \
			"/t { $p2 /* ${perm1}, }"
	fi

done

#ix implies m if it is applied, and no other rule overrides because of priority
	verify_binary_equality "'$p1'x'$p2' ix implies m" \
		       "/t { $p1 /foo ix, }" \
		       "/t { $p2 /foo mix, }"

	verify_binary_equality "'$p1'x'$p2' ix owner implies m" \
		       "/t { $p1 owner /foo ix, }" \
		       "/t { $p2 owner /foo mix, }"

	verify_binary_equality "'$p1'x'$p2' ix other implies m" \
		       "/t { $p1 other /foo ix, }" \
		       "/t { $p2 other /foo mix, }"

	verify_binary_inequality "'$p1'x'$p2' ix implies m owner != all" \
		       "/t { $p1 /foo ix, }" \
		       "/t { $p2 owner /foo mix, }"

	verify_binary_inequality "'$p1'x'$p2' ix implies m other != all" \
		       "/t { $p1 /foo ix, }" \
		       "/t { $p2 other /foo mix, }"

	verify_binary_inequality "'$p1'x'$p2' ix implies m owner != other" \
		       "/t { $p1 owner /foo ix, }" \
		       "/t { $p2 other /foo mix, }"

	verify_binary_equality "'$p1'x'$p2' ix implies m with exact match over glob" \
		       "/t { $p1 /** px, $p1 /foo ix, }" \
		       "/t { $p2 /** px, $p2 /foo mix, }"

	verify_binary_equality "'$p1'x'$p2' reverse order ix implies m with exact match over glob" \
		       "/t { $p1 /** px, $p1 /foo mix, }" \
		       "/t { $p2 /** px, $p2 /foo ix, }"

	verify_binary_equality "'$p1'x'$p2' deny removed ix and implied m" \
		       "/t { $p1 audit deny /foo x, $p1 /foo rix, }" \
		       "/t { $p2 /foo r, }"

	verify_binary_equality "'$p1'x'$p2' deny glob removed ix and implied m" \
		       "/t { $p1 audit deny /** x, $p1 /foo rix, }" \
		       "/t { $p2 /foo r, }"

	verify_binary_equality "'$p1'x'$p2' deny removed ix and not explicit m" \
		       "/t { $p1 audit deny /foo x, $p1 /foo mrix, }" \
		       "/t { $p2 /foo mr, }"

	verify_binary_equality "'$p1'x'$p2' deny glob removed ix not explicit m" \
		       "/t { $p1 audit deny /** x, $p1 /foo mrix, }" \
		       "/t { $p2 /foo mr, }"

# ix implied m is not set if ix overridden by higher x priority rule
if priority_gt "$p1" $p2 ; then
	verify_binary_equality "'$p1'x'$p2' Higher priority overrides implied m" \
		       "/t { $p1 /foo px, $p2 /foo ix, }" \
		       "/t { /foo px, }"
	verify_binary_equality "'$p1'x'$p2' Higher priority glob overrides implied m" \
		       "/t { $p1 /** px, $p2 /foo ix, }" \
		       "/t { /** px, }"

	verify_binary_equality "'$p1'x'$p2' > pri deny removed ix and implied m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo rix, }" \
		       "/t { /foo r, }"

	verify_binary_equality "'$p1'x'$p2' > pri deny glob removed ix and implied m" \
		       "/t { $p1 audit deny /** x, $p2 /foo rix, }" \
		       "/t { /foo r, }"

	verify_binary_equality "'$p1'x'$p2' > pri deny removed ix and not explicit m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo mrix, }" \
		       "/t { /foo mr, }"

	verify_binary_equality "'$p1'x'$p2' > pri deny glob removed ix not explicit m" \
		       "/t { $p1 audit deny /** x, $p2 /foo mrix, }" \
		       "/t { /foo mr, }"

elif priority_eq "$p1" $p2 ; then # skip any conflicts
	verify_binary_equality "'$p1'x'$p2' eq pri deny removed ix and implied m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo rix, }" \
		       "/t { /foo r, }"

	verify_binary_equality "'$p1'x'$p2' eq deny glob removed ix and implied m" \
		       "/t { $p1 audit deny /** x, $p2 /foo rix, }" \
		       "/t { /foo r, }"

	verify_binary_equality "'$p1'x'$p2' eq pri deny removed ix and not explicit m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo mrix, }" \
		       "/t { /foo mr, }"

	verify_binary_equality "'$p1'x'$p2' eq pri deny glob removed ix not explicit m" \
		       "/t { $p1 audit deny /** x, $p2 /foo mrix, }" \
		       "/t { /foo mr, }"
elif priority_lt "$p1" $p2 ; then
	verify_binary_inequality "'$p1'x'$p2' negative case ix is overiding px" \
		       "/t { $p1 /foo px, $p2 /foo ix, }" \
		       "/t { /foo px, }"
	verify_binary_equality "'$p1'x'$p2' ix of higher priority overrides and implies m" \
		       "/t { $p1 /foo px, $p2 /foo ix, }" \
		       "/t { /foo mix, }" \
		       "/t { /foo ix, }"
	verify_binary_inequality "'$p1'x'$p2' negative case ix overrides px glob" \
		       "/t { $p1 /** px, $p2 /foo ix, }" \
		       "/t { /** px, }"
	verify_binary_equality "'$p1'x'$p2' ix glob of higher priority overrides and implies" \
		       "/t { $p1 /** px, $p2 /** ix, }" \
		       "/t { /** mix, }" \
		       "/t { /** ix, }"
	verify_binary_equality "'$p1'x'$p2' < pri deny no effect on implied m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo rix, }" \
		       "/t { /foo rix, }"

	verify_binary_equality "'$p1'x'$p2' < pri deny glob no effect on ix and implied m" \
		       "/t { $p1 audit deny /** x, $p2 /foo rix, }" \
		       "/t { /foo rix, }"

	verify_binary_equality "'$p1'x'$p2' < pri deny no effect on ix and not explicit m" \
		       "/t { $p1 audit deny /foo x, $p2 /foo mrix, }" \
		       "/t { /foo mrix, }"

	verify_binary_equality "'$p1'x'$p2' < pri deny no effect on ix not explicit m" \
		       "/t { $p1 audit deny /** x, $p2 /foo mrix, }" \
		       "/t { /foo mrix, }"
fi


#Test deny carves out permission
if priority_gt "$p1" "" ; then
	verify_binary_equality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[abc] r, }"

	verify_binary_inequality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[ac] r, }"

#this one may not be true in the future depending on if the compiled profile
#is explicitly including deny permissions for dynamic composition
	verify_binary_equality "'$p1'x'$p2' Deny of ungranted perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b w, }" \
		       "/t { $p2 /foo/[abc] r, }"
elif priority_eq "$p1" "" ; then
	verify_binary_inequality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[abc] r, }"

	verify_binary_equality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[ac] r, }"

#this one may not be true in the future depending on if the compiled profile
#is explicitly including deny permissions for dynamic composition
	verify_binary_equality "'$p1'x'$p2' Deny of ungranted perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b w, }" \
		       "/t { $p2 /foo/[abc] r, }"
else
	verify_binary_inequality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[abc] r, }"

	verify_binary_equality "'$p1'x'$p2' Deny removes r perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b r, }" \
		       "/t { $p2 /foo/[ac] r, }"

#this one may not be true in the future depending on if the compiled profile
#is explicitly including deny permissions for dynamic composition
	verify_binary_equality "'$p1'x'$p2' Deny of ungranted perm" \
		       "/t { $p1 /foo/[abc] r, audit deny /foo/b w, }" \
		       "/t { $p2 /foo/[abc] r, }"
fi

verify_binary_equality "'$p1'x'$p2' change_profile == change_profile -> **" \
		       "/t { $p1 change_profile, }" \
		       "/t { $p2 change_profile -> **, }"

verify_binary_equality "'$p1'x'$p2' change_profile /** == change_profile /** -> **" \
		       "/t { $p1 change_profile /**, }" \
		       "/t { $p2 change_profile /** -> **, }"

verify_binary_equality "'$p1'x'$p2' change_profile /** == change_profile /** -> **" \
		       "/t { $p1 change_profile unsafe /**, }" \
		       "/t { $p2 change_profile unsafe /** -> **, }"

verify_binary_equality "'$p1'x'$p2' change_profile /** == change_profile /** -> **" \
		       "/t { $p1 change_profile /**, }" \
		       "/t { $p2 change_profile safe /** -> **, }"

verify_binary_inequality "'$p1'x'$p2' change_profile /** == change_profile /** -> **" \
			 "/t { $p1 change_profile /**, }" \
			 "/t { $p2 change_profile unsafe /**, }"

verify_binary_equality "'$p1'x'$p2' profile name is hname in rule" \
	":ns:/hname { $p1 signal peer=/hname, }" \
	":ns:/hname { $p2 signal peer=@{profile_name}, }"

verify_binary_inequality "'$p1'x'$p2' profile name is NOT fq name in rule" \
	":ns:/hname { $p1 signal peer=:ns:/hname, }" \
	":ns:/hname { $p2 signal peer=@{profile_name}, }"

verify_binary_equality "'$p1'x'$p2' profile name is hname in sub pofile rule" \
	":ns:/hname { profile child { $p1 signal peer=/hname//child, } }" \
	":ns:/hname { profile child { $p2 signal peer=@{profile_name}, } }"

verify_binary_inequality "'$p1'x'$p2' profile name is NOT fq name in sub profile rule" \
	":ns:/hname { profile child { $p1 signal peer=:ns:/hname//child, } }" \
	":ns:/hname { profile child { $p2 signal peer=@{profile_name}, } }"

verify_binary_equality "'$p1'x'$p2' profile name is hname in hat rule" \
	":ns:/hname { ^child { $p1 signal peer=/hname//child, } }" \
	":ns:/hname { ^child { $p2 signal peer=@{profile_name}, } }"

verify_binary_inequality "'$p1'x'$p2' profile name is NOT fq name in hat rule" \
	":ns:/hname { ^child { $p1 signal peer=:ns:/hname//child, } }" \
	":ns:/hname { ^child { $p2 signal peer=@{profile_name}, } }"

verify_binary_equality "'$p1'x'$p2' @{profile_name} is literal in peer" \
	"/{a,b} { $p1 signal peer=/\{a,b\}, }" \
	"/{a,b} { $p2 signal peer=@{profile_name}, }"

verify_binary_equality "'$p1'x'$p2' @{profile_name} is literal in peer with pattern" \
	"/{a,b} { $p1 signal peer={/\{a,b\},c}, }" \
	"/{a,b} { $p2 signal peer={@{profile_name},c}, }"

verify_binary_inequality "'$p1'x'$p2' @{profile_name} is not pattern in peer" \
	"/{a,b} { $p1 signal peer=/{a,b}, }" \
	"/{a,b} { $p2 signal peer=@{profile_name}, }"

verify_binary_equality "'$p1'x'$p2' @{profile_name} is literal in peer with esc sequence" \
	"/\\\\a { $p1 signal peer=/\\\\a, }" \
	"/\\\\a { $p2 signal peer=@{profile_name}, }"

verify_binary_equality "'$p1'x'$p2' @{profile_name} is literal in peer with esc alt sequence" \
	"/\\{a,b\\},c { $p1 signal peer=/\\{a,b\\},c, }" \
	"/\\{a,b\\},c { $p2 signal peer=@{profile_name}, }"



# Unfortunately we can not just compare an empty profile and hat to a
# ie. "/t { ^test { /f r, }}"
# to the second profile with the equivalent rule inserted manually
# because policy write permission "w" actually expands to multiple permissions
# under the hood, and the parser is not adding those permissions
# to the rules it auto generates
# So we insert the rule with "append" permissions, and rely on the parser
# merging permissions of rules.
# If the parser isn't adding the rules "append" is not equivalent to
# the "write" permission in the second profile and the test will fail.
# If the parser is adding the change_hat proc attr rules then the
# rules should merge and be equivalent.
#
# if priorities are different then the implied rule priority then the
# implied rule will completely override or completely be overriden.
# (the change_hat implied rule has a priority of 0)
# because of the difference in 'a' vs 'w' permission the two rules should
# only be equal when the append rule has the same priority as the implied
# rule (allowing them to combine) AND the other rule is not overridden by
# the implied rule, or both being overridden by the implied rule
# the implied rule
if { priority_lt "$p1" "" && priority_lt "$p2" "" ; } ||
   { priority_eq "$p1" "" && ! priority_lt "$p2" "" ; }; then
    verify_binary_equality "'$p1'x'$p2' change_hat rules automatically inserted"\
		       "/t { $p1 owner /proc/[0-9]*/attr/{apparmor/,}current a, ^test { $p1 owner /proc/[0-9]*/attr/{apparmor/,}current a, /f r, }}" \
		       "/t { $p2 owner /proc/[0-9]*/attr/{apparmor/,}current w, ^test { $p2 owner /proc/[0-9]*/attr/{apparmor/,}current w, /f r, }}"
else
    verify_binary_equality "'$p1'x'$p2' change_hat rules automatically inserted"\
		       "/t { $p1 owner /proc/[0-9]*/attr/{apparmor/,}current a, ^test { $p1 owner /proc/[0-9]*/attr/{apparmor/,}current a, /f r, }}" \
		       "/t { $p2 owner /proc/[0-9]*/attr/{apparmor/,}current w, ^test { $p2 owner /proc/[0-9]*/attr/{apparmor/,}current w, /f r, }}"
fi

# verify slash filtering for unix socket address paths.
# see https://bugs.launchpad.net/apparmor/+bug/1856738
verify_binary_equality "'$p1'x'$p2' unix rules addr conditional" \
                       "/t { $p1 unix bind addr=@/a/bar, }" \
                       "/t { $p2 unix bind addr=@/a//bar, }" \
                       "/t { $p2 unix bind addr=@//a/bar, }" \
                       "/t { $p2 unix bind addr=@/a///bar, }" \
                       "@{HOME}=/a/
                           /t { $p2 unix bind addr=@@{HOME}/bar, }" \
                       "@{HOME}=/a/
                           /t { $p2 unix bind addr=@//@{HOME}bar, }" \
                       "@{HOME}=/a/
                           /t { $p2 unix bind addr=@/@{HOME}/bar, }"

verify_binary_equality "'$p1'x'$p2' unix rules peer addr conditional" \
                       "/t { $p1 unix peer=(addr=@/a/bar), }" \
                       "/t { $p2 unix peer=(addr=@/a//bar), }" \
                       "/t { $p2 unix peer=(addr=@//a/bar), }" \
                       "/t { $p2 unix peer=(addr=@/a///bar), }" \
                       "@{HOME}=/a/
                           /t { $p2 unix peer=(addr=@@{HOME}/bar), }" \
                       "@{HOME}=/a/
                           /t { $p2 unix peer=(addr=@//@{HOME}bar), }" \
                       "@{HOME}=/a/
                           /t { $p2 unix peer=(addr=@/@{HOME}/bar), }"

# verify slash filtering for mount rules
verify_binary_equality "'$p1'x'$p2' mount rules slash filtering" \
                       "/t { $p1 mount /dev/foo -> /mnt/bar, }" \
                       "/t { $p2 mount ///dev/foo -> /mnt/bar, }" \
                       "/t { $p2 mount /dev/foo -> /mnt//bar, }" \
                       "/t { $p2 mount /dev///foo -> ////mnt/bar, }" \
                       "@{MNT}=/mnt/
                           /t { $p2 mount /dev///foo -> @{MNT}/bar, }" \
                       "@{FOO}=/foo
                           /t { $p2 mount /dev//@{FOO} -> /mnt/bar, }"

# verify slash filtering for link rules
verify_binary_equality "'$p1'x'$p2' link rules slash filtering" \
                       "/t { $p1 link /dev/foo -> /mnt/bar, }" \
                       "/t { $p2 link ///dev/foo -> /mnt/bar, }" \
                       "/t { $p2 link /dev/foo -> /mnt//bar, }" \
                       "/t { $p2 link /dev///foo -> ////mnt/bar, }" \
                       "@{BAR}=/mnt/
                           /t { $p2 link /dev///foo -> @{BAR}/bar, }" \
                       "@{FOO}=/dev/
                           /t { $p2 link @{FOO}//foo -> /mnt/bar, }" \
                       "@{FOO}=/dev/
                        @{BAR}=/mnt/
                           /t { $p2 link @{FOO}/foo -> @{BAR}/bar, }"

# Verify equality with mount detached source

verify_binary_equality "'$p1'x'$p2' mount detached vs empty source" \
                       "/t { $p1 mount \"\" -> /destination, }" \
					   "/t { $p2 mount detached -> /destination, }"

# This can potentially fail as ideally it requires a better dfa comparison
# routine as it can generates hormomorphic dfas. The enumeration of the
# dfas dumped will be different, even if the binary is the same
# Note: this test in the future will require -O filter-deny and
# -O minimize and -O remove-unreachable.
verify_binary_equality "'$p1'x'$p2' mount specific deny doesn't affect non-overlapping" \
			"/t { $p1 mount options=bind /e/ -> /**, }" \
			"/t { $p2 audit deny mount /s/** -> /**,
			      mount options=bind /e/ -> /**, }"


## priority override equivalence tests
## compare single rule, to multi-rule profile where one rule overrides
## the other rule via priority.


verify_binary_equality "'$p1'x'$p2' dbus variable expansion, multiple values/rules" \
	"/t { dbus (send, receive) path=/com/foo, }" \
	"/t { $p1 dbus (send, receive) path=/com/foo, $p2 dbus (send, receive) path=/com/foo, }" \
	"@{FOO}=foo
	    /t { $p1 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com/foo, }" \

verify_binary_equality "'$p1'x'$p2' dbus variable expansion, ensure rule de-duping occurs" \
	"/t { $p1 dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=bar foo bar foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=bar foo bar foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, dbus (send, receive) path=/com/@{FOO}, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with all perms" \
	"/t { $p1 dbus, }" \
	"/t { $p2 dbus bus=session, $p2 dbus, }" \
	"/t { $p2 dbus (send, receive, bind, eavesdrop), $p2 dbus, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with bind" \
	"/t { $p1 dbus bind, }" \
	"/t { $p2 dbus bind bus=session, $p2 dbus bind, }" \
	"/t { $p2 dbus bind bus=system name=com.foo, $p2 dbus bind, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with send and a bus conditional" \
	"/t { $p1 dbus send bus=system, }" \
	"/t { $p2 dbus send bus=system path=/com/foo interface=com.foo member=bar, dbus send bus=system, }" \
	"/t { $p2 dbus send bus=system peer=(label=/usr/bin/foo), $p2 dbus send bus=system, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with an audit modifier" \
	"/t { $p1 audit dbus eavesdrop, }" \
	"/t { $p2 audit dbus eavesdrop bus=session, $p2 audit dbus eavesdrop, }"

verify_binary_equality "'$p1'x'$p2' dbus minimization with a deny modifier" \
	"/t { $p1 deny dbus send bus=system peer=(name=com.foo), }" \
	"/t { $p2 deny dbus send bus=system peer=(name=com.foo label=/usr/bin/foo), $p2 deny dbus send bus=system peer=(name=com.foo), }" \

verify_binary_equality "'$p1'x'$p2' dbus minimization found in dbus abstractions" \
	"/t { $p1 dbus send bus=session, }" \
	"/t { $p2 dbus send
                   bus=session
                   path=/org/freedesktop/DBus
                   interface=org.freedesktop.DBus
                   member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}
                   peer=(name=org.freedesktop.DBus),
	      $p2 dbus send bus=session, }"

# verify slash filtering for dbus paths.
verify_binary_equality "'$p1'x'$p2' dbus slash filtering for paths" \
	"/t { $p1 dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com///foo, dbus (send, receive) path=///com/bar, }" \
	"/t { $p2 dbus (send, receive) path=/com//{foo,bar}, }" \
	"/t { $p2 dbus (send, receive) path={//com/foo,/com//bar}, }" \
	"@{FOO}=/foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=/foo /bar
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=/bar //foo
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=//{bar,foo}
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=/foo
	 @{BAR}=bar
	    /t { $p2 dbus (send, receive) path=/com/@{FOO}, $p2 dbus (send, receive) path=/com//@{BAR}, }"



#### end of wrapper fn
}


run_tests()
{
	printf "Equality Tests:\n"

	#rules that don't support priority

	# verify rlimit data conversions
	verify_binary_equality "set rlimit rttime <= 12 weeks" \
                       "/t { set rlimit rttime <= 12 weeks, }" \
                       "/t { set rlimit rttime <= $((12 * 7)) days, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24)) hours, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24 * 60)) minutes, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24 * 60 * 60)) seconds, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24 * 60 * 60 * 1000)) ms, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24 * 60 * 60 * 1000 * 1000)) us, }" \
                       "/t { set rlimit rttime <= $((12 * 7 * 24 * 60 * 60 * 1000 * 1000)), }"

	verify_binary_equality "set rlimit cpu <= 42 weeks" \
                       "/t { set rlimit cpu <= 42 weeks, }" \
                       "/t { set rlimit cpu <= $((42 * 7)) days, }" \
                       "/t { set rlimit cpu <= $((42 * 7 * 24)) hours, }" \
                       "/t { set rlimit cpu <= $((42 * 7 * 24 * 60)) minutes, }" \
                       "/t { set rlimit cpu <= $((42 * 7 * 24 * 60 * 60)) seconds, }" \
                       "/t { set rlimit cpu <= $((42 * 7 * 24 * 60 * 60)), }"

	verify_binary_equality "set rlimit memlock <= 2GB" \
                       "/t { set rlimit memlock <= 2GB, }" \
                       "/t { set rlimit memlock <= $((2 * 1024)) MB, }" \
                       "/t { set rlimit memlock <= $((2 * 1024 * 1024)) KB, }" \
                       "/t { set rlimit memlock <= $((2 * 1024 * 1024 * 1024)) , }"

	run_port_range=$(kernel_features network_v8/af_inet)
	if [ "$run_port_range" != "true" ]; then
	    echo -e "\nSkipping network af_inet tests. $run_port_range\n"
	else
	    # network port range
	    # select features file that contains netv8 af_inet
	    features_file="features.af_inet"
	    verify_binary_equality "network port range" \
			   "/t { network port=3456-3460, }" \
			   "/t { network port=3456, \
				 network port=3457, \
				 network port=3458, \
				 network port=3459, \
				 network port=3460, }"

	    verify_binary_equality "network peer port range" \
			   "/t { network peer=(port=3456-3460), }" \
			   "/t { network peer=(port=3456), \
				 network peer=(port=3457), \
				 network peer=(port=3458), \
				 network peer=(port=3459), \
				 network peer=(port=3460), }"

	    verify_binary_inequality "network port range allows more than single port" \
			     "/t { network port=3456-3460, }" \
			     "/t { network port=3456, }"

	    verify_binary_inequality "network peer port range allows more than single port" \
			     "/t { network peer=(port=3456-3460), }" \
			     "/t { network peer=(port=3456), }"
	    # return to default
	    features_file=$default_features_file
	fi

	# Equality tests that set explicit priority level
	# TODO: priority handling for file paths is currently broken

	# This test is not actually correct due to two subtle
	# interactions: - /* is special-cased to expand to /[^/\x00]+
	# with at least one character - Quieting of [^a] in the DFA is
	# different and cannot be manually fixed

	#verify_binary_xequality "file rule carveout regex vs priority" \
	#	"/t { deny /[^a]* rwxlk, /a r, }" \
	#	"/t { priority=-1 deny /* rwxlk, /a r, }" \

	# Not grouping all three together because parser correctly handles
	# the equivalence of carveout regex and default audit deny
	verify_binary_equality "file rule carveout regex vs priority (audit)" \
			"/t { audit deny /[^a]* rwxlk, /a r, }" \
			"/t { priority=-1 audit deny /* rwxlk, /a r, }"

	verify_binary_equality "file rule default audit deny vs audit priority carveout" \
			"/t { /a r, }" \
			"/t { priority=-1 audit deny /* rwxlk, /a r, }"

	# Tests that do not use priority keywords at all

	verify_binary_equality "attachment slash filtering" \
				"/t /bin/foo { }" \
				"/t /bin//foo { }" \
				"@{BAR}=/bin/
					/t @{BAR}/foo { }" \
				"@{FOO}=/foo
					/t /bin/@{FOO} { }" \
				"@{BAR}=/bin/
					@{FOO}=/foo
					/t @{BAR}/@{FOO} { }"
	# verify comment at end of variable assignment is not treated as a value
	verify_binary_equality "comment at end of set var" \
				"/t { /bin/ r, }" \
				"@{BAR}=/bin/   #a tail comment
					/t { @{BAR} r, }"

	verify_binary_equality "value like comment at end of set var" \
				"/t { /{bin/,#value} r, }" \
				"@{BAR}=bin/   \#value
					/t { /@{BAR} r, }"

	# verify combinations of different priority levels
	# for single rule comparisons, rules should keep same expected result
	# even when the priorities are different.
	# different priorities within a profile comparison resulting in
	# different permission could affected expected results


	priorities="none 0 1 -1"

	for pri1 in $priorities ; do
	    if [ "$pri1" = "none" ] ; then
		priority1=""
	    else
		priority1="priority=$pri1"
	    fi
	    for pri2 in $priorities  ; do
		if [ "$pri2" = "none" ] ; then
		    priority2=""
		else
		    priority2="priority=$pri2"
		fi

		verify_set "$priority1" "$priority2"
	    done
	done

	[ -z "${verbose}" ] && printf "\n"
	if [ $fails -ne 0 ] || [ $errors -ne 0 ]; then
		printf "ERRORS: %d\nFAILS: %d\n" $errors $fails 1>&2
		exit $((fails + errors))
	else
		printf "PASS\n"
		exit 0
	fi
}


usage()
{
	local progname="$0"
	local rc="$1"
	local msg="usage: ${progname} [Options]

Run the equality tests if no options given, otherwise run as directed
by the options.

Options:
  -h, --help	display this help
  -e base args	run an equality test on the following args
  -n base args	run an inequality test on the following args
  -xequality	run a known proble equality test
  -xinequality	run a known proble inequality test
  -r		on failure retain failed test output and abort
  -d		include dfa dumps with failed test output
  -f arg	features file to use
  -p arg	parser to invoke
  --description	description to print with test
  -v		verbose
examples:
$ equality.sh
...
$ equality.sh -r
....
inary equality 'priority=1'x'' Exec perm \"ux\" - most specific match: same as glob
FAIL: Hash values do not match
parser: ../apparmor_parser --config-file=./parser.conf --features-file=./features_files/features.all
known-good (0344cd377ccb239aba4cce768b818010961d68091d8c7fae72c755cfcb48d4a2) != profile-under-test (33fdf4575322a036c2acb75f93a7154179036f1189ef68ab9f1ae98e7f865780) for the following profiles:
known-good         /t { priority=1 /* ux, /f px -> b, }
profile-under-test /t {  /* ux, }

$ equality.sh -e \"/t { priority=1 /* Px -> b, /f Px, }\" \"/t {  /* Px, }\"
$ equality.sh -e \"/t { priority=1 /* Px -> b, /f Px, }\" \"/t {  /* Px, }\""

	echo "$msg"
}


POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
	-h|--help)
	  usage
	  exit 0
	  ;;
	-e|--equality)
	    testtype="equality"
	    shift # past argument
	    ;;
	--xequality)
	    testtype="xequality"
	    shift # past argument
	    ;;
	-n|--inequality)
	    testtype="inequality"
	    shift # past argument
	    ;;
	--xinequality)
	    testtype="xinequality"
	    shift # past argument
	    ;;
	-d|--dfa)
	    dumpdfa=1
	    shift # past argument
	    ;;
	-r|--retain)
	    retain=1
	    shift # past argument
	    ;;
	-v|--verbose)
	    verbos=1
	    shift # past argument
	    ;;
	-f|--feature-file)
	    features_file="$2"
	    shift # past argument
	    shift # past option
	    ;;
	--description)
	    description="$2"
	    shift # past argument
	    shift # past option
	    ;;
	-p|--parser)
	    APPARMOR_PARSER="$2"
	    shift # past argument
	    shift # past option
	    ;;
	-*|--*)
	    echo "Unknown option $1"
	    exit 1
	    ;;
	*)
	    POSITIONAL_ARGS+=("$1") # save positional arg
	    shift # past argument
	    ;;
    esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ $# -eq 0 -o -z "$testtype" ] ; then
	run_tests "$@"
	exit $?
fi

for profile in "$@" ; do
	verify_binary "$testtype" "$description" "$known" "$profile"
done
