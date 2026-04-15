#! /bin/bash
#	Copyright (C) 2022 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME e2e
#=DESCRIPTION
# Verifies basic parser functionality.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

# load_and_verify - Generate and load a profile, then verify that raw_data
#                            matches the generated cached policy
# $1: A description of this test
load_and_verify() {
    local desc=$1
    local prof="dummy_test"
    local cache_dir=$(${subdomain} --print-cache-dir)
    local cache_md5
    local kernel_md5

    # Since we're not testing any binary, force test global var to our dummy profile
    test="$prof"

    # Write to cache
    parser_args="${parser_config} -q -W"

    echo "profile $prof {}" | genprofile image=$prof --stdin

    # Check for the zstd magic number and decompress the cache if needed
    if [ $(hexdump -s 8 -n 4 --format "\"%x\"" $cache_dir/profile) = "fd2fb528" ]; then
        # Skip past our own custom header
        cache_md5=$(cat $cache_dir/profile | tail -c +9 | zstdcat | md5sum | awk '{ print $1 }')
    else
        cache_md5=$(cat $cache_dir/profile | md5sum | awk '{ print $1 }')
    fi

    local matching=0
    for binary_policy in /sys/kernel/security/apparmor/policy/profiles/$prof*/raw_data; do
        kernel_md5=$(cat $binary_policy | md5sum | awk '{ print $1 }')
        if [ $kernel_md5 = $cache_md5 ]; then
            matching=1
            break
        fi
    done

    if [ $matching -eq 0 ]; then
        echo "Error: ${testname}, ${desc} failed. raw_data profile doesn't match the generated cached one"
        testfailed
    elif [ -n "$VERBOSE" ]; then
        echo "ok: ${desc}"
    fi

    removeprofile
}

load_and_verify "E2E load profile and read from kernel"
