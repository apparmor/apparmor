#! /bin/bash
#	Copyright (C) 2026 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME compression
#=DESCRIPTION
# Verifies that compressed policies are correctly sent to the kernel.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

if ! $subdomain --help 2>&1 | grep -q zstd-compress-level; then
	echo "SKIP: Compression not supported by parser. Skipping..."
	exit 0
fi

if ! command -v strace &> /dev/null; then
	echo "SKIP: strace not found. Skipping..."
	exit 0
fi

requires_kernel_features policy/compressed_load

prof="compression_test_profile"
testfile=$tmpdir/testfile
touch $testfile

cat > $profile <<EOF
abi <kernel>,
profile $prof $testfile {
  $testfile rw,
  /etc/passwd r,
  /usr/lib/** r,
  /usr/share/** r,
  /var/log/** rw,
  capability net_admin,
  capability sys_ptrace,
  ptrace (read) peer=@{profile_name},
}
EOF
echo "$prof" > $profilenames

# test_scenario DESC MODE
#   DESC: description string for output
#   MODE: "normal", "stdin", or "recompress"
#
# For "normal": load profile from file
# For "stdin": pipe profile to parser via stdin
# For "recompress": create cache at level 0, then reload with -O zstd-recompress
test_scenario()
{
	local desc=$1
	local mode=$2
	local prev_size=0
	local prev_level=-1
	local cache_dir=$tmpdir/cache_${mode}
	local uncompressed_size=0

	if [ "$mode" = "recompress" ]; then
		mkdir -p $cache_dir
	fi

	for level in 0 1 10 19; do
		if [ $profileloaded -eq 1 ]; then
			removeprofile
		fi

		strace_out=$tmpdir/strace_${mode}_c${level}.txt

		# For recompress: seed cache at level 0 first
		if [ "$mode" = "recompress" ]; then
			rm -rf $cache_dir/*
			$subdomain ${parser_config} --write-cache \
				--cache-loc=$cache_dir -q -c0 -r $profile \
				> /dev/null 2>&1
			removeprofile
		fi

		rc=0
		case $mode in
		normal)
			strace -f -e write -o $strace_out \
				$subdomain ${parser_config} -q -c$level \
				-r $profile > /dev/null 2>&1 || rc=$?
			;;
		stdin)
			# Export level so sh -c subprocess can expand it
			export level
			strace -f -e write -o $strace_out \
				sh -c "cat $profile | $subdomain ${parser_config} -q -c\$level -r" \
				> /dev/null 2>&1 || rc=$?
			;;
		recompress)
			strace -f -e write -o $strace_out \
				$subdomain ${parser_config} --write-cache \
				--cache-loc=$cache_dir -q -c$level \
				-O zstd-recompress -r $profile \
				> /dev/null 2>&1 || rc=$?
			;;
		esac

		if [ $rc -ne 0 ]; then
			echo "FAIL: ($desc) failed. Compression level $level failed to load (rc=$rc)"
			testfailed
			continue
		fi
		profileloaded=1

		# The kernel .replace interface returns the uncompressed
		# policy size on every write. Use this to identify
		# the kernel write among cache/stderr writes.
		if [ $uncompressed_size -eq 0 ]; then
			# Level 0 (uncompressed): write_size == return_value
			size=$(grep -E 'write\([0-9]+,' $strace_out | tail -1 | sed -E 's/.*,\s*([0-9]+)\)\s*=.*/\1/')
			uncompressed_size=$size
		else
			# Compressed: find kernel write by its return value
			size=$(grep -E 'write\([0-9]+,' $strace_out | grep "= $uncompressed_size" | head -1 | sed -E 's/.*,\s*([0-9]+)\)\s*=.*/\1/')
		fi

		if [ -z "$size" ] || [ "$size" = "-1" ]; then
			echo "FAIL: ($desc) compression level $level - could not determine write size"
			testfailed
			continue
		fi

		if [ $prev_size -gt 0 ]; then
			if [ $size -lt $prev_size ]; then
				if [ -n "$VERBOSE" ]; then
					echo "PASS: ($desc) level $level - $size bytes"
				fi
			elif [ $size -eq $prev_size ]; then
				echo "SKIP: ($desc) level $level same size as level $prev_level ($size bytes) - is compression enabled?"
			else
				echo "FAIL: ($desc) level $level ($size bytes) > level $prev_level ($prev_size bytes)"
				testfailed
			fi
		elif [ -n "$VERBOSE" ]; then
			echo "PASS: ($desc) level $level - $size bytes"
		fi

		prev_size=$size
		prev_level=$level
	done

	if [ $profileloaded -eq 1 ]; then
		removeprofile
	fi
}

# 1. Normal Load
test_scenario "Normal Load" normal

# 2. Stdin Load
test_scenario "Stdin Load" stdin

# 3. Load with recompression from cache
test_scenario "Recompressed Load" recompress

exit 0
