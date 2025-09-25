#! /bin/bash
#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME i18n
#=DESCRIPTION
# This script tests some of the basic handling of i18n characters in the
# kernel and (eventually) the parser. We try to open a file with weird bytes 
# in the name.
#=END

LANG=C

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

okperm=rw
badperm1=r
badperm2=w
globfile=${tmpdir}/file_*_post

settest open

# skip NULL (\x0) and / (\x2F) because they can't be part of filenames
# skip DEL (\x7f) for now until Ican get it properly passed through
# skip \ (\x5c) because they are dropped as invalid escape sequences

# Older rust coreutils broke when given non-utf8 paths
# If you encounter issues here, remove $(seq 128 255) below
# Order the high-bytes first to catch this potential issue earlier
for i in $(seq 128 255) $(seq  1 46) $(seq 48 91) $(seq 93 126); do
#for i in $(seq 127 127 ); do
	symbol=$(printf "\\$(printf "%03o" $i)")
	# Sigh, in the case of \012, bash would strip it out during
	# variable assignment. -ENOCLUE why it doesn't work for \177
	case "$i" in 
		10) 	file=$tmpdir/file_$'\012'_post
		    	;;
		127) 	file=$tmpdir/file_$'\177'_post
		    	;;
		*)	file=$tmpdir/file_${symbol}_post
			;;
	esac
	parser_file=$tmpdir/file_\\$(printf "%03o" $i)_post

	#echo "$i '$symbol' $file $parser_file"
	#echo "$file" | od -x
	touch "$file"
	chmod 600 "$file"

	# PASS TEST
	genprofile "${globfile}:$okperm"
	runchecktest "i18n ($i) OPEN (glob) \"${file}\" RW" pass "$file"

	# FAIL TEST
	#genprofile "${globfile}:$badperm2"
	#runchecktest "i18n ($i) OPEN (glob) \"${file}\" W" fail "$file"

	# skip the ':', since it is a delimiter for mkprofile
	# We'll test it below in the \octal test.
	if [ "${symbol}" != ":" ] ; then 
		# PASS TEST
		genprofile -E "${file}:$okperm"
		runchecktest "i18n ($i) OPEN \"${file}\" RW" pass "$file"

		# FAIL TEST
		#genprofile -E "${file}:$badperm2"
		#runchecktest "i18n ($i) OPEN \"${file}\" W" fail "$file"
	fi 

	# PASS TEST
	genprofile -E ${parser_file}:$okperm
	runchecktest "i18n ($i) OPEN (octal) \"${file}\" RW" pass "$file"

	# FAIL TEST
	genprofile -E "${parser_file}:$badperm2"
	runchecktest "i18n ($i) OPEN (octal) \"${file}\" W" fail "$file"
done
