#! /bin/bash
#	Copyright (C) 2021 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME attach_disconnected
#=DESCRIPTION 
# This test verifies that the attached_disconnected flag is indeed restricting
# access to disconnected paths.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"
. "$bin/net_supports.inc"

# needs more than just kernel support, needs corresponding parser support
# as well
requires supports_unix_rules

settest unix_fd_server
disk_img=$tmpdir/disk_img
new_root=$tmpdir/new_root/
put_old=${new_root}put_old/
fstype="ext2"
file=$tmpdir/file
socket=$tmpdir/unix_fd_test
att_dis_client=$pwd/attach_disconnected

. "$bin/mount.inc"

attach_disconnected_cleanup() {
	if [ ! -z "$loop_device" ]; then
		losetup -d $loop_device
	fi

	mountpoint -q "$new_root"
	if [ $? -eq 0 ] ; then
		umount "$new_root"
	fi

	prop_cleanup
}
do_onexit="attach_disconnected_cleanup"

if [ ! -b /dev/loop0 ] ; then
	modprobe loop
fi

dd if=/dev/zero of="$disk_img" bs=1024 count=512 2> /dev/null
/sbin/mkfs -t "$fstype" -F "$disk_img" > /dev/null 2> /dev/null
# mounting will be done by the test binary
loop_device=$(losetup -fP --show "${disk_img}")

# content generated with:
# dd if=/dev/urandom bs=32 count=4 2> /dev/null | od -x | head -8 | sed -e 's/^[[:xdigit:]]\{7\}//g' -e 's/ //g'
# required by unix_fd_server which this test is based on
cat > ${file} << EOM
4bcd0f741e97195c57f1ff72dbdf2dd9
8284a4cd56699628c185f6f647805a1c
8bdee094b7e73f9834ada004c570ad49
a9a92856edb4a206f271b537fe73081f
ac62547499fffd79021898cc8653e36b
c943fd5f8f4cfa4690a08505e44b0906
7532527375fb6dc0ddadfcb2f1bcdd82
150223d965fefe996f8a6c602cc1b514
EOM

do_test()
{
	local desc="ATTACH_DISCONNECTED ($1)"
	shift
	runchecktest "$desc" "$@"
}

# Needed for clone(CLONE_NEWNS) and pivot_root()
cap=capability:sys_admin
file_perm="$file:rw $put_old/$file:rw"
socket_perm="$socket:rw $put_old/$socket:rw"
create_dir="$new_root:w $put_old:w"

# Ensure everything works as expected when unconfined
do_test "attach_disconnected" pass $file $att_dis_client $socket $loop_device $new_root $put_old

# TODO: adding attach_disconnected.path to a replaced unconfined

# ALLOW ALL does not include attach_disconnected
if [ "$(parser_supports 'all,')" = "true" ]; then
	genprofile "all" flag:attach_disconnected -- image=$att_dis_client "all"
	do_test "attach_disconnected allow all" pass $file $att_dis_client $socket $loop_device $new_root $put_old

	genprofile "all" -- image=$att_dis_client "all"
	do_test "attach_disconnected allow all no flag" fail $file $att_dis_client $socket $loop_device $new_root $put_old
fi

genprofile $file_perm unix:create $socket_perm $att_dis_client:px -- image=$att_dis_client $file_perm unix:create $socket_perm $create_dir $cap "pivot_root:ALL" "mount:ALL" flag:attach_disconnected

do_test "attach_disconnected" pass $file $att_dis_client $socket $loop_device $new_root $put_old

genprofile $file_perm unix:create $socket_perm $att_dis_client:px -- image=$att_dis_client $file_perm unix:create $socket_perm $create_dir $cap "pivot_root:ALL" "mount:ALL" flag:attach_disconnected.path=/foo/

do_test "attach_disconnected.path rule at /" fail $file $att_dis_client $socket $loop_device $new_root $put_old

genprofile $file_perm unix:create $socket_perm $att_dis_client:px -- image=$att_dis_client $file_perm unix:create $socket_perm $create_dir $cap "pivot_root:ALL" "mount:ALL" flag:attach_disconnected.path=$put_old

do_test "attach_disconnected.path" pass $file $att_dis_client $socket $loop_device $new_root $put_old

genprofile $file_perm unix:create $socket_perm $att_dis_client:px -- image=$att_dis_client $file_perm unix:create $socket_perm $create_dir $cap "pivot_root:ALL" "mount:ALL" flag:no_attach_disconnected

do_test "no_attach_disconnected" fail $file $att_dis_client $socket $loop_device $new_root $put_old

# Ensure default is no_attach_disconnected - no flags set
genprofile $file_perm unix:create $socket_perm $att_dis_client:px -- image=$att_dis_client $file_perm unix:create $socket_perm $create_dir $cap "pivot_root:ALL" "mount:ALL"

do_test "no_attach_disconnected" fail $file $att_dis_client $socket $loop_device $new_root $put_old

# TODO: Add .path to the attach_disconnected flag
