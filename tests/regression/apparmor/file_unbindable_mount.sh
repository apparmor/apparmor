#! /bin/bash
#	Copyright (C) 2024 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME file_unbindable_mount
#=DESCRIPTION
# Verifies that file rules work across unbindable mounts
#=END

pwd=$(dirname "$0")
pwd=$(cd "$pwd" || exit ; /bin/pwd)

bin=$pwd

. "$bin/prologue.inc"

backing_file="$tmpdir/loop_file"
mount_target="$tmpdir/mount_target"

mkdir "${mount_target}"
# rust core utils is ~11MB
fallocate -l 16M "${backing_file}"
mkfs.fat -F 32 "${backing_file}" > /dev/null 2> /dev/null

losetup -f "${backing_file}" || fatalerror 'Unable to set up a loop device'
loop_device="$(/sbin/losetup -n -O NAME -l -j "${backing_file}")"

mount --make-unbindable "${loop_device}" "${mount_target}"
fallocate -l 2M "${mount_target}/a_file"
# echo is also a builtin, making things a bit more complicated
cp "$(type -P echo)" "${mount_target}/echo"

settest file_unbindable_mount "${bin}/complain"

genprofile addimage:"${mount_target}/echo" "${mount_target}/a_file:r" "${mount_target}/echo:ix"
runchecktest "Read file in unbindable mount" pass read "${mount_target}/a_file"
runchecktest "Exec in unbindable mount" pass exec "${mount_target}/echo" PASS

umount "${loop_device}"

losetup -d "${loop_device}"
rm "${backing_file}"
