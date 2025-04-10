#! /bin/bash
#Copyright (C) 2022 Canonical, Ltd.
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License as
#published by the Free Software Foundation, version 2 of the
#License.

#=NAME posix_mq
#=DESCRIPTION
# This test verifies if mediation of posix message queues is working
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

requires_kernel_features ipc/posix_mqueue
requires_parser_support "mqueue,"

settest posix_mq_rcv

sender="$bin/posix_mq_snd"
receiver="$bin/posix_mq_rcv"
queuename="/queuename"
queuename2="/queuename2"
pipe="/tmp/mqueuepipe"

user="foo"
adduser --gecos "First Last,RoomNumber,WorkPhone,HomePhone" --no-create-home --disabled-password $user >/dev/null
echo "$user:password" | sudo chpasswd
userid=$(id -u $user)

# workaround to not have to set o+x
chmod 6755 "$receiver"
setcap cap_dac_read_search+pie "$receiver"

cleanup()
{
    rm -f /dev/mqueue/$queuename
    rm -f /dev/mqueue/$queuename2
    rm -f $pipe
    deluser foo >/dev/null
}
do_onexit="cleanup"

do_test()
{
    local desc="POSIX MQUEUE ($1)"
    shift
    runchecktest "$desc" "$@"
}


do_tests()
{
    prefix=$1
    expect_send=$2
    expect_recv=$3
    expect_open=$4

    all_args=("$@")
    rest_args=("${all_args[@]:5}")

    do_test "$prefix" "$expect_send" "$sender" "$expect_recv" -c "$sender" -k $queuename "${rest_args[@]}"

    # notify requires netlink permissions
    do_test "$prefix : mq_notify" "$expect_send" "$sender" "$expect_recv" -c "$sender" -k $queuename -n mq_notify -p $pipe "${rest_args[@]}"

    do_test "$prefix : select" "$expect_open" -c "$sender" -k $queuename -n select "${rest_args[@]}"

    do_test "$prefix : poll" "$expect_open" -c "$sender" -k $queuename -n poll "${rest_args[@]}"

    do_test "$prefix : epoll" "$expect_open" -c "$sender" -k $queuename -n epoll "${rest_args[@]}"
}


for username in "root" "$userid" ; do
    if [ $username = "root" ] ; then
	usercmd=""
    else
	usercmd="-u $userid"
    fi

    do_tests "unconfined $username" pass pass pass pass $usercmd

    # No mqueue perms
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "$sender:px" "$pipe:rw" -- "image=$sender" "$pipe:rw"
    do_tests "confined $username - no perms" fail fail fail fail $usercmd


    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "deny:mqueue" "$sender:px" "$pipe:rw" -- "image=$sender" "deny mqueue" "$pipe:rw"
    do_tests "confined $username - deny perms" fail fail fail fail $usercmd

    if [ "$(parser_supports 'all,')" = "true" ]; then
	genprofile "all" -- "image=$sender" "all"
	do_tests "confined $username - allow all" pass pass pass pass $usercmd
    fi

    # generic mqueue
    # 2 Potential failures caused by missing other x permission in path
    # to tests. Usually on the user home dir as it is now default to
    # create a user without that
    # * if you seen a capability dac_read_search denied failure from
    #   apparmor when doing "root" username tests
    # * if doing the $userid set of tests and you see
    #   Permission denied in the test output
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue" "$pipe:rw"
    do_tests "confined $username - mqueue" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:type=posix" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:type=posix" "$pipe:rw"
    do_tests "confined $username - mqueue type=posix" pass pass pass pass $usercmd

    # queue name
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:$queuename" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:$queuename" "$pipe:rw"
    do_tests "confined $username - mqueue /name 1" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:$queuename" "$pipe:rw"
    do_tests "confined $username - mqueue /name 2" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:$queuename" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue" "$pipe:rw"
    do_tests "confined $username - mqueue /name 3" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:$queuename" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:$queuename2" "$pipe:rw"
    do_tests "confined $username - mqueue /name 4" fail fail fail fail $usercmd -t 1


    # specific permissions
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,delete,getattr,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 1" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(read,delete,getattr,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 2" fail fail fail fail $usercmd -t 1

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,delete,getattr,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 3" fail fail fail fail $usercmd -t 1

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,getattr,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 4" fail fail fail fail $usercmd -t 1

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,delete,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 5" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,delete,getattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:write" "$pipe:rw"
    do_tests "confined $username - specific 6" pass pass pass pass $usercmd

    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,delete,getattr,setattr)" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:read" "$pipe:rw"
    do_tests "confined $username - specific 7" fail fail fail fail $usercmd -t 1

    # unconfined receiver
    genprofile "image=$sender" "mqueue"
    do_tests "confined sender $username - unconfined receiver" pass pass pass pass $usercmd


    # unconfined sender
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink"  "mqueue" "$sender:ux" "$pipe:rw"
    do_tests "confined receiver $username - unconfined sender" pass pass pass pass $usercmd


    labelres="xpass"
    if [ "$(kernel_features ipc/posix_mqueue/label)" = "true" ]; then
        labelres="pass"
    fi

    # queue label
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:label=$receiver" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:label=$receiver" "$pipe:rw"
    do_tests "confined $username - mqueue label 1" $labelres $labelres $labelres $labelres $usercmd


    # queue name and label
    genprofile "qual=deny:cap:sys_resource" "cap:setuid" "cap:fowner" "network:netlink" "mqueue:(create,read,delete):type=posix:label=$receiver:$queuename" "$sender:px" "$pipe:rw" -- "image=$sender" "mqueue:(open,write):type=posix:label=$receiver:$queuename" "$pipe:rw"
    do_tests "confined $username - mqueue label 2" $labelres $labelres $labelres $labelres $usercmd

    # ensure we are cleaned up for next pass
    removeprofile
    rm -f /dev/mqueue/$queuename
    rm -f /dev/mqueue/$queuename2
done

# cross user tests


# confined root with cap ??override


# confined root without cap ??override

