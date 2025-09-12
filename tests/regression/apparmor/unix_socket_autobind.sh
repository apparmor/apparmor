#! /bin/bash
#
# Copyright (C) 2014 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Canonical Ltd.

#=NAME unix_socket_autobind abstract sockets
#=DESCRIPTION
# This tests access to autobinding abstract unix domain sockets. The
# server opens a socket, forks a client with it's own profile, passes
# an fd across exec, sends a message to the client over the socket, and
# sees what happens.
#=END
#
# TODO: peer_addr auto, just generates a pattern it would be better if we
# could extract the bound socket name and pass that in to the profile
# generation

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"
. "$bin/net_supports.inc"
. "$bin/unix_socket.inc"
requires_any_of_kernel_features policy/versions/v7 policy/versions/v8 policy/versions/v9
requires supports_unix_rules

settest unix_socket

addr=auto
#TODO: replace client_addr pattern with actual autobound address
client_addr=@[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].client

# Test autobind stream server and client
do_test "autobind" \
	"server" \
	"create,setopt" \
	"bind,listen,getopt,shutdown,getattr" \
	stream \
	"$addr" \
	"accept,read,write" \
	"unconfined" \
	"" \
	dgram \
	"@autoXXX" \
	"${test}XXX" \
	""
do_test "autobind" \
	"client" \
	"" \
	"create,getopt,setopt,getattr" \
	stream \
	"" \
	"connect,write,read" \
	"$test" \
	"$addr" \
	seqpacket \
	"" \
	"${test}XXX" \
	"@autoXXX"

# Test autobind dgram server and client
do_test "autobind" \
	"server" \
	"create,setopt" \
	"bind,getopt,shutdown,getattr" \
	dgram \
	"$addr" \
	"read,write" \
	"unconfined" \
	"$client_addr" \
	seqpacket \
	"@autoXXX" \
	"${test}XXX" \
	"${client_addr}XXX"
do_test "autobind" \
	"client" \
	"create,setopt,getattr" \
	"bind,getopt,getattr" \
	dgram \
	"$client_addr" \
	"write,read" \
	"$test" \
	"$addr" \
	stream \
	"${client_addr}XXX" \
	"${test}XXX" \
	"@autoXXX"

# Test autobind seqpacket server and client
do_test "autobind" \
	"server" \
	"create,setopt" \
	"bind,listen,getopt,shutdown,getattr" \
	seqpacket \
	"$addr" \
	"accept,read,write" \
	"unconfined" \
	"" \
	stream \
	"@autoXXX" \
	"${test}XXX" \
	""
do_test "autobind" \
	"client" \
	"" \
	"create,getopt,setopt,getattr" \
	seqpacket \
	"" \
	"connect,write,read" \
	"$test" \
	"$addr" \
	dgram \
	"" \
	"${test}XXX" \
	"@autoXXX"
