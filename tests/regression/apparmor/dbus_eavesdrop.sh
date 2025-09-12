#! /bin/bash
#	Copyright (C) 2013 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME dbus_eavesdrop
#=DESCRIPTION
# This test verifies that dbus eavesdropping is restricted for confined
# processes.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"
. "$bin/net_supports.inc"
requires_kernel_features dbus
requires_parser_support "dbus,"

#with v9 af_unix mediation, dbus is present but always allow unless
#policy encodes unix support. So check that unix rules are supported
requires supports_unix_rules

. "$bin/dbus.inc"

args="--session"

settest dbus_eavesdrop

run_tests()
{
	# Make sure we can eavesdrop unconfined

	runchecktest "eavesdrop (unconfined)" pass $args

	# Make sure we get denials when confined but not allowed

	gendbusprofile
	runchecktest "eavesdrop (confined w/o dbus perms)" fail $args

	gendbusprofile "dbus send,"
	runchecktest "eavesdrop (confined w/ only send allowed)" fail $args

	gendbusprofile "dbus eavesdrop,"
	runchecktest "eavesdrop (confined w/ only eavesdrop allowed)" fail $args

	# Make sure we're okay when confined with appropriate permissions

	if [ "$(parser_supports 'all,')" = "true" ]; then
		gendbusprofile "all,"
		runchecktest "eavesdrop (allow all)" pass $args
	fi

	gendbusprofile "dbus,"
	runchecktest "eavesdrop (dbus allowed)" pass $args

	gendbusprofile "dbus (send eavesdrop),"
	runchecktest "eavesdrop (send, eavesdrop allowed)" pass $args

	gendbusprofile "dbus (send eavesdrop) bus=session,"
	runchecktest "eavesdrop (send, eavesdrop allowed w/ bus conditional)" pass $args

	gendbusprofile "dbus send bus=session path=/org/freedesktop/DBus \
			interface=org.freedesktop.DBus \
			member=Hello, \
		dbus send bus=session path=/org/freedesktop/DBus \
			interface=org.freedesktop.DBus \
			member=AddMatch, \
		dbus eavesdrop bus=session,"
	runchecktest "eavesdrop (send, eavesdrop allowed w/ bus and send member conditionals)" pass $args

	gendbusprofile "dbus send, \
		audit dbus eavesdrop,"
	runchecktest "eavesdrop (send allowed, eavesdrop audited)" pass $args

	# Make sure we're denied when confined without appropriate conditionals

	gendbusprofile "dbus send bus=session, \
		dbus eavesdrop bus=system,"
	runchecktest "eavesdrop (wrong bus)" fail $args

	gendbusprofile "dbus send, \
		deny dbus eavesdrop,"
	runchecktest "eavesdrop (send allowed, eavesdrop denied)" fail $args

	# don't forget to remove the profile so the test can run again
	removeprofile
}

if start_dbus_daemon
then
	run_tests
	kill_dbus_daemon
else
	echo "Starting DBus Daemon failed. Skipping tests..."
fi

# Eavesdropping is deprecated in DBus Broker
# from https://github.com/bus1/dbus-broker/wiki/Deviations
#
# "The concept of eavesdropping has been deprecated in favor of
# monitoring upstream ... For the time being eavesdropping is not
# implemented in dbus-broker."
#
# TODO: add tests for the "BecomeMonitor" method
echo "DBus Broker does not support eavesdrop. Skipping tests..."
