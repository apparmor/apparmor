/*
 *   Copyright (c) 2014
 *   Canonical Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */
#include "rule.h"
#include "parser.h"
#include <iostream>

const char *aa_class_table[] = {
	"nullcond",
	"unknown",
	"file",
	"capability",
	"network",
	"rlimit",
	"domain",
	"mount",
	"ns_domain",
	"ptrace",
	"signal",
	"xmatch",
	"env",
	"argv",
	"network",
	"network_v9",
	"label",
	"mqueue",
	"mqueue",
	"module",
	"display_lsm",
	"userns",
	"io_uring",
	"unknown23",
	"unknown24",
	"unknown25",
	"unknown26",
	"unknown27",
	"unknown28",
	"unknown29",
	"unknown30",
	"X",
	"dbus",
	NULL
};

std::ostream &operator<<(std::ostream &os, rule_t &rule)
{
	return rule.dump(os);
};

/* do we want to warn once/profile or just once per compile?? */
void rule_t::warn_once(const char *name, const char *msg)
{
    common_warn_once(name, msg, &warned_name);
}
