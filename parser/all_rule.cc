/*
 *   Copyright (c) 2023
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
 *   along with this program; if not, contact Canonical Ltd.
 */

#include "profile.h"
#include "all_rule.h"
#include "af_unix.h"
#include "dbus.h"
#include "io_uring.h"
#include "mqueue.h"
#include "ptrace.h"
#include "signal.h"
#include "userns.h"
#include "mount.h"
#include "parser.h"

#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>



void all_rule::add_implied_rules(Profile &prof)
{
	prefix_rule_t *rule;
	const prefixes *prefix = this;

	rule = new unix_rule(0xffffffff, audit, rule_mode);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new dbus_rule(0, NULL, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new io_uring_rule(0, NULL, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new mqueue_rule(0, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new ptrace_rule(0, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new signal_rule(0, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new userns_rule(0, NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new mnt_rule(NULL, NULL, NULL, NULL, AA_MAY_MOUNT);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new mnt_rule(NULL, NULL, NULL, NULL, AA_DUMMY_REMOUNT);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new mnt_rule(NULL, NULL, NULL, NULL, AA_MAY_UMOUNT);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new mnt_rule(NULL, NULL, NULL, NULL, AA_MAY_PIVOTROOT);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);

	rule = new network_rule(0, (struct cond_entry *)NULL, (struct cond_entry *)NULL);
	(void) rule->add_prefix(*prefix);
	prof.rule_ents.push_back(rule);
	
	/* rules that have not been converted to use rule.h */

	//file no x
	{
		const char *error;
		struct cod_entry *entry;
		char *path = strdup("/{**,}");
		int perms = (AA_BASE_PERMS & ~(AA_EXEC_TYPE | AA_MAY_EXEC));
		if (rule_mode != RULE_DENY)
		/* duplicate to other permission set */
		perms |= perms << AA_OTHER_SHIFT;
		if (!path)
			yyerror(_("Memory allocation error."));
		entry = new_entry(path, perms, NULL);
		if (!entry) {
			yyerror(_("Memory allocation error."));
		}
		if (!entry_add_prefix(entry, *prefix, error)) {
			yyerror(_("%s"), error);
		}
		add_entry_to_policy(&prof, entry);
	}
	// lower priority ix
	{
		const char *error;
		struct cod_entry *entry;
		char *path = strdup("/{**,}");
		int perms = AA_MAY_EXEC;
		prefixes ix_prefix;

		// TODO:
		// need a better way to make sure the prefix is intialized
		// without a constructor or copy constructor
		ix_prefix.priority = prefix->priority -1;
		ix_prefix.audit = prefix->audit;
		ix_prefix.rule_mode = prefix->rule_mode;
		ix_prefix.owner = prefix->owner;

		ix_prefix.priority -= 1;
		if (rule_mode != RULE_DENY)
			perms |= AA_EXEC_INHERIT;
		/* duplicate to other permission set */
		perms |= perms << AA_OTHER_SHIFT;
		if (!path)
			yyerror(_("Memory allocation error."));
		entry = new_entry(path, perms, NULL);
		if (!entry) {
			yyerror(_("Memory allocation error."));
		}
		if (!entry_add_prefix(entry, ix_prefix, error)) {
			yyerror(_("%s"), error);
		}
		add_entry_to_policy(&prof, entry);
	}
	// caps
	{
		if (prefix->owner)
			yyerror(_("owner prefix not allowed on capability rules"));

		if (rule_mode == RULE_DENY && audit == AUDIT_FORCE) {
			prof.caps.deny |= 0xffffffffffffffff;
		} else if (rule_mode == RULE_DENY) {
			prof.caps.deny |= 0xffffffffffffffff;
			prof.caps.quiet |= 0xffffffffffffffff;
		} else {
			prof.caps.allow |= 0xffffffffffffffff;
			if (audit != AUDIT_UNSPECIFIED)
				prof.caps.audit |= 0xffffffffffffffff;
		}
	}
	
	// TODO: rlimit
}
