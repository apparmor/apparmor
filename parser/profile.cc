/*
 *   Copyright (c) 2012, 2013
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#include "libapparmor_re/aare_rules.h"
#include "profile.h"
#include "rule.h"
#include "parser.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>
#include <algorithm>

using namespace std;

const char *profile_mode_table[] = {
	"",
	"enforce",
	"complain",
	"kill",
	"unconfined",
	"prompt",
	"default_allow",
	"conflict"		/* should not ever be displayed */
};

Profile::~Profile()
{
	hat_table.clear();
	flags.clear();
	free_cond_entry_list(xattrs);

	if (dfa.rules)
		delete dfa.rules;
	if (dfa.dfa)
		free(dfa.dfa);
	if (policy.rules)
		delete policy.rules;
	if (policy.dfa)
		free(policy.dfa);
	if (xmatch)
		free(xmatch);
	if (name)
		free(name);
	if (attachment)
		free(attachment);
	if (identities)
		free_value_list(identities);
	if (ns)
		free(ns);
	if (rules)
		delete rules;
}

// TODO: move to block rule
// returns number of rules merged
// returns negative number on error
int Profile::merge_rules(void)
{
	return rules->merge_duplicated_rules(name);
}

/* add file rules to access /proc files to call change_hat()
 */
static int profile_add_hat_rules(Profile *prof)
{
	/* don't add hat rules if not hat or profile doesn't have hats */
	if (!has_profile_flag(prof->flags.flags, profile_flag_t::HAT) &&
	    prof->hat_table.empty())
		return 0;

	if (!prof->rules->add_proc_access(CHANGEHAT_PATH))
		return ENOMEM;

	return 0;
}

void Profile::post_parse_profile(void)
{
	/* semantic check stuff that can't be done in parse, like flags */
	if (has_profile_flag(flags.flags, profile_flag_t::INTERRUPTIBLE)) {
		if (!features_supports_flag_interruptible) {
			warn_once(name, "flag interruptible not supported. Ignoring");
			/* TODO: don't clear in parse data, only at encode */
			flags.flags &= ~profile_flag_t::INTERRUPTIBLE;
		}
	}
	if (flags.signal) {
		if (!features_supports_flag_signal) {
			warn_once(name, "kill.signal not supported. Ignoring");
		}
	}
	if (flags.error) {
		if (!features_supports_flag_error) {
			warn_once(name, "error flag not supported. Ignoring");
		}
	}
	rules->post_parse_profile(this);
}

void Profile::add_implied_rules(void)
{
	int error;

	rules->add_implied_rules(this);

	error = profile_add_hat_rules(this);
	if (error) {
		PERROR(_("ERROR adding hat access rule for profile %s\n"),
		       name);
		//return error;
	}

}

/* do we want to warn once/profile or just once per compile?? */
void Profile::warn_once(const char *name, const char *msg)
{
	common_warn_once(name, msg, &warned_name);
}
