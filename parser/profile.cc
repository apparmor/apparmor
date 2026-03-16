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

#include "profile.h"
#include "rule.h"
#include "parser.h"

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
	free_cod_entries(entries);
	free_cond_entry_list(xattrs);

	for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++)
		delete *i;
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
	for (int i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++)
		if (exec_table[i])
			free(exec_table[i]);
}

static bool comp (rule_t *lhs, rule_t *rhs)
{
	return (*lhs < *rhs);
}

// TODO: move to block rule
// returns number of rules merged
// returns negative number on error
int Profile::merge_rules(void)
{
	int count = 0;
	std::vector<rule_t *> table;

	for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++) {
		if ((*i)->is_mergeable() && !(*i)->skip())
			table.push_back(*i);
	}
	if (table.size() < 2)
		return 0;
	std::sort(table.begin(), table.end(), comp);
	unsigned long n = table.size();
	for (unsigned long i = 0, j = 1; j < n; j++) {
		if (table[j]->skip())
			continue;
		if (table[i]->cmp(*table[j]) == 0) {
			if (table[i]->merge(*table[j]))
				count++;
			continue;
		}
		i = j;
	}

	return count;
}


int add_entry_to_x_table(Profile *prof, char *name)
{
	int i;
	for (i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++) {
		if (!prof->exec_table[i]) {
			prof->exec_table[i] = name;
			return i;
		} else if (strcmp(prof->exec_table[i], name) == 0) {
			/* name already in table */
			free(name);
			return i;
		}
	}
	free(name);
	return 0;
}

void add_entry_to_policy(Profile *prof, struct cod_entry *entry)
{
	entry->next = prof->entries;
	prof->entries = entry;
	if (entry->rule_mode == rule_mode_t::PROMPT)
		prof->uses_prompt_rules = true;
}

static int add_named_transition(Profile *prof, struct cod_entry *entry)
{
	char *name = NULL;

	/* check to see if it is a local transition */
	if (!label_contains_ns(entry->nt_name)) {
		char *sub = strstr(entry->nt_name, "//");
		/* does the subprofile name match the rule */

		if (sub && strncmp(prof->name, sub, sub - entry->nt_name) &&
		    strcmp(sub + 2, entry->name) == 0) {
			free(entry->nt_name);
			entry->nt_name = NULL;
			return AA_EXEC_LOCAL >> 10;
		} else if (((entry->perms & AA_USER_EXEC_MODIFIERS) ==
			     SHIFT_PERMS(AA_EXEC_LOCAL, AA_USER_SHIFT)) ||
			    ((entry->perms & AA_OTHER_EXEC_MODIFIERS) ==
			     SHIFT_PERMS(AA_EXEC_LOCAL, AA_OTHER_SHIFT))) {
			if (strcmp(entry->nt_name, entry->name) == 0) {
				free(entry->nt_name);
				entry->nt_name = NULL;
				return AA_EXEC_LOCAL >> 10;
			}
			/* specified as cix so profile name is implicit */
			name = (char *) malloc(strlen(prof->name) + strlen(entry->nt_name)
				      + 3);
			if (!name) {
				PERROR("Memory allocation error\n");
				exit(1);
			}
			sprintf(name, "%s//%s", prof->name, entry->nt_name);
			free(entry->nt_name);
			entry->nt_name = NULL;
		} else {
			/**
			 * pass control of the memory pointed to by nt_name
			 * from entry to add_entry_to_x_table()
			 */
			name = entry->nt_name;
			entry->nt_name = NULL;
		}
	} else {
		/**
		 * pass control of the memory pointed to by nt_name
		 * from entry to add_entry_to_x_table()
		 */
		name = entry->nt_name;
		entry->nt_name = NULL;
	}

	return add_entry_to_x_table(prof, name);
}

static bool add_proc_access(Profile *prof, const char *rule)
{
		/* FIXME: should use @{PROC}/@{PID}/attr/{apparmor/,}{current,exec} */
		struct cod_entry *new_ent;
		/* allow probe for new interfaces */
		char *buffer = strdup("/proc/*/attr/apparmor/");
		if (!buffer) {
			PERROR("Memory allocation error\n");
			return false;
		}
		new_ent = new_entry(buffer, AA_MAY_READ, NULL);
		if (!new_ent) {
			free(buffer);
			PERROR("Memory allocation error\n");
			return false;
		}
		add_entry_to_policy(prof, new_ent);

		/* allow probe if apparmor is enabled for the old interface */
		buffer = strdup("/sys/module/apparmor/parameters/enabled");
		if (!buffer) {
			PERROR("Memory allocation error\n");
			return false;
		}
		new_ent = new_entry(buffer, AA_MAY_READ, NULL);
		if (!new_ent) {
			free(buffer);
			PERROR("Memory allocation error\n");
			return false;
		}
		add_entry_to_policy(prof, new_ent);

		/* allow setting on new and old interfaces */
		buffer = strdup(rule);
		if (!buffer) {
			PERROR("Memory allocation error\n");
			return false;
		}
		new_ent = new_entry(buffer, AA_MAY_WRITE, NULL);
		if (!new_ent) {
			free(buffer);
			PERROR("Memory allocation error\n");
			return false;
		}
		add_entry_to_policy(prof, new_ent);

		return true;
}

#define CHANGEPROFILE_PATH "/proc/*/attr/{apparmor/,}{current,exec}"
void post_process_file_entries(Profile *prof)
{
	struct cod_entry *entry;
	perm32_t cp_perms = 0;

	list_for_each(prof->entries, entry) {
		if (entry->nt_name) {
			perm32_t perms = 0;
			int n = add_named_transition(prof, entry);
			if (!n) {
				PERROR("Profile %s has too many specified profile transitions.\n", prof->name);
				exit(1);
			}
			if (entry->perms & AA_USER_EXEC)
				perms |= SHIFT_PERMS(n << 10, AA_USER_SHIFT);
			if (entry->perms & AA_OTHER_EXEC)
				perms |= SHIFT_PERMS(n << 10, AA_OTHER_SHIFT);
			entry->perms = ((entry->perms & ~AA_ALL_EXEC_MODIFIERS) |
				       (perms & AA_ALL_EXEC_MODIFIERS));
		}
		/* FIXME: currently change_profile also implies onexec */
		cp_perms |= entry->perms & (AA_CHANGE_PROFILE);
	}

	/* if there are change_profile rules, this implies that we need
	 * access to some /proc/ interfaces
	 */
	if (cp_perms & AA_CHANGE_PROFILE) {
		if (!add_proc_access(prof, CHANGEPROFILE_PATH))
			exit(1);
	}
}

void post_process_rule_entries(Profile *prof)
{
	for (RuleList::iterator i = prof->rule_ents.begin(); i != prof->rule_ents.end(); i++) {
		if ((*i)->skip())
			continue;
		(*i)->post_parse_profile(*prof);
  }
}


#define CHANGEHAT_PATH "/proc/[0-9]*/attr/{apparmor/,}current"

/* add file rules to access /proc files to call change_hat()
 */
static int profile_add_hat_rules(Profile *prof)
{
	/* don't add hat rules if not hat or profile doesn't have hats */
	if (!has_profile_flag(prof->flags.flags, profile_flag_t::HAT) &&
	    prof->hat_table.empty())
		return 0;

	if (!add_proc_access(prof, CHANGEHAT_PATH))
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
	post_process_file_entries(this);
	post_process_rule_entries(this);
}

void Profile::add_implied_rules(void)
{
	int error;

	for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++) {
		if ((*i)->skip())
			continue;
		(*i)->add_implied_rules(*this);
	}

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
