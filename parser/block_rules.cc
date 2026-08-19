/*
 *   Copyright (c) 2026
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

#include "block_rules.h"
#include "profile.h"

#include <algorithm>

void block_rules::add_entry(struct cod_entry *entry)
{
	entry->next = entries;
	entries = entry;
	if (entry->rule_mode == rule_mode_t::PROMPT)
		uses_prompt_rules = true;
}

void block_rules::add_rule(rule_t *entry)
{
	rule_ents.push_back(entry);
	if (entry->uses_prompt())
		uses_prompt_rules = true;
}

void block_rules::add_rlimit(const char *id, const char *in_value, const char *unit)
{
	rlim_t value = RLIM_INFINITY;
	long long tmp;
	char *end;

	int limit = get_rlimit(id);
	if (limit == -1)
		yyerror("INVALID RLIMIT '%s'\n", id);

	if (strcmp(in_value, "infinity") == 0) {
		value = RLIM_INFINITY;
	} else {
		const char *kb = "KB";
		const char *mb = "MB";
		const char *gb = "GB";

		tmp = strtoll(in_value, &end, 0);
		switch (limit) {
		case RLIMIT_CPU:
			if (!end || in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s\n", id, in_value);
			tmp = convert_time_units(tmp, SECONDS_P_MS, unit);
			if (tmp == -1LL)
				yyerror("RLIMIT '%s %s' < minimum value of 1s\n", id, in_value);
			else if (tmp < 0LL)
				yyerror("RLIMIT '%s' invalid value %s\n", id, in_value);
			if (!unit)
				pwarn(WARN_MISSING, _("RLIMIT 'cpu' no units specified using default units of seconds\n"));
			value = tmp;
			break;
#ifdef RLIMIT_RTTIME
		case RLIMIT_RTTIME:
			/* RTTIME is measured in microseconds */
			if (!end || in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			tmp = convert_time_units(tmp, 1LL, unit);
			if (tmp < 0LL)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (!unit)
				pwarn(WARN_MISSING, _("RLIMIT 'rttime' no units specified using default units of microseconds\n"));
			value = tmp;
			break;
#endif
		case RLIMIT_NOFILE:
		case RLIMIT_NPROC:
		case RLIMIT_LOCKS:
		case RLIMIT_SIGPENDING:
#ifdef RLIMIT_RTPRIO
		case RLIMIT_RTPRIO:
#endif
			if (!end || in_value == end || unit || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			value = tmp;
			break;
#ifdef RLIMIT_NICE
		case RLIMIT_NICE:
			if (!end || in_value == end || unit)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (tmp < -20 || tmp > 19)
				yyerror("RLIMIT '%s' out of range (-20 .. 19) %lld\n", id, tmp);
			value = tmp + 20;
			break;
#endif
		case RLIMIT_FSIZE:
		case RLIMIT_DATA:
		case RLIMIT_STACK:
		case RLIMIT_CORE:
		case RLIMIT_RSS:
		case RLIMIT_AS:
		case RLIMIT_MEMLOCK:
		case RLIMIT_MSGQUEUE:
			if (in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (!unit) {
				; /* use default of bytes */
			} else if (strstr(kb, unit) == kb) {
				tmp *= 1024;
			} else if (strstr(mb, unit) == mb) {
				tmp *= 1024*1024;
			} else if (strstr(gb, unit) == gb) {
				tmp *= 1024*1024*1024;
			} else {
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit);
			}
			value = tmp;
			break;
		default:
			yyerror("Unknown RLIMIT %s\n", id);
		}
	}
	rlimits.specified |= 1 << limit;
	rlimits.limits[limit] = value;
}

void block_rules::add_capabilities(struct prefixes prefix, uint64_t cap)
{
	/* priority is not supported on capability rules but this is
	 * currently not enforced */
	// if (prefix.priority != 0)
	// 	yyerror(_("priority prefix not allowed on capability rules"));

	if (prefix.owner != owner_t::UNSPECIFIED)
		yyerror(_("owner conditional not allowed on capability rules"));

	if (prefix.rule_mode == rule_mode_t::DENY && prefix.audit == audit_t::FORCE) {
		caps.deny |= cap;
	} else if (prefix.rule_mode == rule_mode_t::DENY) {
		caps.deny |= cap;
		caps.quiet |= cap;
	} else {
		caps.allow |= cap;
		if (prefix.audit != audit_t::UNSPECIFIED)
			caps.audit |= cap;
	}

}

void block_rules::add_compat_net(const network_rule *entry)
{
	/* there is no need to generate compat_net since rules are
	 * already stored in policydb */
	if (features_supports_network_policydb)
		return;

	if (entry->allow) {
		size_t i;
		if (!net.alloc_net_table())
			yyerror(_("Memory allocation error."));
		for (i = 0; i < get_af_max(); i++) {
			net.allow[i] |= entry->allow[i];
			net.audit[i] |= entry->audit[i];
			net.deny[i] |= entry->deny[i];
			net.quiet[i] |= entry->quiet[i];
		}
	}

}

void block_rules::merge_compat_rules(const block_rules *b)
{
	if (!b)
		return;

	caps.allow |= b->caps.allow;
	caps.audit |= b->caps.audit;
	caps.deny |= b->caps.deny;
	caps.quiet |= b->caps.quiet;

	if (rlimits.specified & b->rlimits.specified) {
		PERROR(_("Cannot merge rlimits, more than one value specified for a single rlimit\n"));
		exit(1);
	}
	rlimits.specified |= b->rlimits.specified;
	for (int i = 0; i <  RLIMIT_NLIMITS; i++) {
		if (b->rlimits.limits[i])
			rlimits.limits[i] = b->rlimits.limits[i];
	}

	/* add already does merge due to the nature of compat_net */
	add_compat_net(&(b->net));
	uses_prompt_rules = uses_prompt_rules || b->uses_prompt_rules;
}

void block_rules::merge_block_rules(block_rules *b)
{
	struct cod_entry *last;
	if (!b)
		return;

	if (entries) {
		list_last_entry(entries, last);
		last->next = b->entries;
	} else {
		entries = b->entries;
	}
	b->entries = NULL;

	for (rule_t *rule : b->rule_ents) {
		rule_ents.push_back(rule);
	}
	b->rule_ents.clear();

	bool is_empty = std::all_of(exec_table, exec_table + AA_EXEC_COUNT,
				    [](char* ptr) { return ptr == NULL; });
	if (!is_empty) {
		PERROR("Invalid condition, exec_table should be empty");
		exit(1);
	}
	for (int i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++)
		exec_table[i] = b->exec_table[i];

	merge_compat_rules(b);
}

static int strrcmp(const char *a, int ta,
		   const char *b, int tb)
{
	while (ta >= 0 && tb >= 0) {
		int res = (int) a[ta--] - (int) b[tb--];
		if (res)
			return res;
	}
	if (ta < tb)
		return -1;
	if (ta > tb)
		return 1;
	return 0;
}

static int file_comp(const void *c1, const void *c2)
{
	struct cod_entry **e1, **e2;
	e1 = (struct cod_entry **)c1;
	e2 = (struct cod_entry **)c2;
	int res = 0;

	if ((*e1)->link_name) {
		if ((*e2)->link_name)
			res = strrcmp((*e1)->link_name, (*e1)->llen,
				      (*e2)->link_name, (*e2)->llen);
		else
			return 1;
	} else if ((*e2)->link_name) {
		return -1;
	}
	if (res)
		return res;

	if ((*e1)->link_name)
		res = ((int) (*e2)->subset) - ((int) (*e1)->subset);
	if (res)
		return res;

	if ((*e1)->rule_mode != (*e2)->rule_mode)
		return (*e1)->rule_mode < (*e2)->rule_mode ? -1 : 1;

	if ((*e1)->audit != (*e2)->audit)
		return (*e1)->audit < (*e2)->audit ? -1 : 1;

	if ((*e1)->priority != (*e2)->priority)
		return (*e2)->priority - (*e1)->priority;

	return strrcmp((*e1)->name, (*e1)->len,
		       (*e2)->name, (*e2)->len);
}

int block_rules::merge_file(const char *profname)
{
	struct cod_entry *cur, *next;
	struct cod_entry **table;
	int n, count = 0;

	for (cur = entries; cur; cur = cur->next)
		count++;

	if (count < 2)
		return 0;

	table = (struct cod_entry **) malloc(sizeof(struct cod_entry *) * (count + 1));
	if (!table) {
		PERROR(_("Couldn't merge entries. Out of Memory\n"));
		return -ENOMEM;
	}

	for (cur = entries, n = 0; cur; cur = cur->next, n++) {
		table[n] = cur;
		cur->len = strlen(cur->name);
		cur->llen = cur->link_name ? strlen(cur->link_name) : 0;
	}
	qsort(table, count, sizeof(struct cod_entry *), file_comp);
	table[count] = NULL;
	for (n = 0; n < count; n++)
		table[n]->next = table[n + 1];
	entries = table[0];
	free(table);

	count = 0;
	/* walk the sorted table merging similar entries */
	for (cur = entries, next = cur->next; next; next = cur->next) {
		if (file_comp(&cur, &next) != 0) {
			cur = next;
			continue;
		}

		/* check for merged x consistency */
		if (!is_merged_x_consistent(cur->perms, next->perms)) {
			PERROR(_("profile %s: has merged rule %s with conflicting x modifiers\n"),
                               profname, cur->name);
			return -1;
		}
		cur->perms |= next->perms;
		cur->next = next->next;

		next->next = NULL;
		free_cod_entries(next);
		count++;
	}

	return count;
}

static bool comp(rule_t *lhs, rule_t *rhs)
{
	return (*lhs < *rhs);
}

int block_rules::merge_rule_t(void)
{
	int count = 0;
	std::vector<rule_t *> table;

	for (rule_t *rule : rule_ents) {
		if (rule->is_mergeable() && !rule->skip())
			table.push_back(rule);
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

int block_rules::merge_duplicated_rules(const char *profname)
{
	int file, rule;

	if (!(parseopts.control & CONTROL_RULE_MERGE))
		return 0;

	file = merge_file(profname);
	if (file < 0)
		return file;

	rule = merge_rule_t();
	if (rule < 0)
		return rule;

	if (parseopts.dump & DUMP_RULE_MERGE)
		fprintf(stderr, "RULE MERGE: deleted %d file rules, %d rules\n", file, rule);

	return file + rule;
}

int block_rules::process_variables(void)
{
	int error;
	struct cod_entry *entry;

	list_for_each(entries, entry) {
		error = expand_entry_variables(&entry->name);
		if (error)
			return error;
		if (entry->link_name) {
			error = expand_entry_variables(&entry->link_name);
			if (error)
				return error;
		}
	}

	for (rule_t *rule : rule_ents) {
		if (rule->skip())
			continue;
		error = rule->expand_variables();
		if (error)
			return error;
	}

	return 0;
}

process_result_t block_rules::post_process(Profile *prof)
{
	struct cod_entry *entry;

	list_for_each(entries, entry) {
		if (!process_dfa_entry(prof->dfa.rules, entry))
			return process_result_t::REGEX_ERR;
	}

	for (rule_t *rule : rule_ents) {
		if (rule->skip())
			continue;
		if (rule->gen_policy_re(*prof) == rule_result_t::ERROR)
			return process_result_t::POLICYDB_ERR;
	}

	return process_result_t::SUCCESS;
}

int block_rules::post_parse_profile(Profile *prof)
{
	for (rule_t *rule : rule_ents) {
		if (rule->skip())
			continue;
		rule->post_parse_profile(*prof);
	}
	return post_parse_profile_file(prof);
}

void block_rules::add_implied_rules(Profile *prof)
{
	for (rule_t *rule : rule_ents) {
		if (rule->skip())
			continue;
		rule->add_implied_rules(*prof);
	}
}

int block_rules::add_entry_to_x_table(char *name)
{
	for (int i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++) {
		if (!exec_table[i]) {
			exec_table[i] = name;
			return i;
		} else if (strcmp(exec_table[i], name) == 0) {
			/* name already in table */
			free(name);
			return i;
		}
	}
	free(name);
	return 0;
}

int block_rules::add_named_transition(Profile *prof, struct cod_entry *entry)
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

	return prof->main_block->rules.add_entry_to_x_table(name);
}

bool block_rules::add_proc_access(const char *rule)
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
	add_entry(new_ent);

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
	add_entry(new_ent);

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
	add_entry(new_ent);

	return true;
}

int block_rules::post_parse_profile_file(Profile *prof)
{
	struct cod_entry *entry;
	perm32_t cp_perms = 0;

	list_for_each(entries, entry) {
		if (entry->nt_name) {
			perm32_t perms = 0;
			int n = add_named_transition(prof, entry);
			if (!n) {
				PERROR("Profile %s has too many specified profile transitions.\n", prof->name);
				return -1;
			}
			/* n is bounded by AA_EXEC_COUNT (currently 16)
			 * and that the shifts will therefore never overflow */
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
		if (!prof->main_block->rules.add_proc_access(CHANGEPROFILE_PATH))
			return -1;
	}
	return 0;
}

bool block_rules::add_prefix(const prefixes &p, const char *&error)
{

	struct cod_entry *entry;

	if (p.rule_mode == rule_mode_t::PROMPT)
		uses_prompt_rules = true;

	list_for_each(entries, entry) {
		if (!entry_add_prefix(entry, p, error))
			return false;
	}

	for (rule_t *r : rule_ents) {
		prefix_rule_t *rule = (prefix_rule_t *)r;
		if (!rule->add_prefix(p, error))
			return false;
	}

	net.apply_compat_prefix(p);

	if (!caps.add_prefix(p, error))
		return false;

	if (!rlimits.add_prefix(p, error))
		return false;

	return true;
}

block_rules::block_rules(const block_rules &p)
{
	struct cod_entry *entry, **list;

	entries = NULL;
	std::fill(exec_table, exec_table + AA_EXEC_COUNT, (char *)NULL);

	for (int i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++)
		if (p.exec_table[i])
			exec_table[i] = strdup(p.exec_table[i]);

	if (entries) {
		list_last_entry(entries, entry);
		list = &(entry->next);
	} else {
		list = &entries;
	}

	list_for_each(p.entries, entry) {
		struct cod_entry *copy = copy_cod_entry(entry);
		copy->next = NULL;
		*list = copy;
		list = &(copy->next);
	}

	for (rule_t *r : p.rule_ents) {
		add_rule(r->clone());
	}

	rlimits = p.rlimits;
	caps = p.caps;
	add_compat_net(&(p.net));
	uses_prompt_rules = p.uses_prompt_rules;
}
