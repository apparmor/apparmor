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

#ifndef __AA_BLOCK_RULES_H
#define __AA_BLOCK_RULES_H

#include "parser.h"
#include "capability.h"
#include "rule.h"

struct capabilities {
	uint64_t allow;
	uint64_t audit;
	uint64_t deny;
	uint64_t quiet;

	capabilities(void) { allow = audit = deny = quiet = 0; }

	void dump()
	{
		if (allow != 0ull)
			__debug_capabilities(allow, "Capabilities");
		if (audit != 0ull)
			__debug_capabilities(audit, "Audit Caps");
		if (deny != 0ull)
			__debug_capabilities(deny, "Deny Caps");
		if (quiet != 0ull)
			__debug_capabilities(quiet, "Quiet Caps");
	};

	bool add_prefix(const prefixes &p, const char *&error)
	{
		/* nothing to do if there are no capability rules */
		if ((allow | audit | deny | quiet) == 0)
			return true;

		/* priority is not supported on capability rules but
		 * this is currently not enforced */
		// if (p.priority != 0) {
		// 	error = _("priority prefix not allowed on capability rules");
		// 	return false;
		// }

		if (p.owner != owner_t::UNSPECIFIED) {
			error = _("owner prefix not allowed on capability rules");
			return false;
		}

		if (p.rule_mode == rule_mode_t::UNSPECIFIED &&
		    p.audit == audit_t::UNSPECIFIED)
			return true;

		/* decompose current state into the four mutually exclusive
		 * per-capability groups */
		uint64_t allow_noaudit = allow & ~audit & ~deny;
		uint64_t allow_audit = allow & audit & ~deny;
		uint64_t deny_quiet = deny & quiet;	/* plain deny */
		uint64_t deny_audit = deny & ~quiet;	/* audit deny */

		allow = audit = deny = quiet = 0;

		if (p.rule_mode == rule_mode_t::DENY) {
			/* deny wins: all capabilities become denied. A
			 * capability is audited (no quiet) if it was already
			 * audited or the prefix forces audit; otherwise the
			 * denial is quieted. */
			deny = allow_noaudit | allow_audit | deny_quiet | deny_audit;
			uint64_t audited = allow_audit | deny_audit;
			if (p.audit == audit_t::FORCE)
				audited |= (allow_noaudit | deny_quiet);
			quiet = (allow_noaudit | deny_quiet) & ~audited;
		} else {
			/* allow/audit prefix: allowed capabilities keep being
			 * allowed, denied capabilities stay denied. The audit
			 * prefix adds auditing to allows and converts quiet
			 * denials into audited denials. */
			allow = allow_noaudit | allow_audit;
			deny = deny_quiet | deny_audit;
			if (p.audit == audit_t::FORCE) {
				audit = allow;
				/* audited denials are no longer quieted */
				quiet = 0;
			} else {
				audit = allow_audit;
				quiet = deny_quiet;
			}

		}
		return true;
	}

};

class block_rules {
public:
	struct aa_rlimits rlimits;
	struct capabilities caps;
	RuleList rule_ents;

	block_rules(void): rlimits({0, {}})
	{
	}

	~block_rules(void)
	{
		for (rule_t *rule : rule_ents) {
			delete rule;
		}
	}

	ostream &dump(ostream &os) {
		// TODO add rlimit dump
		caps.dump();

		for (rule_t *rule : rule_ents) {
			rule->dump(os);
		}

		return os;
	}

	void add_rule(rule_t *entry);
	void add_rlimit(const char *id, const char *in_value, const char *unit);
	void add_capabilities(struct prefixes prefix, uint64_t cap);
	void merge_block_rules(block_rules *b);
	int merge_duplicated_rules(void);
	int process_variables(void);
	bool post_process(Profile *prof);
	void post_parse_profile(Profile *prof);
	void add_implied_rules(Profile *prof);
private:
	int merge_rule_t(void);
};

#endif /* __AA_BLOCK_RULES_H */
