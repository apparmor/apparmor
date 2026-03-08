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

#ifndef __AA_ALL_H
#define __AA_ALL_H

#include "rule.h"

#include <libintl.h>

#ifndef _
#define _(s) gettext(s)
#endif

#ifndef aa_unused
#define aa_unused __attribute__ ((unused))
#endif

#define AA_IO_URING_OVERRIDE_CREDS AA_MAY_APPEND
#define AA_IO_URING_SQPOLL AA_MAY_CREATE

#define AA_VALID_IO_URING_PERMS (AA_IO_URING_OVERRIDE_CREDS | \
				 AA_IO_URING_SQPOLL)

class all_rule: public prefix_rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	all_rule(void): prefix_rule_t(RULE_TYPE_ALL) { }

	bool valid_prefix(const prefixes &p, const char *&error) override {
		if (p.priority != 0) {
			error = _("priority prefix not allowed on all rules");
			return false;
		}
		if (p.owner) {
			error = _("owner prefix not allowed on all rules");
			return false;
		}
		return true;
	};

	int expand_variables(void) override
	{
		return 0;
	}
	ostream &dump(ostream &os) override {
		prefix_rule_t::dump(os);

		os << "all";

		return os;
	}
	bool is_mergeable(void) override { return true; }
	int cmp(rule_t const &rhs) const override
	{
		return prefix_rule_t::cmp(rhs);
	};

	void add_implied_rules(Profile &prof) override;

	rule_result_t gen_policy_re(Profile &prof aa_unused) override { return rule_result_t::OK; };

protected:
  void warn_once(const char *name aa_unused, const char *msg aa_unused) override { };
  void warn_once(const char *name aa_unused) override  { };
};

#endif /* __AA_ALL_H */
