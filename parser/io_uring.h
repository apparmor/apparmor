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

#ifndef __AA_IO_URING_H
#define __AA_IO_URING_H

#include "parser.h"

#define AA_IO_URING_OVERRIDE_CREDS AA_MAY_APPEND
#define AA_IO_URING_SQPOLL AA_MAY_CREATE

#define AA_VALID_IO_URING_PERMS (AA_IO_URING_OVERRIDE_CREDS | \
				 AA_IO_URING_SQPOLL)

class io_uring_rule: public perms_rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	char *label;

	io_uring_rule(perm32_t perms, struct cond_entry *conds, struct cond_entry *ring_conds);
	~io_uring_rule() override
	{
		free(label);
	};

	bool valid_prefix(const prefixes &p, const char *&error) override {
		if (p.owner != owner_t::UNSPECIFIED) {
			error = _("owner prefix not allowed on io_uring rules");
			return false;
		}
		return true;
	};

	ostream &dump(ostream &os) override;
	int expand_variables(void) override;
	rule_result_t gen_policy_re(Profile &prof) override;

	bool is_mergeable(void) override { return true; }
	int cmp(rule_t const &rhs) const override
	{
		int res = perms_rule_t::cmp(rhs);
		if (res)
			return res;
		return null_strcmp(label,
			       (rule_cast<io_uring_rule const &>(rhs)).label);
	};

protected:
	void warn_once(const char *name) override;
};

#endif /* __AA_IO_URING_H */
