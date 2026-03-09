/*
 *   Copyright (c) 2022
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
#ifndef __AA_USERNS_H
#define __AA_USERNS_H

#include "parser.h"

#define AA_USERNS_CREATE	8
#define AA_VALID_USERNS_PERMS (AA_USERNS_CREATE)

class userns_rule: public perms_rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	userns_rule(perm32_t perms, struct cond_entry *conds);
	~userns_rule() override
	{
	};

	bool valid_prefix(const prefixes &p, const char *&error) override {
		if (p.owner) {
			error = _("owner prefix not allowed on userns rules");
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
		return perms_rule_t::cmp(rhs);
	};
	/* merge perms not required atm since there's only one permission */

protected:
	void warn_once(const char *name) override;
};

#endif /* __AA_USERNS_H */
