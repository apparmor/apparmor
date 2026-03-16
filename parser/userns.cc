/*
 *   Copyright (c) 2022
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
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include "parser.h"
#include "profile.h"
#include "userns.h"

#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>

void userns_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		/* for now allow only '=' */
		if (cond_ent->comp != cond_comp::EQ)
			yyerror("only \"=\" allowed in conditions of userns rules\n");

		/* no valid conditionals atm */
		yyerror("invalid userns rule conditional \"%s\"\n",
			cond_ent->name);
	}
}

userns_rule::userns_rule(perm32_t perms_p, struct cond_entry *conds):
	perms_rule_t(AA_CLASS_NS)
{
	if (perms_p) {
		if (perms_p & ~AA_VALID_USERNS_PERMS)
			yyerror("perms contains invalid permissions for userns\n");
		perms = perms_p;

	} else {
		/* default to all perms */
		perms = AA_VALID_USERNS_PERMS;
	}

	move_conditionals(conds);
	free_cond_list(conds);
}

ostream &userns_rule::dump(ostream &os)
{
	class_rule_t::dump(os);

	if (perms != AA_VALID_USERNS_PERMS) {
		if (perms & AA_USERNS_CREATE)
			os << " create";
	}

	os << ",\n";

	return os;
}


int userns_rule::expand_variables(void)
{
	return 0;
}

void userns_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "userns rules not enforced");
}

int userns_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer;
	std::string buf;

	if (!features_supports_userns) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}

	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_NS;
	buf = buffer.str();
	if (perms & AA_VALID_USERNS_PERMS) {
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					rule_mode, perms,
					audit == AUDIT_FORCE ? perms : 0,
					parseopts))

			goto fail;
		/* add a mediates_userns rule for every rule added. It
		 * needs to be the same priority
		 */
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					RULE_ALLOW, AA_MAY_READ, 0,
					parseopts))
			goto fail;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}
