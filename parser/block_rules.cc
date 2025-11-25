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

void block_rules::merge_block_rules(block_rules *b)
{
	if (!b)
		return;

	caps.allow |= b->caps.allow;
	caps.audit |= b->caps.audit;
	caps.deny |= b->caps.deny;
	caps.quiet |= b->caps.quiet;
}
