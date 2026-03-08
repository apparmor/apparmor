/*
 *   Copyright (c) 2014
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
#include "ptrace.h"

#include <iomanip>
#include <string>
#include <sstream>

int parse_ptrace_perms(const char *str_perms, perm32_t *perms, int fail)
{
	return parse_X_perms("ptrace", AA_VALID_PTRACE_PERMS, str_perms, perms, fail);
}

void ptrace_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		/* for now disallow keyword 'in' (list) */
		if (!cond_ent->eq)
			yyerror("keyword \"in\" is not allowed in ptrace rules\n");

		if (strcmp(cond_ent->name, "peer") == 0) {
			move_conditional_value("ptrace", &peer_label, cond_ent);
		} else {
			yyerror("invalid ptrace rule conditional \"%s\"\n",
				cond_ent->name);
		}
	}
}

ptrace_rule::ptrace_rule(perm32_t perms_p, struct cond_entry *conds):
	perms_rule_t(AA_CLASS_PTRACE), peer_label(NULL)
{
	if (perms_p) {
		if (perms_p & ~AA_VALID_PTRACE_PERMS)
			yyerror("perms contains invalid permissions for ptrace\n");
		perms = perms_p;
	} else {
		perms = AA_VALID_PTRACE_PERMS;
	}

	move_conditionals(conds);
	free_cond_list(conds);
}

static void format_ptrace_perms(ostream &os, perm32_t perms)
{
	if (perms & AA_MAY_READ)
		os << "read ";
	if (perms & AA_MAY_READBY)
		os << "readby ";
	if (perms & AA_MAY_TRACE)
		os << "trace ";
	if (perms & AA_MAY_TRACEDBY)
		os << "tracedby ";
}

ostream &ptrace_rule::dump(ostream &os)
{
	class_rule_t::dump(os);

	/* override default perm dump */
	if (perms != AA_VALID_PTRACE_PERMS) {
		os << " (";
		format_ptrace_perms(os, perms);
		os << " )";
	}

	if (peer_label)
		os << " " << peer_label;

	/* Show merge information if rule was merged */
	if (saved && saved != perms) {
		os << " /* merged from: ( ";
		format_ptrace_perms(os, saved);
		os << " ) */";
	}

	os << ",\n";

	return os;
}


int ptrace_rule::expand_variables(void)
{
	return expand_entry_variables(&peer_label);
}

void ptrace_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "ptrace rules not enforced");
}

int ptrace_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer;
	std::string buf;

	pattern_t ptype;
	int pos;

	/* ?? do we want to generate the rules in the policy so that it
	 * the compile could be used on another kernel unchanged??
	 * Current caching doesn't support this but in the future maybe
	 */
	if (!features_supports_ptrace) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}

	/* always generate a label and ptrace entry */
	buffer << "(" << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_LABEL << "|)";

	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_PTRACE;

	if (peer_label) {
		ptype = convert_aaregex_to_pcre(peer_label, 0, glob_default, buf, &pos);
		if (ptype == pattern_t::Invalid)
			goto fail;
		buffer << buf;
	} else {
		buffer << anyone_match_pattern;
	}

	buf = buffer.str();
	if (perms & AA_VALID_PTRACE_PERMS) {
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					rule_mode, perms,
					audit == AUDIT_FORCE ? perms : 0,
					parseopts))
			goto fail;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}

