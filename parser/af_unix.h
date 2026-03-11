/*
 *   Copyright (c) 2014
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
#ifndef __AA_AF_UNIX_H
#define __AA_AF_UNIX_H

#include "immunix.h"
#include "network.h"
#include "parser.h"
#include "profile.h"
#include "af_rule.h"

int parse_unix_perms(const char *str_mode, perm32_t *perms, int fail);

class unix_rule: public af_rule {
	void write_to_prot(std::ostringstream &buffer);
	bool write_addr(std::ostringstream &buffer, const char *addr);
	bool write_label(std::ostringstream &buffer, const char *label);
	void move_conditionals(struct cond_entry *conds);
	void move_peer_conditionals(struct cond_entry *conds);
	void downgrade_rule(Profile &prof);
public:
	char *addr;
	char *peer_addr;
	bool downgrade = true;

	unix_rule(unsigned int type_p, audit_t audit_p, rule_mode_t rule_mode_p);
	unix_rule(perm32_t perms, struct cond_entry *conds,
		  struct cond_entry *peer_conds);
	~unix_rule() override
	{
		free(addr);
		free(peer_addr);
	};

	bool valid_prefix(const prefixes &p, const char *&error) override {
		// priority is partially supported for unix rules
		// rules that get downgraded to just network socket
		// won't support them but the fine grained do.
		if (p.owner != owner_t::UNSPECIFIED) {
			error = "owner prefix not allowed on unix rules";
			return false;
		}
		return true;
	};
	bool has_peer_conds(void) override {
		return af_rule::has_peer_conds() || peer_addr;
	}

	ostream &dump_local(ostream &os) override;
	ostream &dump_peer(ostream &os) override;
	int expand_variables(void) override;
	rule_result_t gen_policy_re(Profile &prof) override;

	// inherit is_mergable() from af_rule
	int cmp(rule_t const &rhs) const override
	{
		int res = af_rule::cmp(rhs);
		if (res)
			return res;
		unix_rule const &trhs = (rule_cast<unix_rule const &>(rhs));
		res = null_strcmp(addr, trhs.addr);
		if (res)
			return res;
		return null_strcmp(peer_addr, trhs.peer_addr);
	};

protected:
	void warn_once(const char *name) override;
};

#endif /* __AA_AF_UNIX_H */
