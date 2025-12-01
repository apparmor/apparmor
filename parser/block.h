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

#ifndef __AA_BLOCK_H
#define __AA_BLOCK_H

#include <list>
#include <ostream>

#include "parser.h"
#include "symtab.h"
#include "capability.h"
#include "network.h"
#include "block_rules.h"
#include "rule.h"
#include "profilelist.h"

class cond_expr_set;

class block: public prefix_rule_t {
public:
	Profile *parent;
	std::list<block *> subblocks;
	std::list<cond_expr_set *> conds;
	block_rules rules;
	ProfileList hats;
	/* list of hats defined in this block (recursively) */
	union { ProfileList defined_hats; }; /* don't call destructor (weak ptr to hats) */

	block(): parent(NULL), defined_hats() { };

	bool valid_prefix(const prefixes &p, const char *&error) override {
		if (p.priority != 0) {
			error = _("priority is not allowed on rule blocks");
			return false;
		}
		return true;
	};

	void add_entry(struct cod_entry *entry);
	void add_rule(rule_t *entry);
	void add_capabilities(struct prefixes prefix, uint64_t cap);
	void add_compat_net(const network_rule *entry);
	void add_rlimit(const char *id, const char *value, const char *unit);
	void add_hat(Profile *hat);
	void merge_block(block *b);
	bool add_subblock(block *sb, const char *&error);
	void add_cond_set(cond_expr_set *ces);
	void update_parent(Profile *p);
	void add_to_known_hats(Profile *hat);
	~block();

	bool add_prefix(const prefixes &p, const char *&error) override;
	int expand_variables(void) override;
	int apply_aliases(void);
	int merge_duplicated_rules(void);
	block_rules *consolidate_block_rules(void);
	ostream &dump(ostream &os) override;
	rule_result_t gen_policy_re(Profile &prof aa_unused) override { return rule_result_t::NOT_SUPPORTED; };
	void add_implied_rules(Profile &prof) override;
	rule_t* clone() const { return NULL; }

	template <typename F>
	auto for_each_recursive(F func, bool eval_cond, bool apply_to_hats) -> decltype(func(this));
protected:
	void warn_once(const char *name aa_unused, const char *msg aa_unused) override { };
	void warn_once(const char *name aa_unused) override  { };
};

#endif /* __AA_BLOCK_H */
