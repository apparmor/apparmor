/*
 *   Copyright (c) 2025
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

#include <algorithm>

#include "block.h"
#include "cond_expr.h"
#include "profile.h"

ostream &block::dump(ostream &os) {
	prefix_rule_t::dump(os);
	os << "{\n";
	rules.dump(os);

	for (block *sb : subblocks) {
		sb->dump(os);
	}

	for (cond_expr_set *conds_set : conds) {
		for (cond_expr *cond : conds_set->set) {
			cond->dump(os);
			os << "\n";
		}
		os << "\n";
	}
	os << "\n";
	hats.dump();
	os <<"}\n";
	return os;
}

void block::merge_block(block *b)
{
	if (b->audit != audit_t::UNSPECIFIED) {
		if (audit != audit_t::UNSPECIFIED &&
		    audit != b->audit) {
			PERROR("conflicting audit prefix");
			exit(1);
		}
		audit = b->audit;
	}

	for (Profile *hat : b->hats) {
		add_hat(hat);
	}

	rules.merge_block_rules(&b->rules);
	delete b;
}

block_rules *block::consolidate_block_rules(void)
{
	block_rules *consolidated_br = new block_rules();
	block_rules copy = block_rules(rules);
	consolidated_br->merge_block_rules(&copy);
	for (block *sb : subblocks) {
		block_rules *sb_br = sb->consolidate_block_rules();
		consolidated_br->merge_block_rules(sb_br);
		delete sb_br;
	}
	for (cond_expr_set *ces : conds) {
		if (ces->set_block) {
			block_rules *cond_br = ces->set_block->consolidate_block_rules();
			consolidated_br->merge_block_rules(cond_br);
			delete cond_br;
		}
	}
	return consolidated_br;
}

rule_result_t block::gen_policy_re(Profile &prof)
{
	process_result_t err;
	err = rules.post_process(&prof);
	if (err == process_result_t::REGEX_ERR) {
		PERROR(_("ERROR processing regexs for profile %s, "
			 "failed to load\n"), prof.name);
		return rule_result_t::ERROR;
	} else if (err == process_result_t::POLICYDB_ERR) {
		PERROR(_("ERROR processing policydb rules for profile %s, "
			 "failed to load\n"), prof.name);
		return rule_result_t::ERROR;
	}
	for (block *sb : subblocks) {
		if (sb->gen_policy_re(prof) == rule_result_t::ERROR)
			return rule_result_t::ERROR;
	}
	for (cond_expr_set *ces : conds) {
		if (ces->set_block) {
			if (ces->set_block->gen_policy_re(prof) == rule_result_t::ERROR)
				return rule_result_t::ERROR;
		}
	}
	return rule_result_t::OK;
};


void block::add_entry(struct cod_entry *entry)
{
	rules.add_entry(entry);
}

void block::add_rule(rule_t *entry)
{
	rules.add_rule(entry);
}

void block::add_capabilities(struct prefixes prefix, uint64_t cap)
{
	rules.add_capabilities(prefix, cap);
}

void block::add_compat_net(const network_rule *entry)
{
	rules.add_compat_net(entry);
}

void block::add_rlimit(const char *id, const char *value, const char *unit)
{
	rules.add_rlimit(id, value, unit);
}

void block::add_to_known_hats(Profile *hat)
{
	std::pair<ProfileList::iterator, bool> res;
	res = defined_hats.insert(hat);
	if (!res.second) {
		PERROR("Multiple definitions for profile %s exist,"
		       "bailing out.\n", hat->name);
		exit(1);
	}
}

void block::add_hat(Profile *hat)
{
	hat->parent = parent;

	add_to_known_hats(hat);
	/* ignoring return value since it was already checked above for dups */
	hats.insert(hat);
}

/* note for add_subblock and add_cond_set:
 * since rules such as caps, rlimits, compat_net and uses_prompt_rules
 * are encoded per profile in parser_interface, we merge them when
 * adding the subblock, similarly to what's done for defined_hats */
bool block::add_subblock(block *sb, const char *&error)
{
	const prefixes *prefix = this;
	for (Profile *p : sb->defined_hats) {
		add_to_known_hats(p);
	}
	if (!sb->add_prefix(*prefix, error))
		return false;
	subblocks.push_back(sb);

	rules.merge_compat_rules(&(sb->rules));
	return true;
}

void block::add_cond_set(cond_expr_set *ces)
{
	if (ces->set_block) {
		for (Profile *p : ces->set_block->defined_hats) {
			add_to_known_hats(p);
		}
		rules.merge_compat_rules(&(ces->set_block->rules));
	}
	conds.push_back(ces);
}

void block::update_parent(Profile *p)
{
	parent = p;

	for (block *sb : subblocks) {
		sb->update_parent(p);
	}

	for (cond_expr_set *ces : conds) {
		for (cond_expr *c : ces->set) {
			c->cond_block->update_parent(p);
		}
	}

	for (Profile *h : hats) {
		h->parent = p;
		h->main_block->update_parent(h);
	}
}

block::~block()
{
	for(ProfileList::iterator i = defined_hats.begin(); i != defined_hats.end();) {
		ProfileList::iterator k = i++;
		/* remove from list but don't delete object */
		defined_hats.erase(k);
	}

	for (block *sb : subblocks) {
		delete sb;
	}
	subblocks.clear();

	for (cond_expr_set *ces : conds) {
		delete ces;
	}
	conds.clear();
	hats.clear();
	rules.clear();
};

template <typename F>
auto block::for_each_recursive(F func, bool eval_cond, bool apply_to_hats) -> decltype(func(this))
{
	auto result = func(this);
	if (result)
		return result;

	for (block *sb : subblocks) {
		if ((result = sb->for_each_recursive(func, eval_cond, apply_to_hats)))
			return result;
	}

	for (cond_expr_set *ces : conds) {
		if (eval_cond) {
			if (ces->set_block) {
				if ((result = ces->set_block->for_each_recursive(func,
										 eval_cond,
										 apply_to_hats)))
					return result;
			}
		} else {
			for (cond_expr *c : ces->set) {
				if (c->cond_block) {
					if ((result = c->cond_block->for_each_recursive(func,
											eval_cond,
											apply_to_hats)))
						return result;
				}
			}
		}
	}

	if (apply_to_hats) {
		for (Profile *hat : hats) {
			if (hat->main_block) {
				if ((result = hat->main_block->for_each_recursive(func,
										  eval_cond,
										  apply_to_hats)))
					return result;
			}
		}
	}

	return 0;
}

bool block::add_prefix(const prefixes &p, const char *&error)
{
	if (!prefix_rule_t::add_prefix(p, error))
		return false;

	int rc = for_each_recursive([&](block *b) {
		return b->rules.add_prefix(p, error) ? 0 : -1;
	}, false, true);

	return rc == 0;
}

int block::expand_variables(void)
{
	/* don't expand variables in all conditional branches because
	 * they could not be defined and error out, which we do not
	 * want for thise cases */
	return for_each_recursive([](block *b) {
		return b->rules.process_variables();
	}, true, false);
}

int block::apply_aliases(void)
{
	return for_each_recursive([](block *b) {
		if (b->rules.entries) {
			replace_entries_aliases(b->parent, b->rules.entries);
		}
		return 0;
	}, false, false);
}

int block::merge_duplicated_rules(void)
{
	return for_each_recursive([](block *b) {
		return b->rules.merge_duplicated_rules(b->parent->name);
	}, false, false);
}

void block::post_parse_profile(Profile &prof)
{
	bool result = for_each_recursive([&](block *b) {
		return b->rules.post_parse_profile(&prof);
	}, true, false);
	if (result) {
		/* error message has been displayed already */
		exit(1);
	}
}

void block::add_implied_rules(Profile &prof)
{
	for_each_recursive([&](block *b) {
		b->rules.add_implied_rules(&prof);
		return 0;
	}, true, false);
}
