/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2012 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Wrapper around the dfa to convert aa rules into a dfa
 */
#ifndef __LIBAA_RE_RULES_H
#define __LIBAA_RE_RULES_H

#include <vector>

#include <stdint.h>

#include "../common_optarg.h"
#include "apparmor_re.h"
#include "chfa.h"
#include "expr-tree.h"
#include "../immunix.h"
#include "../perms.h"
#include "../rule.h"

class UniquePerm {
public:
	int priority;
	rule_mode_t mode;
	bool exact_match;
	uint32_t perms;
	uint32_t audit;

	bool operator<(UniquePerm const &rhs)const
	{
		if (priority < rhs.priority)
			return priority < rhs.priority;
		if (mode >= rhs.mode) {
			if (exact_match == rhs.exact_match) {
				if (perms == rhs.perms)
					return audit < rhs.audit;
				return perms < rhs.perms;
			}
			return exact_match;
		}
		return true;  // mode < rhs.mode
	}
};

class UniquePermsCache {
public:
	typedef std::map<UniquePerm, Node*> UniquePermMap;
	typedef UniquePermMap::iterator iterator;
	UniquePermMap nodes;

	UniquePermsCache(void) { };
	~UniquePermsCache() { clear(); }

	void clear()
	{
		for (iterator i = nodes.begin(); i != nodes.end(); i++) {
			delete i->second;
		}
		nodes.clear();
	}

	Node *insert(int priority, rule_mode_t mode, uint32_t perms,
		     uint32_t audit, bool exact_match)
	{
		UniquePerm tmp = { priority, mode, exact_match, perms, audit };
		iterator res = nodes.find(tmp);
		if (res == nodes.end()) {
			Node *node;
			if (mode == RULE_DENY)
				node = new DenyMatchFlag(priority, perms, audit);
			else if (mode == RULE_PROMPT)
				node = new PromptMatchFlag(priority, perms, audit);
			else if (exact_match)
				node = new ExactMatchFlag(priority, perms, audit);
			else
				node = new MatchFlag(priority, perms, audit);
			std::pair<iterator, bool> val = nodes.insert(std::make_pair(tmp, node));
			if (val.second == false) {
				delete node;
				return val.first->second;
			}
			return node;
		}
		return res->second;
	}
};

typedef std::map<Node *, Node *> PermExprMap;

class aare_rules {
	Node *root;
	void add_to_rules(Node *tree, Node *perms);
	UniquePermsCache unique_perms;
	PermExprMap expr_map;
 public:
	int reverse;
	int rule_count;
	aare_rules(void): root(NULL), unique_perms(), expr_map(), reverse(0), rule_count(0) { };
	aare_rules(int reverse): root(NULL), unique_perms(), expr_map(), reverse(reverse), rule_count(0) { };
	~aare_rules();

	bool add_rule(const char *rule, int priority, rule_mode_t mode,
		      perm32_t perms, perm32_t audit, optflags const &opts);
	bool add_rule_vec(int priority, rule_mode_t mode, perm32_t perms,
			  perm32_t audit, int count, const char **rulev,
			  optflags const &opts, bool oob);
	bool append_rule(const char *rule, bool oob, bool with_perm, optflags const &opts);
	CHFA *create_chfa(int *min_match_len,
			  std::vector <aa_perms> &perms_table,
			  optflags const &opts, bool filedfa,
			  int permstable32_version);
	void *create_dfablob(size_t *size, int *min_match_len,
			 std::vector <aa_perms> &perms_table,
			 optflags const &opts,
			 bool filedfa,
			 int permstable32_version);
};

#endif				/* __LIBAA_RE_RULES_H */
