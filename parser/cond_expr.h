/*
 *   Copyright (c) 2024
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

#ifndef __AA_COND_EXPR_H
#define __AA_COND_EXPR_H

#include <list>
#include <set>
#include <string>

#include "block.h"

enum class cond_op {
	EQ_OP,
	NE_OP,
	IN_OP,
	GT_OP,
	GE_OP,
	LT_OP,
	LE_OP,
	BOOLEAN_OP,
	DEFINED_OP,
	BOOLEAN_VALUE,
};

class cond_expr final {
private:
	bool result;
public:
	block *cond_block = NULL;
	cond_expr(bool result);
	cond_expr(const char *var, cond_op op);
	cond_expr(const char *var, cond_op op, const char *cond_id);
	std::set<std::string> get_set(const char *var);
	template <typename T>
	void compare(cond_op op, const T &lhs, const T &rhs);
	ostream &dump(ostream &os);
	virtual ~cond_expr()
	{
		if (cond_block)
			delete cond_block;
	};

	bool eval(void) { return result; }
};

/* set stores the entire conditional block: if, else if, else if, else */
class cond_expr_set {
public:
	std::list<cond_expr *> set;

	/* block that evaluated to true, should not be deleted */
	block *set_block = NULL;

	void add_cond(cond_expr *cond)
	{
		if (!set_block) {
			if (cond->eval())
				set_block = cond->cond_block;
		}
		set.push_back(cond);
	}

	void merge(cond_expr_set *ces)
	{
		if (!set_block) {
			set_block = ces->set_block;
			ces->set_block = NULL;
		}
		set.splice(set.end(), std::move(ces->set));
	}

	~cond_expr_set()
	{
		for (cond_expr *c : set) {
			delete c;
		}
		set.clear();
	};
};

#endif /* __AA_COND_EXPR_H */
