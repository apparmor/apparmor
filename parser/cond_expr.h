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

#include <set>
#include <string>

typedef enum {
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
} cond_op;

class cond_expr {
private:
	bool result;
public:
	cond_expr(bool result);
	cond_expr(const char *var, cond_op op);
	cond_expr(const char *var, cond_op op, const char *cond_id);
	std::set<std::string> get_set(const char *var);
	template <typename T>
	void compare(cond_op op, const T &lhs, const T &rhs);
	virtual ~cond_expr()
	{
	};

	bool eval(void) { return result; }
};

#endif /* __AA_COND_EXPR_H */
