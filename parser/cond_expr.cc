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

#include <algorithm>

#include "cond_expr.h"
#include "parser.h"
#include "symtab.h"

cond_expr::cond_expr(bool result):
	result(result)
{
}

cond_expr::cond_expr(const char *var, cond_op op)
{
	if (op == cond_op::BOOLEAN_VALUE) {
		int boolean = str_to_boolean(var);
		if (boolean == -1) {
			yyerror("Invalid boolean : '%s' is not true or false",
				var);
		}
		result = boolean;
	} else if (op == cond_op::BOOLEAN_OP) {
		variable *ref = global_symtab.get_boolean_var(var);
		if (!ref) {
			yyerror(_("Unset boolean variable %s used in if-expression"), var);
		}
		result = ref->boolean;
	} else if (op == cond_op::DEFINED_OP) {
		variable *ref = global_symtab.get_set_var(var);
		if (!ref) {
			result = false;
		} else {
			PDEBUG("Matched: defined set expr %s value %s\n", var, ref->expanded.begin()->c_str());
			result = true;
		}
	} else
		PERROR("Invalid operation for if-expression");
}

/* variables passed in conditionals can be variables or values.

   if the string passed has the formatting of a variable (@{}), then
   we should look for it in the symtab. if it's present in the symtab,
   expand its values and return the expanded set. if it's not present
   in the symtab, we should error out. if the string passed does not
   have the formatting of a variable, we should treat it as if it was
   a value. add it to a set and return it so comparisons can be made.
*/
std::set<std::string> cond_expr::get_set(const char *var)
{
	char *var_name = variable::process_var(var);
	if (!var_name) {
		/* not a variable */
		return {var};
	}
	variable *ref = global_symtab.lookup_existing_symbol(var_name);
	free(var_name);
	if (!ref) {
		yyerror(_("Error retrieving variable %s"), var);
	}
	if (ref->expand_variable() != 0) {
		/* expand_variable prints error messages already, so
		 * exit quietly here */
		exit(1);
	}
	return ref->expanded;
}

template <typename T>
void cond_expr::compare(cond_op op, const T &lhs, const T &rhs)
{
	switch (op) {
	case cond_op::GT_OP:
		result = lhs > rhs;
		break;
	case cond_op::GE_OP:
		result = lhs >= rhs;
		break;
	case cond_op::LT_OP:
		result = lhs < rhs;
		break;
	case cond_op::LE_OP:
		result = lhs <= rhs;
		break;
	default:
		yyerror("Internal error: invalid comparison operator %d", (int)op);
	}
}

bool nullstr(char *p)
{
	return p && !(*p);
}

long str_set_to_long(std::set<std::string> &src, char **endptr)
{
	long converted_src = 0;
	errno = 0;
	if (src.size() == 1 && !src.begin()->empty())
		converted_src = strtol(src.begin()->c_str(), endptr, 0);
	if (errno == ERANGE)
		yyerror(_("Value out of valid range\n"));
	return converted_src;
}

cond_expr::cond_expr(const char *lhv, cond_op op, const char *rhv)
{
	std::set<std::string> lhs = get_set(lhv);
	std::set<std::string> rhs = get_set(rhv);
	char *p_lhs = NULL, *p_rhs = NULL;
	long converted_lhs = 0, converted_rhs = 0;

	if (op == cond_op::IN_OP) {
		/* if lhs is a subset of rhs */
		result = std::includes(rhs.begin(), rhs.end(),
				       lhs.begin(), lhs.end());
		return;
	} else if (op == cond_op::EQ_OP) {
		result = lhs == rhs;
		return;
	} else if (op == cond_op::NE_OP) {
		result = lhs != rhs;
		return;
	}

	converted_lhs = str_set_to_long(lhs, &p_lhs);
	converted_rhs = str_set_to_long(rhs, &p_rhs);

	if (!nullstr(p_lhs) && !nullstr(p_rhs)) {
		/* sets */
		compare(op, lhs, rhs);
	} else if (nullstr(p_lhs) && nullstr(p_rhs)) {
		/* numbers */
		compare(op, converted_lhs, converted_rhs);
	} else {
		yyerror(_("Can only compare numbers with numbers\n"));
	}
}
