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

#ifndef __AA_SYMTAB_H
#define __AA_SYMTAB_H

#include <unordered_map>
#include <string>

#include "variable.h"

class symtab {
private:
	std::unordered_map<std::string, variable> my_symtab;
public:
	template <typename T>
	int add_var(const char *var, T value);
	int add_var(const char *var, int value);
	int add_var(const char *var, struct value_list *value);
	int add_var(const char *var, const char *value);
	int add_var(variable var);
	int add_set_value(const char *var, struct value_list *value);
	void dump(bool do_expanded);
	void free_symtab(void);
	void expand_variables(void);
	variable *lookup_existing_symbol(const char *var_name);
	variable *get_set_var(const char *var_name);
	variable *get_boolean_var(const char *var_name);
	variable *delete_var(const char *var_name);
};

extern symtab global_symtab;

#endif /* __AA_SYMTAB_H */
