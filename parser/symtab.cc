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
#include <stdlib.h>
#include <utility>

#include "parser.h"
#include "symtab.h"

template <typename T>
int symtab::add_var(const char *var, T value)
{
	char *var_name = variable::process_var(var);
	if (!var_name)
		return 1;
	
	const auto search = my_symtab.find(var_name);
	if (search != my_symtab.end()) {
		/* already existing variable */
		PERROR("'%s' is already defined\n", var);
		free(var_name);
		return 1;
	}
	my_symtab.emplace(var_name, variable(var_name, value));
	free(var_name);
	return 0;
}

int symtab::add_var(const char *var, int value)
{
	return add_var<int>(var, value);
}

int symtab::add_var(const char *var, struct value_list *value)
{
	return add_var<struct value_list *>(var, value);
}

int symtab::add_var(const char *var_name, const char *value)
{
	/* note that here var_name must be processed already */
	const auto search = my_symtab.find(var_name);
	if (search != my_symtab.end()) {
		/* already existing variable */
		PERROR("'%s' is already defined\n", var_name);
		return 1;
	}
	my_symtab.emplace(var_name, variable(var_name, value));
	return 0;
}


int symtab::add_var(variable var)
{
	const auto search = my_symtab.find(var.var_name);
	if (search != my_symtab.end()) {
		/* already existing variable */
		PERROR("'%s' is already defined\n", var.var_name.c_str());
		return 1;
	}
	my_symtab.emplace(var.var_name, var);
	return 0;
}

variable *symtab::lookup_existing_symbol(const char *var_name)
{
	if (!var_name)
		return nullptr;

	const auto var = my_symtab.find(var_name);
	if (var == my_symtab.end()) {
		return nullptr;
	}
	return &(var->second);
}

int symtab::add_set_value(const char *var_name, struct value_list *value)
{
	char *pvar_name = variable::process_var(var_name);
	variable *var = lookup_existing_symbol(pvar_name);
	if (!var) {
		PERROR("Failed to find declaration for: %s\n", pvar_name);
		free(pvar_name);
		return 1;
	}
	free(pvar_name);
	return var->add_set_value(value);
}

variable *symtab::delete_var(const char *var_name)
{
	variable *var = lookup_existing_symbol(var_name);
	if (!var) {
		return var;
	}
	variable *save = new variable(*var);
	my_symtab.erase(var->var_name);
	return save;
}

void symtab::free_symtab()
{
	my_symtab.erase(my_symtab.begin(), my_symtab.end());
}

void symtab::dump(bool do_expanded)
{
	for (auto var : my_symtab) {
		var.second.dump(do_expanded);
	}
}

void symtab::expand_variables()
{
	for (auto var : my_symtab) {
		if (var.second.type != var_type::sd_boolean)
			var.second.expand_variable();
	}
}


variable *symtab::get_set_var(const char *name)
{
	char *var_name = variable::process_var(name);
	variable *var = lookup_existing_symbol(var_name);
	if (!var) {
		goto out;
	}
	if (var->type != var_type::sd_set) {
		PERROR("Variable %s is not a set variable\n", var_name);
		var = nullptr;
		goto out;
	}
	var->expand_variable();
out:
	free(var_name);
	return var;
}

variable *symtab::get_boolean_var(const char *name)
{
	char *var_name = variable::process_var(name);
	variable *var = lookup_existing_symbol(var_name);
	if (!var) {
		goto out;
	}
	if (var->type != var_type::sd_boolean) {
		PERROR("Variable %s is not a boolean variable\n", var_name);
		var = nullptr;
		goto out;
	}
out:
	free(var_name);
	return var;
}

symtab global_symtab;
