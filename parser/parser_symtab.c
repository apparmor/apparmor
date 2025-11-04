/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc.
 */

#include <search.h>
#include <stdlib.h>
#include <stdarg.h>
#include <linux/limits.h>


#ifdef UNIT_TEST

#include <string.h>
#include <errno.h>
#include "immunix.h"
#include "parser.h"
#include "symtab.h"

#include "unit_test.h"

int test_add_set_to_boolean(void)
{
	int rc = 0;
	int retval;
	struct value_list *val;
	/* test adding a set value to a boolean variable */
	retval = global_symtab.add_var("@not_a_set_variable", 1);
	MY_TEST(retval == 0, "new boolean variable 3");

	val = new_value_list(strdup("a set value"));
	retval = global_symtab.add_set_value("@not_a_set_variable", val);
	MY_TEST(retval != 0, "add set value to boolean");

	global_symtab.free_symtab();
	free_value_list(val);

	return rc;
}

int test_expand_bool_within_set(void)
{
	int rc = 0;
	int retval;
	variable *retsym;

	/* test expanding a boolean var within a set variable */
	retval = global_symtab.add_var("@not_a_set_variable", 1);
	MY_TEST(retval == 0, "new boolean variable 4");
	retval = global_symtab.add_var("set_variable", "set_value@{not_a_set_variable}");
	MY_TEST(retval == 0, "add set value with embedded boolean");
	retsym = global_symtab.lookup_existing_symbol("set_variable");
	MY_TEST(retsym != NULL, "get set variable w/boolean");
	retval = retsym->expand_variable();
	MY_TEST(retval != 0, "expand set variable with embedded boolean");

	global_symtab.free_symtab();

	return rc;
}

int test_expand_recursive_set_vars(void)
{
	int rc = 0;
	int retval;
	variable *retsym;

	/* test expanding a recursive var within a set variable */
	retval = global_symtab.add_var("recursive_1", "set_value@{recursive_2}");
	MY_TEST(retval == 0, "new recursive set variable 1");
	retval = global_symtab.add_var("recursive_2", "set_value@{recursive_3}");
	MY_TEST(retval == 0, "new recursive set variable 2");
	retval = global_symtab.add_var("recursive_3", "set_value@{recursive_1}");
	MY_TEST(retval == 0, "new recursive set variable 3");
	retsym = global_symtab.lookup_existing_symbol("recursive_1");
	MY_TEST(retsym != NULL, "get recursive set variable");
	retval = retsym->expand_variable();
	MY_TEST(retval != 0, "expand recursive set variable");

	global_symtab.free_symtab();

	return rc;
}

int test_expand_undefined_set_var(void)
{
	int rc = 0;
	int retval;
	variable *retsym;

	/* test expanding an undefined var within a set variable */
	retval = global_symtab.add_var("defined_var", "set_value@{undefined_var}");
	MY_TEST(retval == 0, "new undefined test set variable");
	retsym = global_symtab.lookup_existing_symbol("defined_var");
	MY_TEST(retsym != NULL, "get undefined test set variable");
	retval = retsym->expand_variable();
	MY_TEST(retval != 0, "expand undefined set variable");

	global_symtab.free_symtab();

	return rc;
}

int test_expand_set_var_during_dump(void)
{
	int rc = 0;
	int retval;
	variable *retsym;

	/* test expanding an defined var within a set variable during var dump*/
	retval = global_symtab.add_var("set_var_1", "set_value@{set_var_2}");
	MY_TEST(retval == 0, "new dump expansion set variable 1");
	retval = global_symtab.add_var("set_var_2", "some other set_value");
	MY_TEST(retval == 0, "new dump expansion set variable 2");
	retsym = global_symtab.lookup_existing_symbol("set_var_1");
	MY_TEST(retsym != NULL, "get dump expansion set variable 1");
	retsym->dump(false);
	retsym->dump(true);
	retsym->dump(false);

	global_symtab.free_symtab();

	return rc;
}

int test_delete_set_var(void)
{
	int rc = 0;
	int retval;
	variable *deleted;
	variable *retsym;

	retval = global_symtab.add_var("deleteme", "delete this variable");
	MY_TEST(retval == 0, "new delete set variable");
	deleted = global_symtab.delete_var("deleteme");
	MY_TEST(deleted != NULL, "delete set variable");
	retsym = global_symtab.lookup_existing_symbol(deleted->var_name.c_str());
	MY_TEST(retsym == NULL, "deleteme was deleted from symtable");

	global_symtab.free_symtab();

	return rc;
}

int main(void)
{
	int rc = 0;
	int retval;
	struct value_list *list;
	struct value_list *val;
	variable *retsym;

	val = new_value_list(strdup("a set value"));
	retval = global_symtab.add_set_value("@not_a_set_variable", val);

	retval = test_add_set_to_boolean();
	if (rc == 0)
		rc = retval;

	retval = test_expand_bool_within_set();
	if (rc == 0)
		rc = retval;

	retval = test_expand_recursive_set_vars();
	if (rc == 0)
		rc = retval;

	retval = test_expand_undefined_set_var();
	if (rc == 0)
		rc = retval;

	retval = test_expand_set_var_during_dump();
	if (rc == 0)
		rc = retval;

	retval = test_delete_set_var();
	if (rc == 0)
		rc = retval;

	retval = global_symtab.add_var("test", "test value");
	MY_TEST(retval == 0, "new set variable 1");

	retval = global_symtab.add_var("test", "different value");
	MY_TEST(retval != 0, "new set variable 2");

	retval = global_symtab.add_var("testing", "testing");
	MY_TEST(retval == 0, "new set variable 3");

	retval = global_symtab.add_var("monopuff", "Mockingbird");
	MY_TEST(retval == 0, "new set variable 4");

	retval = global_symtab.add_var("stereopuff", "Unsupervised");
	MY_TEST(retval == 0, "new set variable 5");

	val = new_value_list(strdup("Fun to Steal"));
	list = val;
	retval = global_symtab.add_set_value("@stereopuff", val);
	MY_TEST(retval == 0, "add set value 1");

	val = new_value_list(strdup("/in/direction"));
	list_append(list, val);
	retval = global_symtab.add_set_value("@stereopuff", val);
	MY_TEST(retval == 0, "add set value 2");

	val = new_value_list(strdup("stereopuff"));
	list_append(list, val);
	retval = global_symtab.add_set_value("@no_such_variable", val);
	MY_TEST(retval != 0, "add to non-existent set var");

	retval = global_symtab.add_var("@abuse", 0);
	MY_TEST(retval == 0, "new boolean variable 1");

	retval = global_symtab.add_var("@abuse", 1);
	MY_TEST(retval != 0, "duplicate boolean variable 1");

	retval = global_symtab.add_var("@stereopuff", 1);
	MY_TEST(retval != 0, "duplicate boolean variable 2");

	retval = global_symtab.add_var("@shenanigan", 1);
	MY_TEST(retval == 0, "new boolean variable 2");

	retsym = global_symtab.get_boolean_var("@shenanigan");
	MY_TEST(retsym != NULL, "boolean variable 1 exists");
	MY_TEST(retsym->boolean == 1, "get boolean variable 1");

	retsym = global_symtab.get_boolean_var("@abuse");
	MY_TEST(retsym != NULL, "boolean variable 2 exists");
	MY_TEST(retsym->boolean == 0, "get boolean variable 2");

	retsym = global_symtab.get_boolean_var("@non_existant");
	MY_TEST(retsym == NULL, "get nonexistent boolean variable");

	retsym = global_symtab.get_boolean_var("@stereopuff");
	MY_TEST(retsym == NULL, "get boolean variable that's declared a set var");

	retsym = global_symtab.get_set_var("@daves_not_here_man");
	MY_TEST(retsym == NULL, "get nonexistent set variable");

	retsym = global_symtab.get_set_var("@abuse");
	MY_TEST(retsym == NULL, "get set variable that's declared a boolean");

	/* test walking set values */
	retsym = global_symtab.get_set_var("@monopuff");
	MY_TEST(retsym != NULL, "get set variable 1");
	MY_TEST(retsym->values.size() == 1, "only one value");
	MY_TEST(retsym->expanded.size() == 1, "only one expanded");

	for (std::string value : retsym->values) {
		retval = strcmp(value.c_str(), "Mockingbird");
		MY_TEST(retval == 0, "get set value 1");
	}

	for (std::string value : retsym->expanded) {
		retval = strcmp(value.c_str(), "Mockingbird");
		MY_TEST(retval == 0, "get set value 1 expanded");
	}

	retval = global_symtab.add_var("eek", "Mocking@{monopuff}bir@{stereopuff}d@{stereopuff}");
	MY_TEST(retval == 0, "new set variable 4");

	global_symtab.dump(false);
	global_symtab.expand_variables();
	global_symtab.dump(false);
	global_symtab.dump(true);

	free_value_list(list);
	global_symtab.free_symtab();

	return rc;
}
#endif /* UNIT_TEST */
