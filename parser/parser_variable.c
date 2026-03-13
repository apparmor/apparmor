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

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <linux/limits.h>

#include <string>

/* #define DEBUG */

#include "parser.h"
#include "profile.h"
#include "mount.h"
#include "dbus.h"
#include "symtab.h"

/* doesn't handle variables in options atm */
int expand_entry_variables(char **name)
{
	return variable::expand_by_alternation(name);
}

static int process_variables_in_entries(struct cod_entry *entry_list)
{
	int error = 0;
	struct cod_entry *entry;

	list_for_each(entry_list, entry) {
		error = expand_entry_variables(&entry->name);
		if (error)
			return error;
		if (entry->link_name) {
			error = expand_entry_variables(&entry->link_name);
			if (error)
				return error;
		}
	}

	return 0;
}

static int process_variables_in_rules(Profile &prof)
{
	for (RuleList::iterator i = prof.rule_ents.begin(); i != prof.rule_ents.end(); i++) {
		if ((*i)->skip())
			continue;
		int error = (*i)->expand_variables();
		if (error)
			return error;
	}

	return 0;
}


static int process_variable_in_attach_disconnected(char **disconnected)
{
	int error = expand_entry_variables(disconnected);
	if (error)
		return error;
	filter_slashes(*disconnected);
	// TODO: semantic check should go somewhere else
	if ((*disconnected)[0] != '/')
		yyerror(_("attach_disconnected path must begin with a /"));
	int n = strlen(*disconnected);
	// removing trailing / */
	while (n && (*disconnected)[n-1] == '/')
		(*disconnected)[--n] = 0;
	return error;
}

static int process_variables_in_name(Profile &prof)
{
	/* this needs to be done before alias expansion, ie. altnames are
	 * setup
	 */
	int error = expand_entry_variables(&prof.name);
	if (!error) {
		if (prof.attachment)
			error = expand_entry_variables(&prof.attachment);
		else if (prof.name[0] == '/') {
			/* had to wait to do this until after processing the
			 * variables in the profile name
			 */
			prof.attachment = strdup(local_name(prof.name));
			if (!prof.attachment) {
				errno = ENOMEM;
				return -1;
			}
			filter_slashes(prof.attachment);
		}
	}

	if (!error && prof.flags.disconnected_path)
		error = process_variable_in_attach_disconnected(&prof.flags.disconnected_path);
	if (!error && prof.flags.disconnected_ipc)
		error = process_variable_in_attach_disconnected(&prof.flags.disconnected_ipc);
	return error;
}

static std::string escape_re(std::string str)
{
	for (size_t i = 0; i < str.length(); i++) {
		if (str[i] == '\\') {
			/* skip \ and follow char. Skipping \ and first
			 * char is enough for multichar escape sequence
			 */
			i++;
			continue;
		}
		if (strchr("{}[]*?", str[i]) != NULL) {
			str.insert(i++, "\\");
		}
	}

	return str;
}

int process_profile_variables(Profile *prof)
{
	int error = 0;
	variable *saved_exec_path = NULL;
	variable *saved_attach_path = NULL;
	variable *tmp = NULL;

	/* needs to be before PROFILE_NAME_VARIABLE so that variable will
	 * have the correct name
	 */
	error = process_variables_in_name(*prof);

	if (error)
		goto out;

	/* escape profile name elements that could be interpreted as
	 * regular expressions.
	 */
	error = global_symtab.add_var(PROFILE_NAME_VARIABLE, escape_re(prof->get_name(false)).c_str());
	if (error)
		goto out;

	if (prof->attachment) {
		/* IF we didn't want a path based profile name to generate
		 * an attachment. The code could be moved here. Add the
		 * output fed into the vars directly instead of setting
		 * the attachment.
		 */
		/* need to take into account alias, but not yet */
		saved_attach_path = global_symtab.delete_var(PROFILE_ATTACH_VAR);
		error = global_symtab.add_var(PROFILE_ATTACH_VAR, (const char*) prof->attachment);
		if (error)
			goto cleanup_name;
		/* update to use kernel vars if available */
		saved_exec_path = global_symtab.delete_var(PROFILE_EXEC_VAR);
		error = global_symtab.add_var(PROFILE_EXEC_VAR, (const char*) prof->attachment);
		if (error)
			goto cleanup_attach;
	}

	error = process_variables_in_entries(prof->entries);
	if (error)
		goto cleanup;
	error = process_variables_in_rules(*prof);

cleanup:
	/* ideally these variables would be local scoped and we would not
	 * have to clean them up here, but unfortunately variables
	 * don't support that yet.
	 */
	if (prof->attachment) {
		tmp = global_symtab.delete_var(PROFILE_EXEC_VAR);
		delete tmp;
		if (saved_exec_path)
			global_symtab.add_var(*saved_exec_path);
	}
cleanup_attach:
	if (prof->attachment) {
		tmp = global_symtab.delete_var(PROFILE_ATTACH_VAR);
		delete tmp;
		if (saved_attach_path)
			global_symtab.add_var(*saved_attach_path);
	}
cleanup_name:
	tmp = global_symtab.delete_var(PROFILE_NAME_VARIABLE);
	delete tmp;
	delete saved_exec_path;
	delete saved_attach_path;
out:
	return error;
}

#ifdef UNIT_TEST

#include "unit_test.h"

int test_split_string(void)
{
	int rc = 0;
	char *tst_string;
	const char *prefix = "abcdefg";
	const char *var = "boogie";
	const char *suffix = "suffixication";
	std::tuple<std::string, std::string, std::string> result;
	std::string result_prefix;
	std::string result_var;
	std::string result_suffix;
	char *pvar;

	asprintf(&tst_string, "%s@{%s}%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "split string 1 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "split string 1 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "split string 1 suffix");
	free(pvar);
	free(tst_string);

	asprintf(&tst_string, "@{%s}%s", var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(result_prefix.empty(), "split string 2 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "split string 2 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "split string 2 suffix");
	free(pvar);
	free(tst_string);

	asprintf(&tst_string, "%s@{%s}", prefix, var);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "split string 3 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "split string 3 var");
	MY_TEST(result_suffix.empty(), "split string 3 suffix");
	free(pvar);
	free(tst_string);

	asprintf(&tst_string, "@{%s}", var);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(result_prefix.empty(), "split string 4 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "split string 4 var");
	MY_TEST(result_suffix.empty(), "split string 4 suffix");
	free(pvar);
	free(tst_string);

	asprintf(&tst_string, "%s%s%s", prefix, var, suffix);;
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	MY_TEST(result_prefix.empty(), "split string 5 prefix");
	MY_TEST(result_var.empty(), "split string 5 var");
	MY_TEST(result_suffix.empty(), "split string 5 suffix");
	free(tst_string);

	return rc;
}

int test_split_out_var(void)
{
	int rc = 0;
	char *tst_string, *tmp;
	const char *prefix = "abcdefg";
	const char *var = "boogie";
	const char *var2 = "V4rW1thNum5";
	const char *var3 = "boogie_board";
	const char *suffix = "suffixication";
	std::tuple<std::string, std::string, std::string> result;
	std::string result_prefix;
	std::string result_var;
	std::string result_suffix;
	char *pvar = NULL;

	/* simple case */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable 1 pvar");
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "extract_variable 1 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 1 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "extract_variable 1 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* no prefix */
	asprintf(&tst_string, "@{%s}%s", var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable 2 pvar");
	MY_TEST(result_prefix.empty(), "extract_variable 2 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 2 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "extract_variable 2 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* no suffix */
	asprintf(&tst_string, "%s@{%s}", prefix, var);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable 3 pvar");
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "extract_variable 3 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 3 var");
	MY_TEST(result_suffix.empty(), "extract_variable 3 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* var only */
	asprintf(&tst_string, "@{%s}", var);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable 4 pvar");
	MY_TEST(result_prefix.empty(), "extract_variable 4 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 4 var");
	MY_TEST(result_suffix.empty(), "extract_variable 4 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* quoted var, shouldn't split  */
	asprintf(&tst_string, "%s\\@{%s}%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	MY_TEST(result_prefix.empty(), "extract_variable - quoted @ prefix");
	MY_TEST(result_var.empty(), "extract_variable - quoted @ var");
	MY_TEST(result_suffix.empty(), "extract_variable - quoted @ suffix");
	free(tst_string);

	/* quoted \, split should succeed */
	asprintf(&tst_string, "%s\\\\@{%s}%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	tmp = strndup(tst_string, strlen(prefix) + 2);
	MY_TEST(pvar != NULL, "extract_variable 5 pvar");
	MY_TEST(strcmp(result_prefix.c_str(), tmp) == 0, "extract_variable 5 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 5 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "extract_variable 5 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);
	free(tmp);

	/* un terminated var, should fail */
	asprintf(&tst_string, "%s@{%s%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	MY_TEST(result_prefix.empty(), "extract_variable - un-terminated var prefix");
	MY_TEST(result_var.empty(), "extract_variable - un-terminated var var");
	MY_TEST(result_suffix.empty(), "extract_variable - un-terminated var suffix");
	free(tst_string);

	/* invalid char in var, should fail */
	asprintf(&tst_string, "%s@{%s^%s}%s", prefix, var, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar == NULL, "process_var - invalid char in var");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* two vars, should only strip out first */
	asprintf(&tmp, "@{%s}%s}", suffix, suffix);
	asprintf(&tst_string, "%s@{%s}%s", prefix, var, tmp);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable 6 pvar");
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "extract_variable 6 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 6 var");
	MY_TEST(strcmp(result_suffix.c_str(), tmp) == 0, "extract_variable 6 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);
	free(tmp);

	/* quoted @ followed by var, split should succeed */
	asprintf(&tst_string, "%s\\@@{%s}%s", prefix, var, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	tmp = strndup(tst_string, strlen(prefix) + 2);
	MY_TEST(pvar != NULL, "extract_variable 7 pvar");
	MY_TEST(strcmp(result_prefix.c_str(), tmp) == 0, "extract_variable 7 prefix");
	MY_TEST(strcmp(pvar, var) == 0, "extract_variable 7 var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "extract_variable 7 suffix");
	if (pvar)
		free(pvar);
	free(tst_string);
	free(tmp);

	/* numeric char in var, should succeed */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var2, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable numeric var pvar");
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "split out numeric var prefix");
	MY_TEST(strcmp(pvar, var2) == 0, "split numeric var var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "split out numeric var suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* numeric first char in var, should fail */
	asprintf(&tst_string, "%s@{6%s}%s", prefix, var2, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar == NULL, "process_var - invalid char in var");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* underscore char in var, should succeed */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var3, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar != NULL, "extract_variable underscore var pvar");
	MY_TEST(strcmp(result_prefix.c_str(), prefix) == 0, "split out underscore var prefix");
	MY_TEST(strcmp(pvar, var3) == 0, "split out underscore var");
	MY_TEST(strcmp(result_suffix.c_str(), suffix) == 0, "split out underscore var suffix");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* underscore first char in var, should fail */
	asprintf(&tst_string, "%s@{_%s%s}%s", prefix, var2, var3, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar == NULL, "process_var - invalid char in var");
	if (pvar)
		free(pvar);
	free(tst_string);

	/* empty var name, should fail */
	asprintf(&tst_string, "%s@{}%s", prefix, suffix);
	result = extract_variable(tst_string);
	result_prefix = std::get<0>(result);
	result_var = std::get<1>(result);
	result_suffix = std::get<2>(result);
	pvar = variable::process_var(result_var.c_str());
	MY_TEST(pvar == NULL, "process_var - empty var name");
	if (pvar)
		free(pvar);
	free(tst_string);
	
	return rc;
}
int main(void)
{
	int rc = 0;
	int retval;

	retval = test_split_string();
	if (retval != 0)
		rc = retval;

	retval = test_split_out_var();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
