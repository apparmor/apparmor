/*
 *   Copyright (c) 2022
 *   Canonical, Ltd. (All rights reserved)
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

#include "parser.h"
#include "profile.h"
#include "mqueue.h"

#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>

int parse_mqueue_perms(const char *str_perms, perm32_t *perms, int fail)
{
	return parse_X_perms("mqueue", AA_VALID_MQUEUE_PERMS, str_perms, perms, fail);
}

static bool is_all_digits(char *str)
{
	const char *s = str;
	while (*str && isdigit(*str))
		str++;
	return str != s && *str == 0;
}

void mqueue_rule::validate_qname(void)
{
	if (qname[0] == '/') {
		// TODO full syntax check of name
		if (qtype == mqueue_sysv)
			yyerror("mqueue type=sysv invalid name '%s', sysv "
				"message queues must be identified by a "
				"positive integer.\n", qname);
		qtype = mqueue_posix; // implied by name
	} else if (is_all_digits(qname)) {
		if (qtype == mqueue_posix)
			yyerror("mqueue type=posix invalid name '%s', posix "
				"message queues names must begin with a /\n",
				qname);
		qtype = mqueue_sysv; // implied
	} else {
		yyerror("mqueue invalid name '%s', message queue names must begin with a / or be a positive integer.\n", qname);
	}
}

void mqueue_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		/* for now disallow keyword 'in' (list) */
		if (!cond_ent->eq)
			yyerror("keyword \"in\" is not allowed in mqueue rules\n");

		if (strcmp(cond_ent->name, "label") == 0) {
			move_conditional_value("mqueue", &label, cond_ent);
		} else if (strcmp(cond_ent->name, "type") == 0) {
			char *tmp = NULL;
			move_conditional_value("mqueue", &tmp, cond_ent);
			if (strcmp(tmp, "posix") == 0)
				qtype = mqueue_posix;
			else if (strcmp(tmp, "sysv") == 0)
				qtype = mqueue_sysv;
			else
				yyerror("mqueue invalid type='%s'\n", tmp);
			free(tmp);
		} else {
			yyerror("invalid mqueue rule conditional \"%s\"\n",
				cond_ent->name);
		}
	}
}

mqueue_rule::mqueue_rule(perm32_t perms_p, struct cond_entry *conds, char *qname_p):
	// mqueue uses multiple classes, arbitrary choice to represent group
	// withing the AST
	perms_rule_t(AA_CLASS_POSIX_MQUEUE),
	qtype(mqueue_unspecified), qname(qname_p), label(NULL)
{
	move_conditionals(conds);
	free_cond_list(conds);

	if (qname)
		validate_qname();
	if (perms_p) {
		// do we want to allow perms to imply type like we do for
		// qname?
		if (qtype == mqueue_posix && (perms_p & ~AA_VALID_POSIX_MQ_PERMS)) {
			yyerror("perms contains invalid permissions for mqueue type=posix\n");
		} else if (qtype == mqueue_sysv && (perms_p & ~AA_VALID_SYSV_MQ_PERMS)) {
			yyerror("perms contains invalid permissions for mqueue type=sysv\n");
		} else if (perms_p & ~AA_VALID_MQUEUE_PERMS) {
			yyerror("perms contains invalid permissions for mqueue\n");
		}
		perms = perms_p;
	} else {
		// default to all perms
		perms = AA_VALID_MQUEUE_PERMS;
	}
	qname = qname_p;

}

ostream &mqueue_rule::dump(ostream &os)
{
	class_rule_t::dump(os);

	// do we want to always put type out or leave it implied if there
	// is a qname
	if (qtype == mqueue_posix)
		os << " type=posix";
	else if (qtype == mqueue_sysv)
		os << " type=sysv";

	if (perms != AA_VALID_MQUEUE_PERMS) {
		os << " ( ";

		if (perms & AA_MQUEUE_WRITE)
			os << "write ";
		if (perms & AA_MQUEUE_READ)
			os << "read ";
		if (perms & AA_MQUEUE_OPEN)
			os << "open ";
		if (perms & AA_MQUEUE_CREATE)
			os << "create ";
		if (perms & AA_MQUEUE_DELETE)
			os << "delete ";
		if (perms & AA_MQUEUE_SETATTR)
			os << "setattr ";
		if (perms & AA_MQUEUE_GETATTR)
			os << "getattr ";

		os << ")";
	}

	if (qname)
		os << " " << qname;

	os << ",\n";

	return os;
}

int mqueue_rule::expand_variables(void)
{
	int error = expand_entry_variables(&qname);
	if (error)
		return error;
	error = expand_entry_variables(&label);
	if (error)
		return error;

	return 0;
}

/* TODO: this is not right, need separate warning for each type */
void mqueue_rule::warn_once(const char *name)
{
	if (qtype == mqueue_unspecified)
		rule_t::warn_once(name, "mqueue rules not enforced");
	else if (qtype == mqueue_posix)
		rule_t::warn_once(name, "mqueue type=posix rules not enforced");
	else if (qtype == mqueue_sysv)
		rule_t::warn_once(name, "mqueue type=sysv rules not enforced");
}

int mqueue_rule::gen_policy_re(Profile &prof)
{
	std::string labelbuf;
	std::string buf;
	const int size = 2;
	const char *vec[size];


	if (qtype == mqueue_posix && !features_supports_posix_mqueue) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	} else if (qtype == mqueue_sysv && !features_supports_sysv_mqueue) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	} else if (qtype == mqueue_unspecified &&
		   !(features_supports_posix_mqueue ||
		     features_supports_sysv_mqueue)) {
		warn_once(prof.name);
		// should split into warning where posix and sysv can
		// be separated from nothing being enforced
		return RULE_NOT_SUPPORTED;
	}

	/* always generate a label and mqueue entry */

	//buffer << "(" << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_LABEL << "|)"; //is this required?

	// posix and generic
	if (qtype != mqueue_sysv) {
		std::ostringstream buffer;
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_POSIX_MQUEUE;
		buf.assign(buffer.str());
		if (qname) {
			if (!convert_entry(buf, qname))
				goto fail;
		} else {
			buf += default_match_pattern;
		}
		vec[0] = buf.c_str();

		if (label) {
			if (!convert_entry(labelbuf, label))
				goto fail;
			vec[1] = labelbuf.c_str();
		} else {
			vec[1] = anyone_match_pattern;
		}

		if (perms & AA_VALID_POSIX_MQ_PERMS) {
			/* store perms at name match so label doesn't need
			 * to be checked
			 */
			if (!label && !prof.policy.rules->add_rule_vec(
						priority,
						rule_mode,
						map_mqueue_perms(perms),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms) : 0, 1,
						vec, parseopts, false))
				goto fail;

			/* create should be allowed when label is present since the
			 * queue needs to be created to have a label associated to it
			 */
			if (perms & AA_MQUEUE_CREATE &&
			    !prof.policy.rules->add_rule_vec(
						priority,
						rule_mode,
						map_mqueue_perms(perms & AA_MQUEUE_CREATE_PERMS),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms & AA_MQUEUE_CREATE_PERMS) : 0, 1,
						vec, parseopts, false))
				goto fail;

			/* also provide label match with perm */
			if (!prof.policy.rules->add_rule_vec(priority,
						rule_mode,
						map_mqueue_perms(perms),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms) : 0,
						size, vec, parseopts, false))
				goto fail;
		}
	}
	// sysv and generic
	if (qtype != mqueue_posix) {
		std::ostringstream buffer;
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_SYSV_MQUEUE;

		if (qname) {
			int key;
			sscanf(qname, "%d", &key);
			u32 tmp = htobe32((u32) key);
			u8 *byte = (u8 *) &tmp;
			for (int i = 0; i < 4; i++){
				buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(byte[i]);
			}
		} else {
			buffer << "....";
		}
		buf.assign(buffer.str());
		vec[0] = buf.c_str();

		if (label) {
			if (!convert_entry(labelbuf, label))
				goto fail;
			vec[1] = labelbuf.c_str();
		} else {
			vec[1] = anyone_match_pattern;
		}

		if (perms & AA_VALID_SYSV_MQ_PERMS) {
			if (!label &&
			    !prof.policy.rules->add_rule_vec(priority,
						rule_mode,
						map_mqueue_perms(perms),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms) : 0, 1,
						vec, parseopts, false))
				goto fail;

			/* create should be allowed when label is present since the
			 * queue needs to be created to have a label associated to it
			 */
			if (perms & AA_MQUEUE_CREATE &&
			    !prof.policy.rules->add_rule_vec(
						priority,
						rule_mode,
						map_mqueue_perms(perms & AA_MQUEUE_CREATE_PERMS),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms & AA_MQUEUE_CREATE_PERMS) : 0, 1,
						vec, parseopts, false))
				goto fail;

			/* also provide label match with perm */
			if (!prof.policy.rules->add_rule_vec(priority,
						rule_mode,
						map_mqueue_perms(perms),
						audit == AUDIT_FORCE ? map_mqueue_perms(perms) : 0,
						size, vec, parseopts, false))
				goto fail;
		}
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}
