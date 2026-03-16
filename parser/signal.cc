/*
 *   Copyright (c) 2014
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

#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>

#include <iomanip>
#include <string>
#include <sstream>
#include <unordered_map>

#include "parser.h"
#include "profile.h"
#include "parser_yacc.h"
#include "signal.h"

using namespace std;

#define MAXMAPPED_SIG 35
#define MINRT_SIG 128		/* base of RT sigs */
#define MAXRT_SIG 32		/* Max RT above MINRT_SIG */

/* Signal names mapped to and internal ordering */
static unordered_map<string, int> signal_map = {
	{"hup",		1},
	{"int",		2},
	{"quit",	3},
	{"ill",		4},
	{"trap",	5},
	{"abrt",	6},
	{"bus",		7},
	{"fpe",		8},
	{"kill",	9},
	{"usr1",	10},
	{"segv",	11},
	{"usr2",	12},
	{"pipe",	13},
	{"alrm",	14},
	{"term",	15},
	{"stkflt",	16},
	{"chld",	17},
	{"cont",	18},
	{"stop",	19},
	{"stp",		20}, // parser's previous name for SIGTSTP
	{"tstp",	20},
	{"ttin",	21},
	{"ttou",	22},
	{"urg",		23},
	{"xcpu",	24},
	{"xfsz",	25},
	{"vtalrm",	26},
	{"prof",	27},
	{"winch",	28},
	{"io",		29}, // SIGIO == SIGPOLL
	{"poll",	29},
	{"pwr",		30},
	{"sys",		31},
	{"emt",		32},
	{"exists",	35},
};

/* this table is ordered post sig_map[sig] mapping */
static const char *const sig_names[MAXMAPPED_SIG + 1] = {
	"unknown",
	"hup",
	"int",
	"quit",
	"ill",
	"trap",
	"abrt",
	"bus",
	"fpe",
	"kill",
	"usr1",
	"segv",
	"usr2",
	"pipe",
	"alrm",
	"term",
	"stkflt",
	"chld",
	"cont",
	"stop",
	"tstp",
	"ttin",
	"ttou",
	"urg",
	"xcpu",
	"xfsz",
	"vtalrm",
	"prof",
	"winch",
	"io", // SIGIO == SIGPOLL
	"pwr",
	"sys",
	"emt",
	"lost",
	"unused",

	"exists",	/* always last existence test mapped to MAXMAPPED_SIG */
};


int parse_signal_perms(const char *str_perms, perm32_t *perms, int fail)
{
	return parse_X_perms("signal", AA_VALID_SIGNAL_PERMS, str_perms, perms, fail);
}

int find_signal_mapping(const char *sig)
{
	if (strncmp("rtmin+", sig, 6) == 0) {
		char *end;
		unsigned long n = strtoul(sig + 6, &end, 10);
		if (end == sig || n > MAXRT_SIG)
			return -1;
		return MINRT_SIG + n;
	} else {
		// Can't use string_view because that requires C++17
		auto sigmap = signal_map.find(string(sig));
		if (sigmap != signal_map.end()) {
			return sigmap->second;
		} else {
			return -1;
		}
	}
}

void signal_rule::extract_sigs(struct value_list **list)
{
	struct value_list *entry, *tmp, *prev = NULL;
	list_for_each_safe(*list, entry, tmp) {
		int i = find_signal_mapping(entry->value);
		if (i != -1) {
			signals.insert(i);
			list_remove_at(*list, prev, entry);
			free_value_list(entry);
		} else {
			yyerror("unknown signal \"%s\"\n", entry->value);
			prev = entry;
		}
	}
}

void signal_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		/* for now allow only '=' */
		if (cond_ent->comp != cond_comp::EQ)
			yyerror("only \"=\" allowed in conditions of signal rules\n");
		if (strcmp(cond_ent->name, "set") == 0) {
			extract_sigs(&cond_ent->vals);
		} else if (strcmp(cond_ent->name, "peer") == 0) {
			move_conditional_value("signal", &peer_label, cond_ent);
		} else {
			yyerror("invalid signal rule conditional \"%s\"\n",
				cond_ent->name);
		}
	}
}

signal_rule::signal_rule(perm32_t perms_p, struct cond_entry *conds):
	perms_rule_t(AA_CLASS_SIGNAL), signals(), peer_label(NULL)
{
	if (perms_p) {
		perms = perms_p;
		if (perms & ~AA_VALID_SIGNAL_PERMS)
			yyerror("perms contains invalid permission for signals\n");
	} else {
		perms = AA_VALID_SIGNAL_PERMS;
	}

	move_conditionals(conds);

	free_cond_list(conds);
}

ostream &signal_rule::dump(ostream &os)
{
	class_rule_t::dump(os);

	if (perms != AA_VALID_SIGNAL_PERMS) {
		os << " (";

		if (perms & AA_MAY_SEND)
			os << "send ";
		if (perms & AA_MAY_RECEIVE)
			os << "receive ";
		os << ")";
	}

	if (!signals.empty()) {
		os << " set=(";
		for (Signals::iterator i = signals.begin(); i != signals.end();
		     i++) {
			if (i != signals.begin())
				os << ", ";
			if (*i < MINRT_SIG)
				os << sig_names[*i];
			else
				os << "rtmin+" << (*i - MINRT_SIG);
		}
		os << ")";
	}

	if (peer_label)
		os << " " << peer_label;

	os << ",\n";

	return os;
}

int signal_rule::expand_variables(void)
{
	return expand_entry_variables(&peer_label);
}

static int cmp_set_int(Signals const &lhs, Signals const &rhs)
{
	int res = lhs.size() - rhs.size();
	if (res)
		return res;

	for (Signals::iterator i = lhs.begin(),
			       j = rhs.begin();
	     i != lhs.end(); i++, j++) {
		res = *i - *j;
		if (res)
			return res;
	}

	return 0;
}

int signal_rule::cmp(rule_t const &rhs) const
{
	int res = perms_rule_t::cmp(rhs);
	if (res)
		return res;
	signal_rule const &trhs = rule_cast<signal_rule const &>(rhs);
	res = null_strcmp(peer_label, trhs.peer_label);
	if (res)
		return res;
	return cmp_set_int(signals, trhs.signals);
}

void signal_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "signal rules not enforced");
}

int signal_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer;
	std::string buf;

	pattern_t ptype;
	int pos;

	/* Currently do not generate the rules if the kernel doesn't support
	 * it. We may want to switch this so that a compile could be
	 * used for full support on kernels that don't support the feature
	 */
	if (!features_supports_signal) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}

	if (signals.size() == 0) {
		/* not conditional on signal set, so will generate a label
		 * rule as well
		 */
		buffer << "(" << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_LABEL << "\\x" << AA_CLASS_SIGNAL << "|";
	}

	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_SIGNAL;

	if (signals.size()) {
		buffer << "[";
		for (Signals::iterator i = signals.begin(); i != signals.end(); i++) {
			buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << *i;
		}
		buffer << "]";
	} else {
		/* match any char */
		buffer << ".";
	}

	if (signals.size() == 0) {
		/* close alternation */
		buffer << ")";
	}
	if (peer_label) {
		ptype = convert_aaregex_to_pcre(peer_label, 0, glob_default, buf, &pos);
		if (ptype == ePatternInvalid)
			goto fail;
		buffer << buf;
	} else {
		buffer << anyone_match_pattern;
	}

	buf = buffer.str();
	if (perms & (AA_MAY_SEND | AA_MAY_RECEIVE)) {
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					rule_mode,
					perms, audit == AUDIT_FORCE ? perms : 0,
					parseopts))
			goto fail;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}
