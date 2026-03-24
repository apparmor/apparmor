/*
 *   Copyright (c) 2012
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
 */
#ifndef __AA_PROFILE_H
#define __AA_PROFILE_H

#ifndef aa_unused
#define aa_unused __attribute__ ((unused))
#endif

#include <set>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <map>

#include "capability.h"
#include "parser.h"
#include "rule.h"
#include "libapparmor_re/aare_rules.h"
#include "network.h"
#include "signal.h"
#include "immunix.h"
#include "perms.h"
#include "profilelist.h"

extern const char*profile_mode_table[];
/* use profile_mode_packed to convert to the packed representation */
enum class profile_mode : int {
	UNSPECIFIED = 0,
	ENFORCE = 1,
	COMPLAIN = 2,
	KILL = 3,
	UNCONFINED = 4,
	PROMPT = 5,
	DEFAULT_ALLOW = 6,
	CONFLICT = 7	/* greater than MODE_LAST */
};
static constexpr profile_mode MODE_LAST = profile_mode::DEFAULT_ALLOW;

static inline profile_mode operator++(profile_mode &mode)
{
	mode = static_cast<profile_mode>(static_cast<int>(mode) + 1);
	return mode;
}

static inline profile_mode merge_profile_mode(profile_mode l, profile_mode r)
{
	if (l == r || r == profile_mode::UNSPECIFIED)
		return l;
	else if (l == profile_mode::UNSPECIFIED)
		return r;
	return profile_mode::CONFLICT;
}

static inline uint32_t profile_mode_packed(profile_mode mode)
{
	/* until dominance is fixed use unconfined mode for default_allow */
	if (mode == profile_mode::DEFAULT_ALLOW)
		mode = profile_mode::UNCONFINED;
	/* kernel doesn't have an unspecified mode everything
	 * shifts down by 1
	 */
	if (static_cast<uint32_t>(mode))
		return static_cast<uint32_t>(mode) - 1;
	/* unspecified defaults to same as enforce */
	return 0;
}

static inline void mode_dump(ostream &os, profile_mode mode)
{
	if (mode <= MODE_LAST)
		os << profile_mode_table[static_cast<size_t>(mode)];
	else
		os << "unknown";
}

static inline profile_mode str_to_mode(const char *str)
{
	for (profile_mode i = profile_mode::ENFORCE; i <= MODE_LAST; ++i) {
		if (strcmp(profile_mode_table[static_cast<size_t>(i)], str) == 0)
			return i;
	}

	return profile_mode::UNSPECIFIED;
};

static struct {
    const char *name;
    int code;
} errnos[] = {
    #include "errnos.h"
};
static const int errnos_len = sizeof(errnos) / sizeof(errnos[0]);

static int find_error_code_mapping(const char *name)
{
	for (int i = 0; i < errnos_len; i++) {
		if (strcasecmp(errnos[i].name,  name) == 0)
			return errnos[i].code;
	}
	return -1;
}

static const char *find_error_name_mapping(int code)
{
	for (int i = 0; i < errnos_len; i++) {
		if (errnos[i].code == code)
			return errnos[i].name;
	}
	return NULL;
}

enum class profile_flag_t : unsigned int {
	NONE = 0,
	HAT = 1 << 0,
	DEBUG1 = 1 << 1,
	DEBUG2 = 1 << 2,
	INTERRUPTIBLE = 1 << 3,
	PROMPT_COMPAT = 1 << 4,
};

static inline unsigned int profile_flag_bits(profile_flag_t flags)
{
	return static_cast<unsigned int>(flags);
}

static inline profile_flag_t operator|(profile_flag_t lhs, profile_flag_t rhs)
{
	return static_cast<profile_flag_t>(profile_flag_bits(lhs) |
					  profile_flag_bits(rhs));
}

static inline profile_flag_t operator&(profile_flag_t lhs, profile_flag_t rhs)
{
	return static_cast<profile_flag_t>(profile_flag_bits(lhs) &
					  profile_flag_bits(rhs));
}

static inline profile_flag_t operator~(profile_flag_t flags)
{
	return static_cast<profile_flag_t>(~profile_flag_bits(flags));
}

static inline profile_flag_t &operator|=(profile_flag_t &lhs, profile_flag_t rhs)
{
	lhs = lhs | rhs;
	return lhs;
}

static inline profile_flag_t &operator&=(profile_flag_t &lhs, profile_flag_t rhs)
{
	lhs = lhs & rhs;
	return lhs;
}

static inline bool has_profile_flag(profile_flag_t flags, profile_flag_t flag)
{
	return profile_flag_bits(flags & flag) != 0;
}

/* sigh, used in parse union so needs trivial constructors. */
class flagvals {
public:
	profile_flag_t flags;
	profile_mode mode;
	int audit;
	int path;
	char *disconnected_path;
	char *disconnected_ipc;
	int signal;
	int error;

	// stupid not constructor constructors
	void init(void)
	{
		flags = profile_flag_t::NONE;
		mode = profile_mode::UNSPECIFIED;
		audit = 0;
		path = 0;
		disconnected_path = NULL;
		disconnected_ipc = NULL;
		signal = 0;
		error = 0;
	}

	void clear(void) {
		free(disconnected_path);
		free(disconnected_ipc);
	}

	void init(const char *str)
	{
		init();
		profile_mode pmode = str_to_mode(str);

		if (strcmp(str, "debug") == 0) {
			/* DEBUG2 is left for internal compiler use atm */
			flags |= profile_flag_t::DEBUG1;
		} else if (pmode != profile_mode::UNSPECIFIED) {
			mode = pmode;
		} else if (strcmp(str, "audit") == 0) {
			audit = 1;
		} else if (strcmp(str, "chroot_relative") == 0) {
			path |= PATH_CHROOT_REL;
		} else if (strcmp(str, "namespace_relative") == 0) {
			path |= PATH_NS_REL;
		} else if (strcmp(str, "mediate_deleted") == 0) {
			path |= PATH_MEDIATE_DELETED;
		} else if (strcmp(str, "delegate_deleted") == 0) {
			path |= PATH_DELEGATE_DELETED;
		} else if (strcmp(str, "attach_disconnected") == 0) {
			path |= PATH_ATTACH;
		} else if (strcmp(str, "no_attach_disconnected") == 0) {
			path |= PATH_NO_ATTACH;
		} else if (strcmp(str, "chroot_attach") == 0) {
			path |= PATH_CHROOT_NSATTACH;
		} else if (strcmp(str, "chroot_no_attach") == 0) {
			path |= PATH_CHROOT_NO_ATTACH;
		} else if (strncmp(str, "attach_disconnected.path=", 25) == 0) {
			/* TODO: make this a proper parse */
			path |= PATH_ATTACH;
			disconnected_path = strdup(str + 25);
		} else if (strncmp(str, "kill.signal=", 12) == 0) {
			/* TODO: make this a proper parse */
			signal = find_signal_mapping(str + 12);
			if (signal == -1)
				yyerror("unknown signal specified for kill.signal=\'%s\'\n", str + 12);
		} else if (strncmp(str, "error=", 6) == 0) {
			error = find_error_code_mapping(str + 6);
			if (error == -1)
				yyerror("unknown error code specified for error=\'%s\'\n", str + 6);
		} else if (strcmp(str, "interruptible") == 0) {
				flags |= profile_flag_t::INTERRUPTIBLE;
		} else if (strcmp(str, "attach_disconnected.ipc") == 0) {
			path |= PATH_IPC_ATTACH;
		} else if (strncmp(str, "attach_disconnected.ipc=", 24) == 0) {
			/* TODO: make this a proper parse */
			path |= PATH_IPC_ATTACH;
			disconnected_ipc = strdup(str + 24);
		} else {
			yyerror(_("Invalid profile flag: %s."), str);
		}
	}

	ostream &dump(ostream &os)
	{
		os << "Mode: ";
		mode_dump(os, mode);
		if (audit)
			os << ", Audit";

		if (has_profile_flag(flags, profile_flag_t::HAT))
			os << ", Hat";

		if (disconnected_path)
			os << ", attach_disconnected.path=" << disconnected_path;
		if (signal)
			os << ", kill.signal=" << signal;
		if (error)
			os << ", error=" << find_error_name_mapping(error);
		if (disconnected_ipc)
			os << ", attach_disconnected.ipc=" << disconnected_ipc;

		if (has_profile_flag(flags, profile_flag_t::PROMPT_COMPAT))
			os << ", prompt_dev";

		os << "\n";

		return os;
	}
	ostream &debug(ostream &os)
	{
#ifdef DEBUG
		return dump(os);
#else
		return os;
#endif
	}

	/* warning for now disconnected_path is just passed on (not copied),
	 * or leaked on error. It is not freed here, It is freed when the
	 * profile destroys it self.
	 */
	void merge(const flagvals &rhs)
	{
		if (merge_profile_mode(mode, rhs.mode) == profile_mode::CONFLICT)
			yyerror(_("Profile flag '%s' conflicts with '%s'"),
				profile_mode_table[static_cast<size_t>(mode)],
				profile_mode_table[static_cast<size_t>(rhs.mode)]);
		mode = merge_profile_mode(mode, rhs.mode);
		audit = audit || rhs.audit;
		path = path | rhs.path;
		if ((path & (PATH_CHROOT_REL | PATH_NS_REL)) ==
		    (PATH_CHROOT_REL | PATH_NS_REL))
			yyerror(_("Profile flag chroot_relative conflicts with namespace_relative"));

		if ((path & (PATH_MEDIATE_DELETED | PATH_DELEGATE_DELETED)) ==
		    (PATH_MEDIATE_DELETED | PATH_DELEGATE_DELETED))
			yyerror(_("Profile flag mediate_deleted conflicts with delegate_deleted"));
		if ((path & (PATH_ATTACH | PATH_NO_ATTACH)) ==
		    (PATH_ATTACH | PATH_NO_ATTACH))
			yyerror(_("Profile flag attach_disconnected conflicts with no_attach_disconnected"));
		if ((path & (PATH_IPC_ATTACH | PATH_NO_ATTACH)) ==
		    (PATH_IPC_ATTACH | PATH_NO_ATTACH))
			yyerror(_("Profile flag attach_disconnected.ipc conflicts with no_attach_disconnected"));
		if ((path & (PATH_CHROOT_NSATTACH | PATH_CHROOT_NO_ATTACH)) ==
		    (PATH_CHROOT_NSATTACH | PATH_CHROOT_NO_ATTACH))
			yyerror(_("Profile flag chroot_attach conflicts with chroot_no_attach"));

		if (rhs.disconnected_path) {
			if (disconnected_path) {
				if (strcmp(disconnected_path, rhs.disconnected_path) != 0) {
					yyerror(_("Profile flag attach_disconnected set to conflicting values: '%s' and '%s'"), disconnected_path, rhs.disconnected_path);
				}
				// same ignore rhs.disconnect_path
			} else {
				disconnected_path = strdup(rhs.disconnected_path);
			}
		}
		if (rhs.disconnected_ipc) {
			if (disconnected_ipc) {
				if (strcmp(disconnected_ipc, rhs.disconnected_ipc) != 0) {
					yyerror(_("Profile flag attach_disconnected set to conflicting values: '%s' and '%s'"), disconnected_ipc, rhs.disconnected_ipc);
				}
				// same so do nothing
			} else {
				disconnected_ipc = strdup(rhs.disconnected_ipc);
			}
		}
		if (rhs.signal) {
			if (signal) {
				if (signal != rhs.signal) {
					yyerror(_("Profile flag kill.signal set to conflicting values: '%d' and '%d'"), signal, rhs.signal);
				}
				// same so do nothing
			} else {
				signal = rhs.signal;
			}
		}
		if (rhs.error) {
			if (error) {
				if (error != rhs.error) {
					yyerror(_("Profile flag error set to conflicting values: '%s' and '%s'"), find_error_name_mapping(error), find_error_name_mapping(rhs.error));
				}
				// same so do nothing
			} else {
				error = rhs.error;
			}
		}


		/* if we move to duplicating disconnected_path it will need to have
		 * an assignment and copy constructor and a destructor
		 */
	}
};

struct capabilities {
	uint64_t allow;
	uint64_t audit;
	uint64_t deny;
	uint64_t quiet;

	capabilities(void) { allow = audit = deny = quiet = 0; }

	void dump()
		{
			if (allow != 0ull)
				__debug_capabilities(allow, "Capabilities");
			if (audit != 0ull)
				__debug_capabilities(audit, "Audit Caps");
			if (deny != 0ull)
				__debug_capabilities(deny, "Deny Caps");
			if (quiet != 0ull)
				__debug_capabilities(quiet, "Quiet Caps");
		};
};

struct dfa_stuff {
	aare_rules *rules;
	void *dfa;
	size_t size;
	size_t file_start;		/* special start in welded dfa */
	std::vector <aa_perms> perms_table;
	dfa_stuff(void): rules(NULL), dfa(NULL), size(0) { }
};

class Profile final {
public:
	bool uses_prompt_rules;
	char *ns;
	char *name;
	char *attachment;
	struct alt_name *altnames;
	struct value_list *identities;
	void *xmatch;
	size_t xmatch_size;
	int xmatch_len;
	std::vector <aa_perms> xmatch_perms_table;
	struct cond_entry_list xattrs;

	/* char *sub_name; */			/* subdomain name or NULL */
	/* bool default_deny; */
	bool local;

	Profile *parent;

	flagvals flags;
	struct capabilities caps;
	network_rule net;

	struct aa_rlimits rlimits;

	char *exec_table[AA_EXEC_COUNT];
	struct cod_entry *entries;
	RuleList rule_ents;

	ProfileList hat_table;

	struct dfa_stuff dfa;
	struct dfa_stuff policy;

	Profile(void)
	{
		uses_prompt_rules = false;
		ns = name = attachment = NULL;
		altnames = NULL;
		xmatch = NULL;
		xmatch_size = 0;
		xmatch_len = 0;

		xattrs.list = NULL;
		xattrs.name = NULL;

		identities = NULL;
		parent = NULL;

		flags.init();
		rlimits = {0, {}};

		std::fill(exec_table, exec_table + AA_EXEC_COUNT, (char *)NULL);

		entries = NULL;
	};

	~Profile();

	bool operator<(Profile const &rhs)const
	{
		if (ns) {
			if (rhs.ns) {
				int res = strcmp(ns, rhs.ns);
				if (res != 0)
					return res < 0;
			} else
				return false;
		} else if (rhs.ns)
			return true;
		return strcmp(name, rhs.name) < 0;
	}

	/*
	 * Requires the merged rules have customized methods
	 * cmp(), is_mergeable() and merge()
	 */
	virtual int merge_rules(void);

	void dump(void)
	{
		if (ns)
			printf("Ns:\t\t%s\n", ns);

		if (name)
			printf("Name:\t\t%s\n", name);
		else
			printf("Name:\t\t<NULL>\n");
		if (attachment)
			printf("Attachment:\t%s\n", attachment);
		else {
			const char *local = local_name(name);
			printf("Attachment:\t%s\n", local[0] == '/' ? local : "<NULL>");
		}
		if (parent)
			printf("Local To:\t%s\n", parent->name);
		else
			printf("Local To:\t<NULL>\n");

		if (identities) {
			printf("Identities:\t(");
			print_value_list(identities, std::cout);
			printf(")\n");
		}

		flags.dump(cerr);
		caps.dump();

		if (entries)
			debug_cod_entries(entries);

		std::map<rule_t *, unsigned int> visible_rule_lines;
		unsigned int fake_lineno = 1;
		for (auto i = rule_ents.cbegin(); i != rule_ents.cend(); i++) {
			if ((*i)->skip()) {
				if (((*i)->flags & rule_flags_t::MERGED) != rule_flags_t::NONE && (*i)->removed_by)
					fake_lineno += 2;  // merged rules print two lines.
				continue;
			}
			visible_rule_lines[*i] = fake_lineno++;
		}

		fake_lineno = 1;
		for (auto i = rule_ents.cbegin(); i != rule_ents.cend(); i++) {
			if ((*i)->skip()) {
				if (((*i)->flags & rule_flags_t::MERGED) != rule_flags_t::NONE && (*i)->removed_by) {
					auto merged_into = visible_rule_lines.find((*i)->removed_by);
					std::cout << fake_lineno << ": # The following rule was merged into a rule on line " << merged_into->second << std::endl;
					fake_lineno++;
					std::cout << fake_lineno << ": # ";
					(*i)->dump(std::cout);
					fake_lineno++; // account for the extra comment.
				}
				continue;
			}
			std::cout << fake_lineno << ": ";
			(*i)->dump(std::cout);
			fake_lineno++;
		}

		printf("\n");
		hat_table.dump();
	}

	std::string hname(void)
	{
		if (!parent)
			return name;

		return parent->hname() + "//" + name;
	}

	/* assumes ns is set as part of profile creation */
	std::string fqname(void)
	{
		if (parent)
			return parent->fqname() + "//" + name;
		else if (!ns)
			return hname();
		return ":" + std::string(ns) + "://" + hname();
	}

	std::string get_name(bool fqp)
	{
		if (fqp)
			return fqname();
		return hname();
	}

	void dump_name(bool fqp)
	{
		std::cout << get_name(fqp);;
	}

	void post_parse_profile(void);
	void add_implied_rules(void);

protected:
	const char *warned_name = NULL;
	virtual void warn_once(const char *name, const char *msg);
};


#endif /* __AA_PROFILE_H */
