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

#include "capability.h"
#include "parser.h"
#include "rule.h"
#include "libapparmor_re/aare_rules.h"
#include "network.h"
#include "signal.h"
#include "immunix.h"
#include "perms.h"

class Profile;

class block {
public:

};


struct deref_profileptr_lt {
	bool operator()(Profile * const &lhs, Profile * const &rhs) const;
};

class ProfileList {
public:
	std::set<Profile *, deref_profileptr_lt> list;

	typedef std::set<Profile *, deref_profileptr_lt>::iterator iterator;
	iterator begin() { return list.begin(); }
	iterator end() { return list.end(); }

	ProfileList() { };
	virtual ~ProfileList() { clear(); }
	virtual bool empty(void) { return list.empty(); }
	virtual std::pair<ProfileList::iterator,bool> insert(Profile *);
	virtual void erase(ProfileList::iterator pos);
	void clear(void);
	void dump(void);
	void dump_profile_names(bool children);
};

extern const char*profile_mode_table[];
/* use profile_mode_packed to convert to the packed representation */
enum profile_mode {
	MODE_UNSPECIFIED = 0,
	MODE_ENFORCE = 1,
	MODE_COMPLAIN = 2,
	MODE_KILL = 3,
	MODE_UNCONFINED = 4,
	MODE_PROMPT = 5,
	MODE_DEFAULT_ALLOW = 6,
	MODE_CONFLICT = 7	/* greater than MODE_LAST */
};
#define MODE_LAST MODE_DEFAULT_ALLOW

static inline enum profile_mode operator++(enum profile_mode &mode)
{
	mode = (enum profile_mode)((int) mode + 1);
	return mode;
}

static inline enum profile_mode merge_profile_mode(enum profile_mode l, enum profile_mode r)
{
	if (l == r || r == MODE_UNSPECIFIED)
		return l;
	else if (l == MODE_UNSPECIFIED)
		return r;
	return MODE_CONFLICT;
}

static inline uint32_t profile_mode_packed(enum profile_mode mode)
{
	/* until dominance is fixed use unconfined mode for default_allow */
	if (mode == MODE_DEFAULT_ALLOW)
		mode = MODE_UNCONFINED;
	/* kernel doesn't have an unspecified mode everything
	 * shifts down by 1
	 */
	if ((uint32_t) mode)
		return (uint32_t) mode - 1;
	/* unspecified defaults to same as enforce */
	return 0;
}

static inline void mode_dump(ostream &os, enum profile_mode mode)
{
	if (mode <= MODE_LAST)
		os << profile_mode_table[(int) mode];
	else
		os << "unknown";
}

static inline enum profile_mode str_to_mode(const char *str)
{
	for (enum profile_mode i = MODE_ENFORCE; i <= MODE_LAST; ++i) {
		if (strcmp(profile_mode_table[i], str) == 0)
			return i;
	}

	return MODE_UNSPECIFIED;
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

#define FLAG_HAT 1
#define FLAG_DEBUG1 2
#define FLAG_DEBUG2 4
#define FLAG_INTERRUPTIBLE 8
#define FLAG_PROMPT_COMPAT 0x10

/* sigh, used in parse union so needs trivial constructors. */
class flagvals {
public:
	int flags;
	enum profile_mode mode;
	int audit;
	int path;
	char *disconnected_path;
	char *disconnected_ipc;
	int signal;
	int error;

	// stupid not constructor constructors
	void init(void)
	{
		flags = 0;
		mode = MODE_UNSPECIFIED;
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
		enum profile_mode pmode = str_to_mode(str);

		if (strcmp(str, "debug") == 0) {
			/* DEBUG2 is left for internal compiler use atm */
			flags |= FLAG_DEBUG1;
		} else if (pmode) {
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
				flags |= FLAG_INTERRUPTIBLE;
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

		if (flags & FLAG_HAT)
			os << ", Hat";

		if (disconnected_path)
			os << ", attach_disconnected.path=" << disconnected_path;
		if (signal)
			os << ", kill.signal=" << signal;
		if (error)
			os << ", error=" << find_error_name_mapping(error);
		if (disconnected_ipc)
			os << ", attach_disconnected.ipc=" << disconnected_ipc;

		if (flags & FLAG_PROMPT_COMPAT)
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
		if (merge_profile_mode(mode, rhs.mode) == MODE_CONFLICT)
			yyerror(_("Profile flag '%s' conflicts with '%s'"),
				profile_mode_table[mode],
				profile_mode_table[rhs.mode]);
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


		/* if we move to dupping disconnected_path will need to have
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

class Profile {
public:
	bool uses_prompt_rules;
	char *ns;
	char *name;
	char *attachment;
	struct alt_name *altnames;
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

		parent = NULL;

		flags.init();
		rlimits = {0, {}};

		std::fill(exec_table, exec_table + AA_EXEC_COUNT, (char *)NULL);

		entries = NULL;
	};

	virtual ~Profile();

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

		flags.dump(cerr);
		caps.dump();

		if (entries)
			debug_cod_entries(entries);

		for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++) {
			(*i)->dump(std::cout);
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
