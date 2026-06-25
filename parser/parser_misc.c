/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2013
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
 *   along with this program; if not, contact Novell, Inc.
 */

/* assistance routines */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/apparmor.h>
#include <sys/apparmor_private.h>

#include <algorithm>
#include <unordered_map>

#include "capability.h"
#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "parser_yacc.h"
#include "mount.h"
#include "dbus.h"

/* #define DEBUG */
#ifdef DEBUG
#undef PDEBUG
#define PDEBUG(fmt, args...) fprintf(stderr, "Lexer: " fmt, ## args)
#else
#undef PDEBUG
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	return realloc(ptr, nmemb * size);
}
#endif

#ifndef NULL
#define NULL nullptr
#endif

using namespace std;

int is_blacklisted(const char *name, const char *path)
{
	int retval = _aa_is_blacklisted(name);

	if (retval == -1)
		PERROR("Ignoring: '%s'\n", path ? path : name);

	return !retval ? 0 : 1;
}

static const unordered_map<string, int> keyword_table = {
	/* network */
	{"network",		TOK_NETWORK},
	{"unix",		TOK_UNIX},
	/* misc keywords */
	{"capability",		TOK_CAPABILITY},
	{"if",			TOK_IF},
	{"else",		TOK_ELSE},
	{"not",			TOK_NOT},
	{"defined",		TOK_DEFINED},
	{"change_profile",	TOK_CHANGE_PROFILE},
	{"unsafe",		TOK_UNSAFE},
	{"safe",		TOK_SAFE},
	{"link",		TOK_LINK},
	{"owner",		TOK_OWNER},
	{"user",		TOK_OWNER},
	{"other",		TOK_OTHER},
	{"subset",		TOK_SUBSET},
	{"audit",		TOK_AUDIT},
	{"deny",		TOK_DENY},
	{"allow",		TOK_ALLOW},
	{"prompt",		TOK_PROMPT},
	{"set",			TOK_SET},
	{"rlimit",		TOK_RLIMIT},
	{"alias",		TOK_ALIAS},
	{"rewrite",		TOK_ALIAS},
	{"ptrace",		TOK_PTRACE},
	{"file",		TOK_FILE},
	{"mount",		TOK_MOUNT},
	{"remount",		TOK_REMOUNT},
	{"umount",		TOK_UMOUNT},
	{"unmount",		TOK_UMOUNT},
	{"pivot_root",		TOK_PIVOTROOT},
	{"in",			TOK_IN},
	{"dbus",		TOK_DBUS},
	{"signal",		TOK_SIGNAL},
	{"send",                TOK_SEND},
	{"receive",             TOK_RECEIVE},
	{"bind",                TOK_BIND},
	{"read",                TOK_READ},
	{"write",               TOK_WRITE},
	{"eavesdrop",		TOK_EAVESDROP},
	{"peer",		TOK_PEER},
	{"trace",		TOK_TRACE},
	{"tracedby",		TOK_TRACEDBY},
	{"readby",		TOK_READBY},
	{"abi",			TOK_ABI},
	{"userns",		TOK_USERNS},
	{"mqueue",		TOK_MQUEUE},
	{"delete",		TOK_DELETE},
	{"open",		TOK_OPEN},
	{"io_uring",		TOK_IO_URING},
	{"override_creds",	TOK_OVERRIDE_CREDS},
	{"sqpoll",		TOK_SQPOLL},
	{"all",			TOK_ALL},
	{"priority",		TOK_PRIORITY},
	{"and",			TOK_AND},
	{"or",			TOK_OR},
};

/* glibc maps bsd ofile to nofile but musl does not. */
#ifndef RLIMIT_OFILE
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif

static const unordered_map<string, int> rlimit_table = {
	{"cpu",			RLIMIT_CPU},
	{"fsize",		RLIMIT_FSIZE},
	{"data",		RLIMIT_DATA},
	{"stack",		RLIMIT_STACK},
	{"core",		RLIMIT_CORE},
	{"rss",			RLIMIT_RSS},
	{"nofile",		RLIMIT_NOFILE},
	{"ofile",		RLIMIT_OFILE},
	{"as",			RLIMIT_AS},
	{"nproc",		RLIMIT_NPROC},
	{"memlock",		RLIMIT_MEMLOCK},
	{"locks",		RLIMIT_LOCKS},
	{"sigpending",		RLIMIT_SIGPENDING},
	{"msgqueue",		RLIMIT_MSGQUEUE},
#ifdef RLIMIT_NICE
	{"nice",		RLIMIT_NICE},
#endif
#ifdef RLIMIT_RTPRIO
	{"rtprio",		RLIMIT_RTPRIO},
#endif
#ifdef RLIMIT_RTTIME
	{"rttime",		RLIMIT_RTTIME},
#endif
};

/* for alpha matches, check for keywords */
static int get_table_token(const char *name aa_unused, const unordered_map<string, int> &table,
			   const string &keyword)
{
	auto token_entry = table.find(keyword);
	if (token_entry == table.end()) {
		PDEBUG("Unable to find %s %s\n", name, keyword.c_str());
		return -1;
	} else {
		PDEBUG("Found %s %s\n", name, keyword.c_str());
		return token_entry->second;
	}
}

/* for alpha matches, check for keywords */
int get_keyword_token(const char *keyword)
{
	// Can't use string_view because that requires C++17
	return get_table_token("keyword", keyword_table, string(keyword));
}

int get_rlimit(const char *name)
{
	// Can't use string_view because that requires C++17
	return get_table_token("rlimit", rlimit_table, string(name));
}


/*
 * WARNING: if the format of the following table is changed then
 *          the Makefile targets, cap_names.h and generated_cap_names.h
 *          must be updated.
 */
struct capability_table {
	const char *name;
	unsigned int cap;
	unsigned int backmap;
	capability_flags flags;
};

/*
 * Enum for the results of adding a capability, with values assigned to match
 * the int values returned by the old capable_add_cap function:
 *
 * -1: error
 *  0: no change - capability already in table
 *  1: added flag to capability in table
 *  2: added new capability
 */
enum add_cap_result {
	ERROR = -1, // Was only used for OOM conditions
	ALREADY_EXISTS = 0,
	FLAG_ADDED = 1,
	CAP_ADDED = 2
};

static struct capability_table base_capability_table[] = {
	/* capabilities */
	#include "cap_names.h"
};
static const size_t BASE_CAP_TABLE_SIZE = sizeof(base_capability_table)/sizeof(struct capability_table);

class capability_lookup {
	vector<capability_table> cap_table;
	// Use unordered_map to avoid pulling in two map implementations
	// We may want to switch to boost::multiindex to avoid duplication
	unordered_map<string, capability_table&> name_cap_map;
	unordered_map<unsigned int, capability_table&> int_cap_map;

	private:
	void add_capability_table_entry_raw(capability_table entry) {
		cap_table.push_back(entry);
		capability_table &entry_ref = cap_table.back();
		name_cap_map.emplace(string(entry_ref.name), entry_ref);
		int_cap_map.emplace(entry_ref.cap, entry_ref);
	}
	public:
	capability_lookup() :
			cap_table(vector<capability_table>()),
			name_cap_map(unordered_map<string, capability_table&>(BASE_CAP_TABLE_SIZE)),
			int_cap_map(unordered_map<unsigned int, capability_table&>(BASE_CAP_TABLE_SIZE)) {
		cap_table.reserve(BASE_CAP_TABLE_SIZE);
		for (size_t i=0; i<BASE_CAP_TABLE_SIZE; i++) {
			add_capability_table_entry_raw(base_capability_table[i]);
		}
	}

	capability_table* find_cap_entry_by_name(string const & name) const {
		auto map_entry = this->name_cap_map.find(name);
		if (map_entry == this->name_cap_map.end()) {
			return NULL;
		} else {
			PDEBUG("Found %s %s\n", name.c_str(), map_entry->second.name);
			return &map_entry->second;
		}
	}

	capability_table* find_cap_entry_by_num(unsigned int cap) const {
		auto map_entry = this->int_cap_map.find(cap);
		if (map_entry == this->int_cap_map.end()) {
			return NULL;
		} else {
			PDEBUG("Found %d %d\n", cap, map_entry->second.cap);
			return &map_entry->second;
		}
	}

	int name_to_capability(string const &cap) const {
		auto map_entry = this->name_cap_map.find(cap);
		if (map_entry == this->name_cap_map.end()) {
			PDEBUG("Unable to find %s %s\n", "capability", cap.c_str());
			return -1;
		} else {
			return map_entry->second.cap;
		}
	}

	const char *capability_to_name(unsigned int cap) const {
		auto map_entry = this->int_cap_map.find(cap);
		if (map_entry == this->int_cap_map.end()) {
			return "invalid-capability";
		} else {
			return map_entry->second.name;
		}
	}

	int capability_backmap(unsigned int cap) const {
		auto map_entry = this->int_cap_map.find(cap);
		if (map_entry == this->int_cap_map.end()) {
			return NO_BACKMAP_CAP;
		} else {
			return map_entry->second.backmap;
		}
	}

	bool capability_in_kernel(unsigned int cap) const {
		auto map_entry = this->int_cap_map.find(cap);
		if (map_entry == this->int_cap_map.end()) {
			return false;
		} else {
			return (map_entry->second.flags & capability_flags::KERNEL_FEATURE) != capability_flags::CLEAR;
		}
	}

	void __debug_capabilities(uint64_t capset, const char *name) const {
		printf("%s:", name);

		for (auto it = this->cap_table.cbegin(); it != this->cap_table.cend(); it++) {
			if ((1ull << it->cap) & capset)
				printf (" %s", it->name);
		}
		printf("\n");
	}

	add_cap_result capable_add_cap(string const & str, unsigned int cap,
			    capability_flags flag) {
		struct capability_table *ent = this->find_cap_entry_by_name(str);
		if (ent) {
			if (ent->cap != cap) {
				pwarn(WARN_UNEXPECTED, "feature capability '%s:%d' does not equal expected %d. Ignoring ...\n", str.c_str(), cap, ent->cap);
				/* TODO: make warn to error config */
				return add_cap_result::ALREADY_EXISTS;
			}
			if ((ent->flags & flag) != capability_flags::CLEAR)
				return add_cap_result::ALREADY_EXISTS;
			ent->flags |= flag;
			return add_cap_result::FLAG_ADDED;
		} else {
			struct capability_table new_entry;
			new_entry.name = strdup(str.c_str());
			if (!new_entry.name) {
				yyerror(_("Out of memory"));
				return add_cap_result::ERROR;
			}
			new_entry.cap = cap;
			new_entry.backmap = 0;
			new_entry.flags = flag;
			try {
				this->add_capability_table_entry_raw(new_entry);
			} catch (const std::bad_alloc &_e) {
				yyerror(_("Out of memory"));
				return add_cap_result::ERROR;
			}
			// TODO: exception catching for causes other than OOM
			return add_cap_result::CAP_ADDED;
		}
	}

	void clear_cap_flag(capability_flags flags)
	{
		for (auto it = this->cap_table.begin(); it != this->cap_table.end(); it++) {
			PDEBUG("Clearing capability flag for capability \"%s\"\n",  it->name);
			it->flags &= ~flags;
		}
	}
};

static capability_lookup cap_table;

/* don't mark up str with \0 */
static const char *strn_token(const char *str, size_t &len)
{
	const char *start;

	while (isspace(*str))
		str++;
	start = str;
	while (*str && !isspace(*str))
		str++;
	if (start == str)
		return NULL;

	len = str - start;
	return start;
}

int null_strcmp(const char *s1, const char *s2)
{
	if (s1) {
		if (s2)
			return strcmp(s1, s2);
		return 1;
	} else if (s2) {
		return -1;
	}

	// both null
	return 0;
}

bool strcomp (const char *lhs, const char *rhs)
{
	return null_strcmp(lhs, rhs) < 0;
}

bool add_cap_feature_mask(struct aa_features *features, capability_flags flags)
{
	autofree char *value = NULL;
	const char *capstr;
	size_t valuelen, len = 0;
	int n;

	value = aa_features_value(features, "caps/mask", &valuelen);
	if (!value)
		/* nothing to add, just use existing set */
		return true;

	n = 0;
	for (capstr = strn_token(value, len);
	     capstr;
	     capstr = strn_token(capstr + len, len)) {
		string capstr_as_str = string(capstr, len);
		if (cap_table.capable_add_cap(capstr_as_str, n, flags) < 0)
			return false;
		n++;
		if (len > valuelen) {
			PDEBUG("caplen is > remaining feature string");
			return false;
		}
		valuelen -= len;
		PDEBUG("Adding %d capabilities\n", n);
	}

	return true;
}

void clear_cap_flag(capability_flags flags)
{
	cap_table.clear_cap_flag(flags);
}

int name_to_capability(const char *cap)
{
	return cap_table.name_to_capability(string(cap));
}

const char *capability_to_name(unsigned int cap)
{
	return cap_table.capability_to_name(cap);
}

int capability_backmap(unsigned int cap)
{
	return cap_table.capability_backmap(cap);
}

bool capability_in_kernel(unsigned int cap)
{
	return cap_table.capability_in_kernel(cap);
}

void __debug_capabilities(uint64_t capset, const char *name)
{
	cap_table.__debug_capabilities(capset, name);
}

char *processunquoted(const char *string, int len)
{
	char *buffer, *s;

	s = buffer = (char *) malloc(len + 1);
	if (!buffer)
		return NULL;

	while (len > 0) {
		const char *pos = string + 1;
		long c;
		if (*string == '\\' && len > 1 &&
		    (c = strn_escseq(&pos, "", len)) != -1) {
			/* catch \\ or \134 and other aare special chars and
			 * pass it through to be handled by the backend
			 * pcre conversion
			 */
			if (c == 0) {
				strncpy(s, string, pos - string);
				s += pos - string;
			} else if (strchr("*?[]{}^,\\", c) != NULL) {
				*s++ = '\\';
				*s++ = c;
			} else
				*s++ = c;
			len -= pos - string;
			string = pos;
		} else {
			/* either unescaped char OR
			 * unsupported escape sequence resulting in char being
			 * copied.
			 */
			*s++ = *string++;
			len--;
		}
	}
	*s = 0;

	return buffer;
}

/* rewrite a quoted string substituting escaped characters for the
 * real thing.  Strip the quotes around the string */
char *processquoted(const char *string, int len)
{
	/* skip leading " and eat trailing " */
	if (*string == '"') {
		if (string[len -1] != '"')
			return NULL;
		len -= 2;
		if (len < 0)	/* start and end point to same quote */
			len = 0;
		return processunquoted(string + 1, len);
	}

	/* no quotes? treat as unquoted */
	return processunquoted(string, len);
}

char *processid(const char *string, int len)
{
	/* lexer should never call this fn if len <= 0 */
	assert(len > 0);

	if (*string == '"')
		return processquoted(string, len);
	return processunquoted(string, len);
}

/* returns -1 if value != true or false, otherwise 0 == false, 1 == true */
int str_to_boolean(const char *value)
{
	int retval = -1;

	if (strcasecmp("TRUE", value) == 0)
		retval = 1;
	if (strcasecmp("FALSE", value) == 0)
		retval = 0;
	return retval;
}

static int warned_uppercase = 0;

void warn_uppercase(void)
{
	if (!warned_uppercase) {
		pwarn(WARN_DEPRECATED, _("Uppercase qualifiers \"RWLIMX\" are deprecated, please convert to lowercase\n"
			"See the apparmor.d(5) manpage for details.\n"));
		warned_uppercase = 1;
	}
}

static perm32_t parse_sub_perms(const char *str_perms, const char *perms_desc aa_unused)
{

#define IS_DIFF_QUAL(perms, q) (((perms) & AA_MAY_EXEC) && (((perms) & AA_EXEC_TYPE) != ((q) & AA_EXEC_TYPE)))

	perm32_t perms = 0;
	const char *p;

	PDEBUG("Parsing perms: %s\n", str_perms);

	if (!str_perms)
		return 0;

	p = str_perms;
	while (*p) {
		char thisc = *p;
		char next = *(p + 1);
		char lower;
		perm32_t tperms = 0;

reeval:
		switch (static_cast<cod_t>(thisc)) {
		case cod_t::READ:
			if (read_implies_exec) {
				PDEBUG("Parsing perms: found %s READ imply X\n", perms_desc);
				perms |= AA_MAY_READ | AA_OLD_EXEC_MMAP;
			} else {
				PDEBUG("Parsing perms: found %s READ\n", perms_desc);
				perms |= AA_MAY_READ;
			}
			break;

		case cod_t::WRITE:
			PDEBUG("Parsing perms: found %s WRITE\n", perms_desc);
			if ((perms & AA_MAY_APPEND) && !(perms & AA_MAY_WRITE))
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			perms |= AA_MAY_WRITE | AA_MAY_APPEND;
			break;

		case cod_t::APPEND:
			PDEBUG("Parsing perms: found %s APPEND\n", perms_desc);
			if (perms & AA_MAY_WRITE)
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			perms |= AA_MAY_APPEND;
			break;

		case cod_t::LINK:
			PDEBUG("Parsing perms: found %s LINK\n", perms_desc);
			perms |= AA_OLD_MAY_LINK;
			break;

		case cod_t::LOCK:
			PDEBUG("Parsing perms: found %s LOCK\n", perms_desc);
			perms |= AA_OLD_MAY_LOCK;
			break;

		case cod_t::INHERIT:
			PDEBUG("Parsing perms: found INHERIT\n");
			if (perms & AA_EXEC_MODIFIERS) {
				yyerror(_("Exec qualifier 'i' invalid, conflicting qualifier already specified"));
			} else {
				if (next != tolower(next))
					warn_uppercase();
				perms |= (AA_EXEC_INHERIT | AA_MAY_EXEC);
				p++;	/* skip 'x' */
			}
			break;

		case cod_t::UNSAFE_UNCONFINED:
			tperms = AA_EXEC_UNSAFE;
			pwarn(WARN_DANGEROUS, _("Unconfined exec qualifier (%c%c) allows some dangerous environment variables "
				"to be passed to the unconfined process; 'man 5 apparmor.d' for details.\n"),
			      cod_char_value(cod_t::UNSAFE_UNCONFINED), cod_char_value(cod_t::EXEC));
			/* fall through */
		case cod_t::UNCONFINED:
			tperms |= AA_EXEC_UNCONFINED | AA_MAY_EXEC;
			PDEBUG("Parsing perms: found UNCONFINED\n");
			if (IS_DIFF_QUAL(perms, tperms)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"),
					thisc);
			} else {
				if (next != tolower(next))
					warn_uppercase();
				perms |=  tperms;
				p++;	/* skip 'x' */
			}
			tperms = 0;
			break;

		case cod_t::UNSAFE_PROFILE:
		case cod_t::UNSAFE_LOCAL:
			tperms = AA_EXEC_UNSAFE;
			/* fall through */
		case cod_t::PROFILE:
		case cod_t::LOCAL:
			if (tolower(thisc) == cod_char_value(cod_t::UNSAFE_PROFILE))
				tperms |= AA_EXEC_PROFILE | AA_MAY_EXEC;
			else
			{
				tperms |= AA_EXEC_LOCAL | AA_MAY_EXEC;
			}
			PDEBUG("Parsing perms: found PROFILE\n");
			if (tolower(next) == cod_char_value(cod_t::INHERIT)) {
				tperms |= AA_EXEC_INHERIT;
				if (IS_DIFF_QUAL(perms, tperms)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), thisc, next);
				} else {
					perms |= tperms;
					p += 2;		/* skip x */
				}
			} else if (tolower(next) == cod_char_value(cod_t::UNSAFE_UNCONFINED)) {
				tperms |= AA_EXEC_PUX;
				if (IS_DIFF_QUAL(perms, tperms)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), thisc, next);
				} else {
					perms |= tperms;
					p += 2;		/* skip x */
				}
			} else if (IS_DIFF_QUAL(perms, tperms)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"), thisc);

			} else {
				if (next != tolower(next))
					warn_uppercase();
				perms |= tperms;
				p++;	/* skip 'x' */
			}
			tperms = 0;
			break;

		case cod_t::MMAP:
			PDEBUG("Parsing perms: found %s MMAP\n", perms_desc);
			perms |= AA_OLD_EXEC_MMAP;
			break;

		case cod_t::EXEC:
			/* thisc is valid for deny rules, and named transitions
			 * but invalid for regular x transitions
			 * sort it out later.
			 */
			perms |= AA_MAY_EXEC;
			break;

 		/* error cases */

		default:
			lower = tolower(thisc);
			switch (static_cast<cod_t>(lower)) {
			case cod_t::READ:
			case cod_t::WRITE:
			case cod_t::APPEND:
			case cod_t::LINK:
			case cod_t::INHERIT:
			case cod_t::MMAP:
			case cod_t::EXEC:
				PDEBUG("Parsing perms: found invalid upper case char %c\n", thisc);
				warn_uppercase();
				thisc = lower;
				goto reeval;
				break;
			default:
				yyerror(_("Internal: unexpected perms character '%c' in input"),
					thisc);
				break;
			}
			break;
		}

		p++;
	}

	PDEBUG("Parsed perms: %s 0x%x\n", str_perms, perms);

	return perms;
}

perm32_t parse_perms(const char *str_perms)
{
	perm32_t tmp, perms = 0;
	tmp = parse_sub_perms(str_perms, "");
	perms = SHIFT_PERMS(tmp, AA_USER_SHIFT);
	perms |= SHIFT_PERMS(tmp, AA_OTHER_SHIFT);
	if (perms & ~AA_VALID_PERMS)
		yyerror(_("Internal error generated invalid perm 0x%x\n"), perms);
	return perms;
}

static int parse_X_sub_perms(const char *X, const char *str_perms, perm32_t *result, int fail, const char *perms_desc aa_unused)
{
	perm32_t perms = 0;
	const char *p;

	PDEBUG("Parsing %s perms: %s\n", X, str_perms);

	if (!str_perms)
		return 0;

	p = str_perms;
	while (*p) {
		char current = *p;
		char lower;

reeval:
		switch (static_cast<cod_t>(current)) {
		case cod_t::READ:
			PDEBUG("Parsing %s perms: found %s READ\n", X, perms_desc);
			perms |= AA_DBUS_RECEIVE;
			break;

		case cod_t::WRITE:
			PDEBUG("Parsing %s perms: found %s WRITE\n", X,
			       perms_desc);
			perms |= AA_DBUS_SEND;
			break;

		/* error cases */

		default:
			lower = tolower(current);
			switch (static_cast<cod_t>(lower)) {
			case cod_t::READ:
			case cod_t::WRITE:
				PDEBUG("Parsing %s perms: found invalid upper case char %c\n",
				       X, current);
				warn_uppercase();
				current = lower;
				goto reeval;
				break;
			default:
				if (fail)
					yyerror(_("Internal: unexpected %s perms character '%c' in input"),
						X, current);
				else
					return 0;
				break;
			}
			break;
		}
		p++;
	}

	PDEBUG("Parsed %s perms: %s 0x%x\n", X, str_perms, perms);

	*result = perms;
	return 1;
}

int parse_X_perms(const char *X, int valid, const char *str_perms, perm32_t *perms, int fail)
{
	*perms = 0;
	if (!parse_X_sub_perms(X, str_perms, perms, fail, ""))
		return 0;
	if (*perms & ~valid) {
		if (fail)
			yyerror(_("Internal error generated invalid %s perm 0x%x\n"),
				X, *perms);
		else
			return 0;
	}
	return 1;
}

/**
 * parse_label - break a label down to the namespace and profile name
 * @stack: Will be true if the first char in @label is '&' to indicate stacking
 * @ns: Will point to the first char in the namespace upon return or NULL
 *      if no namespace is present
 * @ns_len: Number of chars in the namespace string or 0 if no namespace
 *          is present
 * @name: Will point to the first char in the profile name upon return
 * @name_len: Number of chars in the name string
 * @label: The label to parse into namespace and profile name
 *
 * The returned pointers will point to locations within the original
 * @label string. No new strings are allocated.
 *
 * Returns 0 upon success or non-zero with @ns, @ns_len, @name, and
 * @name_len undefined upon error. Error codes are:
 *
 * 1) Namespace is not terminated despite @label starting with ':'
 * 2) Namespace is empty meaning @label starts with "::"
 * 3) Profile name is empty
 */
static int _parse_label(bool *stack,
			char **ns, size_t *ns_len,
			char **name, size_t *name_len,
			const char *label)
{
	const char *name_start = NULL;
	const char *ns_start = NULL;
	const char *ns_end = NULL;

	if (label[0] == '&') {
		/**
		 * Leading ampersand means that the current profile should
		 * be stacked with the rest of the label
		 */
		*stack = true;
		label++;
	} else {
		*stack = false;
	}

	if (label[0] != ':') {
		/* There is no namespace specified in the label */
		name_start = label;
	} else {
		/* A leading ':' indicates that a namespace is specified */
		ns_start = label + 1;
		ns_end = strstr(ns_start, ":");

		if (!ns_end)
			return 1;

		/**
		 * Handle either of the two namespace formats:
		 *  1) :ns:name
		 *  2) :ns://name
		 */
		name_start = ns_end + 1;
		if (!strncmp(name_start, "//", 2))
			name_start += 2;
	}

	/**
	 * The casts below are to allow @label to be const, signifying
	 * that this function doesn't modify it, while allowing callers to
	 * decide if they want to pass in pointers to const or non-const
	 * strings.
	 */
	*ns = (char *)ns_start;
	*name = (char *)name_start;
	*ns_len = ns_end - ns_start;
	*name_len = strlen(name_start);

	if (*ns && *ns_len == 0)
		return 2;
	else if (*name_len == 0)
		return 3;

	return 0;
}

bool label_contains_ns(const char *label)
{
	bool stack = false;
	char *ns = NULL;
	char *name = NULL;
	size_t ns_len = 0;
	size_t name_len = 0;

	return _parse_label(&stack, &ns, &ns_len, &name, &name_len, label) == 0 && ns;
}

bool parse_label(bool *_stack, char **_ns, char **_name,
		 const char *label, bool yyerr)
{
	const char *err = NULL;
	char *ns = NULL;
	char *name = NULL;
	size_t ns_len = 0;
	size_t name_len = 0;
	int res;

	res = _parse_label(_stack, &ns, &ns_len, &name, &name_len, label);
	if (res == 1) {
		err = _("Namespace not terminated: %s\n");
	} else if (res == 2) {
		err = _("Empty namespace: %s\n");
	} else if (res == 3) {
		err = _("Empty named transition profile name: %s\n");
	} else if (res != 0) {
		err = _("Unknown error while parsing label: %s\n");
	}

	if (err) {
		if (yyerr)
			yyerror(err, label);
		else
			fprintf(stderr, err, label);

		return false;
	}

	if (ns) {
		*_ns = strndup(ns, ns_len);
		if (!*_ns)
			goto alloc_fail;
	} else {
		*_ns = NULL;
	}

	*_name = strndup(name, name_len);
	if (!*_name) {
		free(*_ns);
		goto alloc_fail;
	}

	return true;

alloc_fail:
	err = _("Memory allocation error.");
	if (yyerr)
		yyerror("%s", err);
	else
		fprintf(stderr, "%s", err);

	return false;
}

struct cod_entry *new_entry(char *id, perm32_t perms, char *link_id)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)calloc(1, sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->priority = 0;
	entry->name = id;
	entry->len = 0;
	entry->link_name = link_id;
	entry->llen = 0;
	entry->perms = perms;
	entry->audit = audit_t::UNSPECIFIED;
	entry->rule_mode = rule_mode_t::UNSPECIFIED;

	entry->pattern_type = pattern_t::Invalid;
	entry->pat.regex = NULL;

	entry->subset = false;
	entry->next = NULL;

	PDEBUG(" Insertion of: (%s)\n", entry->name);
	return entry;
}

struct cod_entry *copy_cod_entry(struct cod_entry *orig)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)calloc(1, sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	DUP_STRING(orig, entry, name, err);
	DUP_STRING(orig, entry, link_name, err);
	DUP_STRING(orig, entry, nt_name, err);
	entry->priority = orig->priority;
	entry->perms = orig->perms;
	entry->audit = orig->audit;
	entry->rule_mode = orig->rule_mode;

	/* XXX - need to create copies of the patterns, too */
	entry->pattern_type = orig->pattern_type;
	entry->pat.regex = NULL;

	entry->next = orig->next;
	entry->subset = orig->subset;

	return entry;

err:
	free_cod_entries(entry);
	return NULL;
}

void free_cod_entries(struct cod_entry *list)
{
	if (!list)
		return;
	if (list->next)
		free_cod_entries(list->next);
	if (list->name)
		free(list->name);
	if (list->link_name)
		free(list->link_name);
	if (list->nt_name)
		free(list->nt_name);
	if (list->pat.regex)
		free(list->pat.regex);
	free(list);
}

static void debug_base_perm_mask(int mask)
{
	if (HAS_MAY_READ(mask))
		printf("%c", cod_char_value(cod_t::READ));
	if (HAS_MAY_WRITE(mask))
		printf("%c", cod_char_value(cod_t::WRITE));
	if (HAS_MAY_APPEND(mask))
		printf("%c", cod_char_value(cod_t::APPEND));
	if (HAS_MAY_LINK(mask))
		printf("%c", cod_char_value(cod_t::LINK));
	if (HAS_MAY_LOCK(mask))
		printf("%c", cod_char_value(cod_t::LOCK));
	if (HAS_EXEC_MMAP(mask))
		printf("%c", cod_char_value(cod_t::MMAP));
	if (HAS_MAY_EXEC(mask))
		printf("%c", cod_char_value(cod_t::EXEC));
}

void debug_cod_entries(struct cod_entry *list)
{
	struct cod_entry *item = NULL;

	printf("--- Entries ---\n");

	list_for_each(list, item) {
		printf("Perms:\t");
		if (HAS_CHANGE_PROFILE(item->perms))
			printf(" change_profile");
		if (HAS_EXEC_UNSAFE(item->perms))
			printf(" unsafe");
		debug_base_perm_mask(SHIFT_TO_BASE(item->perms, AA_USER_SHIFT));
		printf(":");
		debug_base_perm_mask(SHIFT_TO_BASE(item->perms, AA_OTHER_SHIFT));

		printf(" priority=%d ", item->priority);
		if (item->name)
			printf("\tName:\t(%s)\n", item->name);
		else
			printf("\tName:\tNULL\n");

		if (AA_LINK_BITS & item->perms)
			printf("\tlink: subset=%d\t(%s)\n", item->subset, item->link_name ? item->link_name : "/**");

	}
}

bool check_x_qualifier(struct cod_entry *entry, const char *&error)
{
	if (entry->perms & AA_EXEC_BITS) {
		if ((entry->rule_mode == rule_mode_t::DENY) &&
		    (entry->perms & ALL_AA_EXEC_TYPE)) {
			error = _("Invalid perms, in deny rules 'x' must not be preceded by exec qualifier 'i', 'p', or 'u'");
			return false;
		} else if ((entry->rule_mode != rule_mode_t::DENY) &&
			   !(entry->perms & ALL_AA_EXEC_TYPE)) {
			error = _("Invalid perms, 'x' must be preceded by exec qualifier 'i', 'p', or 'u'");
			return false;
		}
	}
	return true;
}

// cod_entry version of ->add_prefix here just as file rules aren't converted yet
bool entry_add_prefix(struct cod_entry *entry, const prefixes &p, const char *&error)
{
	/* apply rule mode */
	if (p.rule_mode != rule_mode_t::UNSPECIFIED) {
		if (entry->rule_mode != rule_mode_t::UNSPECIFIED &&
		    entry->rule_mode != p.rule_mode) {
			error = "conflicting mode prefix";
			return false;
		}
		entry->rule_mode = p.rule_mode;
	}

	/* apply owner/other */
	if (p.owner == owner_t::SPECIFIED)
		entry->perms &= (AA_USER_PERMS | AA_SHARED_PERMS);
	else if (p.owner == owner_t::NOT)
		entry->perms &= (AA_OTHER_PERMS | AA_SHARED_PERMS);

	if (p.priority != 0)
		entry->priority = p.priority;

	if (p.audit != audit_t::UNSPECIFIED) {
		if (entry->audit != audit_t::UNSPECIFIED &&
		    entry->audit != audit_t::IMPLIED &&
		    entry->audit != p.audit) {
			error = "conflicting audit prefix";
			return false;
		}
	}
	/* implied audit modifier */
	if ((p.rule_mode == rule_mode_t::DENY || entry->rule_mode == rule_mode_t::DENY) &&
	    (p.audit.audit == audit_t::FORCE || entry->audit.audit == audit_t::FORCE)) {
		entry->rule_mode = rule_mode_t::DENY;
		entry->audit = audit_t::UNSPECIFIED;
	} else if (p.rule_mode == rule_mode_t::DENY) {
		entry->rule_mode = rule_mode_t::DENY;
		entry->audit = audit_t::IMPLIED;
	} else if (p.audit != audit_t::UNSPECIFIED) {
		entry->audit = p.audit;
	}

	return check_x_qualifier(entry, error);
}

// these need to move to stl
int ordered_cmp_value_list(value_list *lhs, value_list *rhs)
{
	std::vector<const char *> lhstable;
	std::vector<const char *> rhstable;

	struct value_list *entry;
	list_for_each(lhs, entry) {
		lhstable.push_back(entry->value);
	}
	list_for_each(rhs, entry) {
		rhstable.push_back(entry->value);
	}

	int res = lhstable.size() - rhstable.size();
	if (res)
		return res;

	std::sort(lhstable.begin(), lhstable.end(), strcomp);
	std::sort(rhstable.begin(), rhstable.end(), strcomp);

	for (unsigned long i = 0; i < lhstable.size(); i++) {
		res = null_strcmp(lhstable[i], rhstable[i]);
		if (res)
			return res;
	}

	return 0;
}

int cmp_value_list(value_list *lhs, value_list *rhs)
{
	if (lhs) {
		if (rhs) {
			return ordered_cmp_value_list(lhs, rhs);
		}
		return 1;
	} else if (rhs) {
		return -1;
	}

	return 0;
}

struct value_list *new_value_list(char *value)
{
	struct value_list *val = (struct value_list *) calloc(1, sizeof(struct value_list));
	if (val)
		val->value = value;
	return val;
}

void free_value_list(struct value_list *list)
{
	struct value_list *next;

	while (list) {
		next = list->next;
		if (list->value)
			free(list->value);
		free(list);
		list = next;
	}
}

void print_value_list(struct value_list *list, std::ostream &os)
{
	struct value_list *entry;

	if (!list)
		return;

	os << list->value;
	list = list->next;
	list_for_each(list, entry) {
		os << ", " << entry->value;
	}
}

void move_conditional_value(const char *rulename, char **dst_ptr,
			    struct cond_entry *cond_ent)
{
	if (*dst_ptr)
		yyerror("%s conditional \"%s\" can only be specified once\n",
			rulename, cond_ent->name);

	*dst_ptr = cond_ent->vals->value;
	cond_ent->vals->value = NULL;
}

struct cond_entry *new_cond_entry(char *name, cond_comp comp, struct value_list *list)
{
	struct cond_entry *ent = (struct cond_entry *) calloc(1, sizeof(struct cond_entry));
	if (ent) {
		ent->name = name;
		ent->vals = list;
		ent->comp = comp;
	}

	return ent;
}

void free_cond_entry(struct cond_entry *ent)
{
	if (ent) {
		free(ent->name);
		free_value_list(ent->vals);
		free(ent);
	}
}

void free_cond_list(struct cond_entry *ents)
{
	struct cond_entry *entry, *tmp;

	if (ents) {
		list_for_each_safe(ents, entry, tmp) {
			free_cond_entry(entry);
		}
	}
}

void free_cond_entry_list(struct cond_entry_list &cond)
{
	free_cond_list(cond.list);
	free(cond.name);
	cond.list = NULL;
	cond.name = NULL;
}

void print_cond_entry(struct cond_entry *ent)
{
	if (ent) {
		fprintf(stderr, "%s=(", ent->name);
		print_value_list(ent->vals, std::cerr);
		fprintf(stderr, ")\n");
	}
}


struct time_units {
	const char *str;
	long long value;
};

static struct time_units time_units[] = {
	{ "us", 1LL },
	{ "microsecond", 1LL },
	{ "microseconds", 1LL },
	{ "ms", 1000LL },
	{ "millisecond", 1000LL },
	{ "milliseconds", 1000LL },
	{ "s", 1000LL * 1000LL },
	{ "sec", SECONDS_P_MS },
	{ "second", SECONDS_P_MS },
	{ "seconds", SECONDS_P_MS },
	{ "min" , 60LL * SECONDS_P_MS },
	{ "minute", 60LL * SECONDS_P_MS },
	{ "minutes", 60LL * SECONDS_P_MS },
	{ "h", 60LL * 60LL * SECONDS_P_MS },
	{ "hour", 60LL * 60LL * SECONDS_P_MS },
	{ "hours", 60LL * 60LL * SECONDS_P_MS },
	{ "d", 24LL * 60LL * 60LL * SECONDS_P_MS },
	{ "day", 24LL * 60LL * 60LL * SECONDS_P_MS },
	{ "days", 24LL * 60LL * 60LL * SECONDS_P_MS },
	{ "week", 7LL * 24LL * 60LL * 60LL * SECONDS_P_MS },
	{ "weeks", 7LL * 24LL * 60LL * 60LL * SECONDS_P_MS },
	{ NULL, 0 }
};

long long convert_time_units(long long value, long long base, const char *units)
{
	struct time_units *ent;
	if (!units)
		/* default to base if no units */
		return value;

	for (ent = time_units; ent->str; ent++) {
		if (strcmp(ent->str, units) == 0) {
			if (value * ent->value < base)
				return -1LL;
			return value * ent->value / base;
		}
	}
	return -2LL;
}

#ifdef UNIT_TEST

#include "unit_test.h"

int test_str_to_boolean(void)
{
	int rc = 0;
	int retval;

	retval = str_to_boolean("TRUE");
	MY_TEST(retval == 1, "str2bool for TRUE");

	retval = str_to_boolean("TrUe");
	MY_TEST(retval == 1, "str2bool for TrUe");

	retval = str_to_boolean("false");
	MY_TEST(retval == 0, "str2bool for false");

	retval = str_to_boolean("flase");
	MY_TEST(retval == -1, "str2bool for flase");

	return rc;
}

#define MY_TEST_UNQUOTED(input, expected, description) \
	do { 										\
		char *result_str = NULL;						\
		char *output_str = NULL;						\
											\
		result_str = processunquoted((input), strlen((input)));			\
		asprintf(&output_str, "processunquoted: %s\tinput = '%s'\texpected = '%s'\tresult = '%s'", \
				(description), (input), (expected), result_str);	\
		MY_TEST(strcmp((expected), result_str) == 0, output_str);		\
											\
		free(output_str);							\
		free(result_str); 							\
	}										\
	while(0)

int test_processunquoted(void)
{
	int rc = 0;

	MY_TEST_UNQUOTED("", "", "empty string");
	MY_TEST_UNQUOTED("\\1", "\001", "one digit octal");
	MY_TEST_UNQUOTED("\\8", "\\8", "invalid octal digit \\8");
	MY_TEST_UNQUOTED("\\18", "\0018", "one digit octal followed by invalid octal digit");
	MY_TEST_UNQUOTED("\\1a", "\001a", "one digit octal followed by hex digit a");
	MY_TEST_UNQUOTED("\\1z", "\001z", "one digit octal follow by char z");
	MY_TEST_UNQUOTED("\\11", "\011", "two digit octal");
	MY_TEST_UNQUOTED("\\118", "\0118", "two digit octal followed by invalid octal digit");
	MY_TEST_UNQUOTED("\\11a", "\011a", "two digit octal followed by hex digit a");
	MY_TEST_UNQUOTED("\\11z", "\011z", "two digit octal followed by char z");
	MY_TEST_UNQUOTED("\\111", "\111", "three digit octal");
	MY_TEST_UNQUOTED("\\378", "\0378", "three digit octal two large, taken as 2 digit octal plus trailing char");
	MY_TEST_UNQUOTED("123\\421123", "123\0421123", "two character octal followed by valid octal digit \\421");
	MY_TEST_UNQUOTED("123\\109123", "123\109123", "octal 109");
	MY_TEST_UNQUOTED("123\\1089123", "123\1089123", "octal 108");

	return rc;
}

int test_processquoted(void)
{
	int rc = 0;
	const char *teststring, *processedstring;
	char *out;

	teststring = "";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(teststring, out) == 0,
			"processquoted on empty string");
	free(out);

	teststring = "\"abcdefg\"";
	processedstring = "abcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on simple string");
	free(out);

	teststring = "\"abcd\\tefg\"";
	processedstring = "abcd\tefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on string with tab");
	free(out);

	teststring = "\"abcdefg\\\"";
	processedstring = "abcdefg\\";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on trailing slash");
	free(out);

	teststring = "\"a\\\\bcdefg\"";
	processedstring = "a\\\\bcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted slash");
	free(out);

	teststring = "\"a\\\"bcde\\\"fg\"";
	processedstring = "a\"bcde\"fg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted quotes");
	free(out);

	teststring = "\"\\rabcdefg\"";
	processedstring = "\rabcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted \\r");
	free(out);

	teststring = "\"abcdefg\\n\"";
	processedstring = "abcdefg\n";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted \\n");
	free(out);

	teststring = "\"\\Uabc\\Ndefg\\x\"";
	processedstring = "\\Uabc\\Ndefg\\x";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough on invalid quoted chars");
	free(out);

	teststring = "\"abc\\042defg\"";
	processedstring = "abc\"defg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted octal \\042");
	free(out);

	teststring = "\"abcdefg\\176\"";
	processedstring = "abcdefg~";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted octal \\176");
	free(out);

	teststring = "\"abc\\429defg\"";
	processedstring = "abc\0429defg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted invalid octal \\429");
	free(out);

	teststring = "\"abcdefg\\4\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted one digit trailing octal \\4");
	free(out);

	teststring = "\"abcdefg\\04\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted two digit trailing octal \\04");
	free(out);

	teststring = "\"abcdefg\\004\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted three digit trailing octal \\004");
	free(out);

	return rc;
}

#define TIME_TEST(V, B, U, R)					\
MY_TEST(convert_time_units((V), (B), U) == (R),		\
	"convert " #V " with base of " #B ", " #U " units")

int test_convert_time_units()
{
	int rc = 0;

	TIME_TEST(1LL, 1LL, NULL, 1LL);
	TIME_TEST(12345LL, 1LL, NULL, 12345LL);
	TIME_TEST(10LL, 10LL, NULL, 10LL);
	TIME_TEST(123450LL, 10LL, NULL, 123450LL);

	TIME_TEST(12345LL, 1LL, "us", 12345LL);
	TIME_TEST(12345LL, 1LL, "microsecond", 12345LL);
	TIME_TEST(12345LL, 1LL, "microseconds", 12345LL);

	TIME_TEST(12345LL, 1LL, "ms", 12345LL*1000LL);
	TIME_TEST(12345LL, 1LL, "millisecond", 12345LL*1000LL);
	TIME_TEST(12345LL, 1LL, "milliseconds", 12345LL*1000LL);

	TIME_TEST(12345LL, 1LL, "s", 12345LL*1000LL*1000LL);
	TIME_TEST(12345LL, 1LL, "sec", 12345LL*1000LL*1000LL);
	TIME_TEST(12345LL, 1LL, "second", 12345LL*1000LL*1000LL);
	TIME_TEST(12345LL, 1LL, "seconds", 12345LL*1000LL*1000LL);

	TIME_TEST(12345LL, 1LL, "min", 12345LL*1000LL*1000LL*60LL);
	TIME_TEST(12345LL, 1LL, "minute", 12345LL*1000LL*1000LL*60LL);
	TIME_TEST(12345LL, 1LL, "minutes", 12345LL*1000LL*1000LL*60LL);

	TIME_TEST(12345LL, 1LL, "h", 12345LL*1000LL*1000LL*60LL*60LL);
	TIME_TEST(12345LL, 1LL, "hour", 12345LL*1000LL*1000LL*60LL*60LL);
	TIME_TEST(12345LL, 1LL, "hours", 12345LL*1000LL*1000LL*60LL*60LL);

	TIME_TEST(12345LL, 1LL, "d", 12345LL*1000LL*1000LL*60LL*60LL*24LL);
	TIME_TEST(12345LL, 1LL, "day", 12345LL*1000LL*1000LL*60LL*60LL*24LL);
	TIME_TEST(12345LL, 1LL, "days", 12345LL*1000LL*1000LL*60LL*60LL*24LL);

	TIME_TEST(12345LL, 1LL, "week", 12345LL*1000LL*1000LL*60LL*60LL*24LL*7LL);
	TIME_TEST(12345LL, 1LL, "weeks", 12345LL*1000LL*1000LL*60LL*60LL*24LL*7LL);

	return rc;
}

int main(void)
{
	int rc = 0;
	int retval;

	retval = test_str_to_boolean();
	if (retval != 0)
		rc = retval;

	retval = test_processunquoted();
	if (retval != 0)
		rc = retval;

	retval = test_processquoted();
	if (retval != 0)
		rc = retval;

	retval = test_convert_time_units();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
