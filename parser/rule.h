/*
 *   Copyright (c) 2014
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
#ifndef __AA_RULE_H
#define __AA_RULE_H

#include <cstdint>
#include <list>
#include <ostream>

#include "perms.h"
#include "policydb.h"

enum class prompt_compat_t : int {
	UNKNOWN = 0,
	IGNORE = 1,
	PERMSV2 = 2,
	FLAG = 4,
};


class Profile;

enum class rule_result_t : int {
	ERROR = -1,
	NOT_SUPPORTED = 0,
	OK = 1,
};

#define RULE_TYPE_RULE		0
#define RULE_TYPE_PREFIX	1
#define RULE_TYPE_PERMS		2
#define RULE_TYPE_ALL		3
// RULE_TYPE_CLASS needs to be last because various class follow it
#define RULE_TYPE_CLASS		4

// rule_cast should only be used after a comparison of rule_type to ensure
// that it is valid. Change to dynamic_cast for debugging
//#define rule_cast dynamic_cast
#define rule_cast static_cast

enum class rule_flags_t : unsigned int {
	NONE = 0,
	DELETED = 1,	// rule deleted - skip
	MERGED = 2,	// rule merged with another rule
	EXPANDED = 4,	// variable expanded
	SUB = 8,	// rule expanded to subrule(s)
	IMPLIED = 16,	// rule not specified in policy but
			// added because it is implied
};

inline rule_flags_t operator|(rule_flags_t a, rule_flags_t b)
{
    return static_cast<rule_flags_t>(static_cast<unsigned int>(a) | static_cast<unsigned int>(b));
}

inline rule_flags_t operator&(rule_flags_t a, rule_flags_t b)
{
    return static_cast<rule_flags_t>(static_cast<unsigned int>(a) & static_cast<unsigned int>(b));
}

inline rule_flags_t& operator|=(rule_flags_t &a, const rule_flags_t &b)
{
	a = a | b;
	return a;
}

class rule_t {
public:
	int rule_type;
	rule_flags_t flags;

	rule_t *removed_by;

	rule_t(int t): rule_type(t), flags(rule_flags_t::NONE), removed_by(NULL) { }
	virtual ~rule_t() { };

	bool is_type(int type) { return rule_type == type; }

	// rule has been marked as should be skipped by regular processing
	bool skip()
	{
		return (flags & rule_flags_t::DELETED) != rule_flags_t::NONE;
	}
	//virtual bool operator<(rule_t const &rhs)const = 0;
	virtual std::ostream &dump(std::ostream &os) = 0;

	// Follow methods in order of being called by the parse

	// called when profile is finished parsing
	virtual void post_parse_profile(Profile &prof __attribute__ ((unused))) { };

	// called before final expansion of variables. So implied rules
	// can reference variables
	virtual void add_implied_rules(Profile &prof __attribute__ ((unused))) { };

	// currently only called post parse
	// needs to change to being iteratively called during parse
	// to support expansion in include names and profile names
	virtual int expand_variables(void) = 0;

	virtual int cmp(rule_t const &rhs) const {
		return rule_type - rhs.rule_type;
	}
	virtual bool operator<(rule_t const &rhs) const {
		return cmp(rhs) < 0;
	}
	// called by duplicate rule merge/elimination after final expand_vars
	// to get default rule dedup
	// child object need to provide
	// - cmp, operator<
	// - is_mergeable() returning true
	// if a child object wants to provide merging of permissions,
	// it needs to provide a custom cmp fn that doesn't include
	// permissions and a merge routine that does more than flagging
	// as dup as below
	virtual bool is_mergeable(void) { return false; }

	// returns true if merged
	virtual bool merge(rule_t &rhs)
	{
		if (rule_type != rhs.rule_type)
			return false;
		if (skip() || rhs.skip())
			return false;
		// default merge is just dedup
		flags |= rule_flags_t::MERGED;
		rhs.flags |= (rule_flags_t::MERGED | rule_flags_t::DELETED);
		rhs.removed_by = this;

		return true;
	};

	// called late frontend to generate data for regex backend
	virtual rule_result_t gen_policy_re(Profile &prof) = 0;

protected:
	const char *warned_name = NULL;
	virtual void warn_once(const char *name, const char *msg);
	virtual void warn_once(const char *name) = 0;


};

std::ostream &operator<<(std::ostream &os, rule_t &rule);

typedef std::list<rule_t *> RuleList;

/* Scoped enums used in the bison front end */
enum class audit_t { UNSPECIFIED, IMPLIED, FORCE, QUIET };
enum class rule_mode_t { UNSPECIFIED, ALLOW, DENY, PROMPT };
enum class owner_t { UNSPECIFIED, SPECIFIED, NOT };

class internal_audit_t {
public:
	audit_t audit;
	operator audit_t() const {
		return audit;
	}

	internal_audit_t& operator=(const audit_t& rhs) {
		audit = rhs;
		return *this;
	}

	bool operator==(const audit_t& rhs) const {
		if (rhs == audit_t::FORCE)
			return (this->audit == rhs) || (this->audit == audit_t::IMPLIED);
		return this->audit == rhs;
	}

	bool operator!=(const audit_t& rhs) const {
		return !(*this == rhs);
	}

	bool operator==(const internal_audit_t& rhs) const {
		return *this == rhs.audit;
	}

	bool operator!=(const internal_audit_t& rhs) const {
		return !(*this == rhs);
	}

	bool operator-(const internal_audit_t& rhs) const {
		return (int) this->audit - (int) rhs.audit;
	}

	bool operator<(const internal_audit_t& rhs) const {
		return this->audit < rhs.audit;
	}
};

/* NOTE: we can not have a constructor for class prefixes. This is
 * because it will break bison, and we would need to transition to
 * the C++ bison bindings. Instead get around this by using a
 * special rule class that inherits prefixes and handles the
 * construction
 */
class prefixes {
public:
	int priority;
	internal_audit_t audit;
	rule_mode_t rule_mode;
	owner_t owner;

	ostream &dump(ostream &os)
	{
		bool output = true;

		if (priority != 0)
			os << "priority=" << priority << " ";
		switch (audit) {
		case audit_t::FORCE:
			os << "audit";
			break;
		case audit_t::QUIET:
			os << "quiet";
			break;
		default:
			output = false;
		}

		switch (rule_mode) {
		case rule_mode_t::ALLOW:
			if (output)
				os << " ";

			os << "allow";
			output = true;
			break;
		case rule_mode_t::DENY:
			if (output)
				os << " ";

			os << "deny";
			output = true;
			break;
		case rule_mode_t::PROMPT:
			if (output)
				os << " ";

			os << "prompt";
			output = true;
			break;
		default:
			break;
		}

		switch (owner) {
		case owner_t::SPECIFIED:
			if (output)
				os << " ";
			os << "owner";
			output = true;
			break;
		case owner_t::NOT:
			if (output)
				os << " ";
			os << "!owner";
			output = true;
			break;
		default:
			break;
		}

		if (output)
			os << " ";

		return os;
	}

	int cmp(prefixes const &rhs) const {
		int tmp = priority - rhs.priority;
		if (tmp != 0)
			return tmp;
		tmp = audit - rhs.audit;
		if (tmp != 0)
			return tmp;
		tmp = (int) rule_mode - (int) rhs.rule_mode;
		if (tmp != 0)
			return tmp;
		if ((unsigned int) owner < (unsigned int) rhs.owner)
			return -1;
		if ((unsigned int) owner > (unsigned int) rhs.owner)
			return 1;
		return 0;
	}

	bool operator<(prefixes const &rhs) const {
		if (cmp(rhs) < 0)
			return true;
		return false;
	}
};

class prefix_rule_t: public rule_t, public prefixes {
public:
	prefix_rule_t(int t = RULE_TYPE_PREFIX) : rule_t(t)
	{
		/* Must construct prefix here see note on prefixes */
		priority = 0;
		audit = audit_t::UNSPECIFIED;
		rule_mode = rule_mode_t::UNSPECIFIED;
		owner = owner_t::UNSPECIFIED;
	};

	virtual bool valid_prefix(const prefixes &p, const char *&error) = 0;

	virtual bool add_prefix(const prefixes &p, const char *&error) {
		if (!valid_prefix(p, error))
			return false;

		// priority does NOT conflict but allowed at the block
		// level yet. priority at the block level applies to
		// the entire block, but only for the level of rules
		// it is at.
		// priority within the block arranges order of rules
		// within the block.
		if (priority != 0) {
			error = "priority levels not supported";
			return false;
		}
		priority = p.priority;

		/* audit conflicts */
		if (p.audit != audit_t::UNSPECIFIED) {
			if (audit != audit_t::UNSPECIFIED &&
			    audit != audit_t::IMPLIED &&
			    audit != p.audit) {
				error = "conflicting audit prefix";
				return false;
			}
//			audit = p.audit;
		}

		/* allow deny prompt conflicts */
		if (p.rule_mode != rule_mode_t::UNSPECIFIED) {
			if (rule_mode != rule_mode_t::UNSPECIFIED &&
			    rule_mode != p.rule_mode) {
				error = "conflicting mode prefix";
				return false;
			}
			rule_mode = p.rule_mode;
		}

		/* owner !owner conflicts */
		if (p.owner != owner_t::UNSPECIFIED) {
			if (owner != owner_t::UNSPECIFIED &&
			    owner != p.owner) {
				error = "conflicting owner prefix";
				return false;
			}
			owner = p.owner;
		}

		/* TODO: MOVE this ! */
		/* does the prefix imply a modifier */
		if ((p.rule_mode == rule_mode_t::DENY || rule_mode == rule_mode_t::DENY) &&
		    (p.audit.audit == audit_t::FORCE || audit.audit == audit_t::FORCE)) {
			rule_mode = rule_mode_t::DENY;
			audit = audit_t::UNSPECIFIED;
		} else if (p.rule_mode == rule_mode_t::DENY) {
			rule_mode = rule_mode_t::DENY;
			audit = audit_t::IMPLIED;
		} else if (p.audit != audit_t::UNSPECIFIED) {
			audit = p.audit;
		}

		return true;
	}
	virtual bool add_prefix(const prefixes &p) {
		const char *err;
		return add_prefix(p, err);
	}

	int cmp(prefixes const &rhs) const {
		return prefixes::cmp(rhs);
	}

	virtual bool operator<(prefixes const &rhs) const {
		const prefixes *ptr = this;
		return *ptr < rhs;
	}

	int cmp(rule_t const &rhs) const override {
		int res = rule_t::cmp(rhs);
		if (res)
			return res;
		prefix_rule_t const &pr = rule_cast<prefix_rule_t const &>(rhs);
		const prefixes *lhsptr = this, *rhsptr = &pr;
		return lhsptr->cmp(*rhsptr);
	}

	bool operator<(rule_t const &rhs) const override {
		if (rule_type < rhs.rule_type)
			return true;
		if (rhs.rule_type < rule_type)
			return false;
		prefix_rule_t const &pr = rule_cast<prefix_rule_t const &>(rhs);
		const prefixes *rhsptr = &pr;
		return *this < *rhsptr;
	}

	ostream &dump(ostream &os) override {
		prefixes::dump(os);

		return os;
	}

};

/* NOTE: rule_type is RULE_TYPE_CLASS + AA_CLASS */
class class_rule_t: public prefix_rule_t {
public:
	class_rule_t(int c): prefix_rule_t(RULE_TYPE_CLASS + c) { }

	int aa_class(void) { return rule_type - RULE_TYPE_CLASS; }

	/* inherit cmp */

	/* we do not inherit operator< so class_rule children
	 * can inherit the generic one that redirects to cmp()
	 * that does get overridden
	 */
	bool operator<(rule_t const &rhs) const override {
		return cmp(rhs) < 0;
	}

	ostream &dump(ostream &os) override {
		prefix_rule_t::dump(os);

		os << aa_class_table[aa_class()];

		return os;
	}

};

/* same as perms_rule_t except enable rule merging instead of just dedup
 * original permission set is saved off
 */
class perms_rule_t: public class_rule_t {
public:
	perms_rule_t(int c): class_rule_t(c), perms(0), saved(0) { };

	int cmp(rule_t const &rhs) const override {
		/* don't compare perms so they can be merged */
		return class_rule_t::cmp(rhs);
	}

	bool merge(rule_t &rhs) override
	{
		int res = class_rule_t::merge(rhs);
		if (!res)
			return res;
		if (!saved)
			saved = perms;
		perms |= (rule_cast<perms_rule_t const &>(rhs)).perms;
		return true;
	};

	/* default perms, override/mask off if none default used */
	ostream &dump(ostream &os) override {
		class_rule_t::dump(os);

		std::ios::fmtflags fmt(os.flags());

		if (saved)
			os << "(0x" << std::hex << perms << "/orig " << saved << ") ";
		else
			os << "(0x" << std::hex << perms << ") ";

		os.flags(fmt);
		return os;
	}

	perm32_t perms, saved;
};

// alternate perms rule class that only does dedup instead of perms merging
class dedup_perms_rule_t: public class_rule_t {
public:
	dedup_perms_rule_t(int c): class_rule_t(c), perms(0) { };

	int cmp(rule_t const &rhs) const override {
		int res = class_rule_t::cmp(rhs);
		if (res)
			return res;
		return perms - (rule_cast<perms_rule_t const &>(rhs)).perms;
	}

	// inherit default merge which does dedup

	/* default perms, override/mask off if none default used */
	ostream &dump(ostream &os) override {
		class_rule_t::dump(os);

		std::ios::fmtflags fmt(os.flags());

		os << "(0x" << std::hex << perms << ") ";

		os.flags(fmt);
		return os;
	}

	perm32_t perms;
};


#endif /* __AA_RULE_H */

