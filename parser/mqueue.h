/*
 *   Copyright (c) 2022
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

/* sysv and posix mqueue mediation. */

#ifndef __AA_MQUEUE_H
#define __AA_MQUEUE_H

#include "immunix.h"
#include "parser.h"

#define AA_MQUEUE_WRITE		AA_MAY_WRITE
#define AA_MQUEUE_READ		AA_MAY_READ

#define AA_MQUEUE_CREATE	0x0010		/* create */
#define AA_MQUEUE_DELETE	0x0020		/* destroy, unlink */
#define AA_MQUEUE_OPEN		0x0040		/* associate */
#define AA_MQUEUE_RENAME	0x0080		/* ?? pair */

#define AA_MQUEUE_SETATTR	0x0100		/* setattr */
#define AA_MQUEUE_GETATTR	0x0200		/* getattr */

#define AA_MQUEUE_CHMOD		0x1000		/* pair */
#define AA_MQUEUE_CHOWN		0x2000		/* pair */
#define AA_MQUEUE_CHGRP		0x4000		/* pair */
#define AA_MQUEUE_LOCK		0x8000		/* LINK_SUBSET overlaid */

/* sysv and posix mqueues use different terminology, allow mapping
 * between. To be as common as possible.
 *
 * sysv and posix mqueues have different levels of mediation possible
 * in the kernel. Only the most basic mqueue rules can be shared
 * eg.
 *    mqueue rw,
 *    mqueue rw label=foo,
 *
 * kernel doesn't allow for us to control
 * - posix
 *   - notify
 *   - labels at anything other than mqueue label, via mqueue inode.
 */

#define AA_VALID_POSIX_MQ_PERMS (AA_MQUEUE_WRITE | AA_MQUEUE_READ |    \
				 AA_MQUEUE_CREATE | AA_MQUEUE_DELETE | \
				 AA_MQUEUE_OPEN |		       \
				 AA_MQUEUE_SETATTR | AA_MQUEUE_GETATTR)

 /* TBD - for now make it wider than posix */
#define AA_VALID_SYSV_MQ_PERMS (AA_MQUEUE_WRITE | AA_MQUEUE_READ |    \
				 AA_MQUEUE_CREATE | AA_MQUEUE_DELETE | \
				 AA_MQUEUE_OPEN |			\
				 AA_MQUEUE_SETATTR | AA_MQUEUE_GETATTR)

#define AA_VALID_MQUEUE_PERMS (AA_VALID_POSIX_MQ_PERMS | \
			       AA_VALID_SYSV_MQ_PERMS)

/* read and write needed with create because mq_open can be called
 * with O_CREAT | O_RDWR, which all show up in the requested perms at
 * the same time during creation
 */
#define AA_MQUEUE_CREATE_PERMS (AA_MQUEUE_CREATE | AA_MQUEUE_READ | \
				AA_MQUEUE_WRITE)
// warning getting into overlap area

/* Type of mqueue - can be explicit or implied by rule id/path */
typedef enum mqueue_type {
	mqueue_unspecified,
	mqueue_posix,
	mqueue_sysv
} mqueue_type;

static inline uint32_t map_mqueue_perms(uint32_t mask)
{
	return (mask & 0x7f) |
		((mask & (AA_MQUEUE_GETATTR | AA_MQUEUE_SETATTR)) << (AA_OTHER_SHIFT - 8));
}

int parse_mqueue_perms(const char *str_perms, perm32_t *perms, int fail);

class mqueue_rule: public perms_rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	mqueue_type qtype;
	char *qname;
	char *label;

	mqueue_rule(perm32_t perms, struct cond_entry *conds, char *qname = NULL);
	virtual ~mqueue_rule()
	{
		free(qname);
		free(label);
	};

	virtual bool valid_prefix(const prefixes &p, const char *&error) {
		// not yet, but soon
		if (p.owner) {
			error = _("owner prefix not allowed on mqueue rules");
			return false;
		}
		return true;
	};
	virtual ostream &dump(ostream &os);
	virtual int expand_variables(void);
	virtual int gen_policy_re(Profile &prof);

	virtual bool is_mergeable(void) { return true; }
	virtual int cmp(rule_t const &rhs) const
	{
		int res = perms_rule_t::cmp(rhs);
		if (res)
			return res;
		mqueue_rule const &trhs = rule_cast<mqueue_rule const &>(rhs);
		res = qtype - trhs.qtype;
		if (res)
			return res;
		res = null_strcmp(qname, trhs.qname);
		if (res)
			return res;
		return null_strcmp(label, trhs.label);
	};

protected:
	virtual void warn_once(const char *name) override;
	void validate_qname(void);
};

#endif /* __AA_MQUEUE_H */
