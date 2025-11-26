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
/*
 * This is a set of functions to provide convertion from old style permission
 * mappings, to new style kernel mappings. It is based on the kernel to
 * as the kernel needs this for backwards compatibility. This allows the
 * userspace to convert to the new permission mapping without reworking
 * the internal dfa permission tracking.
 *
 * In the future this code will be converted to go the reverse direction
 * i.e. new mappings into old, which the parser will need for backwards
 * compat with old kernels.
 */

#include <stdint.h>

#include "policy_compat.h"
#include "../perms.h"
extern int prompt_compat_mode;


/* remap old accept table embedded permissions to separate permission table */
static uint32_t dfa_map_xindex(uint16_t mask)
{
	uint16_t old_index = (mask >> 10) & 0xf;
	uint32_t index = 0;

	if (mask & 0x100)
		index |= AA_X_UNSAFE;
	if (mask & 0x200)
		index |= AA_X_INHERIT;
	if (mask & 0x80)
		index |= AA_X_UNCONFINED;

	if (old_index == 1) {
		index |= AA_X_UNCONFINED;
	} else if (old_index == 2) {
		index |= AA_X_NAME;
	} else if (old_index == 3) {
		index |= AA_X_NAME | AA_X_CHILD;
	} else if (old_index) {
		index |= AA_X_TABLE;
		index |= old_index - 4;
	}

	return index;
}

/*
 * map old dfa inline permissions to new format
 */

static inline uint32_t dfa_user_allow(uint32_t accept1)
{
	return (accept1 & 0x7f) | (accept1 & 0x80000000);
}

static inline uint32_t dfa_user_xbits(uint32_t accept1)
{
	return (accept1 >> 7) & 0x7f;
}

static inline uint32_t dfa_user_audit(uint32_t accept1 __attribute__((unused)), uint32_t accept2)
{
	return accept2 & 0x7f;
}

static inline uint32_t dfa_user_quiet(uint32_t accept1 __attribute__((unused)), uint32_t accept2)
{
	 return (accept2 >> 7) & 0x7f;
}

static inline uint32_t dfa_user_xindex(uint32_t accept1)
{
	return dfa_map_xindex(accept1 & 0x3fff);
}

static inline uint32_t dfa_other_allow(uint32_t accept1)
{
	return ((accept1 >> 14) & 0x7f) | (accept1 & 0x80000000);
}

static inline uint32_t dfa_other_xbits(uint32_t accept1)
{
	return ((accept1 >> 7) >> 14) & 0x7f;
}

static inline uint32_t dfa_other_audit(uint32_t accept1 __attribute__((unused)), uint32_t accept2)
{
	return (accept2 >> 14) & 0x7f;
}

static inline uint32_t dfa_other_quiet(uint32_t accept1 __attribute__((unused)), uint32_t accept2)
{
	return ((accept2 >> 7) >> 14) & 0x7f;
}

static inline uint32_t dfa_other_xindex(uint32_t accept1)
{
	return dfa_map_xindex((accept1 >> 14) & 0x3fff);
}

/**
 * map_old_perms - map old file perms layout to the new layout
 * @old: permission set in old mapping
 *
 * Returns: new permission mapping
 */
static uint32_t map_old_perms(uint32_t old)
{
	uint32_t perm = old & 0xf;

	if (old & AA_MAY_READ)
		perm |= AA_MAY_GETATTR | AA_MAY_OPEN;
	if (old & AA_MAY_WRITE)
		perm |= AA_MAY_SETATTR | AA_MAY_CREATE | AA_MAY_DELETE |
		       AA_MAY_CHMOD | AA_MAY_CHOWN | AA_MAY_OPEN;
	if (old & 0x10)
		perm |= AA_MAY_LINK;
	/* the old mapping lock and link_subset flags where overlaid
	 * and use was determined by part of a pair that they were in
	 */
	if (old & 0x20)
		perm |= AA_MAY_LOCK | AA_LINK_SUBSET;
	if (old & 0x40)	/* AA_EXEC_MMAP */
		perm |= AA_EXEC_MMAP;

	return perm;
}

static void compute_fperms_allow(struct aa_perms *perms, uint32_t accept1)
{
	perms->allow |= AA_MAY_GETATTR;

	/* change_profile wasn't determined by ownership in old mapping */
	if (accept1 & 0x80000000)
		perms->allow |= AA_MAY_CHANGE_PROFILE;
	if (accept1 & 0x40000000)
		perms->allow |= AA_MAY_ONEXEC;
}

struct aa_perms compute_fperms_user(uint32_t accept1, uint32_t accept2,
				    uint32_t accept3)
{
	struct aa_perms perms = { };

	perms.allow = map_old_perms(dfa_user_allow(accept1));
	perms.prompt = map_old_perms(dfa_user_allow(accept3));
	perms.audit = map_old_perms(dfa_user_audit(accept1, accept2));
	perms.quiet = map_old_perms(dfa_user_quiet(accept1, accept2));
	perms.xindex = dfa_user_xindex(accept1);

	compute_fperms_allow(&perms, accept1);
	perms.prompt &= ~(perms.allow | perms.deny);
	return perms;
}

struct aa_perms compute_fperms_other(uint32_t accept1, uint32_t accept2,
				     uint32_t accept3)
{
	struct aa_perms perms = { };

	perms.allow = map_old_perms(dfa_other_allow(accept1));
	perms.prompt = map_old_perms(dfa_other_allow(accept3));
	perms.audit = map_old_perms(dfa_other_audit(accept1, accept2));
	perms.quiet = map_old_perms(dfa_other_quiet(accept1, accept2));
	perms.xindex = dfa_other_xindex(accept1);

	compute_fperms_allow(&perms, accept1);
	perms.prompt &= ~(perms.allow | perms.deny);
	return perms;
}

static uint32_t map_other(uint32_t x)
{
	return ((x & 0x3) << 8) |	/* SETATTR/GETATTR */
		((x & 0x1c) << 18) |	/* ACCEPT/BIND/LISTEN */
		((x & 0x60) << 19);	/* SETOPT/GETOPT */
}

struct aa_perms compute_perms_entry(uint32_t accept1, uint32_t accept2,
				    uint32_t accept3)
// don't need to worry about version internally within the parser
//					   uint32_t version)
{
	struct aa_perms perms = { };

	perms.allow = dfa_user_allow(accept1);
	perms.prompt = dfa_user_allow(accept3);
	perms.audit = dfa_user_audit(accept1, accept2);
	perms.quiet = dfa_user_quiet(accept1, accept2);
	if (accept1 & AA_COMPAT_CONT_MATCH)
		perms.allow |= AA_CONT_MATCH;

	/*
	 * This mapping is convulated due to history.
	 * v1-v4: only file perms, which are handled by compute_fperms
	 * v5: added policydb which dropped user conditional to gain new
	 *     perm bits, but had to map around the xbits because the
	 *     userspace compiler was still munging them.
	 * v9: adds using the xbits in policydb because the compiler now
	 *     supports treating policydb permission bits different.
	 *     Unfortunately there is no way to force auditing on the
	 *     perms represented by the xbits
	 */
	perms.allow |= map_other(dfa_other_allow(accept1));
	// v9 encoding never rolled out. AA_MAY_LOCK needed to fix
	// non fs unix locking see kernel commit
	// 1cf26c3d2c4c apparmor: fix apparmor mediating locking non-fs unix sockets
	//if (VERSION_LE(version, v8))
		perms.allow |= AA_MAY_LOCK;
	//else
	//	perms.allow |= map_xbits(dfa_user_xbits(dfa, state));

	/*
	 * for v5-v9 perm mapping in the policydb, the other set is used
	 * to extend the general perm set
	 */
	perms.prompt |= map_other(dfa_other_allow(accept3));
	perms.audit |= map_other(dfa_other_audit(accept1, accept2));
	perms.quiet |= map_other(dfa_other_quiet(accept1, accept2));
	//if (VERSION_GT(version, v8))
	//	perms.quiet |= map_xbits(dfa_other_xbits(dfa, state));

	return perms;
}

