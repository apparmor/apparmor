/*
 *   Copyright (c) 2020
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

#ifndef __AA_CAPABILITY_H
#define __AA_CAPABILITY_H

#include <cstdint>
#include <linux/capability.h>

#define NO_BACKMAP_CAP 0xff


#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif
#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL 30
#endif
#ifndef CAP_SETFCAP
#define CAP_SETFCAP	     31
#endif
#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE     32
#endif

#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ 37
#endif

#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif

#ifndef CAP_BPF
#define CAP_BPF 39
#endif

#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE 40
#endif

enum class capability_flags {
	CLEAR = 0,
	BASE_FEATURE = 1,
	KERNEL_FEATURE = 2,
	POLICY_FEATURE = 4,
	EXTERNAL_FEATURE = 8,
};

inline capability_flags operator|(capability_flags a, capability_flags b)
{
	return static_cast<capability_flags>(static_cast<int>(a) | static_cast<int>(b));
}
inline capability_flags operator&(capability_flags a, capability_flags b)
{
	return static_cast<capability_flags>(static_cast<int>(a) & static_cast<int>(b));
}
inline capability_flags operator~(capability_flags a)
{
	return static_cast<capability_flags>(~static_cast<int>(a));
}
inline capability_flags &operator|=(capability_flags &a, capability_flags b)
{
	return a = a | b;
}
inline capability_flags &operator&=(capability_flags &a, capability_flags b)
{
	return a = a & b;
}

int name_to_capability(const char *keyword);
void __debug_capabilities(uint64_t capset, const char *name);
bool add_cap_feature_mask(struct aa_features *features, capability_flags flags);
void clear_cap_flag(capability_flags flags);
int capability_backmap(unsigned int cap);
bool capability_in_kernel(unsigned int cap);

#endif /* __AA_CAPABILITY_H */
