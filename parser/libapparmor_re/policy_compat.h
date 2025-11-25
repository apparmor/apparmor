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
#ifndef __LIBAA_RE_POLICY_COMPAT_H
#define __LIBAA_RE_POLICY_COMPAT_H

struct aa_perms compute_fperms_user(uint32_t accept1, uint32_t accept2, uint32_t accept3);
struct aa_perms compute_fperms_other(uint32_t accept1, uint32_t accept2, uint32_t accept3);
struct aa_perms compute_perms_entry(uint32_t accept1, uint32_t accept2, uint32_t accept3);

#endif /* __AA_POLICY_COMPAT_H */
