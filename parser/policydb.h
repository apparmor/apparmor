/*
 * Copyright 2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __AA_POLICYDB_H
#define __AA_POLICYDB_H

/*
 * Class of private mediation types in the AppArmor policy db
 *
 * See libapparmor's apparmor.h for public mediation types
 */
#define AA_CLASS_COND		0
#define AA_CLASS_UNKNOWN	1
#define AA_CLASS_FILE		2
#define AA_CLASS_CAP		3
#define AA_CLASS_NET		4
#define AA_CLASS_RLIMITS	5
#define AA_CLASS_DOMAIN		6
#define AA_CLASS_MOUNT		7
#define AA_CLASS_NS_DOMAIN	8
#define AA_CLASS_PTRACE		9
#define AA_CLASS_SIGNAL		10
#define AA_CLASS_XMATCH		11
#define AA_CLASS_ENV		12
#define AA_CLASS_ARGV		13
#define AA_CLASS_NETV8		14
#define AA_CLASS_NETV9		15
#define AA_CLASS_LABEL		16
#define AA_CLASS_POSIX_MQUEUE	17
#define AA_CLASS_SYSV_MQUEUE	18
#define AA_CLASS_MODULE		19
#define AA_CLASS_DISPLAY_LSM	20
#define AA_CLASS_NS		21
#define AA_CLASS_IO_URING	22
/* 23 unallocated */
#define AA_CLASS_PGID		24
#define AA_CLASS_SID		25
#define AA_CLASS_SCHED		26
#define AA_CLASS_IOPRI		27
#define AA_CLASS_PRCTL		28
/* 29 unallocated */
#define AA_CLASS_NETV9_SKB	30
#define AA_CLASS_X		31
/* defined in libapparmor's apparmor.h #define AA_CLASS_DBUS 32 */

extern const char *aa_class_table[];

#endif /* __AA_POLICYDB_H */
