/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010 - 2014
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */
#ifndef __AA_COMMON_OPTARG_H
#define __AA_COMMON_OPTARG_H

#include "common_flags.h"


/*
 * flag: 1 - allow no- inversion
 * flag: 2 - flags specified should be masked off
 * flag: 4 - flags specified are the default value
 */
#define OPT_FLAG_CONTROL_PREFIX_NO	1
#define OPT_FLAG_CONTROL_MASK		2
#define OPT_FLAG_CONTROL_DEFAULT	4
typedef struct {
	int control;
	const char *option;
	const char *desc;
	optflags_t flags;
} optflag_table_t;

extern optflag_table_t dumpflag_table[];
extern optflag_table_t dfaoptflag_table[];


void print_flags(const char *prefix, optflag_table_t *table,
		 optflags_t flags);
int handle_flag_table(optflag_table_t *table, const char *optarg,
		      optflags_t *flags);
void flagtable_help(const char *name, const char *header, const char *command,
		    optflag_table_t *table);

#endif /* __AA_COMMON_OPTARG_H */

