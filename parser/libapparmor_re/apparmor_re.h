/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2012 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  */

#ifndef __LIBAA_RE_APPARMOR_RE_H
#define __LIBAA_RE_APPARMOR_RE_H

#include "../common_flags.h"

#define CONTROL_DFA_EQUIV		(1 << 0)
#define CONTROL_DFA_TREE_NORMAL		(1 << 1)
#define CONTROL_DFA_TREE_SIMPLE		(1 << 2)
#define CONTROL_DFA_TREE_LEFT 		(1 << 3)
#define CONTROL_DFA_MINIMIZE 		(1 << 4)
#define CONTROL_DFA_FILTER_DENY		(1 << 6)
#define CONTROL_DFA_REMOVE_UNREACHABLE	(1 << 7)
#define CONTROL_DFA_TRANS_HIGH		(1 << 8)
#define CONTROL_DFA_DIFF_ENCODE		(1 << 9)
#define CONTROL_RULE_MERGE		(1 << 10)
#define CONTROL_DFA_STATE32		(1 << 11)
#define CONTROL_DFA_FLAGS_TABLE		(1 << 12)


#define DUMP_DFA_DIFF_PROGRESS		(1 << 0)
#define DUMP_DFA_DIFF_ENCODE		(1 << 1)
#define DUMP_DFA_DIFF_STATS		(1 << 2)
#define DUMP_DFA_MIN_PARTS 		(1 << 3)
#define DUMP_DFA_UNIQ_PERMS 		(1 << 4)
#define DUMP_DFA_MIN_UNIQ_PERMS 	(1 << 5)
#define DUMP_DFA_TREE_STATS 		(1 << 6)
#define DUMP_DFA_TREE 			(1 << 7)
#define DUMP_DFA_SIMPLE_TREE 		(1 << 8)
#define DUMP_DFA_PROGRESS 		(1 << 9)
#define DUMP_DFA_STATS			(1 << 10)
#define DUMP_DFA_STATES 		(1 << 11)
#define DUMP_DFA_GRAPH			(1 << 12)
#define DUMP_DFA_TRANS_PROGRESS 	(1 << 13)
#define DUMP_DFA_TRANS_STATS 		(1 << 14)
#define DUMP_DFA_TRANS_TABLE 		(1 << 15)
#define DUMP_DFA_EQUIV			(1 << 16)
#define DUMP_DFA_EQUIV_STATS 		(1 << 17)
#define DUMP_DFA_MINIMIZE 		(1 << 18)
#define DUMP_DFA_UNREACHABLE 		(1 << 19)
#define DUMP_DFA_RULE_EXPR 		(1 << 20)
#define DUMP_DFA_NODE_TO_DFA 		(1 << 21)
#define DUMP_RULE_MERGE			(1 << 22)
#define DUMP_DFA_STATE32		(1 << 23)
#define DUMP_DFA_FLAGS_TABLE		(1 << 24)
#define DUMP_DFA_STATES_INIT 		(1 << 25)
#define DUMP_DFA_STATES_POST_FILTER 	(1 << 26)
#define DUMP_DFA_STATES_POST_MINIMIZE	(1 << 27)
#define DUMP_DFA_STATES_POST_UNREACHABLE (1 << 28)
#define DUMP_DFA_COMPTRESSED_STATES	(1 << 29)
#define DUMP_DFA_PERMS			(1 << 30)

#endif /* APPARMOR_RE_H */
