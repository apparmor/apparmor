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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_optarg.h"
#include "parser.h"

optflag_table_t dumpflag_table[] = {
	{ 1, "rule-exprs", "Dump rule to expr tree conversions",
	  DUMP_DFA_RULE_EXPR },
	{ 1, "expr-stats", "Dump stats on expr tree", DUMP_DFA_TREE_STATS },
	{ 1, "expr-tree", "Dump expression tree", DUMP_DFA_TREE },
	{ 1, "expr-simplified", "Dump simplified expression tree",
	  DUMP_DFA_SIMPLE_TREE },
	{ 1, "stats", "Dump all compile stats",
	  DUMP_DFA_TREE_STATS | DUMP_DFA_STATS | DUMP_DFA_TRANS_STATS |
	  DUMP_DFA_EQUIV_STATS | DUMP_DFA_DIFF_STATS },
	{ 1, "progress", "Dump progress for all compile phases",
	  DUMP_DFA_PROGRESS | DUMP_DFA_STATS | DUMP_DFA_TRANS_PROGRESS |
	  DUMP_DFA_TRANS_STATS | DUMP_DFA_DIFF_PROGRESS | DUMP_DFA_DIFF_STATS },
	{ 1, "dfa-progress", "Dump dfa creation as in progress",
	  DUMP_DFA_PROGRESS | DUMP_DFA_STATS },
	{ 1, "dfa-stats", "Dump dfa creation stats", DUMP_DFA_STATS },
	{ 1, "dfa-states", "Dump final dfa state information", DUMP_DFA_STATES },
	{ 1, "dfa-compressed-states", "Dump compressed dfa state information", DUMP_DFA_COMPTRESSED_STATES },
	{ 1, "dfa-states-initial", "Dump dfa state immediately after initial build", DUMP_DFA_STATES_INIT },
	{ 1, "dfa-states-post-filter", "Dump dfa state immediately after filtering deny", DUMP_DFA_STATES_POST_FILTER },
	{ 1, "dfa-states-post-minimize", "Dump dfa state immediately after initial build", DUMP_DFA_STATES_POST_MINIMIZE },
	{ 1, "dfa-states-post-unreachable", "Dump dfa state immediately after filtering deny", DUMP_DFA_STATES_POST_UNREACHABLE },
	{ 1, "dfa-perms-build", "Dump permission being built from accept node", DUMP_DFA_PERMS },
	{ 1, "dfa-graph", "Dump dfa dot (graphviz) graph", DUMP_DFA_GRAPH },
	{ 1, "dfa-minimize", "Dump dfa minimization", DUMP_DFA_MINIMIZE },
	{ 1, "dfa-unreachable", "Dump dfa unreachable states",
	  DUMP_DFA_UNREACHABLE },
	{ 1, "dfa-node-map", "Dump expr node set to state mapping",
	  DUMP_DFA_NODE_TO_DFA },
	{ 1, "dfa-uniq-perms", "Dump unique perms",
	  DUMP_DFA_UNIQ_PERMS },
	{ 1, "dfa-minimize-uniq-perms", "Dump unique perms post minimization",
	  DUMP_DFA_MIN_UNIQ_PERMS },
	{ 1, "dfa-minimize-partitions", "Dump dfa minimization partitions",
	  DUMP_DFA_MIN_PARTS },
	{ 1, "compress-progress", "Dump progress of compression",
	  DUMP_DFA_TRANS_PROGRESS | DUMP_DFA_TRANS_STATS },
	{ 1, "compress-stats", "Dump stats on compression",
	  DUMP_DFA_TRANS_STATS },
	{ 1, "compressed-dfa", "Dump compressed dfa", DUMP_DFA_TRANS_TABLE },
	{ 1, "equiv-stats", "Dump equivalence class stats",
	  DUMP_DFA_EQUIV_STATS },
	{ 1, "equiv", "Dump equivalence class", DUMP_DFA_EQUIV },
	{ 1, "diff-encode", "Dump differential encoding",
	  DUMP_DFA_DIFF_ENCODE },
	{ 1, "diff-stats", "Dump differential encoding stats",
	  DUMP_DFA_DIFF_STATS },
	{ 1, "diff-progress", "Dump progress of differential encoding",
	  DUMP_DFA_DIFF_PROGRESS | DUMP_DFA_DIFF_STATS },
	{ 1, "rule-merge", "dump information about rule merging", DUMP_RULE_MERGE},
	{ 1, "state32", "Dump encoding 32 bit states",
	  DUMP_DFA_STATE32 },
	{ 1, "flags_table", "Dump encoding flags table",
	  DUMP_DFA_FLAGS_TABLE },
	{ 0, NULL, NULL, 0 },
};

optflag_table_t dfaoptflag_table[] = {
	{ 2, "0", "no optimizations",
	  CONTROL_DFA_TREE_NORMAL | CONTROL_DFA_TREE_SIMPLE |
	  CONTROL_DFA_MINIMIZE | CONTROL_DFA_REMOVE_UNREACHABLE |
	  CONTROL_DFA_DIFF_ENCODE | CONTROL_DFA_STATE32 |
	  CONTROL_DFA_FLAGS_TABLE
	},
	{ 1, "equiv", "use equivalent classes", CONTROL_DFA_EQUIV },
	{ 1, "expr-normalize", "expression tree normalization",
	  CONTROL_DFA_TREE_NORMAL },
	{ 1, "expr-simplify", "expression tree simplification",
	  CONTROL_DFA_TREE_SIMPLE },
	{ 0, "expr-left-simplify", "left simplification first",
	  CONTROL_DFA_TREE_LEFT },
	{ 2, "expr-right-simplify", "right simplification first",
	  CONTROL_DFA_TREE_LEFT },
	{ 1, "minimize", "dfa state minimization", CONTROL_DFA_MINIMIZE },
	{ 1, "filter-deny", "filter out deny information from final dfa",
	  CONTROL_DFA_FILTER_DENY },
	{ 1, "remove-unreachable", "dfa unreachable state removal",
	  CONTROL_DFA_REMOVE_UNREACHABLE },
	{ 0, "compress-small",
	  "do slower dfa transition table compression",
	  CONTROL_DFA_TRANS_HIGH },
	{ 2, "compress-fast", "do faster dfa transition table compression",
	  CONTROL_DFA_TRANS_HIGH },
	{ 1, "diff-encode", "Differentially encode transitions",
	  CONTROL_DFA_DIFF_ENCODE },
	{ 1, "rule-merge", "turn on rule merging", CONTROL_RULE_MERGE},
	{ 1, "state32", "use 32 bit state transitions",
	  CONTROL_DFA_STATE32 },
	{ 1, "flags-table", "use independent flags table",
	  CONTROL_DFA_FLAGS_TABLE },
	{ 1, "zstd-recompress", "Recompress if the compressed level is higher than the existing cache",
	  CONTROL_ZSTD_FLAGS_RECOMPRESS },
	{ 0, NULL, NULL, 0 },
};


void print_flag_table(optflag_table_t *table)
{
	int i;
	unsigned int longest = 0;
	for (i = 0; table[i].option; i++) {
		if (strlen(table[i].option) > longest)
			longest = strlen(table[i].option);
	}

	printf("%-*s \t%s\n", longest, "     show", "show flags that have been set and exit");
	for (i = 0; table[i].option; i++) {
		printf("%5s%-*s \t%s\n",
		       (table[i].control & OPT_FLAG_CONTROL_PREFIX_NO) ? "[no-]" : "",
		       longest, table[i].option, table[i].desc);
	}
}

void print_flags(const char *prefix, optflag_table_t *table,
		 optflags_t flags)
{
	int i, count = 0;

	printf("%s=", prefix);
	for (i = 0; table[i].option; i++) {
		if ((table[i].flags & flags) == table[i].flags) {
			if (count)
				printf(", ");
			printf("%s", table[i].option);
			count++;
		}
	}
	if (count)
		printf("\n");
}

int handle_flag_table(optflag_table_t *table, const char *optarg,
		      optflags_t *flags)
{
	const char *arg = optarg;
	int i, invert = 0;

	if (strncmp(optarg, "no-", 3) == 0) {
		arg = optarg + 3;
		invert = 1;
	}

	for (i = 0; table[i].option; i++) {
		if (strcmp(table[i].option, arg) == 0) {
			/* check if leading no- was specified but is not
			 * supported by the option */
			if (invert && !(table[i].control & 1))
				return 0;
			if (table[i].control & 2)
				invert |= 1;
			if (invert)
				*flags &= ~table[i].flags;
			else
				*flags |= table[i].flags;
			return 1;
		}
	}
	return 0;
}

void flagtable_help(const char *name, const char *header, const char *command,
		    optflag_table_t *table)
{
	display_version();
	printf("\n%s: %s[Option]\n\n"
	       "%s"
	       "Options:\n"
	       "--------\n"
	       ,command, name, header);
	print_flag_table(table);
}
