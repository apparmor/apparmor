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
 *
 *
 * Create a compressed hfa from and hfa
 */

#include <map>
#include <vector>
#include <ostream>
#include <iostream>
#include <fstream>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "hfa.h"
#include "chfa.h"
#include "../immunix.h"
#include "../policydb.h"
#include "flex-tables.h"

void CHFA::init_free_list(vector<pair<size_t, size_t> > &free_list,
				     size_t prev, size_t start)
{
	for (size_t i = start; i < free_list.size(); i++) {
		if (prev)
			free_list[prev].second = i;
		free_list[i].first = prev;
		prev = i;
	}
	free_list[free_list.size() - 1].second = 0;
}


/**
 * new Construct the transition table.
 *
 * TODO: split dfaflags into separate control and dump so we can fold in
 *       permtable index flag
 */
CHFA::CHFA(DFA &dfa, map<transchar, transchar> &eq, optflags const &opts,
	   bool permindex, bool prompt): eq(eq)
{
	if (opts.dump & DUMP_DFA_TRANS_PROGRESS)
		fprintf(stderr, "Compressing HFA:\r");

	chfaflags = 0;
	if (dfa.diffcount)
		chfaflags |= YYTH_FLAG_DIFF_ENCODE;
	if (dfa.oob_range)
		chfaflags |= YYTH_FLAG_OOB_TRANS;

	if (eq.empty())
		max_eq = 255;
	else {
		max_eq = 0;
		for (map<transchar, transchar>::iterator i = eq.begin();
		     i != eq.end(); i++) {
			if (i->second > max_eq)
				max_eq = i->second;
		}
	}

	/* Do initial setup adding up all the transitions and sorting by
	 * transition count.
	 */
	size_t optimal = 2;
	multimap<size_t, State *> order;
	vector<pair<size_t, size_t> > free_list;

	for (Partition::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
		if (*i == dfa.start || *i == dfa.nonmatching)
			continue;
		optimal += (*i)->trans.size();
		if (opts.control & CONTROL_DFA_TRANS_HIGH) {
			size_t range = 0;
			if ((*i)->trans.size())
				range =
				    (*i)->trans.rbegin()->first.c -
				    (*i)->trans.begin()->first.c;
			size_t ord = ((dfa.max_range - (*i)->trans.size()) << dfa.ord_range) | (dfa.max_range - range);
			/* reverse sort by entry count, most entries first */
			order.insert(make_pair(ord, *i));
		}
	}

	/* Insert the dummy nonmatching transition by hand */
	next_check.push_back(make_pair(dfa.nonmatching, dfa.nonmatching));
	default_base.push_back(make_pair(dfa.nonmatching, 0));
	num.insert(make_pair(dfa.nonmatching, num.size()));

	/* minimum size is 2 */
	accept.resize(max(dfa.states.size(), (size_t) 2));
	if (!permindex || dfa.filedfa)
		/* currently only using accept2 for owner cond in the
		 * file dfa
		 */
		accept2.resize(max(dfa.states.size(), (size_t) 2));
	if (permindex) {
		accept[0] = dfa.nonmatching->idx;
		accept[1] = dfa.start->idx;
		/* accept2 owner flag doesn't matter for nonmatching and
		 * start state
		 */
	} else {
		uint32_t accept3;
		dfa.nonmatching->perms->map_perms_to_accept(accept[0],
							    accept2[0],
							    accept3,
							    prompt);
		dfa.start->perms->map_perms_to_accept(accept[1],
						      accept2[1],
						      accept3,
						      prompt);
	}
	next_check.resize(max(optimal, (size_t) dfa.max_range));
	free_list.resize(next_check.size());

	first_free = 1;
	init_free_list(free_list, 0, 1);

	start = dfa.start;
	insert_state(free_list, dfa.start, dfa);
	num.insert(make_pair(dfa.start, num.size()));

	int count = 2;

	if (!(opts.control & CONTROL_DFA_TRANS_HIGH)) {
		for (Partition::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
			if (*i != dfa.nonmatching && *i != dfa.start) {
				uint32_t accept3;
				insert_state(free_list, *i, dfa);
				if (permindex) {
					accept[num.size()] = (*i)->idx;
					/* set owner conditional */
					if (dfa.filedfa)
						accept2[num.size()] = 1; // TODO: Define this flag
				} else {
					(*i)->perms->map_perms_to_accept(accept[num.size()],
								  accept2[num.size()],
								  accept3,
								  prompt);
				}
				num.insert(make_pair(*i, num.size()));
			}
			if (opts.dump & (DUMP_DFA_TRANS_PROGRESS)) {
				count++;
				if (count % 100 == 0)
					fprintf(stderr, "\033[2KCompressing trans table: insert state: %d/%zd\r",
						count, dfa.states.size());
			}
		}
	} else {
		for (multimap<size_t, State *>::iterator i = order.begin();
		     i != order.end(); i++) {
			if (i->second != dfa.nonmatching &&
			    i->second != dfa.start) {
				uint32_t accept3;
				insert_state(free_list, i->second, dfa);
				if (permindex) {
					accept[num.size()] = i->second->idx;
					if (dfa.filedfa)
						accept2[num.size()] = 1; // TODO: Define this flag.
				} else {
					i->second->perms->map_perms_to_accept(accept[num.size()],
								       accept2[num.size()],
								       accept3,
								       prompt);
				}
				num.insert(make_pair(i->second, num.size()));
			}
			if (opts.dump & (DUMP_DFA_TRANS_PROGRESS)) {
				count++;
				if (count % 100 == 0)
					fprintf(stderr, "\033[2KCompressing trans table: insert state: %d/%zd\r",
						count, dfa.states.size());
			}
		}
	}

	if (opts.dump & (DUMP_DFA_TRANS_STATS | DUMP_DFA_TRANS_PROGRESS)) {
		ssize_t size = 4 * next_check.size() + 6 * dfa.states.size();
		fprintf(stderr, "\033[2KCompressed trans table: states %zd, next/check %zd, optimal next/check %zd avg/state %.2f, compression %zd/%zd = %.2f %%\n",
			dfa.states.size(), next_check.size(), optimal,
			(float)next_check.size() / (float)dfa.states.size(),
			size, 512 * dfa.states.size(),
			100.0 - ((float)size * 100.0 /(float)(512 * dfa.states.size())));
	}
}

/**
 * Does <trans> fit into position <base> of the transition table?
 */
bool CHFA::fits_in(vector<pair<size_t, size_t> > &free_list
			      __attribute__ ((unused)), size_t pos,
			      StateTrans &trans)
{
	ssize_t c, base = pos - trans.begin()->first.c;

	if (base < 0)
		return false;
	for (StateTrans::iterator i = trans.begin(); i != trans.end(); i++) {
		c = base + i->first.c;
		/* if it overflows the next_check array it fits in as we will
		 * resize */
		if (c >= (ssize_t) next_check.size())
			return true;
		if (next_check[c].second)
			return false;
	}

	return true;
}

/**
 * Insert <state> of <dfa> into the transition table.
 */
void CHFA::insert_state(vector<pair<size_t, size_t> > &free_list,
				   State *from, DFA &dfa)
{
	State *default_state = dfa.nonmatching;
	ssize_t base = 0;
	int resize;
	StateTrans &trans = from->trans;
	ssize_t c;
	ssize_t prev = 0;
	ssize_t x = first_free;

	if (from->otherwise)
		default_state = from->otherwise;
	if (trans.empty())
		goto do_insert;

	c = trans.begin()->first.c;
repeat:
	resize = 0;
	/* get the first free entry that won't underflow */
	while (x && ((x < c) || (x + c < 0))) {
		prev = x;
		x = free_list[x].second;
	}

	/* try inserting until we succeed. */
	while (x && !fits_in(free_list, x, trans)) {
		prev = x;
		x = free_list[x].second;
	}
	if (!x) {
		resize = dfa.upper_bound - c;
		x = free_list.size();
		/* set prev to last free */
	} else if (x + (dfa.upper_bound - 1) - c >= (ssize_t) next_check.size()) {
		resize = ((dfa.upper_bound -1) - c - (next_check.size() - 1 - x));
		for (size_t y = x; y; y = free_list[y].second)
			prev = y;
	}
	if (resize) {
		/* expand next_check and free_list */
		ssize_t old_size = free_list.size();
		next_check.resize(next_check.size() + resize);
		free_list.resize(free_list.size() + resize);
		init_free_list(free_list, prev, old_size);
		if (!first_free)
			first_free = old_size;;
		if (x == old_size)
			goto repeat;
	}

	base = x - c;
	for (StateTrans::iterator j = trans.begin(); j != trans.end(); j++) {
		next_check[base + j->first.c] = make_pair(j->second, from);
		size_t prev = free_list[base + j->first.c].first;
		size_t next = free_list[base + j->first.c].second;
		if (prev)
			free_list[prev].second = next;
		if (next)
			free_list[next].first = prev;
		if (base + j->first.c == first_free)
			first_free = next;
	}

	/* these flags will only be set on states that have transitions */
	if (c < 0) {
		base |= MATCH_FLAG_OOB_TRANSITION;
	}
do_insert:
	/* While a state without transitions could have the diff encode
	 * flag set, it would be pointless resulting in just an extra
	 * state transition in the encoding chain, and so it should be
	 * considered an error
	 * TODO: add check that state without transitions isn't being
	 * given a diffencode flag
	 */
	if (from->flags & DiffEncodeFlag)
		base |= DiffEncodeBit32;
	default_base.push_back(make_pair(default_state, base));
}

/**
 * Text-dump the transition table (for debugging).
 */
void CHFA::dump(ostream &os)
{
	map<size_t, const State *> st;
	for (map<const State *, size_t>::iterator i = num.begin(); i != num.end(); i++) {
		st.insert(make_pair(i->second, i->first));
	}

	os << "size=" << default_base.size() << " (accept, accept2, default, base):  {state} -> {default state}" << "\n";
	for (size_t i = 0; i < default_base.size(); i++) {
		os << i << ": ";
		os << "(" << accept[i] << ", ";
		if (accept2.size() > 0)
			os << accept2[i];
		else
			os << "---, ";
		os << num[default_base[i].first] << ", " <<
			default_base[i].second << ")";
		if (st[i])
			os << " " << *st[i];
		if (default_base[i].first)
			os << " -> " << *default_base[i].first;
		os << "\n";
	}

	os << "size=" << next_check.size() << " (next, check): {check state} -> {next state} : offset from base\n";
	for (size_t i = 0; i < next_check.size(); i++) {
		if (!next_check[i].second)
			continue;

		os << i << ": ";
		if (next_check[i].second) {
			os << "(" << num[next_check[i].first] << ", "
			   << num[next_check[i].second] << ")" << " "
			   << *next_check[i].second << " -> "
			   << *next_check[i].first << ": ";

			size_t offs = i - base_mask_size(default_base[num[next_check[i].second]].second);
			if (eq.size())
				os << offs;
			else
				os << (transchar) offs;
		}
		os << "\n";
	}
}

/**
 * Create a flex-style binary dump of the DFA tables. The table format
 * was partly reverse engineered from the flex sources and from
 * examining the tables that flex creates with its --tables-file option.
 * (Only the -Cf and -Ce formats are currently supported.)
 */

#define YYTH_REGEX_MAGIC 0x1B5E783D

static inline size_t pad64(size_t i)
{
	return (i + (size_t) 7) & ~(size_t) 7;
}

string fill64(size_t i)
{
	const char zeroes[8] = { };
	string fill(zeroes, (i & 7) ? 8 - (i & 7) : 0);
	return fill;
}

template<class Iter> size_t flex_table_size(Iter pos, Iter end)
{
	return pad64(sizeof(struct table_header) + sizeof(*pos) * (end - pos));
}

template<class Iter>
    void write_flex_table(ostream &os, int id, Iter pos, Iter end)
{
	struct table_header td = { 0, 0, 0, 0 };
	size_t size = end - pos;

	td.td_id = htons(id);
	td.td_flags = htons(sizeof(*pos));
	td.td_lolen = htonl(size);
	os.write((char *)&td, sizeof(td));

	for (; pos != end; ++pos) {
		switch (sizeof(*pos)) {
		case 4:
			os.put((char)(*pos >> 24));
			os.put((char)(*pos >> 16));
			/* Fall through */
		case 2:
			os.put((char)(*pos >> 8));
			/* Fall through */
		case 1:
			os.put((char)*pos);
			/* Fall through */
		}
	}

	os << fill64(sizeof(td) + sizeof(*pos) * size);
}

template<class STATE_TYPE>
void flex_table_serialize(CHFA &chfa, ostream &os,
			  uint32_t max_size)
{
	const char th_version[] = "notflex";
	struct table_set_header th = { 0, 0, 0, 0 };

	/**
	 * Change the following two data types to adjust the maximum flex
	 * table size.
	 */
	typedef uint32_t trans_t;

	if (chfa.default_base.size() >= (max_size)) {
		cerr << "Too many states (" << chfa.default_base.size() << ") for "
		    "type state_t\n";
		exit(1);
	}
	if (chfa.next_check.size() >= (trans_t) - 1) {
		cerr << "Too many transitions (" << chfa.next_check.size()
		     << ") for " "type trans_t\n";
		exit(1);
	}

	/**
	 * Create copies of the data structures so that we can dump the tables
	 * using the generic write_flex_table() routine.
	 */
	vector<uint8_t> equiv_vec;
	if (chfa.eq.size()) {
		equiv_vec.resize(256);
		for (map<transchar, transchar>::iterator i = chfa.eq.begin(); i != chfa.eq.end(); i++) {
			equiv_vec[i->first.c] = i->second.c;
		}
	}

	vector<STATE_TYPE> default_vec;
	vector<trans_t> base_vec;
	for (DefaultBase::iterator i = chfa.default_base.begin(); i != chfa.default_base.end(); i++) {
		default_vec.push_back(chfa.num[i->first]);
		base_vec.push_back(i->second);
	}

	vector<STATE_TYPE> next_vec;
	vector<STATE_TYPE> check_vec;
	for (NextCheck::iterator i = chfa.next_check.begin(); i != chfa.next_check.end(); i++) {
		next_vec.push_back(chfa.num[i->first]);
		check_vec.push_back(chfa.num[i->second]);
	}

	/* Write the actual flex parser table. */
	/* TODO: add max_oob */
	// sizeof(th_version) includes trailing \0
	size_t hsize = pad64(sizeof(th) + sizeof(th_version));
	th.th_magic = htonl(YYTH_REGEX_MAGIC);
	th.th_flags = htons(chfa.chfaflags);
	th.th_hsize = htonl(hsize);
	th.th_ssize = htonl(hsize +
			    flex_table_size(chfa.accept.begin(),
					    chfa.accept.end()) +
			    (chfa.accept2.size() ?
			     flex_table_size(chfa.accept2.begin(),
					     chfa.accept2.end()) : 0) +
			    (chfa.eq.size() ?
			     flex_table_size(equiv_vec.begin(),
					     equiv_vec.end()) : 0) +
			    flex_table_size(base_vec.begin(),
					    base_vec.end()) +
			    flex_table_size(default_vec.begin(),
					    default_vec.end()) +
			    flex_table_size(next_vec.begin(), next_vec.end()) +
			    flex_table_size(check_vec.begin(),
					    check_vec.end()));
	os.write((char *)&th, sizeof(th));
	os.write(th_version, sizeof(th_version));
	os << fill64(sizeof(th) + sizeof(th_version));

	write_flex_table(os, YYTD_ID_ACCEPT, chfa.accept.begin(),
			 chfa.accept.end());
	if (chfa.accept2.size())
		write_flex_table(os, YYTD_ID_ACCEPT2, chfa.accept2.begin(),
				 chfa.accept2.end());
	if (chfa.eq.size())
		write_flex_table(os, YYTD_ID_EC, equiv_vec.begin(),
				 equiv_vec.end());
	write_flex_table(os, YYTD_ID_BASE, base_vec.begin(), base_vec.end());
	write_flex_table(os, YYTD_ID_DEF, default_vec.begin(), default_vec.end());
	write_flex_table(os, YYTD_ID_NXT, next_vec.begin(), next_vec.end());
	write_flex_table(os, YYTD_ID_CHK, check_vec.begin(), check_vec.end());
}

void CHFA::flex_table(ostream &os, optflags const &opts) {

	if (opts.control & CONTROL_DFA_STATE32 &&
	    default_base.size() > (1 << 16) - 1) {
// TODO: implement support for flags in separate table
//		if (opts.control & CONTROL_DFA_FLAGS_TABLE) {
//			if (opts.dump & DUMP_FLAGS_TABLE)
//				cerr << "using flags table\n";
//			flex_table_serialize(os, uint32_t, (1 << 32) - 1);
//		} else { /* only 24 bits available */
		if (opts.dump & DUMP_DFA_STATE32)
			cerr << "using 32 bit state tables, embedded flags\n";
		flex_table_serialize<uint32_t>(*this, os, (1 << 24) - 1);
	} else {
		if (opts.control & CONTROL_DFA_FLAGS_TABLE) {
			cerr << "Flags table specified when using 16 bit state\n";
			exit(1);
		}
		if (opts.dump & DUMP_DFA_STATE32)
			cerr << "using 16 bit state tables, embedded flags\n";
		flex_table_serialize<uint16_t>(*this, os, (1 << 16) - 1);
	}
}

/*
 * @file_chfa: chfa to add on to the policy chfa
 * @new_start: new start state for where the @file_dfa is in the new chfa
 *
 * Make a new chfa that is a combination of policy and file chfas. It
 * assumes policy is built with AA_CLASS_FILE support transition. The
 * resultant chfa will have file states and indexes offset except for
 * start and null states.
 *
 * NOTE:
 * - modifies chfa
 * requires:
 * - no ec
 * - policy chfa has transitions state[start].next[AA_CLASS_FILE]
 * - policy perms table is build if using permstable

 */
void CHFA::weld_file_to_policy(CHFA &file_chfa, size_t &new_start,
			       bool accept_idx, bool prompt,
			       vector <aa_perms>  &policy_perms,
			       vector <aa_perms> &file_perms)
{
	// doesn't support remapping eq classes yet
	if (eq.size() > 0 || file_chfa.eq.size() > 0)
		throw 1;

	size_t old_base_size = default_base.size();
	size_t old_next_size = next_check.size();

	const State *nonmatching = default_base[0].first;
	//const State *start = default_base[1].first;
	const State *file_nonmatching = file_chfa.default_base[0].first;

	// renumber states from file_dfa by appending to policy dfa
	num.insert(make_pair(file_nonmatching, 0));	// remap to policy nonmatching
	for (map<const State *, size_t>::iterator i = file_chfa.num.begin(); i != file_chfa.num.end() ; i++) {
		if (i->first == file_nonmatching)
			continue;
		num.insert(make_pair(i->first, i->second + old_base_size));
	}

	// handle default and base table expansion, and setup renumbering
	// while we remap file_nonmatch within the table, we still keep its
	// slot.
	bool first = true;
	for (DefaultBase::iterator i = file_chfa.default_base.begin(); i != file_chfa.default_base.end(); i++) {
		const State *def;
		size_t base;
		if (first) {
			first = false;
			// remap file_nonmatch to nonmatch
			def = nonmatching;
			base = 0;
		} else {
			def = i->first;
			base = i->second + old_next_size;
		}
		default_base.push_back(make_pair(def, base));
	}

	// mapping for these are handled by num[]
	for (NextCheck::iterator i = file_chfa.next_check.begin(); i != file_chfa.next_check.end(); i++) {
		next_check.push_back(*i);
	}

	// append file perms to policy perms, and rework permsidx if needed
	if (accept_idx) {
		// policy idx double
		// file + doubled offset
		// Requires: policy perms table, so we can double and
		//           update indexes
		//         * file perm idx to start on even idx
		//         * policy perms table size to double and entries
		//           to repeat
		assert(accept.size() == old_base_size);
		accept.resize(accept.size() + file_chfa.accept.size());
		size_t size = policy_perms.size();
		policy_perms.resize(size*2 + file_perms.size());
		// shift and double the policy perms
		for (size_t i = size - 1; size >= 0; i--) {
			policy_perms[i*2] = policy_perms[i];
			policy_perms[i*2 + 1] = policy_perms[i];
		}
		// update policy accept idx for the new shifted perms table
		for (size_t i = 0; i < old_base_size; i++) {
			accept[i] = accept[i]*2;
		}
		// copy over file perms
		for (size_t i = 0; i < file_perms.size(); i++) {
			policy_perms[size*2 + i] = file_perms[i];
		}
		// shift file accept indexs
		for (size_t i = 0; i < file_chfa.accept.size(); i++) {
			accept[old_base_size + i] = file_chfa.accept[i] + size*2;
		}
	} else {
		// perms are stored in accept just append the perms
		size_t size = accept.size();
		accept.resize(size + file_chfa.accept.size());
		accept2.resize(size + file_chfa.accept.size());
		for (size_t i = 0; i < file_chfa.accept.size(); i++) {
			accept[size + i] = file_chfa.accept[i];
			accept2[size + i] = file_chfa.accept2[i];
		}
	}

	// Rework transition state[start].next[AA_CLASS_FILE]
	next_check[default_base[1].second + AA_CLASS_FILE].first = file_chfa.start;

	new_start = num[file_chfa.start];
}
