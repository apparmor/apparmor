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
 * Create a compressed hfa (chfa) from an hfa
 */
#ifndef __LIBAA_RE_CHFA_H
#define __LIBAA_RE_CHFA_H

#include <map>
#include <vector>

#include "hfa.h"
#include "../perms.h"

#define BASE32_FLAGS 0xff000000
#define DiffEncodeBit32 0x80000000
#define MATCH_FLAG_OOB_TRANSITION 0x20000000
#define base_mask_size(X) ((X) & ~BASE32_FLAGS)

using namespace std;

typedef vector<pair<const State *, size_t> > DefaultBase;
typedef vector<pair<const State *, const State *> > NextCheck;

class CHFA {
      public:
	CHFA(void);
	CHFA(DFA &dfa, map<transchar, transchar> &eq, optflags const &opts,
	     int permstable32_version, bool prompt);
	void dump(ostream & os);
	void flex_table(ostream &os, optflags const &opts);
	void init_free_list(vector<pair<size_t, size_t> > &free_list,
			    size_t prev, size_t start);
	bool fits_in(vector<pair<size_t, size_t> > &free_list, size_t base,
		     StateTrans &cases);
	void insert_state(vector<pair<size_t, size_t> > &free_list,
			  State *state, DFA &dfa);
	void weld_file_to_policy(CHFA &file_chfa, size_t &new_start,
				 bool accept_idx, bool prompt,
				 vector <aa_perms>  &policy_perms,
				 vector <aa_perms> &file_perms);

	// private:
	// sigh templates suck, friend declaration does not work so for now
	// make these public
	vector<uint32_t> accept;
	vector<uint32_t> accept2;
	DefaultBase default_base;
	NextCheck next_check;
	const State *start;
	Renumber_Map num;
	map<transchar, transchar> eq;
	unsigned int chfaflags;
      private:
	transchar max_eq;
	ssize_t first_free;
};

#endif /* __LIBAA_RE_CHFA_H */
