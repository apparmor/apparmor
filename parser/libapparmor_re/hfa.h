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
  * Base of implementation based on the Lexical Analysis chapter of:
 *   Alfred V. Aho, Ravi Sethi, Jeffrey D. Ullman:
 *   Compilers: Principles, Techniques, and Tools (The "Dragon Book"),
 *   Addison-Wesley, 1986.
 */
#ifndef __LIBAA_RE_HFA_H
#define __LIBAA_RE_HFA_H

#include <list>
#include <map>
#include <vector>
#include <iostream>

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include "expr-tree.h"
#include "policy_compat.h"
#include "../rule.h"
extern int prompt_compat_mode;

#define DiffEncodeFlag 1

class State;

typedef map<transchar, State *> StateTrans;
typedef list<State *> Partition;

#include "../immunix.h"

ostream &operator<<(ostream &os, const State &state);
ostream &operator<<(ostream &os, State &state);

class perms_t {
public:
	perms_t(void): allow(0), deny(0), prompt(0), audit(0), quiet(0) { };
	perms_t(optflags const &opts, NodeVec *match, bool filedfa);

	bool is_accept(void) { return (allow | deny | prompt | audit | quiet); }

	void dump_header(ostream &os)
	{
		os << "(allow/deny/prompt/audit/quiet)";
	}
	void dump(ostream &os)
	{
		os << "(0x " << hex
		   << allow << "/" << deny << "/" << "/" << prompt << "/" << audit << "/" << quiet
		   << ')' << dec;
	}

	void clear(void) {
		allow = deny = prompt = audit = quiet = 0;
	}

	void clear_bits(perm32_t bits)
	{
		allow &= ~bits;
		deny &= ~bits;
		prompt &= ~bits;
		audit &= ~bits;
		quiet &= ~bits;
	}

	void add(perms_t &rhs, bool filedfa)
	{
		deny |= rhs.deny;

		if (filedfa && !is_merged_x_consistent(allow & ALL_USER_EXEC,
					    rhs.allow & ALL_USER_EXEC))
			// different x modifier in same partition
			throw 1;

		if (filedfa && !is_merged_x_consistent(allow & ALL_OTHER_EXEC,
					    rhs.allow & ALL_OTHER_EXEC))
			// different x modifier in same partition
			throw 1;

		allow |= rhs.allow;
		prompt |= rhs.prompt;
		audit |= rhs.audit;
		quiet |= rhs.quiet;

	}


	/* returns true if perm is no longer accept */
	bool apply_and_clear_deny(void)
	{
		if (deny) {
			allow &= ~deny;
			prompt &= ~deny;
			/* don't change audit or quiet based on clearing
			 * deny at this stage. This was made unique in
			 * accept_perms, and the info about whether
			 * we are auditing or quieting based on the explicit
			 * deny has been discarded and can only be inferred.
			 * But we know it is correct from accept_perms()
			 * audit &= deny;
			 * quiet &= deny;
			 */
			deny = 0;
			return !is_accept();
		}
		return false;
	}

	void map_perms_to_accept(perm32_t &accept1, perm32_t &accept2,
				 perm32_t &accept3, bool doprompt) const
	{
		accept1 = allow;
		if (doprompt && prompt_compat_mode == PROMPT_COMPAT_DEV)
			accept2 = PACK_AUDIT_CTL(prompt, quiet);
		else
			accept2 = PACK_AUDIT_CTL(audit, quiet);
		accept3 = prompt;
	}


	bool operator<(perms_t const &rhs)const
	{
		if (allow != rhs.allow)
			return allow < rhs.allow;
		if (deny != rhs.deny)
			return deny < rhs.deny;
		if (prompt != rhs.prompt)
			return prompt < rhs.prompt;
		if (audit != rhs.audit)
			return audit < rhs.audit;
		if (audit != rhs.audit)
			return audit > rhs.audit;
		return quiet < rhs.quiet;
	}

	bool operator==(perms_t const &rhs)const
	{
		if (allow != rhs.allow)
			return false;
		if (deny != rhs.deny)
			return false;
		if (prompt != rhs.prompt)
			return false;
		if (audit != rhs.audit)
			return false;
		return quiet == rhs.quiet;
	}
	bool operator!=(perms_t const &rhs)const
	{
		return !(*this == rhs);
	}
	perm32_t allow, deny, prompt, audit, quiet;
};

struct deref_less_than_perms {
	bool operator()(perms_t * const &lhs, perms_t * const &rhs)const
		{
			return *lhs < *rhs;
		}
};

// a dedup cache for permissions
class perms_t_Cache: public CacheStats {
	std::set<perms_t *, deref_less_than_perms> cache;
public:

	typedef std::set<perms_t *>::iterator iterator;
	iterator begin() { return cache.begin(); }
	iterator end() { return cache.end(); }

	typedef std::set<perms_t *>::const_iterator const_iterator;
	iterator cbegin() { return cache.cbegin(); }
	iterator cend() { return cache.cend(); }

	iterator find(perms_t * const &val) { return cache.find(val); }

	perms_t_Cache(void): cache() { };
	~perms_t_Cache() { clear(); };

	virtual unsigned long size(void) const { return cache.size(); }

	void clear()
	{
		for (iterator i = cache.begin();
		     i != cache.end(); i++) {
			delete *i;
		}
		cache.clear();
		CacheStats::clear();
	}

	// will delete perms if not inserted into cache
	perms_t *insert(perms_t *perms)
	{
		if (!perms)
			return NULL;
		std::pair<iterator,bool> uniq;
		uniq = cache.insert(perms);
		if (uniq.second == false) {
			delete perms;
			dup++;
		}
		return (*uniq.first);
	}

	perms_t *insert(const perms_t &perms)
	{
		perms_t *tmp = new perms_t(perms);
		return insert(tmp);
	}

	perms_t *insert(optflags const &opts, NodeVec *match, bool filedfa)
	{
		perms_t *tmp = new perms_t(opts, match, filedfa);
		return insert(tmp);
	}
};

/*
 * ProtoState - NodeSet and ancillery information used to create a state
 */
class ProtoState {
public:
	NodeVec *nnodes;
	NodeVec *anodes;

	/* init is used instead of a constructor because ProtoState is used
	 * in a union
	 */
	void init(NodeVec *n, NodeVec *a = NULL)
	{
		nnodes = n;
		anodes = a;
	}

	bool operator<(ProtoState const &rhs)const
	{
		if (nnodes == rhs.nnodes)
			return anodes < rhs.anodes;
		return nnodes < rhs.nnodes;
	}

	unsigned long size(void)
	{
		if (anodes)
			return nnodes->size() + anodes->size();
		return nnodes->size();
	}
};

/* Temporary state structure used when building differential encoding
 * @parents - set of states that have transitions to this state
 * @depth - level in the DAG
 * @state - back reference to state this DAG entry belongs
 * @rel - state that this state is relative to for differential encoding
 */
struct DiffDag {
	Partition parents;
	int depth;
	State *state;
	State *rel;
};

/*
 * State - DFA individual state information
 * label: a unique label to identify the state used for pretty printing
 *        the non-matching state is setup to have label == 0 and
 *        the start state is setup to have label == 1
 * audit: the audit permission mask for the state
 * accept: the accept permissions for the state
 * trans: set of transitions from this state
 * otherwise: the default state for transitions not in @trans
 * partition: Is a temporary work variable used during dfa minimization.
 *           it can be replaced with a map, but that is slower and uses more
 *           memory.
 * proto: Is a temporary work variable used during dfa creation.  It can
 *        be replaced by using the nodemap, but that is slower
 */
class State {
public:
	State(perms_t_Cache &cache, optflags const &opts, int l, ProtoState &n,
	      State *other, bool filedfa):
		label(l), flags(0), idx(0), trans()
	{
		perms = cache.insert(opts, n.anodes, filedfa);

		if (other)
			otherwise = other;
		else
			otherwise = this;

		proto = n;
	};

	State *next(transchar c) {
		State *state = this;
		do {
			StateTrans::iterator i = state->trans.find(c);
			if (i != state->trans.end())
				return i->second;

			if (!(state->flags & DiffEncodeFlag))
				return state->otherwise;
			state = state->otherwise;
		} while (state);

		/* never reached */
		assert(0);
		return NULL;
	}

	ostream &dump(ostream &os)
	{
		cerr << *this << "\n";
		for (StateTrans::iterator i = trans.begin(); i != trans.end(); i++) {
			os << "    " << i->first.c << " -> " << *i->second << "\n";
		}
		return os;
	}

	int diff_weight(State *rel, int max_range, int upper_bound);
	int make_relative(State *rel, int upper_bound);
	void flatten_relative(State *, int upper_bound);

	bool apply_and_clear_deny(perms_t_Cache &cache)
	{
		perms_t *tmp = new perms_t(*perms);

		bool res = tmp->apply_and_clear_deny();
		perms = cache.insert(tmp);
		return res;
	}

	int label;
	int flags;
	int idx;
	perms_t *perms;
	StateTrans trans;
	State *otherwise;

	/* temp storage for State construction */
	union {
		Partition *partition;	/* used during minimization */
		ProtoState proto;	/* used during creation */
		DiffDag *diff;		/* used during diff encoding */
	};
};

class NodeMap: public CacheStats
{
public:
	typedef map<ProtoState, State *>::iterator iterator;
	iterator begin() { return cache.begin(); }
	iterator end() { return cache.end(); }

	map<ProtoState, State *> cache;

	NodeMap(void): cache() { };
	~NodeMap() { clear(); };

	virtual unsigned long size(void) const { return cache.size(); }

	void clear()
	{
		cache.clear();
		CacheStats::clear();
	}

	pair<iterator,bool> insert(ProtoState &proto, State *state)
	{
		pair<iterator,bool> uniq;
		uniq = cache.insert(make_pair(proto, state));
		if (uniq.second == false) {
			dup++;
		} else {
			sum += proto.size();
			if (proto.size() > max)
				max = proto.size();
		}
		return uniq;
	}
};

typedef std::map<const State *, size_t> Renumber_Map;
typedef std::map<perms_t * const, size_t, deref_less_than_perms> idxmap_t;

/* Transitions in the DFA. */
class DFA {
	void dump_node_to_dfa(void);
	State *add_new_state(optflags const &opts, NodeSet *nodes,
			     State *other);
	State *add_new_state(optflags const &opts,NodeSet *anodes,
			     NodeSet *nnodes, State *other);
	void update_state_transitions(optflags const &opts, State *state);
	void process_work_queue(const char *header, optflags const &);
	void dump_diff_chain(ostream &os, map<State *, Partition> &relmap,
			     Partition &chain, State *state,
			     unsigned int &count, unsigned int &total,
			     unsigned int &max);

	/* temporary values used during computations */
	NodeVecCache anodes_cache;
	NodeVecCache nnodes_cache;
	NodeMap node_map;
	list<State *> work_queue;

	void cleanup(void) {
		anodes_cache.clear();
		nnodes_cache.clear();

		for (Partition::iterator i = states.begin(); i != states.end(); i++) {
			delete *i;
		}
		states.clear();
	}
public:
	DFA(Node *root, optflags const &flags, bool filedfa);
	virtual ~DFA();

	State *match_len(State *state, const char *str, size_t len);
	State *match_until(State *state, const char *str, const char term);
	State *match(const char *str);

	void remove_unreachable(optflags const &flags);
	bool same_mappings(State *s1, State *s2);
	void minimize(optflags const &flags);
	int apply_and_clear_deny(void);
	void clear_priorities(void);

	void diff_encode(optflags const &flags);
	void undiff_encode(void);
	void dump_diff_encode(ostream &os);

	void dump(ostream &os, Renumber_Map *renum);
	void dump_dot_graph(ostream &os);
	void dump_uniq_perms(const char *s);

	map<transchar, transchar> equivalence_classes(optflags const &flags);
	void apply_equivalence_classes(map<transchar, transchar> &eq);

	void compute_perms_table_ent(perms_t * const perms, size_t pos,
				     std::vector <aa_perms> &perms_table,
				     idxmap_t &idxmap, bool prompt);
	void compute_perms_table(std::vector <aa_perms> &perms_table,
				 bool prompt);

	unsigned int diffcount;
	int oob_range;
	int max_range;
	int ord_range;
	int upper_bound;
	Node *root;
	perms_t_Cache uniq_perms;
	State *nonmatching, *start;
	Partition states;
	bool filedfa;
};

void dump_equivalence_classes(ostream &os, map<transchar, transchar> &eq);

#endif /* __LIBAA_RE_HFA_H */
