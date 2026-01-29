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

#include <list>
#include <vector>
#include <stack>
#include <set>
#include <map>
#include <ostream>
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdint.h>
#include "expr-tree.h"
#include "hfa.h"
#include "policy_compat.h"
#include "../immunix.h"
#include "../perms.h"

ostream &operator<<(ostream &os, const CacheStats &cache)
{
	/* dump the state label */
	os << "cache: size=";
	os << cache.size();
	os << " dups=";
	os << cache.dup;
	os << " longest=";
	os << cache.max;
	if (cache.size()) {
		os << " avg=";
		os << cache.sum / cache.size();
	}
	return os;
}

ostream &operator<<(ostream &os, const ProtoState &proto)
{
	/* dump the state label */
	os << '{';
	os << proto.nnodes;
	os << ',';
	os << proto.anodes;
	os << '}';
	return os;
}

ostream &operator<<(ostream &os, const State &state)
{
	/* dump the state label */
	os << '{';
	os << state.label;
	os << '}';
	return os;
}

ostream &operator<<(ostream &os, State &state)
{
	/* dump the state label */
	os << '{';
	os << state.label;
	os << '}';
	return os;
}

ostream &operator<<(ostream &os,
		    const std::pair<State * const, Renumber_Map *> &p)
{
	/* dump the state label */
	if (p.second && (*p.second)[p.first] != (size_t) p.first->label) {
		os << '{';
		os << (*p.second)[p.first];
		os << " == " << *(p.first);
		os << '}';
	} else {
		os << *(p.first);
	}
	return os;
}

/**
 * diff_weight - Find differential compression distance between @rel and @this
 * @rel: State to compare too
 * Returns: An integer indicating how good rel is as a base, larger == better
 *
 * Find the relative weighted difference for differential state compression
 * with queried state being compressed against @rel
 *
 * +1 for each transition that matches (char and dest - saves a transition)
 * 0 for each transition that doesn't match and exists in both states
 * 0  for transition that self has and @other doesn't (no extra required)
 * -1 for each transition that is in @rel and not in @this (have to override)
 *
 * @rel should not be a state that has already been made differential or it may
 * introduce extra transitions as it does not recurse to find all transitions
 *
 * Should be applied after state minimization 
*/
int State::diff_weight(State *rel, int max_range, int upper_bound)
{
	int weight = 0;
	int first = 0;

	if (this == rel)
		return 0;

	if (rel->diff->rel) {
		/* Can only be diff encoded against states that are relative
		 * to a state of a lower depth. ie, at most one sibling in
		 * the chain
		 */
		if (rel->diff->rel->diff->depth >= this->diff->depth)
			return 0;
	} else if (rel->diff->depth >= this->diff->depth)
		return 0;

	if (rel->trans.begin()->first.c < first)
		first = rel->trans.begin()->first.c;
	if (rel->flags & DiffEncodeFlag) {
		for (int i = first; i < upper_bound; i++) {
			State *state = rel->next(i);
			StateTrans::iterator j = trans.find(i);
			if (j != trans.end()) {
				if (state == j->second)
					weight++;
				/* else
				   0 - keep transition to mask
				*/
			} else if (state == otherwise) {
				/* 0 - match of default against @rel
				 * We don't save a transition but don't have
				 * to mask either
				 */
			} else {
				/* @rel has transition not covered by @this.
				 * Need to add a transition to mask it
				 */
				weight--;
			}
		}
		return weight;
	}

	unsigned int count = 0;
	for (StateTrans::iterator i = rel->trans.begin(); i != rel->trans.end();
 i++) {
		StateTrans::iterator j = trans.find(i->first);
		if (j != trans.end()) {
			if (i->second == j->second)
				weight++;
			/* } else {
				0 - keep transition to mask
			*/
			count++;
		} else if (i->second == otherwise) {
			/* 0 - match of default against @rel
			 * We don't save a transition but don't have to
			 * mask either
			 */
		} else {
			/* rel has transition not covered by @this.  Need to
			 * add a transition to mask
			 */
			weight--;
		}
	}

	/* cover transitions in @this but not in @rel */
	unsigned int this_count = 0;
	if (count < trans.size()) {
		for (StateTrans::iterator i = trans.begin(); i != trans.end(); i++) {
			StateTrans::iterator j = rel->trans.find(i->first);
			if (j == rel->trans.end()) {
				this_count++;
				if (i->second == rel->otherwise)
					/* replaced by rel->cases.otherwise */
					weight++;
			}
		}
	}

	if (rel->otherwise != otherwise) {
		/* rel default transitions have to be masked with transitions
		 * This covers all transitions not covered above
		 */
		weight -= (max_range) - (rel->trans.size() + this_count);
	}

	return weight;
}

/**
 * make_relative - Make this state relative to @rel
 * @rel: state to make this state relative too
 * @upper_bound: the largest value for an input transition (256 for a byte).
 *
 * @rel can be a relative (differentially compressed state)
 */
int State::make_relative(State *rel, int upper_bound)
{
	int weight = 0;
	int first = 0;

	if (this == rel || !rel)
		return 0;

	if (flags & DiffEncodeFlag)
		return 0;

	if (rel->trans.begin()->first.c < 0)
		first = rel->trans.begin()->first.c;

	flags |= DiffEncodeFlag;

	for (int i = first; i < upper_bound ; i++) {
		State *next = rel->next(i);

		StateTrans::iterator j = trans.find(i);
		if (j != trans.end()) {
			if (j->second == next) {
				trans.erase(j);
				weight++;
			}
			/* else keep transition to mask */
		} else if (otherwise == next) {
			/* do nothing, otherwise transition disappears when
			 * reassigned
			 */
		} else {
			/* need a new transition to mask those in lower state */
			trans[i] = otherwise;
			weight--;
		}
	}

	otherwise = rel;

	return weight;
}

/**
 * flatten_differential - remove differential encode from this state
 * @nonmatching: the nonmatching state for the state machine
 * @upper_bound: the largest value for an input transition (256 for a byte).
 */
void State::flatten_relative(State *nonmatching, int upper_bound)
{
	if (!(flags & DiffEncodeFlag))
		return;

	map<State *, int> count;

	int first = 0;
	if (next(-1) != nonmatching)
		first = -1;

	for (int i = first; i < upper_bound; i++)
		count[next(i)] += 1;

	int j = first;
	State *def = next(first);
	for (int i = first + 1; i < upper_bound; i++) {
		if (count[next(i)] > count[next(j)]) {
			j = i;
			def = next(i);
		}
	}

	for (int i = first; i < upper_bound; i++) {
		if (trans.find(i) != trans.end()) {
			if (trans[i] == def)
				trans.erase(i);
		} else {
			if (trans[i] != def)
				trans[i] = next(i);
		}
	}

	otherwise = def;
	flags = flags & ~DiffEncodeFlag;
}

static void split_node_types(NodeSet *nodes, NodeSet **anodes, NodeSet **nnodes
)
{
	*anodes = *nnodes = NULL;
	for (NodeSet::iterator i = nodes->begin(); i != nodes->end(); ) {
		if ((*i)->is_accept()) {
			if (!*anodes)
				*anodes = new NodeSet;
			(*anodes)->insert(*i);
			NodeSet::iterator k = i++;
			nodes->erase(k);
		} else
			i++;
	}
	*nnodes = nodes;
}

State *DFA::add_new_state(optflags const &opts, NodeSet *anodes,
			  NodeSet *nnodes, State *other)
{
	NodeVec *nnodev, *anodev;
	nnodev = nnodes_cache.insert(nnodes);
	anodev = anodes_cache.insert(anodes);

	ProtoState proto;
	proto.init(nnodev, anodev);
	State *state;
	try {
		state = new State(uniq_perms, opts, node_map.size(), proto,
				  other, filedfa);
	} catch(int error) {
		/* this function is called in the DFA object creation,
		 * and the exception prevents the destructor from
		 * being called, so call the helper here */
		cleanup();
		throw error;
	}
	pair<NodeMap::iterator,bool> x = node_map.insert(proto, state);
	if (x.second == false) {
		delete state;
	} else {
		states.push_back(state);
		work_queue.push_back(state);
	}

	return x.first->second;
}

State *DFA::add_new_state(optflags const &opts, NodeSet *nodes, State *other)
{
	/* The splitting of nodes should probably get pushed down into
	 * follow(), ie. put in separate lists from the start
	 */
	NodeSet *anodes, *nnodes;
	split_node_types(nodes, &anodes, &nnodes);

	State *state = add_new_state(opts, anodes, nnodes, other);

	return state;
}

void DFA::update_state_transitions(optflags const &opts, State *state)
{
	/* Compute possible transitions for state->nodes.  This is done by
	 * iterating over all the nodes in state->nodes and combining the
	 * transitions.
	 *
	 * The resultant transition set is a mapping of characters to
	 * sets of nodes.
	 *
	 * Note: the follow set for accept nodes is always empty so we don't
	 * need to compute follow for the accept nodes in a protostate
	 */
	Cases cases;
	for (NodeVec::iterator i = state->proto.nnodes->begin(); i != state->proto.nnodes->end(); i++)
		(*i)->follow(cases);

	/* Now for each set of nodes in the computed transitions, make
	 * sure that there is a state that maps to it, and add the
	 * matching case to the state.
	 */

	/* check the default transition first */
	if (cases.otherwise)
		state->otherwise = add_new_state(opts, cases.otherwise,
						 nonmatching);
	else
		state->otherwise = nonmatching;

	/* For each transition from *from, check if the set of nodes it
	 * transitions to already has been mapped to a state
	 */
	for (Cases::iterator j = cases.begin(); j != cases.end(); j++) {
		State *target;
		try {
			target = add_new_state(opts, j->second, nonmatching);
		} catch (int error) {
			/* when add_new_state fails, there could still
			 * be NodeSets in the rest of cases, so clean
			 * them up before re-throwing the exception */
			for (Cases::iterator k = ++j; k != cases.end(); k++) {
				delete k->second;
			}
			throw error;
		}

		/* Don't insert transition that the otherwise transition
		 * already covers
		 */
		if (target != state->otherwise) {
			state->trans[j->first] = target;
			if (j->first.c < 0 && -j->first.c > oob_range)
				oob_range = -j->first.c;
		}
	}
}

/* WARNING: This routine can only be called from within DFA creation as
 * the nodes value is only valid during dfa construction.
 */
void DFA::dump_node_to_dfa(void)
{
	cerr << "Mapping of States to expr nodes\n"
		"  State  <=   Nodes\n"
		"-------------------\n";
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		cerr << "  " << (*i)->label << " <= " << (*i)->proto << "\n";
}

void DFA::process_work_queue(const char *header, optflags const &opts)
{
	int i = 0;

	while (!work_queue.empty()) {
		if (i % 1000 == 0 && (opts.dump & DUMP_DFA_PROGRESS)) {
			cerr << "\033[2K" << header << ": queue "
			     << work_queue.size()
			     << "\tstates "
			     << states.size()
			     << "\teliminated duplicates "
			     << node_map.dup
			     << "\r";
		}
		i++;

		State *from = work_queue.front();
		work_queue.pop_front();

		/* Update 'from's transitions, and if it transitions to any
		 * unknown State create it and add it to the work_queue
		 */
		update_state_transitions(opts, from);
	}  /* while (!work_queue.empty()) */
}

/**
 * Construct a DFA from a syntax tree.
 */
DFA::DFA(Node *root, optflags const &opts, bool buildfiledfa): root(root), filedfa(buildfiledfa)
{
	diffcount = 0;		/* set by diff_encode */
	max_range = 256;
	upper_bound = 256;
	oob_range = 0;
	ord_range = 8;

	if (opts.dump & DUMP_DFA_PROGRESS)
		fprintf(stderr, "Creating dfa:\r");

	for (depth_first_traversal i(root); i; i++) {
		(*i)->compute_nullable();
		(*i)->compute_firstpos();
		(*i)->compute_lastpos();
	}

	if (opts.dump & DUMP_DFA_PROGRESS)
		fprintf(stderr, "Creating dfa: followpos\r");
	for (depth_first_traversal i(root); i; i++) {
		(*i)->compute_followpos();
	}

	nonmatching = add_new_state(opts, new NodeSet, NULL);
	start = add_new_state(opts, new NodeSet(root->firstpos), nonmatching);

	/* the work_queue contains the states that need to have their
	 * transitions computed.  This could be done with a recursive
	 * algorithm instead of a work_queue, but it would be slightly slower
	 * and consume more memory.
	 *
	 * TODO: currently the work_queue is treated in a breadth first
	 *       search manner.  Test using the work_queue in a depth first
	 *       manner, this may help reduce the number of entries on the
	 *       work_queue at any given time, thus reducing peak memory use.
	 */
	work_queue.push_back(start);
	process_work_queue("Creating dfa", opts);
	max_range += oob_range;
	/* if oob_range is ever greater than 256 need to move to computing this */
	if (oob_range)
		ord_range = 9;
	/* cleanup Sets of nodes used computing the DFA as they are no longer
	 * needed.
	 */
	for (depth_first_traversal i(root); i; i++) {
		(*i)->firstpos.clear();
		(*i)->lastpos.clear();
		(*i)->followpos.clear();
	}

	if (opts.dump & DUMP_DFA_NODE_TO_DFA)
		dump_node_to_dfa();

	if (opts.dump & (DUMP_DFA_STATS)) {
		cerr << "\033[2KCreated dfa: states "
		     << states.size()
		     << " proto { "
		     << node_map
		     << " }, nnodes { "
		     << nnodes_cache
		     << " }, anodes { "
		     << anodes_cache
		     << " }\n";
	}

	/* Clear out uniq_nnodes as they are no longer needed.
	 * Do not clear out uniq_anodes, as we need them for minimizations
	 * diffs, unions, ...
	 */
	nnodes_cache.clear();
	node_map.clear();
}

DFA::~DFA()
{
	cleanup();
}

State *DFA::match_len(State *state, const char *str, size_t len)
{
	for (; len > 0; ++str, --len)
		state = state->next(*str);

	return state;
}

State *DFA::match_until(State *state, const char *str, const char term)
{
	while (*str != term)
		state = state->next(*str++);

	return state;
}

State *DFA::match(const char *str)
{
	return match_until(start, str, 0);
}

void DFA::dump_uniq_perms(const char *s)
{
	cerr << "Unique Permission sets: " << s << " (" << uniq_perms.size() << ")\n";
	cerr << "----------------------\n";
	for (std::set<perms_t *>::iterator i = uniq_perms.begin(); i != uniq_perms.end(); i++) {
	  cerr << "  allow:" << hex << (*i)->allow << " deny:"
	       << (*i)->deny << " audit:" << (*i)->audit
	       << " quiet:" << (*i)->quiet << " prompt:" << (*i)->prompt <<  dec << "\n";
	}
}

/* Remove dead or unreachable states */
void DFA::remove_unreachable(optflags const &opts)
{
	set<State *> reachable;

	/* find the set of reachable states */
	reachable.insert(nonmatching);
	work_queue.push_back(start);
	while (!work_queue.empty()) {
		State *from = work_queue.front();
		work_queue.pop_front();
		reachable.insert(from);

		if (from->otherwise != nonmatching &&
		    reachable.find(from->otherwise) == reachable.end())
			work_queue.push_back(from->otherwise);

		for (StateTrans::iterator j = from->trans.begin(); j != from->trans.end(); j++) {
			if (reachable.find(j->second) == reachable.end())
				work_queue.push_back(j->second);
		}
	}

	/* walk the set of states and remove any that aren't reachable */
	if (reachable.size() < states.size()) {
		int count = 0;
		Partition::iterator i;
		Partition::iterator next;
		for (i = states.begin(); i != states.end(); i = next) {
			next = i;
			next++;
			if (reachable.find(*i) == reachable.end()) {
				if (opts.dump & DUMP_DFA_UNREACHABLE) {
					cerr << "unreachable: " << **i;
					if (*i == start)
						cerr << " <==";
					if ((*i)->perms->is_accept())
						(*i)->perms->dump(cerr);
					cerr << "\n";
				}
				State *current = *i;
				states.erase(i);
				delete(current);
				count++;
			}
		}

		if (count && (opts.dump & DUMP_DFA_STATS))
			cerr << "DFA: states " << states.size() << " removed "
			     << count << " unreachable states\n";
	}
}

/* test if two states have the same transitions under partition_map */
bool DFA::same_mappings(State *s1, State *s2)
{
	/* assumes otherwise is set to best choice, if there are multiple
	 * otherwise choices this will fail to fully minimize the dfa
	 * if we are not careful. Make sure in cases with multiple
	 * equiv otherwise we always choose the same otherwise to avoid
	 */
	if (s1->otherwise->partition != s2->otherwise->partition)
		return false;

	StateTrans::iterator j1;
	StateTrans::iterator j2;
	for (j1 = s1->trans.begin(), j2 = s2->trans.begin();
	     j1 != s1->trans.end() && j2 != s2->trans.end();
	     /*inc inline*/) {
		if (j1->first < j2->first) {
			if (j1->second->partition != s2->otherwise->partition)
				return false;
			j1++;
		} else if (j1->first == j2->first) {
			if (j1->second->partition != j2->second->partition)
				return false;
			j1++;
			j2++;
		} else {
			if (s1->otherwise->partition != j2->second->partition)
				return false;
			j2++;
		}
	}
	for ( ; j1 != s1->trans.end(); j1++) {
		if (j1->second->partition != s2->otherwise->partition)
			return false;
	}
	for ( ; j2 != s2->trans.end(); j2++) {
		if (j2->second->partition != s1->otherwise->partition)
			return false;
	}

	return true;
}

int DFA::apply_and_clear_deny(void)
{
	int c = 0;
	/* TODO: update to remove perms that are no longer in use */
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		c += (*i)->apply_and_clear_deny(uniq_perms);

	return c;
}


typedef map<perms_t *, Partition *, deref_less_than_perms> PermMap;

/* minimize the number of dfa states */
void DFA::minimize(optflags const &opts)
{
	PermMap perm_map;
	list<Partition *> partitions;

	/* Set up the initial partitions
	 * minimum of - 1 non accepting, and 1 accepting
	 */
	int accept_count = 0;
	int final_accept = 0;
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		PermMap::iterator p = perm_map.find((*i)->perms);
		if (p == perm_map.end()) {
			Partition *part = new Partition();
			part->push_back(*i);
			perm_map.insert(make_pair((*i)->perms, part));
			partitions.push_back(part);
			(*i)->partition = part;
			if ((*i)->perms->is_accept())
				accept_count++;
		} else {
			(*i)->partition = p->second;
			p->second->push_back(*i);
		}

		if ((opts.dump & DUMP_DFA_PROGRESS) && (partitions.size() % 1000 == 0))
			cerr << "\033[2KMinimize dfa: partitions "
			     << partitions.size() << "\tinit " << partitions.size()
			     << " (accept " << accept_count << ")\r";
	}

	/* perm_map is no longer needed so free the memory it is using.
	 * Don't remove - doing it manually here helps reduce peak memory usage.
	 */
	perm_map.clear();

	int init_count = partitions.size();
	if (opts.dump & DUMP_DFA_PROGRESS)
		cerr << "\033[2KMinimize dfa: partitions " << partitions.size()
		     << "\tinit " << init_count << " (accept "
		     << accept_count << ")\r";

	/* Now do repartitioning until each partition contains the set of
	 * states that are the same.  This will happen when the partition
	 * splitting stables.  With a worse case of 1 state per partition
	 * ie. already minimized.
	 */
	Partition *new_part;
	int new_part_count;
	do {
		new_part_count = 0;
		for (list<Partition *>::iterator p = partitions.begin();
		     p != partitions.end(); p++) {
			new_part = NULL;
			State *rep = *((*p)->begin());
			Partition::iterator next;
			for (Partition::iterator s = ++(*p)->begin(); s != (*p)->end();) {
				if (same_mappings(rep, *s)) {
					++s;
					continue;
				}
				if (!new_part) {
					new_part = new Partition;
					list<Partition *>::iterator tmp = p;
					partitions.insert(++tmp, new_part);
					new_part_count++;
				}
				new_part->push_back(*s);
				s = (*p)->erase(s);
			}
			/* remapping partition_map for new_part entries
			 * Do not do this above as it messes up same_mappings
			 */
			if (new_part) {
				for (Partition::iterator m = new_part->begin();
				     m != new_part->end(); m++) {
					(*m)->partition = new_part;
				}
			}
			if ((opts.dump & DUMP_DFA_PROGRESS) && (partitions.size() % 100 == 0))
				cerr << "\033[2KMinimize dfa: partitions "
				     << partitions.size() << "\tinit "
				     << init_count << " (accept "
				     << accept_count << ")\r";
		}
	} while (new_part_count);

	if (partitions.size() == states.size()) {
		if (opts.dump & DUMP_DFA_STATS)
			cerr << "\033[2KDfa minimization no states removed: partitions "
			     << partitions.size() << "\tinit " << init_count
			     << " (accept " << accept_count << ")\n";

		goto out;
	}

	/* Remap the dfa so it uses the representative states
	 * Use the first state of a partition as the representative state
	 * At this point all states with in a partition have transitions
	 * to states within the same partitions, however this can slow
	 * down compressed dfa compression as there are more states,
	 */
	if (opts.dump & DUMP_DFA_MIN_PARTS)
		cerr << "Partitions after minimization\n";
	for (list<Partition *>::iterator p = partitions.begin();
	     p != partitions.end(); p++) {
		/* representative state for this partition */
		State *rep = *((*p)->begin());
		if (opts.dump & DUMP_DFA_MIN_PARTS)
			cerr << *rep << " : ";

		/* update representative state's transitions */
		rep->otherwise = *rep->otherwise->partition->begin();

		for (StateTrans::iterator c = rep->trans.begin(); c != rep->trans.end(); ) {
			Partition *partition = c->second->partition;
			if (rep->otherwise != *partition->begin()) {
				c->second = *partition->begin();
				c++;
			} else
				/* transition is now covered by otherwise */
				c = rep->trans.erase(c);
		}

		/* clear the state label for all non representative states,
		 * and accumulate permissions */
		for (Partition::iterator i = ++(*p)->begin(); i != (*p)->end(); i++) {
			if (opts.dump & DUMP_DFA_MIN_PARTS)
				cerr << **i << ", ";
			(*i)->label = -1;
			/* merging perms is only necessary if partitioning doesn't
			 * completely separate base on unique perms.
			 * atm this should be the case. Code to handle case is
			 * only to document what should be done if this is allowed
			 * in the future
			 */
			if ((rep->perms != (*i)->perms) &&
			    (*rep->perms != *(*i)->perms)) {
				throw std::runtime_error("Minimization different permissions in same partion");
				/*
				perms_t tmp = *rep->perms;
				tmp.add((*i)->perms, filedfa);
				rep->perms = uniq_perms.insert(tmp);
				*/
			}
		}
		if (rep->perms->is_accept())
			final_accept++;
		if (opts.dump & DUMP_DFA_MIN_PARTS)
			cerr << "\n";
	}
	if (opts.dump & DUMP_DFA_STATS)
		cerr << "\033[2KMinimized dfa: final partitions "
		     << partitions.size() << " (accept " << final_accept
		     << ")" << "\tinit " << init_count << " (accept "
		     << accept_count << ")\n";

	/* make sure nonmatching and start state are up to date with the
	 * mappings */
	{
		Partition *partition = nonmatching->partition;
		if (*partition->begin() != nonmatching) {
			nonmatching = *partition->begin();
		}

		partition = start->partition;
		if (*partition->begin() != start) {
			start = *partition->begin();
		}
	}

	/* Now that the states have been remapped, remove all states
	 * that are not the representative states for their partition, they
	 * will have a label == -1
	 */
	for (Partition::iterator i = states.begin(); i != states.end();) {
		if ((*i)->label == -1) {
			State *s = *i;
			i = states.erase(i);
			delete(s);
		} else
			i++;
	}

out:
	/* Cleanup */
	while (!partitions.empty()) {
		Partition *p = partitions.front();
		partitions.pop_front();
		delete(p);
	}
}


/* diff_encode helper functions */
static unsigned int add_to_dag(DiffDag *dag, State *state,
			       State *parent)
{
	unsigned int rc = 0;
	if (!state->diff) {
		dag->rel = NULL;
		if (parent)
			dag->depth = parent->diff->depth + 1;
		else
			dag->depth = 1;
		dag->state = state;
		state->diff = dag;
		rc = 1;
	}
	if (parent && parent->diff->depth < state->diff->depth)
		state->diff->parents.push_back(parent);
	return rc;
}

static int diff_partition(State *state, Partition &part, int max_range, int upper_bound, State **candidate)
{
	int weight = 0;
	*candidate = NULL;

	for (Partition::iterator i = part.begin(); i != part.end(); i++) {
		if (*i == state)
			continue;

		int tmp = state->diff_weight(*i, max_range, upper_bound);
		if (tmp > weight) {
			weight = tmp;
			*candidate = *i;
		}
	}
	return weight;
}

/**
 * diff_encode - compress dfa by differentially encoding state transitions
 * @opts: flags controlling dfa creation
 *
 * This function reduces the number of transitions that need to be stored
 * by encoding transitions as the difference between the state and a
 * another transitions that is set as the states default.
 *
 * For performance reasons this function does not try to compute the
 * absolute best encoding (maximal spanning tree) but instead computes
 * a very good encoding within the following limitations.
 *   - Not all states have to be differentially encoded.  This allows for
 *     multiple states to be used as a terminating basis.
 *   - The number of state transitions needed to match an input of length
 *     m will be 2m
 *
 * To guarantee this the ordering and distance calculation is done in the
 * following manner.
 * - A DAG of the DFA is created starting with the start state(s).
 * - A state can only be relative (have a differential encoding) to
 *   another state if that state has
 *   - a lower depth in the DAG
 *   - is a sibling (same depth) that is not relative
 *   - is a sibling that is relative to a state with lower depth in the DAG
 *
 * The run time constraints are maintained by the DAG ordering + relative
 * state constraints.  For any input character C when at state S with S being
 * at level N in the DAG then at most 2N states must be traversed to find the
 * transition for C.  However on the maximal number of transitions is not m*m,
 * because  when a character is matched and forward movement is made through
 * the DFA any relative transition search will move back through the DAG order.
 * So say for character C we start matching on a state S that is at depth 10
 * in the DAG.  The transition for C is not found in S and we recurse backwards
 * to a depth of 6.  A transition is found and it steps to the next state, but
 * the state transition at most will only move 1 deeper into the DAG so for
 * the next state the maximum number of states traversed is 2*7.
 */
void DFA::diff_encode(optflags const &opts)
{
	DiffDag *dag;
	unsigned int xcount = 0, xweight = 0, transitions = 0, depth = 0;

	/* clear the depth flag */
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		(*i)->diff = NULL;
		transitions += (*i)->trans.size();
	}

	/* Prealloc structures we need.  We know the exact number of elements,
	 * and once setup they don't change so we don't need the flexibility
	 * or overhead of stl, just allocate the needed data as an array
	 */
	dag = new DiffDag [states.size()];

	/* Generate DAG ordering and parent sets */
	add_to_dag(&dag[0], nonmatching, NULL);
	add_to_dag(&dag[1], start, NULL);

	unsigned int tail = 2;
	for (unsigned int i = 1; i < tail; i++) {
		State *state = dag[i].state;
		State *child = dag[i].state->otherwise;
		if (child)
			tail += add_to_dag(&dag[tail], child, state);

		for (StateTrans::iterator j = state->trans.begin(); j != state->trans.end(); j++) {
			child = j->second;
			tail += add_to_dag(&dag[tail], child, state);
		}
	}
	depth = dag[tail - 1].depth;

	/* calculate which state to make a transitions relative too */
	for (unsigned int i = 2; i < tail; i++) {
		State *state = dag[i].state;
		State *candidate = NULL;

		int weight = diff_partition(state,
					    state->otherwise->diff->parents, max_range,
					    upper_bound, &candidate);

		for (StateTrans::iterator j = state->trans.begin(); j != state->trans.end(); j++) {
			State *tmp_candidate;
			int tmp = diff_partition(state,
						 j->second->diff->parents, max_range,
						 upper_bound, &tmp_candidate);
			if (tmp > weight) {
				weight = tmp;
				candidate = tmp_candidate;
			}
		}

		if ((opts.dump & DUMP_DFA_DIFF_PROGRESS) && (i % 100 == 0))
			cerr << "\033[2KDiff Encode: " << i << " of "
			     << tail << ".  Diff states " << xcount
			     << " Savings " << xweight << "\r";

		state->diff->rel = candidate;
		if (candidate) {
			xcount++;
			xweight += weight;
		}
	}

	/* now make transitions relative, start at the back of the list so
	 * as to start with the last transitions and work backwards to avoid
	 * having to traverse multiple previous states (that have been made
	 * relative already) to reconstruct previous state transition table
	 */
	unsigned int aweight = 0;
	diffcount = 0;
	for (int i = tail - 1; i > 1; i--) {
		if (dag[i].rel) {
			int weight = dag[i].state->make_relative(dag[i].rel, upper_bound);
			aweight += weight;
			diffcount++;
		}
	}

	if (opts.dump & DUMP_DFA_DIFF_STATS)
		cerr << "Diff encode  states: " << diffcount << " of "
                     << tail << " reached @ depth "  << depth << ". "
		     <<  aweight << " trans removed\n";

	if (xweight != aweight)
		cerr << "Diff encode error: actual savings " << aweight
		     << " != expected " << xweight << "\n";

	if (xcount != diffcount)
		cerr << "Diff encode error: actual count " << diffcount
		     << " != expected " << xcount << " \n";

	/* cleanup */
	for (unsigned int i = 0; i < tail; i++)
		dag[i].parents.clear();
	delete [] dag;
}

/**
 * flatten_differential - remove differential state encoding
 *
 * Flatten the dfa back into a flat encoding.
 */
void DFA::undiff_encode(void)
{
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		(*i)->flatten_relative(nonmatching, upper_bound);
	diffcount = 0;
}

void DFA::dump_diff_chain(ostream &os, map<State *, Partition> &relmap,
			  Partition &chain, State *state, unsigned int &count,
			  unsigned int &total, unsigned int &max)
{
	if (relmap[state].size() == 0) {
		for (Partition::iterator i = chain.begin(); i != chain.end(); i++)
			os << **i << " <- ";
		os << *state << "\n";

		count++;
		total += chain.size() + 1;
		if (chain.size() + 1 > max)
			max = chain.size() + 1;
	}

	chain.push_back(state);
	for (Partition::iterator i = relmap[state].begin(); i != relmap[state].end(); i++)
		dump_diff_chain(os, relmap, chain, *i, count, total, max);
	chain.pop_back();
}

/* Dump the DFA diff_encoding chains */
void DFA::dump_diff_encode(ostream &os)
{
	map<State *, Partition> rel;
	Partition base, chain;

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if ((*i)->flags & DiffEncodeFlag)
			rel[(*i)->otherwise].push_back(*i);
		else
			base.push_back(*i);
	}

	unsigned int count = 0, total = 0, max = 0;
	for (Partition::iterator i = base.begin(); i != base.end(); i++)
		dump_diff_chain(os, rel, chain, *i, count, total, max);

	os << base.size() << " non-differentially encoded states\n";
	os << "chains: " << count - base.size() << "\n";
	os << "average chain size: " << (double) (total - base.size()) / (double) (count - base.size()) << "\n";
	os << "longest chain: " << max << "\n";
}

/**
 * text-dump the DFA (for debugging).
 */
void DFA::dump(ostream &os, Renumber_Map *renum)
{
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if (*i == start || (*i)->perms->is_accept()) {
			os << make_pair(*i, renum);
			if (*i == start) {
				os << " <== ";
				(*i)->perms->dump_header(os);
			}
			if ((*i)->perms->is_accept())
				(*i)->perms->dump(os);
			os << "\n";
		}
	}
	os << "\n";

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		Chars excluded;
		bool first = true;

		for (StateTrans::iterator j = (*i)->trans.begin();
		     j != (*i)->trans.end(); j++) {
			if (j->second == nonmatching) {
				excluded.insert(j->first);
			} else {
				if (first) {
					first = false;
					os << make_pair(*i, renum) << " perms: ";
					if ((*i)->perms->is_accept())
						(*i)->perms->dump(os);
					else
						os << "none";
					os << "\n";
				}
				os << "    "; j->first.dump(os) << " -> " <<
					make_pair(j->second, renum);
				if ((j)->second->perms->is_accept())
					os << " ", (j->second)->perms->dump(os);
				os << "\n";
			}
		}

		if ((*i)->otherwise != nonmatching) {
			if (first) {
				first = false;
				os << make_pair(*i, renum) << " perms: ";
				if ((*i)->perms->is_accept())
					(*i)->perms->dump(os);
				else
					os << "none";
				os << "\n";
			}
			os << "    [";
			if (!excluded.empty()) {
				os << "^";
				for (Chars::iterator k = excluded.begin();
				     k != excluded.end(); k++) {
					os << *k;
				}
			}
			os << "] -> " << make_pair((*i)->otherwise, renum);
			if ((*i)->otherwise->perms->is_accept())
				os << " ", (*i)->otherwise->perms->dump(os);
			os << "\n";
		}
	}
	os << "\n";
}

/**
 * Create a dot (graphviz) graph from the DFA (for debugging).
 */
void DFA::dump_dot_graph(ostream & os)
{
	os << "digraph \"dfa\" {" << "\n";

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if (*i == nonmatching)
			continue;

		os << "\t\"" << **i << "\" [" << "\n";
		if (*i == start) {
			os << "\t\tstyle=bold" << "\n";
		}
		if ((*i)->perms->is_accept()) {
			os << "\t\tlabel=\"" << **i << "\\n";
			(*i)->perms->dump(os);
			os << "\"\n";
		}
		os << "\t]" << "\n";
	}
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		Chars excluded;

		for (StateTrans::iterator j = (*i)->trans.begin(); j != (*i)->trans.end(); j++) {
			if (j->second == nonmatching)
				excluded.insert(j->first);
			else {
				os << "\t\"" << **i << "\" -> \"" << *j->second
				   << "\" [" << "\n";
				os << "\t\tlabel=\"";
				j->first.dump(os);
				os << "\"\n\t]" << "\n";
			}
		}
		if ((*i)->otherwise != nonmatching) {
			os << "\t\"" << **i << "\" -> \"" << *(*i)->otherwise
			   << "\" [" << "\n";
			if (!excluded.empty()) {
				os << "\t\tlabel=\"[^";
				for (Chars::iterator i = excluded.begin();
				     i != excluded.end(); i++) {
					i->dump(os);
				}
				os << "]\"" << "\n";
			}
			os << "\t]" << "\n";
		}
	}
	os << '}' << "\n";
}

/**
 * Compute character equivalence classes in the DFA to save space in the
 * transition table.
 */
map<transchar, transchar> DFA::equivalence_classes(optflags const &opts)
{
	map<transchar, transchar> classes;
	transchar next_class = 1;

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		/* Group edges to the same next state together */
		map<const State *, Chars> node_sets;
		for (StateTrans::iterator j = (*i)->trans.begin(); j != (*i)->trans.end(); j++) {
			if (j->first.c < 0)
				continue;
			node_sets[j->second].insert(j->first);
		}
		for (map<const State *, Chars>::iterator j = node_sets.begin();
		     j != node_sets.end(); j++) {
			/* Group edges to the same next state together by class */
			map<transchar, Chars> node_classes;
			bool class_used = false;
			for (Chars::iterator k = j->second.begin();
			     k != j->second.end(); k++) {
				pair<map<transchar, transchar>::iterator, bool> x = classes.insert(make_pair(*k, next_class));
				if (x.second)
					class_used = true;
				pair<map<transchar, Chars>::iterator, bool> y = node_classes.insert(make_pair(x.first->second, Chars()));
				y.first->second.insert(*k);
			}
			if (class_used) {
				next_class++;
				class_used = false;
			}
			for (map<transchar, Chars>::iterator k = node_classes.begin();
			     k != node_classes.end(); k++) {
			  /**
			   * If any other characters are in the same class, move
			   * the characters in this class into their own new
			   * class
			   */
				map<transchar, transchar>::iterator l;
				for (l = classes.begin(); l != classes.end(); l++) {
					if (l->second == k->first &&
					    k->second.find(l->first) == k->second.end()) {
						class_used = true;
						break;
					}
				}
				if (class_used) {
					for (Chars::iterator l = k->second.begin();
					     l != k->second.end(); l++) {
						classes[*l] = next_class;
					}
					next_class++;
					class_used = false;
				}
			}
		}
	}

	if (opts.dump & DUMP_DFA_EQUIV_STATS)
		fprintf(stderr, "Equiv class reduces to %d classes\n",
			next_class.c - 1);
	return classes;
}

/**
 * Text-dump the equivalence classes (for debugging).
 */
void dump_equivalence_classes(ostream &os, map<transchar, transchar> &eq)
{
	map<transchar, Chars> rev;

	for (map<transchar, transchar>::iterator i = eq.begin(); i != eq.end(); i++) {
		Chars &chars = rev.insert(make_pair(i->second, Chars())).first->second;
		chars.insert(i->first);
	}
	os << "(eq):" << "\n";
	for (map<transchar, Chars>::iterator i = rev.begin(); i != rev.end(); i++) {
		os << i->first.c << ':';
		Chars &chars = i->second;
		for (Chars::iterator j = chars.begin(); j != chars.end(); j++) {
			os << ' ' << *j;
		}
		os << "\n";
	}
}

/**
 * Replace characters with classes (which are also represented as
 * characters) in the DFA transition table.
 */
void DFA::apply_equivalence_classes(map<transchar, transchar> &eq)
{
    /**
     * Note: We only transform the transition table; the nodes continue to
     * contain the original characters.
     */
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		map<transchar, State *> tmp;
		tmp.swap((*i)->trans);
		for (StateTrans::iterator j = tmp.begin(); j != tmp.end(); j++) {
			if (j->first.c < 0)
				continue;
			(*i)->trans.insert(make_pair(eq[j->first], j->second));
		}
	}
}

void DFA::compute_perms_table_ent(perms_t * const perms, size_t pos,
				  std::vector <aa_perms> &perms_table,
				  idxmap_t &idxmap, bool prompt)
{
	uint32_t accept1, accept2, accept3;

	// until front end doesn't map the way it does
	  perms->map_perms_to_accept(accept1, accept2, accept3, prompt);
	idxmap.insert(make_pair(perms, pos));
	if (filedfa) {
		perms_table[pos] = compute_fperms_user(accept1, accept2, accept3);
		perms_table[pos + 1] = compute_fperms_other(accept1, accept2, accept3);
	} else {
		perms_table[pos] = compute_perms_entry(accept1, accept2, accept3);
	}
}

void DFA::compute_perms_table(vector <aa_perms> &perms_table, bool prompt)
{
	idxmap_t idxmap;

	size_t mult = filedfa ? 2 : 1;
	size_t pos = filedfa ? 2 : 1;

	assert(states.size() >= 2);

	perms_table.resize(uniq_perms.size()*mult);
	compute_perms_table_ent(nonmatching->perms, 0, perms_table, idxmap,
				prompt);
	nonmatching->idx = 0;
	start->idx = 0;

	for (perms_t_Cache::const_iterator i = uniq_perms.cbegin(); i != uniq_perms.cend(); i++) {
		if (*i == nonmatching->perms)
			continue;
		compute_perms_table_ent(*i, pos, perms_table, idxmap, prompt);
		pos += mult;
	}

	// nonmatching and start need to be 0 and 1 so handle outside of loop
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if (*i == nonmatching || *i == start)
			continue;
		idxmap_t::iterator j = idxmap.find((*i)->perms);
		if (j == idxmap.end()) {
			perms_t_Cache::iterator k = uniq_perms.find((*i)->perms);
			if (k == uniq_perms.end())
				throw std::runtime_error("permission not in permission table map");
			else
				throw std::runtime_error("permission not in idx table map");
		}
		(*i)->idx = j->second;
	}
}


#if 0
typedef set <ImportantNode *>AcceptNodes;
map<ImportantNode *, AcceptNodes> dominance(DFA & dfa)
{
	map<ImportantNode *, AcceptNodes> is_dominated;

	for (States::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
		AcceptNodes set1;
		for (State::iterator j = (*i)->begin(); j != (*i)->end(); j++) {
			if (AcceptNode * accept = dynamic_cast<AcceptNode *>(*j))
				set1.insert(accept);
		}
		for (AcceptNodes::iterator j = set1.begin(); j != set1.end(); j++) {
			pair<map<ImportantNode *, AcceptNodes>::iterator, bool> x = is_dominated.insert(make_pair(*j, set1));
			if (!x.second) {
				AcceptNodes & set2(x.first->second), set3;
				for (AcceptNodes::iterator l = set2.begin();
				     l != set2.end(); l++) {
					if (set1.find(*l) != set1.end())
						set3.insert(*l);
				}
				set3.swap(set2);
			}
		}
	}
	return is_dominated;
}
#endif

static inline int diff_qualifiers(perm32_t perm1, perm32_t perm2)
{
	return ((perm1 & AA_EXEC_TYPE) && (perm2 & AA_EXEC_TYPE) &&
		(perm1 & AA_EXEC_TYPE) != (perm2 & AA_EXEC_TYPE));
}

// only applied if filedfa
static void add_implied_ix_mmap(optflags const &opts, vector<int> &priority,
				perm32_t &mask)
{
	// ix implies EXEC_MMAP
	if ((mask & AA_MAY_EXEC) && (mask & AA_EXEC_INHERIT)) {
		//USER_EXEC_MAP = 6
		if (priority[EXEC_MMAP_SHIFT] <= priority[MAY_EXEC_SHIFT]) {
			if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << "[6]<=" << priority[EXEC_MMAP_SHIFT] <<  " < " << priority[MAY_EXEC_SHIFT] << " adding implied m to " << hex << "mask: " << mask << dec;
			mask |= AA_USER_EXEC_MMAP;
			priority[EXEC_MMAP_SHIFT] = priority[MAY_EXEC_SHIFT];
		} else if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << "[6]>" << priority[EXEC_MMAP_SHIFT] <<  " > " << priority[MAY_EXEC_SHIFT] << " skipping adding implied m to " << hex << "mask: " << mask << dec;

	}
	// ix implies EXEC_MMAP
	if ((mask & AA_OTHER_EXEC) && (mask & AA_OTHER_EXEC_INHERIT)) {
		//OTHER_EXEC_MAP = 20 = 6 (EXEC_MMAP_SHIFT) + 14 (AA_OTHER_SHIFT)
		if (priority[EXEC_OTHER_MMAP_SHIFT] <= priority[MAY_OTHER_EXEC_SHIFT]) {
			if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << "[20]<=" << priority[EXEC_OTHER_MMAP_SHIFT] <<  " < " << priority[MAY_OTHER_EXEC_SHIFT] << " adding implied m to " << hex << "mask: " << mask << dec;
			mask |= AA_OTHER_EXEC_MMAP;
			priority[EXEC_OTHER_MMAP_SHIFT] = priority[MAY_OTHER_EXEC_SHIFT];
		} else if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << "[20]>" << priority[EXEC_OTHER_MMAP_SHIFT] <<  " > " << priority[MAY_OTHER_EXEC_SHIFT] << " skipping adding implied m to " << hex << "mask: " << mask << dec;

	}
}

/* update a single permission based on priority
 * - only called if match->perm | match-> audit bit set
 */
static int pri_update_perm(optflags const &opts, vector<int> &priority, int i,
			   MatchFlag *match, perms_t &perms, bool filedfa)
{
	perm32_t xmask = 0;
	perm32_t mask = 1 << i;
	perm32_t amask = mask;

	// scaling priority *4
	int pri = match->priority<<2;

	/* use priority to get proper ordering and application of the type
	 * of match flag (rule type).
	 *
	 * Note: this is the last use of priority, it is dropped and not
	 *       used in the backend.
	 */
	if (match->is_type(NODE_TYPE_DENYMATCHFLAG))
		pri += 3;
	// for exec permission bits and their audit control exact match
	// has higher priority
	else if (match->is_type(NODE_TYPE_EXACTMATCHFLAG) &&
		 (mask & AA_EXEC_BITS))
		pri += 2;
	else if (!match->is_type(NODE_TYPE_PROMPTMATCHFLAG))
		pri += 1;
	// else prompt +0

	if (priority[i] > pri) {
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] << " > " << pri << " SKIPPING " << hex << (match->perms) << "/" << (match->audit) << dec << "\n";
		return 0;
	}

	// drop once we move the xindex out of the perms in the front end
	if (filedfa) {
		if (mask & AA_USER_EXEC) {
			xmask = AA_USER_EXEC_TYPE;
			amask = mask | xmask;
		} else if (mask & AA_OTHER_EXEC) {
			xmask = AA_OTHER_EXEC_TYPE;
			amask = mask | xmask;
		}
	}

	if (opts.dump & DUMP_DFA_PERMS)
		cerr << "  " << match << "[" << i << "]=" << priority[i] <<  " vs. " << pri << " mask: " << hex << mask << " xmask: " << xmask << " amask: " << amask << dec << "\n";
	if (priority[i] < pri) {
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " < " << pri << " clearing " << hex << "mask: " << amask << " from " << (perms.allow) << "/" << (perms.audit) << " -> " << dec;
		priority[i] = pri;
		perms.clear_bits(amask);
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << hex << (perms.allow) << "/" << (perms.audit) << dec << "\n";
	}

	// the if conditions in order of permission priority
	if (match->is_type(NODE_TYPE_DENYMATCHFLAG)) {
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] << " <= " << pri << " deny " << hex << (match->perms & amask) << "/" << (match->audit & amask) << dec << "\n";
		// deny x never implies mmap so not used here
		perms.deny |= match->perms & amask;
		perms.quiet |= match->audit & amask;

		perms.allow &= ~amask;
		perms.audit &= ~amask;
		perms.prompt &= ~amask;
	} else if (match->is_type(NODE_TYPE_EXACTMATCHFLAG)) {
		/* exact match only asserts dominance on the XTYPE */
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " exact " << hex << (match->perms & amask) << "/" << (match->audit & amask) << dec << "\n";
		if (filedfa && xmask && (perms.allow & amask) &&
		    !is_merged_x_consistent(perms.allow, match->perms & amask)) {
			if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " exact match conflict" << "\n";
			return 1;
		}
		// dominance is only done for XTYPE so only clear that
		// note xmask only set if setting x perm bit, so this
		// won't clear for other bit types
		perms.allow &= ~xmask;
		perms.audit &= ~xmask;
		perms.prompt &= ~xmask;

		perms.allow |= match->perms & amask;
		perms.audit |= match->audit & amask;
		// can't specify exact prompt atm
	} else if (!match->is_type(NODE_TYPE_PROMPTMATCHFLAG)) {
		// allow perms, if exact has been encountered will
		// already be set if overlaps x here, don't conflict,
		// because exact will override
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " allow " << hex << (match->perms & amask) << "/" << (match->audit & amask) << dec << "\n";
		if (filedfa && xmask && (perms.allow & amask) &&
		    !is_merged_x_consistent(perms.allow, match->perms & amask)) {
			if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " allow match conflict" << "\n";
			return 1;
		}
		perms.allow |= match->perms & amask;
		perms.audit |= match->audit & amask;
	} else { // if (match->is_type(NODE_TYPE_PROMPTMATCHFLAG)) {
		if (opts.dump & DUMP_DFA_PERMS)
			cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " prompt " << hex << (match->perms & amask) << "/" << (match->audit & amask) << dec << "\n";
		if (filedfa && xmask && (perms.allow & amask) &&
		    !is_merged_x_consistent(perms.allow, match->perms & amask)) {
			if (opts.dump & DUMP_DFA_PERMS)
				cerr << "    " << match << "[" << i << "]=" << priority[i] <<  " <= " << pri << " prompt match conflict" << "\n";
			return 1;
		}
		perms.prompt |= match->perms & amask;
		perms.audit |= match->audit & amask;
	}

	return 0;
}

/**
 * Compute the permission flags that this state corresponds to. If we
 * have any exact matches, then they override the execute and safe
 * execute flags.
 */
perms_t::perms_t(optflags const &opts, NodeVec *state, bool filedfa)
{
	int error = 0;
	// scaling priority by *4
	std::vector<int>  priority(sizeof(perm32_t)*8,  MIN_INTERNAL_PRIORITY*4);	// 32 but wasn't tied to perm32_t
	clear();

	if (!state)
		return;
	if (opts.dump & DUMP_DFA_PERMS) {
		cerr << "Building Perms";
		if (filedfa)
			cerr << " (file)";
		cerr << "\n";
	}
	for (NodeVec::iterator i = state->begin(); i != state->end(); i++) {
		if (!(*i)->is_type(NODE_TYPE_MATCHFLAG))
			continue;

		MatchFlag *match = static_cast<MatchFlag *>(*i);

		perm32_t bit = 1;
		perm32_t check = match->perms | match->audit;
		if (filedfa)
			check &= ~ALL_AA_EXEC_TYPE;

		for (int i = 0;  check; i++) {
			if (check & bit) {
				error = pri_update_perm(opts, priority, i, match, *this, filedfa);
				if (error)
					goto out;
			}
			check &= ~bit;
			bit <<= 1;
		}
	}
	if (filedfa && (allow & AA_EXEC_BITS)) {
		add_implied_ix_mmap(opts, priority, allow);
	}
	if (opts.dump & DUMP_DFA_PERMS) {
		cerr << "  computed: ";  dump(cerr); cerr << "\n";
	}
out:
	if (error) {
		fprintf(stderr, "profile has merged rule with conflicting x modifiers\n");
		throw error;
	}
}
