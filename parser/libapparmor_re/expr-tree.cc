/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2013 Canonical Ltd.
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
 * Functions to create/manipulate an expression tree for regular expressions
 * that have been parsed.
 *
 * The expression tree can be used directly after the parse creates it, or
 * it can be factored so that the set of important nodes is smaller.
 * Having a reduced set of important nodes generally results in a dfa that
 * is closer to minimum (fewer redundant states are created).  It also
 * results in fewer important nodes in the state set during subset
 * construction resulting in less memory used to create a dfa.
 *
 * Generally it is worth doing expression tree simplification before dfa
 * construction, if the regular expression tree contains any alternations.
 * Even if the regular expression doesn't simplification should be fast
 * enough that it can be used with minimal overhead.
 */

#include <stdio.h>
#include <string.h>

#include "expr-tree.h"
#include "apparmor_re.h"

using namespace std;

/* Use a single static EpsNode as it carries no node specific information */
EpsNode epsnode;

ostream &transchar::dump(ostream &os) const
{
	const char *search = "\a\033\f\n\r\t|*+[](). ",
		   *replace = "aefnrt|*+[](). ", *s;

	if (this->c < 0)
		os << "-0x" << hex << -this->c << dec;
	else if (this->c > 255)
		os << "0x" << hex << this->c << dec;
	else if ((s = strchr(search, this->c)) && *s != '\0')
		os << '\\' << replace[s - search] << " 0x" << hex << this->c << dec;
	else if (!isprint(this->c))
		os << "0x" << hex << this->c << dec;
	else
		os << (char)this->c << " 0x" << hex << this->c << dec;
	return os;
}

ostream &operator<<(ostream &os, transchar tc)
{
	const char *search = "\a\033\f\n\r\t|*+[](). ",
	    *replace = "aefnrt|*+[](). ", *s;
	short c = tc.c;

	if (c < 0)
		os << "\\d" << "" << tc.c;
	else if ((s = strchr(search, c)) && *s != '\0')
		os << '\\' << replace[s - search];
	else if (!isprint(c))
		os << "\\x" << hex << c << dec;
	else
		os << (char)c;
	return os;
}

/**
 * Text-dump a state (for debugging).
 */
ostream &operator<<(ostream &os, const NodeSet &state)
{
	os << '{';
	if (!state.empty()) {
		NodeSet::iterator i = state.begin();
		for (;;) {
			os << (*i)->label;
			if (++i == state.end())
				break;
			os << ',';
		}
	}
	os << '}';
	return os;
}

ostream &operator<<(ostream &os, const Node &node)
{
	node.dump(os);
	return os;
}

/**
 * hash_NodeSet - generate a hash for the Nodes in the set
 */
unsigned long hash_NodeSet(NodeSet *ns)
{
	unsigned long hash = 5381;

	for (NodeSet::iterator i = ns->begin(); i != ns->end(); i++) {
		hash = ((hash << 5) + hash) + (unsigned long)*i;
	}

	return hash;
}

/**
 * label_nodes - label the node positions for pretty-printing debug output
 *
 * TODO: separate - node labels should be separate and optional, if not
 * present pretty printing should use Node address
 */
void label_nodes(Node *root)
{
	int nodes = 1;
	for (depth_first_traversal i(root); i; i++)
		i->label = nodes++;
}

/**
 * Text-dump the syntax tree (for debugging).
 */
void Node::dump_syntax_tree(ostream &os) const
{
	for (const_depth_first_traversal i(this); i; i++) {
		os << i->label << '\t';
		if ((*i)->child[0] == 0)
			os << **i << '\t' << (*i)->followpos << endl;
		else {
			if ((*i)->child[1] == 0)
				os << (*i)->child[0]->label << **i;
			else
				os << (*i)->child[0]->label << **i
				   << (*i)->child[1]->label;
			os << '\t' << (*i)->firstpos << (*i)->lastpos << endl;
		}
	}
	os << endl;
}

/*
 * Normalize the regex parse tree for factoring and cancellations. Normalization
 * reorganizes internal (alt and cat) nodes into a fixed "normalized" form that
 * simplifies factoring code, in that it produces a canonicalized form for
 * the direction being normalized so that the factoring code does not have
 * to consider as many cases.
 *
 * left normalization (dir == 0) uses these rules
 * (E | a) -> (a | E)
 * (a | b) | c -> a | (b | c)
 * (ab)c -> a(bc)
 *
 * right normalization (dir == 1) uses the same rules but reversed
 * (a | E) -> (E | a)
 * a | (b | c) -> (a | b) | c
 * a(bc) -> (ab)c
 *
 * Note: This is written iteratively for a given node (the top node stays
 *       fixed and the children are rotated) instead of recursively.
 *       For a given node under examination rotate over nodes from
 *       dir to !dir.   Until no dir direction node meets the criteria.
 *       Then recurse to the children (which will have a different node type)
 *       to make sure they are normalized.
 *       Normalization of a child node is guaranteed to not affect the
 *       normalization of the parent.
 *
 *       For cat nodes the depth first traverse order is guaranteed to be
 *       maintained.  This is not necessary for altnodes.
 *
 * Eg. For left normalization
 *
 *              |1               |1
 *             / \              / \
 *            |2  T     ->     a   |2
 *           / \                  / \
 *          |3  c                b   |3
 *         / \                      / \
 *        a   b                    c   T
 *
 */


static Node *simplify_eps_pair(Node *t)
{
	if (t->is_type(node_type_t::TWOCHILD) &&
	    t->child[0] == &epsnode &&
	    t->child[1] == &epsnode) {
		t->release();
		return &epsnode;
	}
	return t;
}

static void rotate_node(Node *t, int dir)
{
	// (a | b) | c -> a | (b | c)
	// (ab)c -> a(bc)
	Node *left = t->child[dir];
	t->child[dir] = left->child[dir];
	left->child[dir] = left->child[!dir];
	left->child[!dir] = t->child[!dir];

        // check that rotation didn't create (E | E)
	t->child[!dir] = simplify_eps_pair(left);
}

/* return False if no work done */
int TwoChildNode::normalize_eps(int dir)
{
	if ((&epsnode == child[dir]) &&
	    (&epsnode != child[!dir])) {
		// (E | a) -> (a | E)
		// Ea -> aE
		// Test for E | (E | E) and E . (E . E) which will
		// result in an infinite loop
		Node *c = simplify_eps_pair(child[!dir]);
		child[!dir] = child[dir];
		child[dir] = c;
		return 1;
	}

	return 0;
}

void CatNode::normalize(int dir)
{
	for (;;) {
		if (normalize_eps(dir)) {
			continue;
		} else if (child[dir]->is_type(node_type_t::CAT)) {
			// (ab)c -> a(bc)
			rotate_node(this, dir);
		} else {
			break;
		}
	}

	if (child[dir])
		child[dir]->normalize(dir);
	if (child[!dir])
		child[!dir]->normalize(dir);
}

void AltNode::normalize(int dir)
{
	for (;;) {
		if (normalize_eps(dir)) {
			continue;
		} else if (child[dir]->is_type(node_type_t::ALT)) {
			// (a | b) | c -> a | (b | c)
			rotate_node(this, dir);
		} else if (child[dir]->is_type(node_type_t::CHARSET) &&
			   child[!dir]->is_type(node_type_t::CHAR)) {
			// [a] | b  ->  b | [a]
			Node *c = child[dir];
			child[dir] = child[!dir];
			child[!dir] = c;
		} else {
			break;
		}
	}

	if (child[dir])
		child[dir]->normalize(dir);
	if (child[!dir])
		child[!dir]->normalize(dir);
}

//charset conversion is disabled for now,
//it hinders tree optimization in some cases, so it need to be either
//done post optimization, or have extra factoring rules added
#if 0
static Node *merge_charset(Node *a, Node *b)
{
	if (dynamic_cast<CharNode *>(a) && dynamic_cast<CharNode *>(b)) {
		Chars chars;
		chars.insert(dynamic_cast<CharNode *>(a)->c);
		chars.insert(dynamic_cast<CharNode *>(b)->c);
		CharSetNode *n = new CharSetNode(chars);
		return n;
	} else if (dynamic_cast<CharNode *>(a) &&
		   dynamic_cast<CharSetNode *>(b)) {
		Chars *chars = &dynamic_cast<CharSetNode *>(b)->chars;
		chars->insert(dynamic_cast<CharNode *>(a)->c);
		return b;
	} else if (dynamic_cast<CharSetNode *>(a) &&
		   dynamic_cast<CharSetNode *>(b)) {
		Chars *from = &dynamic_cast<CharSetNode *>(a)->chars;
		Chars *to = &dynamic_cast<CharSetNode *>(b)->chars;
		for (Chars::iterator i = from->begin(); i != from->end(); i++)
			to->insert(*i);
		return b;
	}
	//return ???;
}

static Node *alt_to_charsets(Node *t, int dir)
{
/*
	Node *first = NULL;
	Node *p = t;
	Node *i = t;
	for (;dynamic_cast<AltNode *>(i);) {
		if (dynamic_cast<CharNode *>(i->child[dir]) ||
		    dynamic_cast<CharNodeSet *>(i->child[dir])) {
			if (!first) {
				first = i;
				p = i;
				i = i->child[!dir];
			} else {
				first->child[dir] = merge_charset(first->child[dir],
						      i->child[dir]);
				p->child[!dir] = i->child[!dir];
				Node *tmp = i;
				i = tmp->child[!dir];
				tmp->child[!dir] = NULL;
				tmp->release();
			}
		} else {
			p = i;
			i = i->child[!dir];
		}
	}
	// last altnode of chain check other dir as well
	if (first && (dynamic_cast<charNode *>(i) ||
		      dynamic_cast<charNodeSet *>(i))) {
		
	}
*/

/*
		if (dynamic_cast<CharNode *>(t->child[dir]) ||
		    dynamic_cast<CharSetNode *>(t->child[dir]))
		    char_test = true;
			    (char_test &&
			     (dynamic_cast<CharNode *>(i->child[dir]) ||
			      dynamic_cast<CharSetNode *>(i->child[dir])))) {
*/
	return t;
}
#endif

static Node *basic_alt_factor(Node *t, int dir)
{
	if (!t->is_type(node_type_t::ALT))
		return t;

	if (t->child[dir]->eq(t->child[!dir])) {
		// (a | a) -> a
		Node *tmp = t->child[dir];
		t->child[dir] = NULL;
		t->release();
		return tmp;
	}
	// (ab) | (ac) -> a(b|c)
	if (t->child[dir]->is_type(node_type_t::CAT) &&
	    t->child[!dir]->is_type(node_type_t::CAT) &&
	    t->child[dir]->child[dir]->eq(t->child[!dir]->child[dir])) {
		// (ab) | (ac) -> a(b|c)
		Node *left = t->child[dir];
		Node *right = t->child[!dir];
		t->child[dir] = left->child[!dir];
		t->child[!dir] = right->child[!dir];
		right->child[!dir] = NULL;
		right->release();
		left->child[!dir] = t;
		return left;
	}
	// a | (ab) -> a (E | b) -> a (b | E)
	if (t->child[!dir]->is_type(node_type_t::CAT) &&
	    t->child[dir]->eq(t->child[!dir]->child[dir])) {
		Node *c = t->child[!dir];
		t->child[dir]->release();
		t->child[dir] = c->child[!dir];
		t->child[!dir] = &epsnode;
		c->child[!dir] = t;
		return c;
	}
	// ab | (a) -> a (b | E)
	if (t->child[dir]->is_type(node_type_t::CAT) &&
	    t->child[dir]->child[dir]->eq(t->child[!dir])) {
		Node *c = t->child[dir];
		t->child[!dir]->release();
		t->child[dir] = c->child[!dir];
		t->child[!dir] = &epsnode;
		c->child[!dir] = t;
		return c;
	}

	return t;
}

static Node *basic_simplify(Node *t, int dir)
{
	if (t->is_type(node_type_t::CAT) && &epsnode == t->child[!dir]) {
		// aE -> a
		Node *tmp = t->child[dir];
		t->child[dir] = NULL;
		t->release();
		return tmp;
	}

	return basic_alt_factor(t, dir);
}

/*
 * assumes a normalized tree.  reductions shown for left normalization
 * aE -> a
 * (a | a) -> a
 ** factoring patterns
 * a | (a | b) -> (a | b)
 * a | (ab) -> a (E | b) -> a (b | E)
 * (ab) | (ac) -> a(b|c)
 *
 * returns t - if no simplifications were made
 *         a new root node - if simplifications were made
 */
Node *simplify_tree_base(Node *t, int dir, bool &mod)
{
	if (t->is_type(node_type_t::IMPORTANT))
		return t;

	for (int i = 0; i < 2; i++) {
		if (t->child[i]) {
			Node *c = simplify_tree_base(t->child[i], dir, mod);
			if (c != t->child[i]) {
				t->child[i] = c;
				mod = true;
			}
		}
	}

	// only iterate on loop if modification made
	for (;; mod = true) {

		Node *tmp = basic_simplify(t, dir);
		if (tmp != t) {
			t = tmp;
			continue;
		}

		/* all tests after this must meet 2 alt node condition */
		if (!t->is_type(node_type_t::ALT) ||
		    !t->child[!dir]->is_type(node_type_t::ALT))
			break;

		// a | (a | b) -> (a | b)
		// a | (b | (c | a)) -> (b | (c | a))
		Node *p = t;
		Node *i = t->child[!dir];
		for (; i->is_type(node_type_t::ALT); p = i, i = i->child[!dir]) {
			if (t->child[dir]->eq(i->child[dir])) {
				Node *tmp = t->child[!dir];
				t->child[!dir] = NULL;
				t->release();
				t = tmp;
				continue;
			}
		}
		// last altnode of chain check other dir as well
		if (t->child[dir]->eq(p->child[!dir])) {
			Node *tmp = t->child[!dir];
			t->child[!dir] = NULL;
			t->release();
			t = tmp;
			continue;
		}
		//exact match didn't work, try factoring front
		//a | (ac | (ad | () -> (a (E | c)) | (...)
		//ab | (ac | (...)) -> (a (b | c)) | (...)
		//ab | (a | (...)) -> (a (b | E)) | (...)
		Node *pp;
		int count = 0;
		Node *subject = t->child[dir];
		Node *a = subject;
		if (subject->is_type(node_type_t::CAT))
			a = subject->child[dir];

		for (pp = p = t, i = t->child[!dir];
		     i->is_type(node_type_t::ALT);) {
			if ((i->child[dir]->is_type(node_type_t::CAT) &&
			     a->eq(i->child[dir]->child[dir])) ||
			    (a->eq(i->child[dir]))) {
				// extract matching alt node
				p->child[!dir] = i->child[!dir];
				i->child[!dir] = subject;
				subject = basic_simplify(i, dir);
				if (subject->is_type(node_type_t::CAT))
					a = subject->child[dir];
				else
					a = subject;

				i = p->child[!dir];
				count++;
			} else {
				pp = p;
				p = i;
				i = i->child[!dir];
			}
		}

		// last altnode in chain check other dir as well
		if ((i->is_type(node_type_t::CAT) &&
		     a->eq(i->child[dir])) || (a->eq(i))) {
			count++;
			if (t == p) {
				t->child[dir] = subject;
				t = basic_simplify(t, dir);
			} else {
				t->child[dir] = p->child[dir];
				p->child[dir] = subject;
				pp->child[!dir] = basic_simplify(p, dir);
			}
		} else {
			t->child[dir] = i;
			p->child[!dir] = subject;
		}

		if (count == 0)
			break;
	}
	return t;
}

int debug_tree(Node *t)
{
	int nodes = 1;

	if (!t->is_type(node_type_t::IMPORTANT)) {
		if (t->child[0])
			nodes += debug_tree(t->child[0]);
		if (t->child[1])
			nodes += debug_tree(t->child[1]);
	}
	return nodes;
}

static void count_tree_nodes(Node *t, struct node_counts *counts)
{
	if (t->is_type(node_type_t::ALT)) {
		counts->alt++;
		count_tree_nodes(t->child[0], counts);
		count_tree_nodes(t->child[1], counts);
	} else if (t->is_type(node_type_t::CAT)) {
		counts->cat++;
		count_tree_nodes(t->child[0], counts);
		count_tree_nodes(t->child[1], counts);
	} else if (t->is_type(node_type_t::PLUS)) {
		counts->plus++;
		count_tree_nodes(t->child[0], counts);
	} else if (t->is_type(node_type_t::STAR)) {
		counts->star++;
		count_tree_nodes(t->child[0], counts);
	} else if (t->is_type(node_type_t::OPTIONAL)) {
		counts->optional++;
		count_tree_nodes(t->child[0], counts);
	} else if (t->is_type(node_type_t::CHAR)) {
		counts->charnode++;
	} else if (t->is_type(node_type_t::ANYCHAR)) {
		counts->any++;
	} else if (t->is_type(node_type_t::CHARSET)) {
		counts->charset++;
	} else if (t->is_type(node_type_t::NOTCHARSET)) {
		counts->notcharset++;
	}
}

#include "stdio.h"
#include "stdint.h"
#include "apparmor_re.h"

// maximum number of passes to iterate on the expression tree doing
// simplification passes. Simplification may exit sooner if no changes
// are made.
#define MAX_PASSES 1
Node *simplify_tree(Node *t, optflags const &opts)
{
	bool update = true;
	int i;

	if (opts.dump & DUMP_DFA_TREE_STATS) {
		struct node_counts counts = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		count_tree_nodes(t, &counts);
		fprintf(stderr,
			"expr tree: c %d, [] %d, [^] %d, | %d, + %d, * %d, . %d, cat %d\n",
			counts.charnode, counts.charset, counts.notcharset,
			counts.alt, counts.plus, counts.star, counts.any,
			counts.cat);
	}
	for (i = 0; update && i < MAX_PASSES; i++) {
		update = false;
		//default to right normalize first as this reduces the number
		//of trailing nodes which might follow an internal *
		//or **, which is where state explosion can happen
		//eg. in one test this makes the difference between
		//    the dfa having about 7 thousands states,
		//    and it having about  1.25 million states
		int dir = 1;
		if (opts.control & CONTROL_DFA_TREE_LEFT)
			dir = 0;
		for (int count = 0; count < 2; count++) {
			bool modified;
			do {
				modified = false;
				if (opts.control & CONTROL_DFA_TREE_NORMAL)
					t->normalize(dir);
				t = simplify_tree_base(t, dir, modified);
				if (modified)
					update = true;
			} while (modified);
			if (opts.control & CONTROL_DFA_TREE_LEFT)
				dir++;
			else
				dir--;
		}
	}
	if (opts.dump & DUMP_DFA_TREE_STATS) {
		struct node_counts counts = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		count_tree_nodes(t, &counts);
		fprintf(stderr,
			"simplified expr tree: c %d, [] %d, [^] %d, | %d, + %d, * %d, . %d, cat %d\n",
			counts.charnode, counts.charset, counts.notcharset,
			counts.alt, counts.plus, counts.star, counts.any,
			counts.cat);
	}
	return t;
}

/**
 * Flip the children of all cat nodes. This causes strings to be matched
 * back-forth.
 */
void flip_tree(Node *node)
{
	for (depth_first_traversal i(node); i; i++) {
		if ((*i)->is_type(node_type_t::CAT)) {
			CatNode *cat = static_cast<CatNode *>(*i);
			swap(cat->child[0], cat->child[1]);
		}
	}
}

void dump_regex_rec(ostream &os, Node *tree)
{
	if (tree->child[0])
		dump_regex_rec(os, tree->child[0]);
	os << *tree;
	if (tree->child[1])
		dump_regex_rec(os, tree->child[1]);
}

void dump_regex(ostream &os, Node *tree)
{
	dump_regex_rec(os, tree);
	os << endl;
}
