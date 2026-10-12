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
 * results in fewer important nodes in a the state set during subset
 * construction resulting in less memory used to create a dfa.
 *
 * Generally it is worth doing expression tree simplification before dfa
 * construction, if the regular expression tree contains any alternations.
 * Even if the regular expression doesn't simplification should be fast
 * enough that it can be used with minimal overhead.
 */
#ifndef __LIBAA_RE_EXPR_H
#define __LIBAA_RE_EXPR_H

#include <cstddef>
#include <map>
#include <set>
#include <ostream>
#include <vector>

#include <stdint.h>

#include "../common_flags.h"  // for optflags
#include "../perms.h"

/*
 * transchar - representative input character for state transitions
 *
 * the transchar is used as the leaf node in the expr tree created
 * by parsing an input regex (parse.y), and is used to build both the
 * states and the transitions for a state machine (hfa.{h,cc}) built
 * from the expression tree.
 *
 * While the state machine is currently based on byte inputs the
 * transchar abstraction allows for flexibility and the option of
 * moving to a larger input in the future. It also allows the ability
 * to specify out of band transitions.
 *
 * Out of band transitions allow for code to specify special transitions
 * that can not be triggered by an input byte stream. As such out of
 * band transitions can be used to separate logical units of a match.
 *
 * eg.
 * you need to allow an arbitrary data match (.*) followed by an arbitrary
 * string match ([^\x00]*), and make an acceptance decision based
 * on both matches.
 *
 * One way to do this is to chain the two matches in a single state
 * machine. However without an out of band transition, the match pattern
 * for the data match (.*) could also consume the input for the string match.
 * To ensure the data pattern match cannot consume characters for the second
 * match a special character is used. This prevents state machine
 * generation from intermixing the two expressions. For string matches
 * this can be achieved with the pattern.
 *    ([^\x00]*)\x00([\x00]*)
 * since \x00 can not be matched by the first expression (and is not a
 * valid character in a C string), the nul character can be used to
 * separate the string match. This however is not possible when matching
 * arbitrary data that can have any input character.
 *
 * Out of band transitions replace the \x00 transition in the string
 * example with a new input transition that comes from the driver
 * code. Once the first match is done, the driver supplies the non-input
 * character, causing the state machine to transition to the second
 * match pattern.
 *
 * Out of band transitions are specified using negative integers
 * (-1..-32k). They allow for different transitions if needed (currently
 * only -1 is used).
 *
 * Negative integers were chosen to represent out of band transitions
 * because it makes the run time match simple, and also keeps the
 * upper positive integer range open for future input character
 * expansion.
 *
 * When a chfa is built, the out of band transition is encoded as
 * a negative offset of the same value specified in the transchar from the
 * state base base value. The check value at the negative offset will
 * contain the owning state value. The chfa state machine is constructed
 * in such a way that this value will always be in bounds, and only an
 * unpack time verification is needed.
 */
class transchar final {
public:
	short c;

	transchar(unsigned char a): c((unsigned short) a) {}
	transchar(short a, bool oob __attribute__((unused))): c(a) {}
	transchar(const transchar &a): c(a.c) {}
	transchar(): c(0) {}

	bool operator==(const transchar &rhs) const {
		return this->c == rhs.c;
	}
	bool operator==(const int &rhs) const {
		return this->c == rhs;
	}
	bool operator!=(const transchar &rhs) const {
		return this->c != rhs.c;
	}
	bool operator>(const transchar &rhs) const {
		return this->c > rhs.c;
	}
	bool operator<(const transchar &rhs) const {
		return this->c < rhs.c;
	}
	bool operator<=(const transchar &rhs) const {
		return this->c <= rhs.c;
	}
	transchar &operator++() {		// prefix
		(this->c)++;
		return *this;
	}
	transchar operator++(int) {		// postfix
		transchar tmp(*this);
		(this->c)++;
		return tmp;
	}

	ostream &dump(ostream &os) const;

};

class Chars final {
public:
	// https://stackoverflow.com/questions/32869247/a-container-for-integer-intervals-such-as-rangeset-for-c
	std::set<transchar> chars;

	typedef std::set<transchar>::iterator iterator;
	typedef std::set<transchar>::const_iterator const_iterator;
	iterator begin() { return chars.begin(); }
	iterator end() { return chars.end(); }
	const_iterator begin() const { return chars.begin(); }
	const_iterator end() const { return chars.end(); }

	Chars(): chars() {}

	bool empty() const
	{
		return chars.empty();
	}
	std::size_t size() const
	{
		return chars.size();
	}
	iterator find(const transchar &key)
	{
		return chars.find(key);
	}
	const_iterator find(const transchar &key) const
	{
		return chars.find(key);
	}
	std::pair<iterator,bool> insert(transchar c)
	{
		return chars.insert(c);
	}
	std::pair<iterator,bool> insert(char c)
	{
		transchar tmp(c);
		return chars.insert(tmp);
	}
};


ostream &operator<<(ostream &os, transchar c);

/* Compute the union of two sets. */
template<class T> std::set<T> operator+(const std::set<T> &a, const std::set<T> &b)
{
	std::set<T> c(a);
	c.insert(b.begin(), b.end());
	return c;
}

/* Move the contents of src into dst, inserting the smaller set into the
 * larger. src is left in an unspecified state.
 */
template<class T> void merge_into(std::set<T> &dst, std::set<T> &src)
{
	if (dst.size() < src.size())
		dst.swap(src);
	dst.insert(src.begin(), src.end());
}

/**
 * When creating DFAs from regex trees, a DFA state is constructed from
 * a set of important nodes in the syntax tree. This includes AcceptNodes,
 * which indicate that when a match ends in a particular state, the
 * regular expressions that the AcceptNode belongs to match.
 */
class Node;
class ImportantNode;
typedef std::set<ImportantNode *> NodeSet;

/**
 * Text-dump a state (for debugging).
 */
ostream &operator<<(ostream &os, const NodeSet &state);

/**
 * Out-edges from a state to another: we store the follow-set of Nodes
 * for each input character that is not a default match in
 * cases (i.e., following a CharNode or CharSetNode), and default
 * matches in otherwise as well as in all matching explicit cases
 * (i.e., following an AnyCharNode or NotCharSetNode). This avoids
 * enumerating all the explicit tranitions for default matches.
 */
typedef struct Cases {
	typedef std::map<transchar, NodeSet *>::iterator iterator;
	iterator begin() { return cases.begin(); }
	iterator end() { return cases.end(); }

	Cases(): otherwise(0) { }
	std::map<transchar, NodeSet *> cases;
	NodeSet *otherwise;
} Cases;

ostream &operator<<(ostream &os, const Node &node);

enum class node_type_t : uint32_t {
	NODE = 0,
	INNER = (1u << 0),
	ONECHILD = (1u << 1),
	NCHILD = (1u << 2),
	LEAF = (1u << 3),
	EPS = (1u << 4),
	IMPORTANT = (1u << 5),
	C = (1u << 6),
	CHAR = (1u << 7),
	CHARSET = (1u << 8),
	NOTCHARSET = (1u << 9),
	ANYCHAR = (1u << 10),
	STAR = (1u << 11),
	OPTIONAL = (1u << 12),
	PLUS = (1u << 13),
	ALT = (1u << 14),
	SHARED = (1u << 15),
	ACCEPT = (1u << 16),
	MATCHFLAG = (1u << 17),
	EXACTMATCHFLAG = (1u << 18),
	DENYMATCHFLAG = (1u << 19),
	PROMPTMATCHFLAG = (1u << 20),
	SHAREDTREE = (1u << 21),
	// CAT NODE needs to be last for factoring
	CAT = (1u << 22),
};

constexpr inline node_type_t operator|(node_type_t lhs, node_type_t rhs)
{
	return static_cast<node_type_t>(
		static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

constexpr inline node_type_t operator&(node_type_t lhs, node_type_t rhs)
{
	return static_cast<node_type_t>(
		static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

inline node_type_t &operator|=(node_type_t &lhs, node_type_t rhs)
{
	lhs = lhs | rhs;
	return lhs;
}

constexpr inline bool has_type(node_type_t flags, node_type_t type)
{
	return static_cast<uint32_t>(flags & type) != 0;
}

/* An abstract node in the syntax tree. */
class Node {
public:
	Node(): child(2), type_flags(node_type_t::NODE), label(0) { }
	Node(Node *left): child{left, NULL}, type_flags(node_type_t::NODE),
		label(0) { }
	Node(Node *left, Node *right): child{left, right},
		type_flags(node_type_t::NODE), label(0) { }
	/* children are released by OneChildNode and NChildNode */
	virtual ~Node() { }

	/**
	 * nullable, firstpos, lastpos, and followpos are used to convert the
	 * syntax tree to a DFA.
	 *
	 * firstpos holds nodes that can match the first character of a string
	 * that matches the syntax tree. For the regex 'a*bcd', firstpos holds
	 * the 'a' and 'b' nodes. firstpos is used to determine the start state
	 * of the DFA.
	 *
	 * lastpos is the same as firstpos for the last character. For the regex
	 * 'a*bcd', lastpos holds the 'd' node. lastpos is used to determine the
	 * accepting states of the DFA.
	 *
	 * followpos holds the set of nodes that can match a character directly
	 * after the current node. For the regexp 'a*bcd', the followpos of the
	 * 'a' node are the 'b' node and the 'a' node itself. followpos is used
	 * to determine the transitions of the DFA.
	 *
	 * nullable indicates that a node can match the empty string. It is used
	 * to compute firstpos and lastpos.
	 *
	 * See the "Dragon Book" 2nd Edition section 3.9.2 for an in-depth
	 * explanation.
	 *
	 * compute_pos computes followpos for the subtree, adds the subtree's
	 * firstpos and lastpos to the passed in sets, and returns nullable.
	 * The passed in sets may already contain the positions of other
	 * subtrees (eg. the left side of an alternation), so a node must
	 * not use them to compute followpos.
	 */
	virtual bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) = 0;

	/*
	 * min_match_len determines the smallest string that can match the
	 * syntax tree. This is used to determine the priority of a regex.
	 */
	virtual int min_match_len() const { return 0; }
	/*
	 * contains_oob returns if the expression tree contains a oob character.
	 * oob characters indicate that the rest of the DFA matches has an
	 * out of band transition. This is used to compute min_match_len.
	 */
	virtual bool contains_oob() const { return false; }

	/*
	 * cmp provides a total ordering of nodes, returning < 0, 0, or > 0.
	 * Nodes are ordered first by type, and then by subclasses on their
	 * contents. cmp() == 0 iff the nodes are equivalent.
	 */
	virtual int cmp(const Node *other) const
	{
		uint32_t a = static_cast<uint32_t>(type_flags);
		uint32_t b = static_cast<uint32_t>(other->type_flags);

		if (a < b)
			return -1;
		else if (a > b)
			return 1;
		return 0;
	}
	virtual int eq(const Node *other) const { return cmp(other) == 0; }
	virtual ostream &dump(ostream &os) const = 0;
	void dump_syntax_tree(ostream &os) const;
	virtual void normalize(int dir __attribute__ ((unused))) {}
	/* return false if no work done */
	virtual int normalize_eps(int dir __attribute__((unused))) { return 0; }

	NodeSet followpos;
	/* child 0 is left, child 1 is right */
	std::vector<Node *> child;

	/*
	 * Bitmap that stores supported pointer casts for the Node, composed
	 * by node_type_t flags. This is used by is_type() as a substitute
	 * of costly dynamic_cast calls.
	 */
	node_type_t type_flags;
	bool is_type(node_type_t type) const { return has_type(type_flags, type); }

	unsigned int label;	/* unique number for debug etc */
	/**
	 * We indirectly release Nodes through a virtual function because
	 * accept and Eps Nodes are shared, and must be treated specially.
	 * We could use full reference counting here but the indirect release
	 * is sufficient and has less overhead
	 */
	virtual void release(void) { delete this; }
};

class InnerNode: public Node {
public:
	InnerNode(): Node() { type_flags |= node_type_t::INNER; };
	InnerNode(Node *left): Node(left) { type_flags |= node_type_t::INNER; };
	InnerNode(Node *left, Node *right): Node(left, right)
	{
		type_flags |= node_type_t::INNER;
	};
};

class OneChildNode: public InnerNode {
public:
	OneChildNode(Node *left): InnerNode(left)
	{
		type_flags |= node_type_t::ONECHILD;
	};
	virtual ~OneChildNode()
	{
		if (child[0])
			child[0]->release();
	};
	void normalize(int dir) override
	{
		if (child[0])
			child[0]->normalize(dir);
	}
	bool contains_oob() const override {
		return child[0]->contains_oob();
	}

	int cmp(const Node *other) const override
	{
		int tmp = InnerNode::cmp(other);
		if (tmp != 0)
			return tmp;

		return child[0]->cmp(other->child[0]);
	}
};


class NChildNode: public InnerNode {
public:
	NChildNode(Node *left, Node *right): InnerNode(left, right)
	{
		type_flags |= node_type_t::NCHILD;
	};
	virtual ~NChildNode()
	{
		std::vector<Node *>::iterator it;
		for (it = child.begin(); it != child.end(); it++) {
			/* old factoring NULLs out children before release */
			if (*it)
				(*it)->release();
		}
	};

	void normalize(int dir) override
	{
		std::vector<Node *>::iterator it;
		for (it = child.begin(); it != child.end(); it++)
			(*it)->normalize(dir);
	}
	int normalize_eps(int dir) override;

	bool contains_oob() const override {
		std::vector<Node *>::const_iterator it;
		for (it = child.begin(); it != child.end(); it++) {
			if ((*it)->contains_oob())
				return true;
		}
		return false;
	}

	// assumes ordered as desired/sorted, this really only affects
	// alt nodes. But is not different than the TwoChild node treating
	// (a|b) as not equal to (b|a). Sorting alt node vectors before
	// comparing removes the ambiguity
	int cmp(const Node *other) const override
	{
		int tmp = InnerNode::cmp(other);
		if (tmp != 0)
			return tmp;

		std::vector<Node *>::const_iterator left;
		std::vector<Node *>::const_iterator right;

		if (child.size() < other->child.size())
			return -1;
		else if (child.size() > other->child.size())
			return 1;

		left = child.begin();
		right = other->child.begin();
		for ( ; left != child.end(); left++, right++) {
			tmp = (*left)->cmp(*right);
			if (tmp != 0)
				return tmp;
		}
		return 0;
	}
};

class LeafNode: public Node {
public:
	LeafNode(): Node() { type_flags |= node_type_t::LEAF; };
	void normalize(int dir __attribute__((unused))) override { return; }
};

/* Match nothing (//). */
class EpsNode: public LeafNode {
public:
	EpsNode(): LeafNode()
	{
		type_flags |= node_type_t::EPS;
		label = 0;
	}
	void release(void) override
	{
		/* don't delete Eps nodes because there is a single static
		 * instance shared by all trees.  Look for epsnode in the code
		 */
	}

	bool compute_pos(NodeSet &firstpos __attribute__((unused)),
			 NodeSet &lastpos __attribute__((unused))) override
	{
		/* nullable, no changes is NodeSets */
		return true;
	}

	ostream &dump(ostream &os) const override
	{
		return os << "[]";
	}
};

/**
 * Leaf nodes in the syntax tree are important to us: they describe the
 * characters that the regular expression matches. We also consider
 * AcceptNodes import: they indicate when a regular expression matches.
 */
class ImportantNode: public LeafNode {
public:
	ImportantNode(): LeafNode() { type_flags |= node_type_t::IMPORTANT; }
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		firstpos.insert(this);
		lastpos.insert(this);

		return false; 		/* nullable */
	}
	virtual void follow(Cases &cases) const = 0;
	virtual int is_accept(void) const = 0;
};

/* common base class for all the different classes that contain
 * character information.
 */
class CNode: public ImportantNode {
public:
	CNode(): ImportantNode() { type_flags |= node_type_t::C; }
	int is_accept(void) const override { return false; }
};

/* Match one specific character (/c/). */
class CharNode: public CNode {
public:
	CharNode(transchar c): c(c) { type_flags |= node_type_t::CHAR; }
	void follow(Cases &cases) const override
	{
		NodeSet **x = &cases.cases[c];
		if (!*x) {
			if (cases.otherwise && c.c >= 0)
				*x = new NodeSet(*cases.otherwise);
			else
				*x = new NodeSet;
		}
		(*x)->insert(followpos.begin(), followpos.end());
	}
	int cmp(const Node *other) const override
	{
		int tmp = CNode::cmp(other);
		if (tmp != 0)
			return tmp;

		const CharNode *o = static_cast<const CharNode *>(other);
		return c.c - o->c.c;
	}
	ostream &dump(ostream &os) const override
	{
		return os << c;
	}

	int min_match_len() const override
	{
		if (c < 0) {
			// oob characters indicates end of string.
			// note: does NOT currently calc match len
			// base on NULL char separator transitions
			// which some match rules use.
			return 0;
		}
		return 1;
	}

	bool contains_oob() const override { return c < 0; }

	transchar c;
};

/* Match a set of characters (/[abc]/). */
class CharSetNode: public CNode {
public:
	CharSetNode(Chars &chars): chars(chars)
	{
		type_flags |= node_type_t::CHARSET;
	}
	void follow(Cases &cases) const override
	{
		for (Chars::const_iterator i = chars.begin(); i != chars.end(); i++) {
			NodeSet **x = &cases.cases[*i];
			if (!*x) {
				if (cases.otherwise && i->c >= 0)
					*x = new NodeSet(*cases.otherwise);
				else
					*x = new NodeSet;
			}
			(*x)->insert(followpos.begin(), followpos.end());
		}
	}
	int cmp(const Node *other) const override
	{
		int tmp = CNode::cmp(other);
		if (tmp != 0)
			return tmp;

		const CharSetNode *o = static_cast<const CharSetNode *>(other);
		if (chars.size() < o->chars.size())
			return -1;
		else if (chars.size() > o->chars.size())
			return 1;

		for (Chars::const_iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end(); i++, j++) {
			tmp = i->c - j->c;
			if (tmp != 0)
				return tmp;
		}
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		os << '[';
		for (Chars::const_iterator i = chars.begin(); i != chars.end(); i++)
			os << *i;
		return os << ']';
	}

	int min_match_len() const override
	{
		if (contains_oob()) {
			return 0;
		}
		return 1;
	}

	bool contains_oob() const override
	{
		for (Chars::const_iterator i = chars.begin(); i != chars.end(); i++) {
			if (*i < 0) {
				return true;
			}
		}
		return false;
	}

	Chars chars;
};

/* Match all except one character (/[^abc]/). */
class NotCharSetNode: public CNode {
public:
	NotCharSetNode(Chars &chars): chars(chars)
	{
		type_flags |= node_type_t::NOTCHARSET;
	}
	void follow(Cases &cases) const override
	{
		if (!cases.otherwise)
			cases.otherwise = new NodeSet;
		for (Chars::const_iterator j = chars.begin(); j != chars.end(); j++) {
			NodeSet **x = &cases.cases[*j];
			if (!*x)
				*x = new NodeSet(*cases.otherwise);
		}
		/* Note: Add to the nonmatching characters after copying away
		 * the old otherwise state for the matching characters.
		 */
		cases.otherwise->insert(followpos.begin(), followpos.end());
		for (Cases::iterator i = cases.begin(); i != cases.end();
		     i++) {
			/* does not match oob transition chars */
			if (i->first.c >=0 && chars.find(i->first) == chars.end())
				i->second->insert(followpos.begin(),
						  followpos.end());
		}
	}
	int cmp(const Node *other) const override
	{
		int tmp = CNode::cmp(other);
		if (tmp != 0)
			return tmp;

		const NotCharSetNode *o = static_cast<const NotCharSetNode *>(other);
		if (chars.size() < o->chars.size())
			return -1;
		else if (chars.size() > o->chars.size())
			return 1;

		for (Chars::const_iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end(); i++, j++) {
			tmp = i->c - j->c;
			if (tmp != 0)
				return tmp;
		}
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		os << "[^";
		for (Chars::const_iterator i = chars.begin(); i != chars.end(); i++)
			os << *i;
		return os << ']';
	}

	int min_match_len() const override
	{
		/* Inverse match does not match any oob char at this time
		 * so only count characters
		 */
		return 1;
	}

	bool contains_oob() const override
	{
		for (Chars::const_iterator i = chars.begin(); i != chars.end(); i++) {
			if (*i < 0) {
				return false;
			}
		}
		return true;
	}

	Chars chars;
};

/* Match any character (/./). */
class AnyCharNode: public CNode {
public:
	AnyCharNode() { type_flags |= node_type_t::ANYCHAR; }
	void follow(Cases &cases) const override
	{
		if (!cases.otherwise)
			cases.otherwise = new NodeSet;
		cases.otherwise->insert(followpos.begin(), followpos.end());
		for (Cases::iterator i = cases.begin(); i != cases.end();
		     i++)
			/* does not match oob transition chars */
			if (i->first.c >= 0)
				i->second->insert(followpos.begin(), followpos.end());
	}
	ostream &dump(ostream &os) const override { return os << "."; }
};

/* Match a node zero or more times. (This is a unary operator.) */
class StarNode: public OneChildNode {
public:
	StarNode(Node *left): OneChildNode(left)
	{
		type_flags |= node_type_t::STAR;
	}
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		NodeSet first, last;

		(void) child[0]->compute_pos(first, last);

		for (NodeSet::iterator i = last.begin(); i != last.end(); i++) {
			(*i)->followpos.insert(first.begin(), first.end());
		}

		merge_into(firstpos, first);
		merge_into(lastpos, last);

		return true;	/* nullable */
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		child[0]->dump(os);
		return os << ")*";
	}
};

/* Match a node zero or one times. */
class OptionalNode: public OneChildNode {
public:
	OptionalNode(Node *left): OneChildNode(left)
	{
		type_flags |= node_type_t::OPTIONAL;
	}
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		(void) child[0]->compute_pos(firstpos, lastpos);

		return true;	/* nullable */
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		child[0]->dump(os);
		return os << ")?";
	}
	/* OptionalNode has never reported oob from its child, keep that
	 * so min_match_len() is unchanged by the move to OneChildNode.
	 * TODO: decide whether this should report child[0]->contains_oob()
	 */
	bool contains_oob() const override { return false; }
};

/* Match a node one or more times. (This is a unary operator.) */
class PlusNode: public OneChildNode {
public:
	PlusNode(Node *left): OneChildNode(left)
	{
		type_flags |= node_type_t::PLUS;
	}
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		NodeSet first, last;

		bool nullable = child[0]->compute_pos(first, last);

		for (NodeSet::iterator i = last.begin(); i != last.end(); i++) {
			(*i)->followpos.insert(first.begin(), first.end());
		}

		merge_into(firstpos, first);
		merge_into(lastpos, last);

		return nullable;
	}
	ostream &dump(ostream &os) const override {
		os << '(';
		child[0]->dump(os);
		return os << ")+";
	}
	int min_match_len() const override { return child[0]->min_match_len(); }
};

/*
 * A subtree that is referenced from multiple places in the expr tree.
 * The important nodes in the subtree are shared, so the dfa build only
 * has one set of positions for them. This is only valid where the
 * subtree has the same context everywhere it is referenced, eg. as a
 * common tail (right factor) appended to every rule, otherwise the
 * contexts are merged.
 *
 * The node is reference counted, get() takes a reference and release()
 * drops one. The subtree is owned by the node, and released with it.
 *
 * Tree simplification treats the node as opaque. It doesn't descend into
 * the subtree or factor across it, and the node is only equal to itself.
 *
 * depth_first_traversal visits the subtree once per reference, so
 * flip_tree() must not be used on a tree containing a SharedTreeNode.
 */
class SharedTreeNode: public OneChildNode {
public:
	SharedTreeNode(Node *tree): OneChildNode(tree), refcount(1)
	{
		type_flags |= node_type_t::SHAREDTREE;
	}
	SharedTreeNode *get(void)
	{
		refcount++;
		return this;
	}
	void release(void) override
	{
		if (--refcount == 0)
			delete this;
	}
	/* computed for every reference, followpos within the subtree is
	 * the same each time as the context is the same
	 * TODO: cache firstpos/lastpos so the subtree is only walked once
	 */
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		return child[0]->compute_pos(firstpos, lastpos);
	}
	/* only equal to itself */
	int cmp(const Node *other) const override
	{
		int tmp = Node::cmp(other);
		if (tmp != 0)
			return tmp;

		if (this < other)
			return -1;
		else if (this > other)
			return 1;
		return 0;
	}
	void normalize(int dir __attribute__((unused))) override { }
	ostream &dump(ostream &os) const override
	{
		return child[0]->dump(os);
	}
	int min_match_len() const override { return child[0]->min_match_len(); }

	unsigned int refcount;
};

/* Match a pair of consecutive nodes. */
class CatNode: public NChildNode {
public:
	CatNode(Node *left, Node *right): NChildNode(left, right)
	{
		type_flags |= node_type_t::CAT;
	}
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		/* being careful about the construction we can reduce the
		 * number of sets being built in computing_pos.
		 * The set of cat nodes is treated as left normalized for
		 * purpose of pos computation
		 *
		 *                   .
		 *                  / \
		 *                 .   f[4]
		 *                / \
		 *               .   e[3]
		 *              / \
		 *             /   \
		 *            /     \
		 *           /       \
		 *          .         |[2]
		 *         / \       / \
		 *     [0]*   *[1]  c   d
		 *        |   |
		 *        a   b
		 * The computed firstpos, lastpos from the previous iteration
		 * are the left, firstpos/lastpos of the next iteration
		 */

		NodeSet left_lastpos;

		std::vector<Node *>::iterator it = child.begin();
		bool nullable = (*it)->compute_pos(firstpos, left_lastpos);

		for (it++; it != child.end(); it++) {
			NodeSet right_firstpos, right_lastpos;

			bool rnullable = (*it)->compute_pos(right_firstpos,
							    right_lastpos);

			for (NodeSet::iterator i = left_lastpos.begin();
			     i != left_lastpos.end(); i++) {
				(*i)->followpos.insert(right_firstpos.begin(),
						       right_firstpos.end());
			}

			/* children so far are all nullable */
			if (nullable)
				merge_into(firstpos, right_firstpos);

			/* left_lastpos becomes lastpos of children so far */
			if (rnullable)
				merge_into(right_lastpos, left_lastpos);
			left_lastpos.swap(right_lastpos);

			nullable = nullable && rnullable;
		}
		merge_into(lastpos, left_lastpos);

		return nullable;
	}
	ostream &dump(ostream &os) const override
	{
		std::vector<Node *>::const_iterator it;
		for (it = child.begin(); it != child.end(); it++) {
			(*it)->dump(os);
		}
		return os;
	}
	void normalize(int dir) override;
	int min_match_len() const override
	{
		int len = 0;
		std::vector<Node *>::const_iterator it;
		for (it = child.begin(); it != child.end(); it++) {
			len += (*it)->min_match_len();
			if ((*it)->contains_oob()) {
				// oob characters are used to indicate when
				// the DFA transitions from matching the path
				// to matching the xattrs. If the left child
				// contains an oob character, the nodes to
				// the right don't contribute to the path match.
				return len;
			}
		}
		return len;
	}
};

/* Match one of two alternative nodes. */
class AltNode: public NChildNode {
public:
	AltNode(Node *left, Node *right): NChildNode(left, right)
	{
		type_flags |= node_type_t::ALT;
	}
	bool compute_pos(NodeSet &firstpos, NodeSet &lastpos) override
	{
		/* all children must be computed, so don't short circuit */
		bool nullable = false;
		std::vector<Node *>::iterator it;
		for (it = child.begin(); it != child.end(); it++)
			nullable |= (*it)->compute_pos(firstpos, lastpos);

		return nullable;
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		std::vector<Node *>::const_iterator it;
		for (it = child.begin(); it != child.end(); it++) {
			if (it != child.begin())
				os << '|';
			(*it)->dump(os);
		}
		os << ')';
		return os;
	}
	void normalize(int dir) override;
	int min_match_len() const override
	{
		int m = child[0]->min_match_len();
		std::vector<Node *>::const_iterator it;
		for (it = ++child.begin(); it != child.end(); it++) {
			int n = (*it)->min_match_len();
			if (n < m)
				m = n;
		}
		return m;
	}
};

class SharedNode: public ImportantNode {
public:
	SharedNode()
	{
		type_flags |= node_type_t::SHARED;
	}
	void release(void) override
	{
		/* don't delete SharedNodes via release as they are shared, and
		 * will be deleted when the table they are stored in is deleted
		 */
	}

	void follow(Cases &cases __attribute__ ((unused))) const override
	{
		/* Nothing to follow. */
	}

	/* requires shared nodes to be common by pointer */
	int eq(const Node *other) const override { return (this == other); }
	/* must be consistent with eq(), only the same node compares equal */
	int cmp(const Node *other) const override
	{
		int tmp = ImportantNode::cmp(other);
		if (tmp != 0)
			return tmp;

		if (this < other)
			return -1;
		else if (this > other)
			return 1;
		return 0;
	}
};

/**
 * Indicate that a regular expression matches. An AcceptNode itself
 * doesn't match anything, so it will never generate any transitions.
 */
class AcceptNode: public SharedNode {
public:
	AcceptNode() { type_flags |= node_type_t::ACCEPT; }
	int is_accept(void) const override { return true; }
};

class MatchFlag: public AcceptNode {
public:
	MatchFlag(int priority, perm32_t perms, perm32_t audit): priority(priority), perms(perms), audit(audit)
	{
		type_flags |= node_type_t::MATCHFLAG;
	}
	
	ostream &dump(ostream &os) const override { return os << "< 0x" << std::hex << perms << std::dec << '>'; }

	/* order by content so sorting is stable across runs, fall back
	 * to SharedNode::cmp so only the same node compares equal
	 */
	int cmp(const Node *other) const override
	{
		int tmp = Node::cmp(other);
		if (tmp != 0)
			return tmp;

		const MatchFlag *o = static_cast<const MatchFlag *>(other);
		if (priority != o->priority)
			return priority < o->priority ? -1 : 1;
		if (perms != o->perms)
			return perms < o->perms ? -1 : 1;
		if (audit != o->audit)
			return audit < o->audit ? -1 : 1;
		return SharedNode::cmp(other);
	}

	int priority;
	perm32_t perms;
	perm32_t audit;
};

class ExactMatchFlag: public MatchFlag {
public:
	ExactMatchFlag(int priority, perm32_t perms, perm32_t audit): MatchFlag(priority, perms, audit)
	{
		type_flags |= node_type_t::EXACTMATCHFLAG;
	}
};

class DenyMatchFlag: public MatchFlag {
public:
	DenyMatchFlag(int priority, perm32_t perms, perm32_t quiet): MatchFlag(priority, perms, quiet)
	{
		type_flags |= node_type_t::DENYMATCHFLAG;
	}
};

class PromptMatchFlag: public MatchFlag {
public:
	PromptMatchFlag(int priority, perm32_t prompt, perm32_t audit): MatchFlag(priority, prompt, audit)
	{
		type_flags |= node_type_t::PROMPTMATCHFLAG;
	}
};


/* Traverse the syntax tree depth-first in an iterator-like manner. */
/*
 * Post order depth first traversal of the expression tree.
 *
 * Iterative so deep trees don't use the C stack, and only tracks the
 * path from the root to the current node, so memory use is O(depth)
 * of the tree, regardless of how many children a node has.
 *
 * A node is visited after all of its children. The visited node's
 * children may be modified (eg. reordered by flip_tree()), but the
 * number of children must not change while the node is visited.
 */
template<class node_type>
class basic_depth_first_traversal {
	struct frame {
		node_type *node;
		size_t next;	/* index of next child to visit */
		frame(node_type *node): node(node), next(0) { }
	};
	std::vector<frame> pos;

	/* descend until the node on top of the stack has no unvisited
	 * children. Leaf nodes and OneChildNodes have NULL entries in
	 * their child vector, which are skipped.
	 */
	void descend(void)
	{
		while (pos.back().node->is_type(node_type_t::INNER)) {
			frame &f = pos.back();
			node_type *c = NULL;

			while (!c && f.next < f.node->child.size())
				c = f.node->child[f.next++];
			if (!c)
				return;
			/* invalidates f */
			pos.push_back(frame(c));
		}
	}
public:
	basic_depth_first_traversal(node_type *node)
	{
		pos.push_back(frame(node));
		descend();
	}
	node_type *operator*() { return pos.back().node; }
	node_type *operator->() { return pos.back().node; }
	operator bool() { return !pos.empty(); }
	void operator++(int)
	{
		pos.pop_back();
		if (!pos.empty())
			descend();
	}
};

typedef basic_depth_first_traversal<Node> depth_first_traversal;
typedef basic_depth_first_traversal<const Node> const_depth_first_traversal;

struct node_counts {
	int charnode;
	int charset;
	int notcharset;
	int alt;
	int plus;
	int star;
	int optional;
	int any;
	int cat;
};

extern EpsNode epsnode;

int debug_tree(Node *t);
Node *simplify_tree(Node *t, optflags const &opts);
void label_nodes(Node *root);
unsigned long hash_NodeSet(NodeSet *ns);
void flip_tree(Node *node);


class NodeVec {
public:
	typedef ImportantNode ** iterator;
	iterator begin() { return nodes; }
	iterator end() { iterator t = nodes ? &nodes[len] : NULL; return t; }

	unsigned long hash;
	unsigned long len;
	ImportantNode **nodes;

	NodeVec(NodeSet *n)
	{
		hash = hash_NodeSet(n);
		len = n->size();
		nodes = new ImportantNode *[n->size()];

		unsigned int j = 0;
		for (NodeSet::iterator i = n->begin(); i != n->end(); i++, j++) {
			nodes[j] = *i;
		}
	}

	NodeVec(NodeSet *n, unsigned long h): hash(h)
	{
		len = n->size();
		nodes = new ImportantNode *[n->size()];
		ImportantNode **j = nodes;
		for (NodeSet::iterator i = n->begin(); i != n->end(); i++) {
			*(j++) = *i;
		}
	}

	~NodeVec()
	{
		delete [] nodes;
	}

	unsigned long size()const { return len; }

	bool operator<(NodeVec const &rhs)const
	{
		if (hash == rhs.hash) {
			if (len == rhs.size()) {
				for (unsigned int i = 0; i < len; i++) {
					if (nodes[i] != rhs.nodes[i])
						return nodes[i] < rhs.nodes[i];
				}
				return false;
			}
			return len < rhs.size();
		}
		return hash < rhs.hash;
	}
};

class CacheStats {
public:
	virtual ~CacheStats() {}
	unsigned long dup, sum, max;

	CacheStats(void): dup(0), sum(0), max(0) { };

	void clear(void) { dup = sum = max = 0; }
	virtual unsigned long size(void) const = 0;
};

struct deref_less_than {
       bool operator()(NodeVec * const &lhs, NodeVec * const &rhs)const
		{
			return *lhs < *rhs;
		}
};

class NodeVecCache: public CacheStats {
public:
	std::set<NodeVec *, deref_less_than> cache;

	NodeVecCache(void): cache() { };
	~NodeVecCache() override { clear(); };

	unsigned long size(void) const override { return cache.size(); }

	void clear()
	{
		for (std::set<NodeVec *>::iterator i = cache.begin();
		     i != cache.end(); i++) {
			delete *i;
		}
		cache.clear();
		CacheStats::clear();
	}

	NodeVec *insert(NodeSet *nodes)
	{
		if (!nodes)
			return NULL;
		std::pair<std::set<NodeVec *>::iterator,bool> uniq;
		NodeVec *nv = new NodeVec(nodes);
		uniq = cache.insert(nv);
		if (uniq.second == false) {
			delete nv;
			dup++;
		} else {
			sum += nodes->size();
			if (nodes->size() > max)
				max = nodes->size();
		}
		delete(nodes);
		return (*uniq.first);
	}
};

#endif /* __LIBAA_RE_EXPR */
