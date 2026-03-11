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

#include <map>
#include <set>
#include <stack>
#include <ostream>

#include <stdint.h>

#include "../perms.h"
#include "apparmor_re.h"

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
 * string match ([^\x00]*), and make an acceptance dission based
 * on both matches.
 *
 * One way to do this is to chain the two matches in a single state
 * machine. However without an out of band transition, the matche pattern
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
 * (-1..-32k). They llow for different transitions if needed (currently
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
class transchar {
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

class Chars {
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
	TWOCHILD = (1u << 2),
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
	CAT = (1u << 14),
	ALT = (1u << 15),
	SHARED = (1u << 16),
	ACCEPT = (1u << 17),
	MATCHFLAG = (1u << 18),
	EXACTMATCHFLAG = (1u << 19),
	DENYMATCHFLAG = (1u << 20),
	PROMPTMATCHFLAG = (1u << 21),
	NULLABLE = (1u << 31),
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
	Node(): type_flags(node_type_t::NODE), label(0)
	{
		child[0] = child[1] = 0;
	}
	Node(Node *left): type_flags(node_type_t::NODE), label(0)
	{
		child[0] = left;
		child[1] = 0;
	}
	Node(Node *left, Node *right): type_flags(node_type_t::NODE), label(0)
	{
		child[0] = left;
		child[1] = right;
	}
	virtual ~Node()
	{
		if (child[0])
			child[0]->release();
		if (child[1])
			child[1]->release();
	}

	/**
	 * firstpos, lastpos, and followpos are used to convert the syntax tree
	 * to a DFA.
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
	 */
	virtual void compute_nullable() { }
	virtual void compute_firstpos() = 0;
	virtual void compute_lastpos() = 0;
	virtual void compute_followpos() { }

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

	virtual int eq(const Node *other) const = 0;
	virtual ostream &dump(ostream &os) const = 0;
	void dump_syntax_tree(ostream &os);
	virtual void normalize(int dir)
	{
		if (child[dir])
			child[dir]->normalize(dir);
		if (child[!dir])
			child[!dir]->normalize(dir);
	}
	/* return false if no work done */
	virtual int normalize_eps(int dir __attribute__((unused))) { return 0; }

	NodeSet firstpos, lastpos, followpos;
	/* child 0 is left, child 1 is right */
	Node *child[2];
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
};

class TwoChildNode: public InnerNode {
public:
	TwoChildNode(Node *left, Node *right): InnerNode(left, right)
	{
		type_flags |= node_type_t::TWOCHILD;
	};
	int normalize_eps(int dir) override;
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
		type_flags |= (node_type_t::EPS | node_type_t::NULLABLE);
		label = 0;
	}
	void release(void) override
	{
		/* don't delete Eps nodes because there is a single static
		 * instance shared by all trees.  Look for epsnode in the code
		 */
	}

	void compute_firstpos() override { }
	void compute_lastpos() override { }
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::EPS))
			return 1;
		return 0;
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
	void compute_firstpos() override { firstpos.insert(this); }
	void compute_lastpos() override { lastpos.insert(this); }
	virtual void follow(Cases &cases) = 0;
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
	void follow(Cases &cases) override
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
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::CHAR)) {
			const CharNode *o = static_cast<const CharNode *>(other);
			return c == o->c;
		}
		return 0;
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
	void follow(Cases &cases) override
	{
		for (Chars::iterator i = chars.begin(); i != chars.end(); i++) {
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
	int eq(const Node *other) const override
	{
		if (!other->is_type(node_type_t::CHARSET))
			return 0;

		const CharSetNode *o = static_cast<const CharSetNode *>(other);
		if (chars.size() != o->chars.size())
			return 0;

		for (Chars::const_iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end(); i++, j++) {
			if (*i != *j)
				return 0;
		}
		return 1;
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
	void follow(Cases &cases) override
	{
		if (!cases.otherwise)
			cases.otherwise = new NodeSet;
		for (Chars::iterator j = chars.begin(); j != chars.end(); j++) {
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
	int eq(const Node *other) const override
	{
		if (!other->is_type(node_type_t::NOTCHARSET))
			return 0;

		const NotCharSetNode *o = static_cast<const NotCharSetNode *>(other);
		if (chars.size() != o->chars.size())
			return 0;

		for (Chars::const_iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end(); i++, j++) {
			if (*i != *j)
				return 0;
		}
		return 1;
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
	void follow(Cases &cases) override
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
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::ANYCHAR))
			return 1;
		return 0;
	}
	ostream &dump(ostream &os) const override { return os << "."; }
};

/* Match a node zero or more times. (This is a unary operator.) */
class StarNode: public OneChildNode {
public:
	StarNode(Node *left): OneChildNode(left)
	{
		type_flags |= (node_type_t::STAR | node_type_t::NULLABLE);
	}
	void compute_firstpos() override { firstpos = child[0]->firstpos; }
	void compute_lastpos() override { lastpos = child[0]->lastpos; }
	void compute_followpos() override
	{
		NodeSet from = child[0]->lastpos, to = child[0]->firstpos;
		for (NodeSet::iterator i = from.begin(); i != from.end(); i++) {
			(*i)->followpos.insert(to.begin(), to.end());
		}
	}
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::STAR))
			return child[0]->eq(other->child[0]);
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		child[0]->dump(os);
		return os << ")*";
	}

	bool contains_oob() const override { return child[0]->contains_oob(); }
};

/* Match a node zero or one times. */
class OptionalNode: public OneChildNode {
public:
	OptionalNode(Node *left): OneChildNode(left)
	{
		type_flags |= (node_type_t::OPTIONAL | node_type_t::NULLABLE);
	}
	void compute_firstpos() override { firstpos = child[0]->firstpos; }
	void compute_lastpos() override { lastpos = child[0]->lastpos; }
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::OPTIONAL))
			return child[0]->eq(other->child[0]);
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		child[0]->dump(os);
		return os << ")?";
	}
};

/* Match a node one or more times. (This is a unary operator.) */
class PlusNode: public OneChildNode {
public:
	PlusNode(Node *left): OneChildNode(left)
	{
		type_flags |= node_type_t::PLUS;
	}
	void compute_nullable() override {
		// The nullable bit is only ever set so no need for else branch
		if (has_type(child[0]->type_flags, node_type_t::NULLABLE)) {
			type_flags |= node_type_t::NULLABLE;
		}
	}
	void compute_firstpos() override { firstpos = child[0]->firstpos; }
	void compute_lastpos() override { lastpos = child[0]->lastpos; }
	void compute_followpos() override
	{
		NodeSet from = child[0]->lastpos, to = child[0]->firstpos;
		for (NodeSet::iterator i = from.begin(); i != from.end(); i++) {
			(*i)->followpos.insert(to.begin(), to.end());
		}
	}
	int eq(const Node *other) const override {
		if (other->is_type(node_type_t::PLUS))
			return child[0]->eq(other->child[0]);
		return 0;
	}
	ostream &dump(ostream &os) const override {
		os << '(';
		child[0]->dump(os);
		return os << ")+";
	}
	int min_match_len() const override { return child[0]->min_match_len(); }
	bool contains_oob() const override { return child[0]->contains_oob(); }
};

/* Match a pair of consecutive nodes. */
class CatNode: public TwoChildNode {
public:
	CatNode(Node *left, Node *right): TwoChildNode(left, right)
	{
		type_flags |= node_type_t::CAT;
	}
	void compute_nullable() override
	{
		/*
		 * To check that both childs are nullable, we can bitwise-AND
		 * both of the type_flags together and then check if the
		 * node_type_t::NULLABLE bit is set on the result.
		 *
		 * The nullable bit is only ever set so no need for else branch
		 */
		if (has_type(child[0]->type_flags & child[1]->type_flags,
			     node_type_t::NULLABLE)) {
			type_flags |= node_type_t::NULLABLE;
		}
	}
	void compute_firstpos() override
	{
		if (has_type(child[0]->type_flags, node_type_t::NULLABLE))
			firstpos = child[0]->firstpos + child[1]->firstpos;
		else
			firstpos = child[0]->firstpos;
	}
	void compute_lastpos() override
	{
		if (has_type(child[1]->type_flags, node_type_t::NULLABLE))
			lastpos = child[0]->lastpos + child[1]->lastpos;
		else
			lastpos = child[1]->lastpos;
	}
	void compute_followpos() override
	{
		NodeSet from = child[0]->lastpos, to = child[1]->firstpos;
		for (NodeSet::iterator i = from.begin(); i != from.end(); i++) {
			(*i)->followpos.insert(to.begin(), to.end());
		}
	}
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::CAT)) {
			if (!child[0]->eq(other->child[0]))
				return 0;
			return child[1]->eq(other->child[1]);
		}
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		child[0]->dump(os);
		child[1]->dump(os);
		return os;
	}
	void normalize(int dir) override;
	int min_match_len() const override
	{
		int len = child[0]->min_match_len();
		if (child[0]->contains_oob()) {
			// oob characters are used to indicate when the DFA transitions
			// from matching the path to matching the xattrs. If the left child
			// contains an oob character, the right side doesn't contribute to
			// the path match.
			return len;
		}
		return len + child[1]->min_match_len();
	}
	bool contains_oob() const override
	{
		return child[0]->contains_oob() || child[1]->contains_oob();
	}
};

/* Match one of two alternative nodes. */
class AltNode: public TwoChildNode {
public:
	AltNode(Node *left, Node *right): TwoChildNode(left, right)
	{
		type_flags |= node_type_t::ALT;
	}
	void compute_nullable() override
	{
		/*
		 * To check that either child is nullable, we can bitwise-OR
		 * both of the type_flags together and then check if the
		 * node_type_t::NULLABLE bit is set on the result.
		 *
		 * The nullable bit is only ever set so no need for else branch
		 */
		if (has_type(child[0]->type_flags | child[1]->type_flags,
			     node_type_t::NULLABLE)) {
			type_flags |= node_type_t::NULLABLE;
		}
	}
	void compute_lastpos() override
	{
		lastpos = child[0]->lastpos + child[1]->lastpos;
	}
	void compute_firstpos() override
	{
		firstpos = child[0]->firstpos + child[1]->firstpos;
	}
	int eq(const Node *other) const override
	{
		if (other->is_type(node_type_t::ALT)) {
			if (!child[0]->eq(other->child[0]))
				return 0;
			return child[1]->eq(other->child[1]);
		}
		return 0;
	}
	ostream &dump(ostream &os) const override
	{
		os << '(';
		child[0]->dump(os);
		os << '|';
		child[1]->dump(os);
		os << ')';
		return os;
	}
	void normalize(int dir) override;
	int min_match_len() const override
	{
		int m1, m2;
		m1 = child[0]->min_match_len();
		m2 = child[1]->min_match_len();
		if (m1 < m2) {
			return m1;
		}
		return m2;
	}
	bool contains_oob() const override
	{
		return child[0]->contains_oob() || child[1]->contains_oob();
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

	void follow(Cases &cases __attribute__ ((unused))) override
	{
		/* Nothing to follow. */
	}

	/* requires shared nodes to be common by pointer */
	int eq(const Node *other) const override { return (this == other); }
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
class depth_first_traversal {
	std::stack<Node *>pos;
	void push_left(Node *node) {
		pos.push(node);

		while (node->is_type(node_type_t::INNER)) {
			pos.push(node->child[0]);
			node = node->child[0];
		}
	}
public:
	depth_first_traversal(Node *node) { push_left(node); }
	Node *operator*() { return pos.top(); }
	Node *operator->() { return pos.top(); }
	operator  bool() { return !pos.empty(); }
	void operator++(int)
	{
		Node *last = pos.top();
		pos.pop();

		if (!pos.empty()) {
			/* no need to dynamic cast, as we just popped a node so
			 * the top node must be an inner node */
			InnerNode *node = (InnerNode *) (pos.top());
			if (node->child[1] && node->child[1] != last) {
				push_left(node->child[1]);
			}
		}
	}
};

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
