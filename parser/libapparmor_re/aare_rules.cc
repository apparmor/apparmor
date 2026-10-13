/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2013 Canonical Ltd. (All rights reserved)
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
 * Wrapper around the dfa to convert aa rules into a dfa
 */

#include <iostream>
#include <sstream>

#include <stdlib.h>

#include "aare_rules.h"
#include "apparmor_re.h"
#include "expr-tree.h"
#include "parse.h"
#include "hfa.h"
#include "chfa.h"

using namespace std;

aare_rules::~aare_rules(void)
{
	if (root)
		root->release();

	/* a shared unique_perms cache is owned by the caller */
	local_perms.clear();
	expr_map.clear();
}

bool aare_rules::add_rule(const char *rule, int priority, rule_mode_t mode,
			  perm32_t perms, perm32_t audit, optflags const &opts)
{
	return add_rule_vec(priority, mode, perms, audit, 1, &rule, opts,
			    false);
}

void aare_rules::add_to_rules(Node *tree, Node *perms)
{
	if (reverse)
		flip_tree(tree);
	Node *base = expr_map[perms];
	if (base)
		expr_map[perms] = new AltNode(base, tree);
	else
		expr_map[perms] = tree;
}

static Node *cat_with_null_separator(Node *l, Node *r)
{
	return new CatNode(new CatNode(l, new CharNode(0)), r);
}

static Node *cat_with_oob_separator(Node *l, Node *r)
{
	return new CatNode(new CatNode(l, new CharNode(transchar(-1, true))), r);
}

bool aare_rules::add_rule_vec(int priority, rule_mode_t mode, perm32_t perms,
			      perm32_t audit, int count, const char **rulev,
			      optflags const &opts, bool oob)
{
	Node *tree = NULL, *accept;
	int exact_match;

	if (regex_parse(&tree, rulev[0]))
		return false;
	for (int i = 1; i < count; i++) {
		Node *subtree = NULL;
		if (regex_parse(&subtree, rulev[i]))
			goto err;
		if (oob)
			tree = cat_with_oob_separator(tree, subtree);
		else
			tree = cat_with_null_separator(tree, subtree);
	}

	/*
	 * Check if we have an expression with or without wildcards. This
	 * determines how exec modifiers are merged in accept_perms() based
	 * on how we split permission bitmasks here.
	 */
	exact_match = 1;
	for (depth_first_traversal i(tree); i && exact_match; i++) {
		if ((*i)->is_type(node_type_t::STAR) ||
		    (*i)->is_type(node_type_t::PLUS) ||
		    (*i)->is_type(node_type_t::ANYCHAR) ||
		    (*i)->is_type(node_type_t::NOTCHARSET))
			exact_match = 0;
	}

	if (reverse)
		flip_tree(tree);

	accept = unique_perms.insert(priority, mode, perms, audit, exact_match);

	if (opts.dump & DUMP_DFA_RULE_EXPR) {
		const char *separator;
		if (oob)
			separator = "\\-x01";
		else
			separator = "\\x00";
		cerr << "rule: ";
		cerr << rulev[0];
		for (int i = 1; i < count; i++) {
			cerr << separator;
			cerr << rulev[i];
		}
		cerr << "  ->  ";
		tree->dump(cerr);
		// TODO: split out from prefixes class
		cerr << " priority=" << priority;
		if (mode == rule_mode_t::DENY)
			cerr << " deny";
		else if (mode == rule_mode_t::PROMPT)
			cerr << " prompt";
		cerr << " (0x" << hex << perms <<"/" << audit << dec << ")";
		accept->dump(cerr);
 		cerr << "\n\n";
	}

	add_to_rules(tree, accept);

	rule_count++;

	return true;

err:
	delete tree;
	return false;
}

/*
 * Finish constructing the expr tree from the different permission set
 * trees, simplifying each. Each permission set's tree is followed by its
 * accept node, or if @tail is set by
 *     (accept | tail)
 * so a rule keeps its permissions at the point the tail is appended, and
 * the tail provides the permissions for matches that continue into it.
 * As the tail has the same context (nothing following it) everywhere it
 * is referenced it is a pure right factor, and can be shared.
 *
 * The trees in expr_map are consumed.
 * @min_match_len: set to the shortest match, not including the tail
 * Returns: the tree, or NULL if there are no rules
 */
Node *aare_rules::build_tree(optflags const &opts, SharedTreeNode *tail,
			     int *min_match_len)
{
	Node *tree = NULL;
	PermExprMap::iterator i;

	for (i = expr_map.begin(); i != expr_map.end(); i++) {
		Node *tmp = i->second;
		if (opts.control & CONTROL_DFA_TREE_SIMPLE)
			tmp = simplify_tree(tmp, opts);

		/* same as min_match_len() of the tree without the tail */
		int len = tmp->min_match_len();
		if (!tree || len < *min_match_len)
			*min_match_len = len;

		Node *end = i->first;
		if (tail)
			end = new AltNode(end, tail->get());
		Node *n = new CatNode(tmp, end);
		tree = tree ? new AltNode(tree, n) : n;
	}
	expr_map.clear();

	return tree;
}

/* create a chfa from the ruleset
 * returns: buffer contain dfa tables, @size set to the size of the tables
 *          else NULL on failure, @min_match_len set to the shortest string
 *          that can match the dfa for determining xmatch priority.
 */
CHFA *aare_rules::create_chfa(int *min_match_len,
			      vector <aa_perms> &perms_table,
			      optflags const &opts, bool filedfa,
			      int permstable32_version, aare_rules *tail,
			      bool tail_oob)
{
	bool extended_perms = permstable32_version >= 2;
	SharedTreeNode *shared = NULL;

	if (tail) {
		/* the tail's accept nodes must have the same lifetime as
		 * ours, and appending to a flipped tree doesn't work
		 */
		if (&tail->unique_perms != &unique_perms ||
		    reverse || tail->reverse)
			return NULL;

		int tail_len;
		Node *t = tail->build_tree(opts, NULL, &tail_len);
		if (t) {
			Node *sep;
			if (tail_oob)
				sep = new CharNode(transchar(-1, true));
			else
				sep = new CharNode(0);
			shared = new SharedTreeNode(new CatNode(sep, t));
		}
	}

	root = build_tree(opts, shared, min_match_len);
	/* drop the reference held while building, root holds the rest */
	if (shared)
		shared->release();
	if (!root)
		return NULL;

	/* dumping of the none simplified tree without -O no-expr-simplify
	 * is broken because we need to build the tree above first, and
	 * simplification is woven into the build. Reevaluate how to fix
	 * this debug dump.
	 */
	label_nodes(root);
	if (opts.dump & DUMP_DFA_TREE) {
		cerr << "\nDFA: Expression Tree\n";
		root->dump(cerr);
		cerr << "\n\n";
	}

	if (opts.control & CONTROL_DFA_TREE_SIMPLE) {
		/* This is old total tree, simplification point
		 * For now just do simplification up front. It gets most
		 * of the benefit running on the smaller chains, and is
		 * overall faster because there are less nodes. Reevaluate
		 * once tree simplification is rewritten
		 */
		//root = simplify_tree(root, opts);

		if (opts.dump & DUMP_DFA_SIMPLE_TREE) {
			cerr << "\nDFA: Simplified Expression Tree\n";
			root->dump(cerr);
			cerr << "\n\n";
		}
	}

	CHFA *chfa = NULL;
	try {
		DFA dfa(root, opts, filedfa);
		if (opts.dump & DUMP_DFA_UNIQ_PERMS)
			dfa.dump_uniq_perms("dfa");

		if (opts.dump & DUMP_DFA_STATES_INIT)
			dfa.dump(cerr, NULL);

		/* since we are building a chfa, use the info about
		 * whether the chfa supports extended perms to help
		 * determine whether we clear the deny info.
		 * This will let us build the minimal dfa for the
		 * information supported by the backed
		 */
		if (!extended_perms ||
		    ((opts.control & CONTROL_DFA_FILTER_DENY))) {
			dfa.apply_and_clear_deny();
			if (opts.dump & DUMP_DFA_STATES_POST_FILTER)
				dfa.dump(cerr, NULL);
		}
		if (opts.control & CONTROL_DFA_MINIMIZE) {
			dfa.minimize(opts);
			if (opts.dump & DUMP_DFA_MIN_UNIQ_PERMS)
				dfa.dump_uniq_perms("minimized dfa");
			if (opts.dump & DUMP_DFA_STATES_POST_MINIMIZE)
				dfa.dump(cerr, NULL);
		}

		if (opts.control & CONTROL_DFA_REMOVE_UNREACHABLE) {
			dfa.remove_unreachable(opts);
			if (opts.dump & DUMP_DFA_STATES_POST_UNREACHABLE)
				dfa.dump(cerr, NULL);
		}
		if (opts.dump & DUMP_DFA_STATES)
			dfa.dump(cerr, NULL);

		if (opts.dump & DUMP_DFA_GRAPH)
			dfa.dump_dot_graph(cerr);

		map<transchar, transchar> eq;
		if (opts.control & CONTROL_DFA_EQUIV) {
			eq = dfa.equivalence_classes(opts);
			dfa.apply_equivalence_classes(eq);

			if (opts.dump & DUMP_DFA_EQUIV) {
				cerr << "\nDFA equivalence class\n";
				dump_equivalence_classes(cerr, eq);
			}
		} else if (opts.dump & DUMP_DFA_EQUIV)
			cerr << "\nDFA did not generate an equivalence class\n";

		if (opts.control & CONTROL_DFA_DIFF_ENCODE) {
			dfa.diff_encode(opts);

			if (opts.dump & DUMP_DFA_DIFF_ENCODE)
				dfa.dump_diff_encode(cerr);
		}

		//cerr << "Checking extended perms " << extended_perms << "\n";
		if (extended_perms) {
			//cerr << "creating permstable\n";
			dfa.compute_perms_table(perms_table);
			// TODO: move perms table to a class
			if (opts.dump & DUMP_DFA_TRANS_TABLE && perms_table.size()) {
				cerr << "Perms Table size: " << perms_table.size() << "\n";
				perms_table[0].dump_header(cerr);
				for (size_t i = 0; i < perms_table.size(); i++) {
					perms_table[i].dump(cerr);
					cerr << "accept1: 0x";
					cerr << ", accept2: 0x";
					cerr << "\n";
				}
				cerr << "\n";
			}
		}
		chfa = new CHFA(dfa, eq, opts, permstable32_version);
		if (opts.dump & DUMP_DFA_TRANS_TABLE)
			chfa->dump(cerr);
		if (opts.dump & DUMP_DFA_COMPTRESSED_STATES)
			dfa.dump(cerr, &chfa->num);
	}
	catch(int error) {
		return NULL;
	}

	return chfa;
}

/* create a dfa from the ruleset
 * returns: buffer contain dfa tables, @size set to the size of the tables
 *          else NULL on failure, @min_match_len set to the shortest string
 *          that can match the dfa for determining xmatch priority.
 */
void *aare_rules::create_dfablob(size_t *size, int *min_match_len,
				 vector <aa_perms> &perms_table,
				 optflags const &opts, bool filedfa,
				 int permstable32_version, aare_rules *tail,
				 bool tail_oob)
{
	char *buffer = NULL;
	stringstream stream;

	try {
		CHFA *chfa = create_chfa(min_match_len, perms_table,
					 opts, filedfa,
					 permstable32_version, tail, tail_oob);
		if (!chfa) {
			*size = 0;
			return NULL;
		}
		chfa->flex_table(stream, opts);
		delete (chfa);
	}
	catch(int error) {
		*size = 0;
		return NULL;
	}

	stringbuf *buf = stream.rdbuf();

	buf->pubseekpos(0);
	*size = buf->in_avail();

	buffer = (char *)malloc(*size);
	if (!buffer)
		return NULL;
	buf->sgetn(buffer, *size);

	return buffer;
}
