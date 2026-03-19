/*
 *   Copyright (c) 2014
 *   Canonical, Ltd. (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>

#include <iomanip>
#include <string>
#include <sstream>

#include "common_optarg.h"
#include "network.h"
#include "parser.h"
#include "profile.h"
#include "af_unix.h"

using namespace std;

/* See unix(7) for autobind address definition */
#define autobind_address_pattern "\\x00[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]";

int parse_unix_perms(const char *str_perms, perm32_t *perms, int fail)
{
	return parse_X_perms("unix", AA_VALID_NET_PERMS, str_perms, perms, fail);
}


static struct supported_cond supported_conds[] = {
	{ "addr", true, false, false, cond_side::either_cond },
	{ NULL, false, false, false, cond_side::local_cond },	/* sentinel */
};

void unix_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *ent;

	list_for_each(conds, ent) {

		if (!cond_check(supported_conds, ent, false, "unix") &&
		    !move_base_cond(ent, false)) {
			yyerror("unix rule: invalid conditional '%s'\n",
				ent->name);
			continue;
		}
		if (strcmp(ent->name, "addr") == 0) {
			move_conditional_value("unix socket", &addr, ent);
			if (addr[0] != '@' &&
			    !(strcmp(addr, "none") == 0 ||
			      strcmp(addr, "auto") == 0))
				yyerror("unix rule: invalid value for addr='%s'\n", addr);
		}

		/* TODO: add conditionals for
		 *   listen queue length
		 *   attrs that can be read/set
		 *   ops that can be read/set
		 * allow in on
		 *   type, protocol
		 * local label match, and set
		 */
	}
}

void unix_rule::move_peer_conditionals(struct cond_entry *conds)
{
	struct cond_entry *ent;

	list_for_each(conds, ent) {
		if (!cond_check(supported_conds, ent, true, "unix") &&
		    !move_base_cond(ent, true)) {
			yyerror("unix rule: invalid peer conditional '%s'\n",
				ent->name);
			continue;
		}
		if (strcmp(ent->name, "addr") == 0) {
			move_conditional_value("unix", &peer_addr, ent);
			if ((peer_addr[0] != '@') &&
			    !(strcmp(peer_addr, "none") == 0 ||
			      strcmp(peer_addr, "auto") == 0))
				yyerror("unix rule: invalid value for addr='%s'\n", peer_addr);
		}
	}
}

unix_rule::unix_rule(unsigned int type_p, audit_t audit_p, rule_mode_t rule_mode_p):
	af_rule(AF_UNIX), addr(NULL), peer_addr(NULL)
{
	if (type_p != 0xffffffff) {
		sock_type_n = type_p;
		sock_type = strdup(net_find_type_name(type_p));
		if (!sock_type)
			yyerror("socket rule: invalid socket type '%d'", type_p);
	}
	perms = AA_VALID_NET_PERMS;
	audit = audit_p;
	rule_mode = rule_mode_p;
	/* if this constructor is used, then there's already a
	 * downgraded network_rule in profile */
	downgrade = false;
}

unix_rule::unix_rule(perm32_t perms_p, struct cond_entry *conds,
		     struct cond_entry *peer_conds):
	af_rule(AF_UNIX), addr(NULL), peer_addr(NULL)
{
	move_conditionals(conds);
	move_peer_conditionals(peer_conds);

	if (perms_p) {
		perms = perms_p;
		if (perms & ~AA_VALID_NET_PERMS)
			yyerror("perms contains invalid permissions for unix socket rules\n");
		else if ((perms & ~AA_PEER_NET_PERMS) && has_peer_conds())
			yyerror("unix socket 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals\n");
	} else {
		perms = AA_VALID_NET_PERMS;
	}

	free_cond_list(conds);
	free_cond_list(peer_conds);

}

ostream &unix_rule::dump_local(ostream &os)
{
	af_rule::dump_local(os);
	if (addr)
		os << " addr='" << addr << "'";
	return os;
}

ostream &unix_rule::dump_peer(ostream &os)
{
	af_rule::dump_peer(os);
	if (peer_addr)
		os << " addr='" << peer_addr << "'";
	return os;
}


int unix_rule::expand_variables(void)
{
	int error = af_rule::expand_variables();
	if (error)
		return error;
	error = expand_entry_variables(&addr);
	if (error)
		return error;
	filter_slashes(addr);
	error = expand_entry_variables(&peer_addr);
	if (error)
		return error;
	filter_slashes(peer_addr);

	return 0;
}


void unix_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "extended network unix socket rules not enforced");
}

static void writeu16(std::ostringstream &o, int v)
{
	u16 tmp = htobe16((u16) v);
	u8 *byte1 = (u8 *)&tmp;
	u8 *byte2 = byte1 + 1;

	o << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(*byte1);
	o << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(*byte2);
}

#define CMD_ADDR	1
#define CMD_LISTEN	2
#define CMD_ACCEPT	3
#define CMD_OPT		4

void unix_rule::downgrade_rule(Profile &prof) {
	perm32_t mask = (perm32_t) -1;

	if (!prof.net.allow && !prof.net.alloc_net_table())
		yyerror(_("Memory allocation error."));
	if (sock_type_n != -1)
		mask = 1 << sock_type_n;
	if (rule_mode != RULE_DENY) {
		prof.net.allow[AF_UNIX] |= mask;
		if (audit == audit_t::FORCE)
			prof.net.audit[AF_UNIX] |= mask;
		const char *error;
		network_rule *netv8 = new network_rule(perms, AF_UNIX, sock_type_n);
		if(!netv8->add_prefix({0, audit, rule_mode, owner}, error))
			yyerror(error);
		prof.rule_ents.push_back(netv8);
	} else {
		/* deny rules have to be dropped because the downgrade makes
		 * the rule less specific meaning it will make the profile more
		 * restrictive and may end up denying accesses that might be
		 * allowed by the profile.
		 */
		if (parseopts.warn & WARN_RULE_NOT_ENFORCED)
			rule_t::warn_once(prof.name, "deny unix socket rule not enforced, can't be downgraded to generic network rule\n");
	}
}

void unix_rule::write_to_prot(std::ostringstream &buffer)
{
	/* This is wrong. Unfortunately this will generate af_unix rules
	 * under v8 even if the kernel only support v8 socket mediation
	 * and v7 af_unix. Since this is already in the wild and generated
	 * by released parsers we are keeping the behavior.
	 * Unfortunately it means there needs to be an ABI break for the
	 * upstream kernel.
	 */
	int c = features_supports_networkv8 ? AA_CLASS_NETV8 : AA_CLASS_NET;

	/* use v9 if available */
	if (features_supports_networkv9)
		c = AA_CLASS_NETV9;
	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << c;
	writeu16(buffer, AF_UNIX);
	if (sock_type)
		writeu16(buffer, sock_type_n);
	else
		buffer << "..";
	if (proto)
		writeu16(buffer, proto_n);
	else
		buffer << "..";
}

bool unix_rule::write_addr(std::ostringstream &buffer, const char *addr)
{
	std::string buf;
	pattern_t ptype;

	if (addr) {
		int pos;
		if (strcmp(addr, "none") == 0) {
			/* anonymous */
			buffer << "\\x01";
		} else if (strcmp(addr, "auto") == 0) {
			/* autobind - special autobind rule written already
			 * just generate pattern that matches autobind
			 * generated addresses.
			 */
			buffer << autobind_address_pattern;
		} else {
			/* skip leading @ */
			ptype = convert_aaregex_to_pcre(addr + 1, 0, glob_null, buf, &pos);
			if (ptype == pattern_t::Invalid)
				return false;
			/* kernel starts abstract with \0 */
			buffer << "\\x00";
			buffer << buf;
		}
	} else
		/* match any addr or anonymous */
		buffer << ".*";

	/* todo: change to out of band separator */
	buffer << "\\x00";

	return true;
}

bool unix_rule::write_label(std::ostringstream &buffer, const char *label)
{
	std::string buf;
	pattern_t ptype;

	if (label) {
		int pos;
		ptype = convert_aaregex_to_pcre(label, 0, glob_default, buf, &pos);
		if (ptype == pattern_t::Invalid)
			return false;
		/* kernel starts abstract with \0 */
		buffer << buf;
	} else
		buffer << default_match_pattern;

	return true;
}

/* v7, v8, v9 Layout
 * v7 set the original layout - Ubuntu af_unix mediation
 * v8 followed v7 layout, and was original attempt to fix abi issue, it
 *    however was generated wrong by the parser, and released into the
 *    wild. Which means the upstream kernel could not support v8, and
 *    not cause ABI breakage in userspace.
 * v9 followed v8 has the same layout again, but fixes the issue that
 *    v8 has.
 *    Notes:
 *      1. v9 is intended to support extensions. This will require additional
 *         feature flags, and these will extend the layout.
 *      2. v9 while having the same layout is not entirely semantically
 *         compatible with the Ubuntu v7/v8 kernel implementation.
 *         - It uses dynamically updated socket labeling instead of
 *           statically the open time socket label
 *           This tightens the profile
 *         - it handles shutdown sockets differently. Only doing implied
 *           deleted fd delegation until, explicit delegation lands
 *           This loosens the profile slightly
 *         - it optionally has some changes around when/how an fs socket
 *           is referenced. This requires the kernel exporting a flag
 *           and the parser encoding fs sockets as part of af_unix
 *           mediation and not path.
 *           If the optional path flag is available and if path data is
 *           encoded in the profile, then v9 af_unix will be used to
 *           mediate unix file accesses, which is different than v7/v8
 *           semantics
 *           To allow a file rule
 *                file rw /var/snapd_socket,
 *           to allow fs unix sockets, it must encode 2 rules (1 for file
 *           and 1 for socket)
 *           The details around switching between policy enforcement
 *           style is documented else wher.
 *
 * Local socket end point perms
 * CLASS_NETv9
 * CLASS_NETv8
 * CLASS_NET   AF  TYPE PROTO  local (addr\0label) \0 cmd cmd_option
 *           ^   ^           ^        ^              ^              ^
 *           |   |           |        |              |              |
 *   stub perm   |           |        |              |              |
 *               |           |        |              |              |
 *   sub stub perm           |        |              |              |
 *                           |        |              |              |
 *                 create perm        |              |              |
 *                                    |              |              |
 *                  v9 optional fs path              |              |
 *                                                   |              |
 *                          bind, accept, get/set attr              |
 *                                                                  |
 *                                           listen, set/get opt perm
 *
 *
 * peer socket end point perms
 * CLASS_NETv9
 * CLASS_NETv8
 * CLASS_NET   AF  TYPE PROTO  local(addr\0label\0) cmd_addr peer(addr\0label)
 *           ^   ^           ^       ^             ^              ^           ^
 *           |   |           |       |             |              |           |
 *   stub perm   |           |       |             |              |           |
 *               |           |       |             |              |           |
 *   sub stub perm           |       |             |              |           |
 *                           |       |             |              |           |
 *                 create perm       |             |              |           |
 *                                   |             |              |           |
 *               v9 optionally fs path             |              |           |
 *                                                 |              |           |
 *                        bind, accept, get/set attr              |           |
 *                                                                |           |
 *                                            v9 optionally fs path           |
 *                                                                            |
 *                                             send/receive connect/accept perm
 *
 * NOTE: accept is encoded twice, locally to check if a socket is allowed
 *       to accept, and then as a pair to test that it can accept the pair.
 *
 * -------------------------------------------------------------------------
 *
 * v9 Semantics changes
 *
 * While v9 keeps the same base layout as v7/8 (except for the class
 * byte) for compatibility. There is a semanitc change due to v9
 * fixing two mediation bug present in v7/v8. This fix to mediation will
 * be applied to v7/v8 policy when it is run through a v9 compatible
 * kernel, either by the parser mapping v7/v8 into v9 OR by a kernel
 * with a compatibility patch.
 *
 * The change is in the syncing of the file permissions cache label
 * and the socket label. Under v9 the socket label is updated and kept
 * in sync with the file label cache. This prevents 2 different labels
 * being used during mediation. On a cache hit mediation would be
 * based off of the local file cache alone, resulting in no
 * revalidation if the peer updated (first bug).
 *
 *    eg. Say we have a subject with a label=subj, and a
 *        peer_label=peer1 The permission check for subj being able to
 *        communicate with peer1 is done, and allowed. The file cache
 *        is updated to use subj. So file_cache=subj Now the peer
 *        passes its end of the socket connection to a task labeled
 *        with peer2.
 *
 *        When subj sends a message over the socket, it could go to
 *        either peer1 or peer2, but the cache only sees that
 *        label=subj matches the cache and has not changed, when the
 *        cache check is done. The cache check short circuits the
 *        permissions check and the send is allowed, even if subj is
 *        not allowed to communicate with peer2.
 *
 * If the file cache check failed and revalidation was done, the peer
 * label obtained from the socked was always the initial labeling of
 * the peer.  This means that the peer match expression might allow
 * sending to security context that the subj did not have permissions
 * to access.  That is to say the peer check is done against a subset
 * of the actual peer. If the subset is equivalent, then the check is
 * good but if the subset is a proper subset (ie. contains fewer
 * elements) the peer label check is bad.
 *
 *    eg. Continuing the above example, when peer hands its end of the
 *        socket to peer2, the label is not updated. So communication
 *        checks are only done against peer1. Not peer1 and peer2 as
 *        should be done. This is effectively unintended/uncontrolled
 *        delegation and it could potentially lead to a confused
 *        deputy privilege escalation.
 *
 * The cross check when done used the socket peer label as a
 * proxy. However because the socket peer label was not correctly
 * updated, this resulted in only partial permission check instead of
 * a check against the full subj label set.
 *
 * This was often mitigated by the receiving task also doing a check
 * within its own subject cred context. ie. the sender has a
 * permission check done on the send, and then the receiver does a
 * permission check at receive.  Unfortunately this is not always the
 * case for every operation, that needs to consider the peer. Internal
 * (to the network stack) caching may mean that the receive permission
 * hook is not always called. And for some other operations the check
 * is only ever done on one side of the socket, not both.
 *
 *    eg. Continuing with the example the peer label is used as a proxy
 *        for the subject. In this case the proxy has to represent
 *        all possible subjects on the peer end, in this case that would
 *        be peer1 and peer2. Unfortunately only peer1 is checked.
 *
 * The socket now keeps 2 labels on each side, in addition to the
 * file cache label. The basic layout is
 *
 * File-------------> socket                    peer socket<------ peer File
 *    |                 |                           |           |
 *    v                 v                           v           v
 * subj_label cache     sk----------------------> peer_sk     peer
 *                      |                           |         subj_label cache
 *                      v                           v
 *                     ctx                       peer  ctx
 *                      |                           |
 *                   +--+--+                    +---+--+
 *                   |     |                    |      |
 *                   v     v                    v      v
 *                 label  peer                 peer   subj
 *                        proxy                label  proxy
 *
 * Under v7/v8
 *
 * - subj_label cache and peer subj_label cache
 *    - were consulted during rcu critical section so the permission check
 *      is only done if something has changed.
 *    - were updated by their respective owners when the file was used as
        a subject in a permission check.
 *
 * - ctx label, and peer ctx label were not correctly updated.
 * - peer proxy and subj proxy did not exist.
 *
 * under v9
 *
 * - subj_label cache and peer subj_label cache
 *    - were consulted during rcu critical section so the permission check
 *      is only done if something has changed (same as v7/8)
 *    - subj_label and peer subj_label cache are updated the same as under
 *      v7/v8
 * - peer proxy, and subj proxy
 *    - are consulted during the lockless rcu critical section cache check
 *      to see if there is a peer update thus allowing updates of sock
 *      based on peer changes to be done without the locking the peer
 *      mediation check does.
 *      Fixes bug of cache being out of sync with peer.
 *    - are updated by peer mediation permission check (needs peer lock)
 * - label and peer_label
 *   - updated by local (subj) permission check if changes are made.
 *   - consulted by peer=(label= mediation check. (needs peer lock).
 *     Fixes bug where peer label check doesn't use full label, and
 *     peer label used as proxy subject is wrong.
 *
 * There are cases where v9 semantics do require additional
 * permissions/rules in a profile, even if that profile declares a
 * v7/8 abi.
 *
 * It is also important to note that the above semantic issue does not
 * affect fs based unix sockets; only abstract and anonymous (socket
 * pairs). Unless the v9 fs in unix sockets extension is used. In that
 * case fs based sockets go through the af_unix socket mediation
 * checks, and paths can be used in place of the local and peer addr.
 * The same set of cache check and semantics will be applied to
 * profiles using this v9 extension.
 *
 * Note: that this extension is placed behind a separate features abi
 *       flag so that it is an opt-in change.
 */
rule_result_t unix_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer;
	std::string buf;

	perm32_t mask = perms;

	/* always generate a downgraded rule. This doesn't change generated
	 * policy size and allows the binary policy to be loaded against
	 * older kernels and be enforced to the best of the old network
	 * rules ability
	 */
	if (downgrade)
		downgrade_rule(prof);

	if (!(features_supports_unixv7 || features_supports_unixv9)) {
		if (features_supports_network || features_supports_networkv8 ||
		    features_supports_networkv9) {
			/* only warn if we are building against a kernel
			 * that requires downgrading */
			if (parseopts.warn & WARN_RULE_DOWNGRADED)
				rule_t::warn_once(prof.name, "downgrading extended network unix socket rule to generic network rule\n");
			/* TODO: add ability to abort instead of downgrade */
			return rule_result_t::OK;
		} else {
			warn_once(prof.name);
		}
		return rule_result_t::NOT_SUPPORTED;
	}

	write_to_prot(buffer);
	if ((mask & AA_NET_CREATE) && !has_peer_conds()) {
		buf = buffer.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
						 rule_mode,
						 map_perms(AA_NET_CREATE),
						 map_perms(audit == audit_t::FORCE ? AA_NET_CREATE : 0),
						 parseopts))
			goto fail;
		mask &= ~AA_NET_CREATE;
	}

	/* write special pattern for autobind? Will not grant bind
	 * on any specific address
	 */
	if ((mask & AA_NET_BIND) && (!addr || (strcmp(addr, "auto") == 0))) {
		std::ostringstream tmp;

		tmp << buffer.str();
		/* todo: change to out of band separator */
		/* skip addr, its 0 length */
		tmp << "\\x00";
		/* local label option */
		if (!write_label(tmp, label))
			goto fail;
		/* separator */
		tmp << "\\x00";

		buf = tmp.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
						 rule_mode,
						 map_perms(AA_NET_BIND),
						 map_perms(audit == audit_t::FORCE ? AA_NET_BIND : 0),
						 parseopts))
			goto fail;
		/* clear if auto, else generic need to generate addr below */
		if (addr)
			mask &= ~AA_NET_BIND;
	}

	if (mask) {
		/* local addr */
		if (!write_addr(buffer, addr))
			goto fail;
		/* local label option */
		if (!write_label(buffer, label))
			goto fail;
		/* separator */
		buffer << "\\x00";

		/* create already masked off */
		int local_mask = has_peer_conds() ? AA_NET_ACCEPT :
					AA_LOCAL_NET_PERMS & ~AA_LOCAL_NET_CMD;
		if (mask & local_mask) {
			buf = buffer.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), priority,
							 rule_mode,
							 map_perms(mask & local_mask),
							 map_perms(audit == audit_t::FORCE ? mask & local_mask : 0),
							 parseopts))
				goto fail;
		}

		if ((mask & AA_NET_LISTEN) && !has_peer_conds()) {
			std::ostringstream tmp(buffer.str());
			tmp.seekp(0, ios_base::end);
			tmp << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_LISTEN;
			/* TODO: backlog conditional: for now match anything*/
			tmp << "..";
			buf = tmp.str();
			if (!prof.policy.rules->add_rule(buf.c_str(),
							 priority,
							 rule_mode,
							 map_perms(AA_NET_LISTEN),
							 map_perms(audit == audit_t::FORCE ? AA_NET_LISTEN : 0),
							 parseopts))
				goto fail;
		}
		if ((mask & AA_NET_OPT) && !has_peer_conds()) {
			std::ostringstream tmp(buffer.str());
			tmp.seekp(0, ios_base::end);
			tmp << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_OPT;
			/* TODO: sockopt conditional: for now match anything */
			tmp << "..";
			buf = tmp.str();
			if (!prof.policy.rules->add_rule(buf.c_str(),
						priority,
						rule_mode,
						map_perms(mask & AA_NET_OPT),
						map_perms(audit == audit_t::FORCE ?
							  AA_NET_OPT : 0),
						parseopts))
				goto fail;
		}
		mask &= ~AA_LOCAL_NET_PERMS | AA_NET_ACCEPT;
	} /* if (mask) */

	if (mask & AA_PEER_NET_PERMS) {
		/* cmd selector */
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_ADDR;

		/* local addr */
		if (!write_addr(buffer, peer_addr))
			goto fail;
		/* local label option */
		if (!write_label(buffer, peer_label))
			goto fail;

		buf = buffer.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
				rule_mode, map_perms(perms & AA_PEER_NET_PERMS),
				map_perms(audit == audit_t::FORCE ? perms & AA_PEER_NET_PERMS : 0),
				parseopts))
			goto fail;
	}

	return rule_result_t::OK;

fail:
	return rule_result_t::ERROR;
}
