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

#ifndef __AA_NETWORK_H
#define __AA_NETWORK_H

#include <fcntl.h>
#include <netinet/in.h>
#include <linux/socket.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "parser.h"
#include "rule.h"


#define AA_NET_WRITE		0x0002
#define AA_NET_SEND		AA_NET_WRITE
#define AA_NET_READ		0x0004
#define AA_NET_RECEIVE		AA_NET_READ

#define AA_NET_CREATE		0x0010
#define AA_NET_SHUTDOWN		0x0020		/* alias delete */
#define AA_NET_CONNECT		0x0040		/* alias open */

#define AA_NET_SETATTR		0x0100
#define AA_NET_GETATTR		0x0200

//#define AA_NET_CHMOD		0x1000		/* pair */
//#define AA_NET_CHOWN		0x2000		/* pair */
//#define AA_NET_CHGRP		0x4000		/* pair */
//#define AA_NET_LOCK		0x8000		/* LINK_SUBSET overlaid */

#define AA_NET_ACCEPT		0x00100000
#define AA_NET_BIND		0x00200000
#define AA_NET_LISTEN		0x00400000

#define AA_NET_SETOPT		0x01000000
#define AA_NET_GETOPT		0x02000000

#define AA_CONT_MATCH		0x08000000
#define AA_SET_LABEL		0x80000000

#define AA_VALID_NET_PERMS (AA_NET_SEND | AA_NET_RECEIVE | AA_NET_CREATE | \
			    AA_NET_SHUTDOWN | AA_NET_CONNECT | \
			    AA_NET_SETATTR | AA_NET_GETATTR | AA_NET_BIND | \
			    AA_NET_ACCEPT | AA_NET_LISTEN | AA_NET_SETOPT | \
			    AA_NET_GETOPT | AA_SET_LABEL | AA_CONT_MATCH)
#define AA_LOCAL_NET_PERMS (AA_NET_CREATE | AA_NET_SHUTDOWN | AA_NET_SETATTR |\
			    AA_NET_GETATTR | AA_NET_BIND | AA_NET_ACCEPT |    \
			    AA_NET_LISTEN | AA_NET_SETOPT | AA_NET_GETOPT)
#define AA_NET_OPT	(AA_NET_SETOPT | AA_NET_GETOPT)
#define AA_LOCAL_NET_CMD (AA_NET_LISTEN | AA_NET_OPT)
#define AA_PEER_NET_PERMS (AA_VALID_NET_PERMS & (~AA_LOCAL_NET_PERMS | \
						 AA_NET_ACCEPT))

#define CMD_ADDR	1
#define CMD_LISTEN	2
#define CMD_OPT		4

#define NONE_SIZE	0
#define IPV4_SIZE	1
#define IPV6_SIZE	2

enum class port_type_t {
	UNSPECIFIED,
	PRIVILEGED,
	UNPRIVILEGED,
	// TDOD allow both??
	REMOTE,		/* internal only */
};

extern void write_net_ip_size(std::ostringstream &o, int size);

struct network_tuple {
	const char *family_name;
	unsigned int family;
	const char *type_name;
	unsigned int type;
	const char *protocol_name;
	unsigned int protocol;
};

struct aa_network_entry {
	long unsigned int family;
	unsigned int type;
	unsigned int protocol;
};

static inline uint32_t map_perms(uint32_t mask)
{
	return (mask & 0x7f) |
		((mask & (AA_NET_GETATTR | AA_NET_SETATTR)) << (AA_OTHER_SHIFT - 8)) |
		((mask & (AA_NET_ACCEPT | AA_NET_BIND | AA_NET_LISTEN)) >> 4) | /* 2 + (AA_OTHER_SHIFT - 20) */
		((mask & (AA_NET_SETOPT | AA_NET_GETOPT)) >> 5); /* 5 + (AA_OTHER_SHIFT - 24) */
};


size_t get_af_max();
int parse_net_perms(const char *str_mode, perm32_t *perms, int fail);
int net_find_type_val(const char *type);
const char *net_find_type_name(int type);
const char *net_find_af_name(unsigned int af);

struct ip_address {
	union {
		uint8_t address_v6[16];
		uint32_t address_v4;
	} address;
	uint16_t family;
};

class ip_conds {
public:
	char *sip = NULL;
	char *sport = NULL;
	char *iface = NULL;
	char *label_match = NULL;

	bool set_label = false; /* unused while label_match is ununsed */
	bool is_ip = false;
	bool is_port = false;

	uint16_t from_port = 0;
	uint16_t to_port = 0;
	port_type_t port_type = port_type_t::UNSPECIFIED;

	struct ip_address ip;

	bool is_none = false;

	void free_conds() {
		if (sip) {
			free(sip);
			sip = NULL;
		}
		if (sport) {
			free(sport);
			sport = NULL;
		}
		if (iface)
			free(iface);
	}
};

class network_rule: public dedup_perms_rule_t {
	void move_conditionals(struct cond_entry *conds, ip_conds &ip_cond);
public:
	std::unordered_map<unsigned int, std::vector<struct aa_network_entry>> network_map;
	std::unordered_map<unsigned int, std::pair<unsigned int, unsigned int>> network_perms;

	ip_conds peer;
	ip_conds local;
	bool has_local_conds(void) { return local.sip || local.sport || local.iface || local.label_match; }
	bool has_peer_conds(void) { return peer.sip || peer.sport; }
	/* empty constructor used only for the profile to access
	 * static elements to maintain compatibility with
	 * AA_CLASS_NET */
	network_rule(): dedup_perms_rule_t(AA_CLASS_NETV8) { }
	network_rule(perm32_t perms_p, struct cond_entry *conds,
		     struct cond_entry *peer_conds);
	network_rule(perm32_t perms_p, const char *family, const char *type,
		     const char *protocol, struct cond_entry *conds,
		     struct cond_entry *peer_conds);
	network_rule(perm32_t perms_p, unsigned int family, unsigned int type);
	~network_rule() override
	{
		peer.iface = NULL; /* stores the same pointer as local */
		peer.free_conds();
		local.free_conds();
		if (allow) {
			free(allow);
			allow = NULL;
		}
		if (audit) {
			free(audit);
			audit = NULL;
		}
		if (deny) {
			free(deny);
			deny = NULL;
		}
		if (quiet) {
			free(quiet);
			quiet = NULL;
		}
	};

	bool gen_ip_conds(Profile &prof, std::list<std::ostringstream> &streams, ip_conds &entry, bool is_peer, bool is_cmd, bool is_iface);
	bool gen_net_rule(Profile &prof, unsigned int netclass, u16 family, unsigned int type_mask, unsigned int protocol, bool skb);
	void set_netperm(unsigned int family, unsigned int type, unsigned int protocol);
	void update_compat_net(void);
	bool parse_address(ip_conds &entry);
	bool parse_port(ip_conds &entry);
	bool parse_iface(ip_conds &entry);

	// update TODO: in equality.sh when priority is a valid prefix
	bool valid_prefix(const prefixes &p, const char *&error) override {
		if (p.priority != 0) {
			error = _("priority prefix not allowed on network rules");
			return false;
		}
		if (p.owner) {
			error = _("owner prefix not allowed on network rules");
			return false;
		}
		return true;
	};

	bool add_prefix(const prefixes &p, const char *&error) override {
		bool rc = dedup_perms_rule_t::add_prefix(p, error);
		/* update compat net needs to run after adding the prefix */
		update_compat_net();
		return rc;
	}

	ostream &dump(ostream &os) override;
	int expand_variables(void) override;
	int gen_policy_re(Profile &prof) override;

	bool is_mergeable(void) override { return true; }
	int cmp(rule_t const &rhs) const override;

	/* array of type masks indexed by AF_FAMILY */
	/* allow, audit, deny and quiet are used for compatibility with AA_CLASS_NET */
	static unsigned int *allow;
	static unsigned int *audit;
	static unsigned int *deny;
	static unsigned int *quiet;

	bool alloc_net_table(void);

protected:
	void warn_once(const char *name) override;
};

#endif /* __AA_NETWORK_H */
