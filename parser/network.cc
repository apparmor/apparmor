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

#include <iomanip>
#include <string>
#include <sstream>
#include <map>
#include <arpa/inet.h>

#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "network.h"

#define ALL_TYPES 0x43e

int parse_net_perms(const char *str_mode, perm32_t *mode, int fail)
{
	return parse_X_perms("net", AA_VALID_NET_PERMS, str_mode, mode, fail);
}

/* Bleah C++ doesn't have non-trivial designated initializers so we just
 * have to make sure these are in order.  This means we are more brittle
 * but there isn't much we can do.
 */
struct sock_type_map {
	const char *name;
	int	value;
};

struct sock_type_map sock_types[] = {
	{ "none",	0 },
	{ "stream",	SOCK_STREAM },
	{ "dgram",	SOCK_DGRAM },
	{ "raw",	SOCK_RAW },
	{ "rdm",	SOCK_RDM },
	{ "seqpacket",	SOCK_SEQPACKET },
	{ "dccp",	SOCK_DCCP },
	{ "invalid",	-1 },
	{ "invalid",	-1 },
	{ "invalid",	-1 },
	{ "packet",	SOCK_PACKET },
	{ NULL, -1 },
	/*
	 * See comment above
	*/
};

int net_find_type_val(const char *type)
{
	int i;
	for (i = 0; sock_types[i].name; i++) {
		if (strcmp(sock_types[i].name, type) == 0)
			return sock_types[i].value;
	}

	return -1;
}

const char *net_find_type_name(int type)
{
	int i;
	for (i = 0; sock_types[i].name; i++) {
		if (sock_types[i].value  == type)
			return sock_types[i].name;
	}

	return NULL;
}


/* FIXME: currently just treating as a bit mask this will have to change
 * set up a table of mappings, there can be several mappings for a
 * given match.
 * currently the mapping does not set the protocol for stream/dgram to
 * anything other than 0.
 *   network inet tcp -> network inet stream 0 instead of
 *   network inet raw tcp.
 * some entries are just provided for completeness at this time
 */
/* values stolen from /etc/protocols - needs to change */
#define RAW_TCP 6
#define RAW_UDP 17
#define RAW_ICMP 1
#define RAW_ICMPv6 58

/* used by af_name.h to auto generate table entries for "name", AF_NAME
 * pair */
#define AA_GEN_NET_ENT(name, AF) \
	{name, AF, "stream",    SOCK_STREAM,    "", 0xffffff}, \
	{name, AF, "dgram",     SOCK_DGRAM,     "", 0xffffff}, \
	{name, AF, "seqpacket", SOCK_SEQPACKET, "", 0xffffff}, \
	{name, AF, "rdm",       SOCK_RDM,       "", 0xffffff}, \
	{name, AF, "raw",       SOCK_RAW,       "", 0xffffff}, \
	{name, AF, "packet",    SOCK_PACKET,    "", 0xffffff},
/*FIXME: missing {name, AF, "dccp", SOCK_DCCP, "", 0xfffffff}, */

static struct network_tuple network_mappings[] = {
	/* basic types */
	#include "af_names.h"
/* FIXME: af_names.h is missing AF_LLC, AF_TIPC */
	/* mapped types */
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "tcp",		1 << RAW_TCP},
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "udp",		1 << RAW_UDP},
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "icmp",	1 << RAW_ICMP},
	{"inet",	AF_INET,	"tcp",		SOCK_STREAM,
	 "",		0xffffffff},	/* should we give raw tcp too? */
	{"inet",	AF_INET,	"udp",		SOCK_DGRAM,
	 "",		0xffffffff},	/* should these be open masks? */
	{"inet",	AF_INET,	"icmp",		SOCK_RAW,
	 "",		1 << RAW_ICMP},
	{"inet6",	AF_INET6,	"tcp",		SOCK_STREAM,
	 "",		0xffffffff},
	{"inet6",	AF_INET6,	"udp",		SOCK_DGRAM,
	 "",		0xffffffff},
/* what do we do with icmp on inet6?
	{"inet6",	AF_INET,	"icmp",		SOCK_RAW,	0},
	{"inet6",	AF_INET,	"icmpv6",	SOCK_RAW,	0},
*/
	/* terminate */
	{NULL, 0, NULL, 0, NULL, 0}
};

/* The apparmor kernel patches up until 2.6.38 didn't handle networking
 * tables with sizes > AF_MAX correctly.  This could happen when the
 * parser was built against newer kernel headers and then used to load
 * policy on an older kernel.  This could happen during upgrades or
 * in multi-kernel boot systems.
 *
 * Try to detect the running kernel version and use that to determine
 * AF_MAX
 */
#define PROC_VERSION "/proc/sys/kernel/osrelease"
static size_t kernel_af_max(void) {
	char buffer[32];
	int major;
	autoclose int fd = -1;
	int res;

	if (!net_af_max_override) {
		return 0;
	}
	/* the override parameter is specifying the max value */
	if (net_af_max_override > 0)
		return net_af_max_override;

	fd = open(PROC_VERSION, O_RDONLY);
	if (fd == -1)
		/* fall back to default provided during build */
		return 0;
	res = read(fd, &buffer, sizeof(buffer) - 1);
	if (res <= 0)
		return 0;
	buffer[res] = '\0';
	res = sscanf(buffer, "2.6.%d", &major);
	if (res != 1)
		return 0;

	switch(major) {
	case 24:
	case 25:
	case 26:
		return 34;
	case 27:
		return 35;
	case 28:
	case 29:
	case 30:
		return 36;
	case 31:
	case 32:
	case 33:
	case 34:
	case 35:
		return 37;
	case 36:
	case 37:
		return 38;
	/* kernels .38 and later should handle this correctly so no
	 * static mapping needed
	 */
	default:
		return 0;
	}
}

/* Yuck. We grab AF_* values to define above from linux/socket.h because
 * they are more accurate than sys/socket.h for what the kernel actually
 * supports. However, we can't just include linux/socket.h directly,
 * because the AF_* definitions are protected with an ifdef KERNEL
 * wrapper, but we don't want to define that because that can cause
 * other redefinitions from glibc. However, because the kernel may have
 * more definitions than glibc, we need make sure AF_MAX reflects this,
 * hence the wrapping function.
 */
size_t get_af_max() {
	size_t af_max;
	/* HACK: declare that version without "create" had a static AF_MAX */
	if (!perms_create && !net_af_max_override)
		net_af_max_override = -1;

#if AA_AF_MAX > AF_MAX
	af_max = AA_AF_MAX;
#else
	af_max = AF_MAX;
#endif

	/* HACK: some kernels didn't handle network tables from parsers
	 * compiled against newer kernel headers as they are larger than
	 * the running kernel expected.  If net_override is defined check
	 * to see if there is a static max specified for that kernel
	 */
	if (net_af_max_override) {
		size_t max = kernel_af_max();
		if (max && max < af_max)
			return max;
	}

	return af_max;
}

const char *net_find_af_name(unsigned int af)
{
	size_t i;

	if (af > get_af_max())
		return NULL;

	for (i = 0; i < sizeof(network_mappings) / sizeof(*network_mappings); i++) {
		if (network_mappings[i].family == af)
			return network_mappings[i].family_name;
	}

	return NULL;
}

const char *net_find_protocol_name(unsigned int protocol)
{
	size_t i;

	for (i = 0; i < sizeof(network_mappings) / sizeof(*network_mappings); i++) {
		if (network_mappings[i].protocol == protocol) {
			return network_mappings[i].protocol_name;
		}
	}

	return NULL;
}

const struct network_tuple *net_find_mapping(const struct network_tuple *map,
					     const char *family,
					     const char *type,
					     const char *protocol)
{
	if (!map)
		map = network_mappings;
	else
		/* assumes it points to last entry returned */
		map++;

	for (; map->family_name; map++) {
		if (family) {
			PDEBUG("Checking family %s\n", map->family_name);
			if (strcmp(family, map->family_name) != 0)
				continue;
			PDEBUG("Found family %s\n", family);
		}
		if (type) {
			PDEBUG("Checking type %s\n", map->type_name);
			if (strcmp(type, map->type_name) != 0)
				continue;
			PDEBUG("Found type %s\n", type);
		}
		if (protocol) {
			/* allows the proto to be the "type", ie. tcp implies
			 * stream */
			if (!type) {
				PDEBUG("Checking protocol type %s\n", map->type_name);
				if (strcmp(protocol, map->type_name) == 0)
					goto match;
			}
			PDEBUG("Checking type %s protocol %s\n", map->type_name, map->protocol_name);
			if (strcmp(protocol, map->protocol_name) != 0)
				continue;
			/* fixme should we allow specifying protocol by #
			 * without needing the protocol mapping? */
		}

		/* if we get this far we have a match */
	match:
		return map;
	}

	return NULL;
}

bool parse_ipv4_address(const char *input, struct ip_address *result)
{
	struct in_addr addr;
	if (inet_pton(AF_INET, input, &addr) == 1) {
		result->family = AF_INET;
		result->address.address_v4 = addr.s_addr;
		return true;
	}
	return false;
}

bool parse_ipv6_address(const char *input, struct ip_address *result)
{
	struct in6_addr addr;
	if (inet_pton(AF_INET6, input, &addr) == 1) {
		result->family = AF_INET6;
		memcpy(result->address.address_v6, addr.s6_addr, 16);
		return true;
	}
	return false;
}

bool parse_ip(const char *ip, struct ip_address *result)
{
	return parse_ipv6_address(ip, result) ||
		parse_ipv4_address(ip, result);
}

bool parse_port_number(const char *port_entry, uint16_t *port) {
	char *eptr;
	unsigned long port_tmp = strtoul(port_entry, &eptr, 10);

	if (port_entry != eptr && *eptr == '\0' &&
	    port_tmp <= UINT16_MAX) {
		*port = port_tmp;
		return true;
	}
	return false;
}

bool parse_range(const char *range, uint16_t *from, uint16_t *to)
{
	char *range_tmp = strdup(range);
	if (!range_tmp) {
		return false;
	}
	char *dash = strchr(range_tmp, '-');
	bool ret = false;
	if (dash == NULL)
		goto out;
	*dash = '\0';

	if (parse_port_number(range_tmp, from)) {
		if (parse_port_number(dash + 1, to)) {
			if (*from > *to) {
				goto out;
			}
			ret = true;
			goto out;
		}
	}

out:
	free(range_tmp);
	return ret;
}

bool network_rule::parse_port(ip_conds &entry)
{
	entry.is_port = true;
	if (parse_range(entry.sport, &entry.from_port, &entry.to_port))
		return true;
	if (parse_port_number(entry.sport, &entry.from_port)) {
		/* if range is not used, from and to have the same value */
		entry.to_port = entry.from_port;
		return true;
	}
	return false;
}

bool network_rule::parse_address(ip_conds &entry)
{
	if (strcmp(entry.sip, "none") == 0) {
		entry.is_none = true;
		return true;
	}
	entry.is_ip = true;
	return parse_ip(entry.sip, &entry.ip);
}

bool network_rule::parse_iface(ip_conds &entry)
{
	std::string buf;
	pattern_t ptype;
	int pos;

	if (!entry.iface)
		yyerror("internal error. null iface passed to parse_iface");

	ptype = convert_aaregex_to_pcre(entry.iface, 0, glob_default, buf, &pos);
	if (ptype == ePatternInvalid)
		return false;

	/* atm just discard buf, this is just so we can detect conversion
	 * error in the front-end. Ideally would store but that is more work atm
	 */
	return true;
}


void network_rule::move_conditionals(struct cond_entry *conds, ip_conds &ip_cond)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		if (strcmp(cond_ent->name, "label") == 0) {
			move_conditional_value("network", &ip_cond.label_match, cond_ent);
			if (cond_ent->comp == cond_comp::SET)
				ip_cond.set_label = true;
			else if (cond_ent->comp == cond_comp::EQ)
				ip_cond.set_label = false;
			else
				yyerror("unsupported operator in label conditional of network rules\n");
		} else if (cond_ent->comp != cond_comp::EQ) { /* next conds only allow '=' */
			yyerror("unsupported operator used in conditions of network rules\n");
		} else if (strcmp(cond_ent->name, "ip") == 0) {
			move_conditional_value("network", &ip_cond.sip, cond_ent);
			if (!parse_address(ip_cond))
				yyerror("network invalid ip='%s'\n", ip_cond.sip);
		} else if (strcmp(cond_ent->name, "port") == 0) {
			move_conditional_value("network", &ip_cond.sport, cond_ent);
			if (!parse_port(ip_cond))
				yyerror("network invalid port='%s'\n", ip_cond.sport);
		} else if (strcmp(cond_ent->name, "interface") == 0) {
			move_conditional_value("network", &ip_cond.iface, cond_ent);
			if (!parse_iface(ip_cond))
				yyerror("network invalid interface='%s'\n", ip_cond.iface);
		} else {
			yyerror("invalid network rule conditional \"%s\"\n",
				cond_ent->name);
		}
	}
}

void network_rule::set_netperm(unsigned int family, unsigned int type, unsigned int protocol)
{
	if (type > SOCK_PACKET) {
		/* setting mask instead of a bit */
		network_perms[family].first |= type;
	} else
		network_perms[family].first |= 1 << type;
	network_perms[family].second |= protocol;
}

network_rule::network_rule(perm32_t perms_p, struct cond_entry *conds,
			   struct cond_entry *peer_conds):
	dedup_perms_rule_t(features_supports_networkv9 ? AA_CLASS_NETV9 : AA_CLASS_NETV8)
{
	size_t family_index, i;

	move_conditionals(conds, local);
	move_conditionals(peer_conds, peer);
	if (peer.iface)
		yyerror("interface cannot be set for peer in network rules\n");
	peer.iface = local.iface;
	free_cond_list(conds);
	free_cond_list(peer_conds);

	if (has_local_conds() || has_peer_conds()) {
		const char *family[] = { "inet", "inet6" };
		for (i = 0; i < sizeof(family)/sizeof(family[0]); i++) {
			const struct network_tuple *mapping = NULL;
			while ((mapping = net_find_mapping(mapping, family[i], NULL, NULL))) {
				network_map[mapping->family].push_back({ mapping->family, mapping->type, mapping->protocol });
				set_netperm(mapping->family, mapping->type, mapping->protocol);
			}
		}
	} else {
		for (family_index = AF_UNSPEC; family_index < get_af_max(); family_index++) {
			network_map[family_index].push_back({ family_index, 0xFFFFFFFF, 0xFFFFFFFF });
			set_netperm(family_index, 0xFFFFFFFF, 0xFFFFFFFF);
		}
	}



	if (perms_p) {
		perms = perms_p;
		if (perms & ~AA_VALID_NET_PERMS)
			yyerror("perms contains invalid permissions for network rules\n");
		else if ((perms & ~AA_PEER_NET_PERMS) && has_peer_conds())
			yyerror("network 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals\n");
	} else {
		perms = AA_VALID_NET_PERMS;
	}
}

network_rule::network_rule(perm32_t perms_p, const char *family, const char *type,
			   const char *protocol, struct cond_entry *conds,
			   struct cond_entry *peer_conds):
	dedup_perms_rule_t(features_supports_networkv9 ? AA_CLASS_NETV9 : AA_CLASS_NETV8)
{
	const struct network_tuple *mapping = NULL;

	move_conditionals(conds, local);
	move_conditionals(peer_conds, peer);
	if (peer.iface)
		yyerror("interface cannot be set for peer in network rules\n");
	peer.iface = local.iface;
	free_cond_list(conds);
	free_cond_list(peer_conds);

	while ((mapping = net_find_mapping(mapping, family, type, protocol))) {
		/* if inet conds and family are specified, fail if
		 * family is not af_inet or af_inet6
		 */
		if ((has_local_conds() || has_peer_conds()) &&
		    mapping->family != AF_INET && mapping->family != AF_INET6) {
			yyerror("network family does not support local or peer conditionals\n");
		}
		network_map[mapping->family].push_back({ mapping->family, mapping->type, mapping->protocol });
		set_netperm(mapping->family, mapping->type, mapping->protocol);
	}

	if (type == NULL && network_map.empty()) {
		while ((mapping = net_find_mapping(mapping, type, family, protocol))) {
			/* if inet conds and type/protocol are
			 * specified, only add rules for af_inet and
			 * af_inet6
			 */
			if ((has_local_conds() || has_peer_conds()) &&
			    mapping->family != AF_INET && mapping->family != AF_INET6)
				continue;

			network_map[mapping->family].push_back({ mapping->family, mapping->type, mapping->protocol });
			set_netperm(mapping->family, mapping->type, mapping->protocol);
		}
	}

	if (network_map.empty())
		yyerror(_("Invalid network entry."));

	if (perms_p) {
		perms = perms_p;
		if (perms & ~AA_VALID_NET_PERMS)
			yyerror("perms contains invalid permissions for network rules\n");
		else if ((perms & ~AA_PEER_NET_PERMS) && has_peer_conds())
			yyerror("network 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals\n");
	} else {
		perms = AA_VALID_NET_PERMS;
	}
}

network_rule::network_rule(perm32_t perms_p, unsigned int family, unsigned int type):
	dedup_perms_rule_t(features_supports_networkv9 ? AA_CLASS_NETV9 : AA_CLASS_NETV8)
{
	network_map[family].push_back({ family, type, 0xFFFFFFFF });
	set_netperm(family, type, 0xFFFFFFFF);

	if (perms_p) {
		perms = perms_p;
		if (perms & ~AA_VALID_NET_PERMS)
			yyerror("perms contains invalid permissions for network rules\n");
		else if ((perms & ~AA_PEER_NET_PERMS) && has_peer_conds())
			yyerror("network 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals\n");
	} else {
		perms = AA_VALID_NET_PERMS;
	}
}

ostream &network_rule::dump(ostream &os)
{
	class_rule_t::dump(os);

	unsigned int count = sizeof(sock_types)/sizeof(sock_types[0]);
	unsigned int mask = ~((1U << count) -1);
	unsigned int j;

	/* This can only be set by an unqualified network rule */
	if (network_map.find(AF_UNSPEC) != network_map.end()) {
		os << ",\n";
		return os;
	}

	for (const auto& perm : network_perms) {
		unsigned int family = perm.first;
		unsigned int type = perm.second.first;
		unsigned int protocol = perm.second.second;

		const char *family_name = net_find_af_name(family);
		if (family_name)
			os << " " << family_name;
		else
			os << " #" << family;

		/* All types/protocols */
		if (type == 0xffffffff || type == ALL_TYPES)
			continue;

		os << " {";

		for (j = 0; j < count; j++) {
			const char *type_name;
			if (type & (1U << j)) {
				type_name = sock_types[j].name;
				if (type_name)
					os << " " << type_name;
				else
					os << " #" << j;
			}
		}
		if (type & mask)
			os << " #" << std::hex << (type & mask);

		os << " }";

		const char *protocol_name = net_find_protocol_name(protocol);
		if (protocol_name)
			os << " " << protocol_name;
		else
			os << " #" << protocol;
	}

	os << ",\n";

	return os;
}


int network_rule::expand_variables(void)
{
	return 0;
}

void network_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "network rules not enforced");
}

std::string gen_ip_cond(struct ip_address const &ip)
{
	std::ostringstream oss;
	int i;
	if (ip.family == AF_INET) {
		/* add a byte containing the size of the following ip */
		oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << IPV4_SIZE;

		u8 *byte = (u8 *) &ip.address.address_v4; /* in network byte order */
		for (i = 0; i < 4; i++)
			oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(byte[i]);
	} else {
		/* add a byte containing the size of the following ip */
		oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << IPV6_SIZE;
		for (i = 0; i < 16; ++i)
			oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(ip.address.address_v6[i]);
	}
	return oss.str();
}

std::string gen_port_cond(uint16_t port)
{
	std::ostringstream oss;
	if (port > 0) {
		oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((port & 0xff00) >> 8);
		oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (port & 0xff);
	} else {
		oss << "..";
	}
	return oss.str();
}

std::string gen_iface_cond(const char *iface)
{
	std::string buf;
	pattern_t ptype;
	std::ostringstream oss;
	if (iface) {
		int pos;
		ptype = convert_aaregex_to_pcre(iface, 0, glob_default, buf, &pos);
		if (ptype == ePatternInvalid)
			throw std::runtime_error("Invalid iface conditional");
		oss << buf;
	} else {
		/* match any iface */
		oss << default_match_pattern;
	}

	oss << "\\x00"; /* null transition */
	
	return oss.str();
}

std::list<std::ostringstream> gen_all_ip_options(std::ostringstream &oss) {

	std::list<std::ostringstream> all_streams;
	std::ostringstream none, ipv4, ipv6;
	int i;
	none << oss.str();
	ipv4 << oss.str();
	ipv6 << oss.str();

	none << "\\x" << std::setfill('0') << std::setw(2) << std::hex << NONE_SIZE;

	/* add a byte containing the size of the following ip */
	ipv4 << "\\x" << std::setfill('0') << std::setw(2) << std::hex << IPV4_SIZE;
	for (i = 0; i < 4; i++)
		ipv4 << ".";

	/* add a byte containing the size of the following ip */
	ipv6 << "\\x" << std::setfill('0') << std::setw(2) << std::hex << IPV6_SIZE;
	for (i = 0; i < 16; ++i)
		ipv6 << ".";

	all_streams.push_back(std::move(none));
	all_streams.push_back(std::move(ipv4));
	all_streams.push_back(std::move(ipv6));

	return all_streams;
}

std::list<std::ostringstream> copy_streams_list(std::list<std::ostringstream> &streams)
{
	std::list<std::ostringstream> streams_copy;
	for (auto &oss : streams) {
		std::ostringstream oss_copy(oss.str());
		streams_copy.push_back(std::move(oss_copy));
	}
	return streams_copy;
}

bool network_rule::gen_ip_conds(Profile &prof, std::list<std::ostringstream> &streams, ip_conds &entry,
				bool is_peer, uint16_t port, bool is_port, bool is_cmd, bool is_iface)
{
	std::string buf;
	perm32_t cond_perms;
	std::list<std::ostringstream> ip_streams;

	for (auto &oss : streams) {
		if (is_port && !(entry.is_ip && entry.is_none)) {
			/* encode port type (privileged - 1, remote - 2, unprivileged - 0) */
			if (!is_peer && perms & AA_NET_BIND && port < IPPORT_RESERVED)
				oss << "\\x01";
			else if (is_peer)
				oss << "\\x02";
			else
				oss << "\\x00";

			oss << gen_port_cond(port);
		} else {
			/* port type + port number */
			oss << "...";
		}
	}

	ip_streams = std::move(streams);
	streams.clear();

	for (auto &oss : ip_streams) {
		if (entry.is_ip) {
			oss << gen_ip_cond(entry.ip);
			streams.push_back(std::move(oss));
		} else if (entry.is_none) {
			oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << NONE_SIZE;
			streams.push_back(std::move(oss));
		} else {
			streams.splice(streams.end(), gen_all_ip_options(oss));
		}
	}

	cond_perms = map_perms(perms);
	if ((!is_cmd && (entry.label_match || is_peer)) || is_iface)
		cond_perms = AA_COMPAT_CONT_MATCH;

	for (auto &oss : streams) {
		oss << "\\x00"; /* null transition */

		buf = oss.str();
		/* AA_CONT_MATCH mapping (cond_perms) only applies to perms, not audit */
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
						 rule_mode, cond_perms,
						 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
						 parseopts))
			return false;

		/* only output for secmark rule rules */
		if (is_iface) {
			/* use an alternation of a direct null or
			 * iface match pattern to ensure kernel can
			 * use direct null to skip iface cond when
			 * determining whether to label a packet,
			 * because iface is not available at this
			 * point
			 */
			if (perms & AA_MAY_SEND)
				oss << "(\\x00|";

			oss << gen_iface_cond(entry.iface);

			if (perms & AA_MAY_SEND)
				oss << ")";

			buf = oss.str();

			perm32_t ifperms = (entry.label_match || is_peer) ? cond_perms : map_perms(perms);
			if (perms & AA_MAY_SEND)
				ifperms |= AA_SET_LABEL;
			if (!prof.policy.rules->add_rule(buf.c_str(), priority,
							 rule_mode, ifperms,
							 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
							 parseopts))
				return false;
		}
		
		if (entry.label_match || is_peer) {
			perm32_t lperms = cond_perms;
			if (!is_peer)
				lperms = map_perms(perms);

			oss << default_match_pattern; /* label - not used for now */

			buf = oss.str();
			if (is_iface && !entry.label_match) {
				/* mandatory perms at this point for
				 * skb because default label has to
				 * match actual perms.
				 * AA_COMPAT_CONT_MATCH is checked on
				 * the null transition */
				if (!prof.policy.rules->add_rule(buf.c_str(), priority,
								 rule_mode, map_perms(perms),
								 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
								 parseopts))
					return false;
			}

			oss << "\\x00"; /* null transition */

			buf = oss.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), priority,
							 rule_mode, lperms,
							 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
							 parseopts))
				return false;
		}
	}
	return true;
}

bool network_rule::gen_net_rule(Profile &prof, unsigned int netclass, u16 family, unsigned int type_mask, unsigned int protocol, bool skb) {
	std::ostringstream buffer;
	std::string buf;
	bool is_iface = skb && features_supports_ifacev9_skb;

	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << netclass;
	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((family & 0xff00) >> 8);
	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (family & 0xff);

	if (type_mask > 0xffff || type_mask == ALL_TYPES) {
		buffer << "..";
	} else {
		bool single_type = type_mask && !(type_mask & (type_mask - 1));
		if (!single_type)
			buffer << "(";
		/* generate rules for types that are set */
		bool first = true;
		for (int t = 0; t < 16; t++) {
			if (type_mask & (1 << t)) {
				if (first)
					first = false;
				else
					buffer << "|";
				buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((t & 0xff00) >> 8);
				buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (t & 0xff);
			}
		}
		if (!single_type)
			buffer << ")";
	}

	if (!skb && (!(features_supports_inetv8 || features_supports_inetv9) || (family != AF_INET && family != AF_INET6))) {
		buf = buffer.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
				rule_mode, map_perms(perms),
				dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
				parseopts))
			return false;
		return true;
	}

	buf = buffer.str();

	/* mandatory cont_match at this point */
	if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					 rule_mode, AA_COMPAT_CONT_MATCH, 0,
					 parseopts))
		return false;

	/* create perms need to be generated excluding the rest of the perms */
	if (!skb && perms & AA_NET_CREATE) {
		if (!prof.policy.rules->add_rule(buf.c_str(), priority,
					   rule_mode, map_perms(perms & AA_NET_CREATE) | AA_COMPAT_CONT_MATCH,
						 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms & AA_NET_CREATE) : 0,
						 parseopts))
			return false;
	}

	/* encode protocol */
	if (protocol > 0xffff) {
		buffer << "..";
	} else {
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((protocol & 0xff00) >> 8);
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (protocol & 0xff);
	}

	if (perms & AA_PEER_NET_PERMS) {
		for (int peer_port = peer.from_port; peer_port <= peer.to_port; peer_port++) {
			std::list<std::ostringstream> streams;
			std::ostringstream cmd_buffer;

			cmd_buffer << buffer.str();
			streams.push_back(std::move(cmd_buffer));

			if (!gen_ip_conds(prof, streams, peer,
					  true, peer_port, peer.is_port,
					  false, is_iface))
				return false;

			for (auto &oss : streams) {
				oss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_ADDR;
			}

			for (int local_port = local.from_port; local_port <= local.to_port; local_port++) {
				std::list<std::ostringstream> localstreams;

				for (auto &oss : streams) {
					/* we need to copy streams because each local_port should be an unique entry */
					std::ostringstream local_buffer;
					local_buffer << oss.str();
					localstreams.push_back(std::move(local_buffer));
				}

				if (!gen_ip_conds(prof, localstreams, local,
						  false, local_port, local.is_port,
						  true, is_iface))
					return false;
			}
		}
	}

	if (skb) /* skip next perms for skb */
		goto out;

	for (int local_port = local.from_port; local_port <= local.to_port; local_port++) {
		std::list<std::ostringstream> streams;
		std::ostringstream common_buffer;

		common_buffer << buffer.str();
		streams.push_back(std::move(common_buffer));
		/* skb is always false for AA_NET_LISTEN and AA_NET_OPT, and therefore so is is_iface */
		if (!gen_ip_conds(prof, streams, local, false, local_port, local.is_port, false, false))
			return false;

		if (perms & AA_NET_LISTEN) {
			std::list<std::ostringstream> cmd_streams;
			cmd_streams = copy_streams_list(streams);

			for (auto &cmd_buffer : streams) {
				std::ostringstream listen_buffer;
				listen_buffer << cmd_buffer.str();
				listen_buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_LISTEN;
				/* length of queue allowed - not used for now */
				listen_buffer << "..";
				buf = listen_buffer.str();
				if (!prof.policy.rules->add_rule(buf.c_str(), priority,
								 rule_mode, map_perms(perms),
								 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
								 parseopts))
					return false;
			}
		}
		if (perms & AA_NET_OPT) {
			std::list<std::ostringstream> cmd_streams;
			cmd_streams = copy_streams_list(streams);

			for (auto &cmd_buffer : streams) {
				std::ostringstream opt_buffer;
				opt_buffer << cmd_buffer.str();
				opt_buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_OPT;
				/* level - not used for now */
				opt_buffer << "..";
				/* socket mapping - not used for now */
				opt_buffer << "..";
				buf = opt_buffer.str();
				if (!prof.policy.rules->add_rule(buf.c_str(), priority,
								 rule_mode, map_perms(perms),
								 dedup_perms_rule_t::audit == AUDIT_FORCE ? map_perms(perms) : 0,
								 parseopts))
					return false;
			}
		}
	}
out:
	return true;
}

int network_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer;
	std::string buf;
	unsigned int netclass = features_supports_networkv9 ? AA_CLASS_NETV9 : AA_CLASS_NETV8;
	bool skb = features_supports_networkv9_skb;

	if (!(features_supports_networkv8 || features_supports_networkv9)) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}

	for (const auto& perm : network_perms) {
		unsigned int family = perm.first;
		unsigned int type = perm.second.first;
		unsigned int protocol = perm.second.second;

		if (!gen_net_rule(prof, netclass, family, type, protocol,
				  false))
			goto fail;
	}
	return RULE_OK;

fail:
	return RULE_ERROR;

}

/* initialize static members */
unsigned int *network_rule::allow = NULL;
unsigned int *network_rule::audit = NULL;
unsigned int *network_rule::deny = NULL;
unsigned int *network_rule::quiet = NULL;

bool network_rule::alloc_net_table()
{
	if (allow && audit && deny && quiet)
		return true;

	allow = (unsigned int *) calloc(get_af_max(), sizeof(unsigned int));
	if (!allow) {
		goto out;
	}
	audit = (unsigned int *) calloc(get_af_max(), sizeof(unsigned int));
	if (!audit) {
		goto out;
	}
	deny = (unsigned int *) calloc(get_af_max(), sizeof(unsigned int));
	if (!deny) {
		goto out;
	}
	quiet = (unsigned int *) calloc(get_af_max(), sizeof(unsigned int));
	if (!quiet) {
		goto out;
	}

	return true;

out:
		free(allow);
		free(audit);
		free(deny);
		free(quiet); // Not possible but easier in case refactor.

		allow = NULL;
		audit = NULL;
		deny = NULL;
		quiet = NULL;

		return false;
}

/* update is required because at the point of the creation of the
 * network_rule object, we don't have owner, rule_mode, or audit
 * set.
 */
void network_rule::update_compat_net(void)
{
	if (!alloc_net_table())
		yyerror(_("Memory allocation error."));

	for (auto& nm: network_map) {
		for (auto& entry : nm.second) {
			if (entry.type > SOCK_PACKET) {
				/* setting mask instead of a bit */
				if (rule_mode == RULE_DENY) {
					deny[entry.family] |= entry.type;
					if (dedup_perms_rule_t::audit != AUDIT_FORCE)
						quiet[entry.family] |= entry.type;
				} else {
					allow[entry.family] |= entry.type;
					if (dedup_perms_rule_t::audit == AUDIT_FORCE)
						audit[entry.family] |= entry.type;
				}
			} else {
				if (rule_mode == RULE_DENY) {
					deny[entry.family] |= 1 << entry.type;
					if (dedup_perms_rule_t::audit != AUDIT_FORCE)
						quiet[entry.family] |= 1 << entry.type;
				} else {
					allow[entry.family] |= 1 << entry.type;
					if (dedup_perms_rule_t::audit == AUDIT_FORCE)
						audit[entry.family] |= 1 << entry.type;
				}
			}
		}
	}
}

static int cmp_ip_conds(ip_conds const &lhs, ip_conds const &rhs)
{
	int res = null_strcmp(lhs.sip, rhs.sip);
	if (res)
		return res;
	res = null_strcmp(lhs.sport, rhs.sport);
	if (res)
		return res;
	res = null_strcmp(lhs.iface, rhs.iface);
	if (res)
		return res;
	res = null_strcmp(lhs.label_match, rhs.label_match);
	if (res)
		return res;
	return lhs.is_none - rhs.is_none;
}

static int cmp_network_map(std::unordered_map<unsigned int, std::pair<unsigned int, unsigned int>> const &lhs,
			   std::unordered_map<unsigned int, std::pair<unsigned int, unsigned int>> const &rhs)
{
	size_t family_index;
	for (family_index = AF_UNSPEC; family_index < get_af_max(); family_index++) {
		std::unordered_map<unsigned int, std::pair<unsigned int, unsigned int>>::const_iterator li = lhs.find(family_index);
		std::unordered_map<unsigned int, std::pair<unsigned int, unsigned int>>::const_iterator ri = rhs.find(family_index);
		if (li == lhs.end()) {
			if (ri != rhs.end())
				return -1;	// lhs < rhs
			continue;		// both undef equiv to ==
		} else if (ri == rhs.end()) {
			return 1;		// lhs > rhs
		}
		if (li->second.first < ri->second.first) {
			return -1;
		}
		if (li->second.first > ri->second.first) {
			return 1;
		}
		if (li->second.second < ri->second.second) {
			return -1;
		}
		if (li->second.second > ri->second.second) {
			return 1;
		}
	}
	return 0;
}

int network_rule::cmp(rule_t const &rhs) const
{
	int res = dedup_perms_rule_t::cmp(rhs);
	if (res)
		return res;
	network_rule const &nrhs = rule_cast<network_rule const &>(rhs);
	res = cmp_network_map(network_perms, nrhs.network_perms);
	if (res)
		return res;
	res = cmp_ip_conds(local, nrhs.local);
	if (res)
		return res;
	return cmp_ip_conds(peer, nrhs.peer);
};
