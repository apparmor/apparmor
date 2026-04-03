#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

struct ip_address {
	union {
		uint8_t address_v6[16];
		uint32_t address_v4;
	} address;
	uint16_t family;
	uint16_t port;
	uint8_t subnet_mask;
	char *interface;
};

int parse_ipv4_address(const char *ip, const char *port, struct ip_address *result)
{
	struct in_addr addr = {0};
	if (inet_pton(AF_INET, ip, &addr) == 1) {
		result->family = AF_INET;
		result->address.address_v4 = addr.s_addr;
		result->port = htons(atoi(port));
		return 1;
	}
	return 0;
}

int parse_ipv6_address(const char *ip, const char *port, struct ip_address *result)
{
	struct in6_addr addr = {0};
	if (inet_pton(AF_INET6, ip, &addr) == 1) {
		result->family = AF_INET6;
		memcpy(result->address.address_v6, addr.s6_addr, 16);
		result->port = htons(atoi(port));
		return 1;
	}
	return 0;
}

int parse_ip(const char *ip, const char *port, struct ip_address *result)
{
	return parse_ipv6_address(ip, port, result) ||
		parse_ipv4_address(ip, port, result);
}

struct sockaddr_in convert_to_sockaddr_in(struct ip_address result)
{
	struct sockaddr_in sockaddr = {0};
	sockaddr.sin_family = result.family;
	sockaddr.sin_port = result.port;
	sockaddr.sin_addr.s_addr = result.address.address_v4;
	return sockaddr;
}

struct sockaddr_in6 convert_to_sockaddr_in6(struct ip_address result)
{
	struct sockaddr_in6 sockaddr = {0};
	sockaddr.sin6_family = result.family;
	sockaddr.sin6_port = result.port;
	if (result.interface)
		sockaddr.sin6_scope_id = if_nametoindex(result.interface);
	memcpy(sockaddr.sin6_addr.s6_addr, result.address.address_v6, 16);
	return sockaddr;
}
