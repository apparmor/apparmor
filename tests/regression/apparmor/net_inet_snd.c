/* Multiple iteration sending test. */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "net_inet.h"

struct connection_info {
	char *bind_ip;
	char *bind_port;
	char *remote_ip;
	char *remote_port;
	char *protocol;
	char *interface;
} net_info = {0};

int send_udp(char *message)
{
	int sock;
	struct sockaddr_in remote, local;
	struct sockaddr_in6 remote6, local6;

	struct ip_address bind_addr = {0};
	if (!parse_ip(net_info.bind_ip, net_info.bind_port, &bind_addr)) {
		fprintf(stderr, "FAIL SND - could not parse bind ip address\n");
		return -1;
	}

	struct ip_address remote_addr = {0};
	if (!parse_ip(net_info.remote_ip, net_info.remote_port, &remote_addr)) {
		fprintf(stderr, "FAIL SND - could not parse remote ip address\n");
		return -1;
	}

	if ((sock = socket(bind_addr.family, SOCK_DGRAM, 0)) < 0) {
		perror("FAIL SND - Could not open socket: ");
		return(-1);
	}

	const int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(int)) < 0)
		perror("FAIL SND - setsockopt(SO_REUSEADDR) failed");

	if (net_info.interface) {
		bind_addr.interface = net_info.interface;
		remote_addr.interface = net_info.interface;
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, net_info.interface, strlen(net_info.interface)) < 0)
			perror("FAIL - setsockopt(SO_BINDTODEVICE) failed");
	}

	if (bind_addr.family == AF_INET) {
		local = convert_to_sockaddr_in(bind_addr);
		if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
			perror("FAIL SND - Bind error: ");
			return(-1);
		}
	} else {
		local6 = convert_to_sockaddr_in6(bind_addr);
		if (bind(sock, (struct sockaddr *) &local6, sizeof(local6)) < 0) {
			perror("FAIL SND - Bind error: ");
			return(-1);
		}
	}

	if (remote_addr.family == AF_INET) {
		remote = convert_to_sockaddr_in(remote_addr);
		//printf("Sending \"%s\"\n", message);
		if (sendto(sock, message, strlen(message), 0, (struct sockaddr *) &remote, sizeof(remote)) <= 0) {
			perror("FAIL SND - Send failed: ");
			return(-1);
		}
	} else {
		remote6 = convert_to_sockaddr_in6(remote_addr);
		//printf("Sending \"%s\"\n", message);
		if (sendto(sock, message, strlen(message), 0, (struct sockaddr *) &remote6, sizeof(remote6)) <= 0) {
			perror("FAIL SND - Send failed: ");
			return(-1);
		}
	}

	shutdown(sock, SHUT_RDWR);
	close(sock);
	return(0);

}

int send_tcp(char *message)
{
	int sock;
	struct sockaddr_in remote, local;
	struct sockaddr_in6 remote6, local6;

	struct ip_address bind_addr = {0};
	if (!parse_ip(net_info.bind_ip, net_info.bind_port, &bind_addr)) {
		fprintf(stderr, "FAIL SND - could not parse bind ip address\n");
		return -1;
	}

	struct ip_address remote_addr = {0};
	if (!parse_ip(net_info.remote_ip, net_info.remote_port, &remote_addr)) {
		fprintf(stderr, "FAIL SND - could not parse remote ip address\n");
		return -1;
	}

	if ((sock = socket(bind_addr.family, SOCK_STREAM, 0)) < 0)
	{
		perror("FAIL SND - Could not open socket: ");
		return(-1);
	}

	const int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(int)) < 0)
		perror("FAIL SND - setsockopt(SO_REUSEADDR) failed");

	if (net_info.interface) {
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, net_info.interface, strlen(net_info.interface)) < 0)
			perror("FAIL - setsockopt(SO_BINDTODEVICE) failed");
	}

	if (bind_addr.family == AF_INET) {
		local = convert_to_sockaddr_in(bind_addr);
		if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
			perror("FAIL SND - Bind error: ");
			return(-1);
		}
	} else {
		local6 = convert_to_sockaddr_in6(bind_addr);
		if (bind(sock, (struct sockaddr *) &local6, sizeof(local6)) < 0) {
			perror("FAIL SND - Bind error: ");
			return(-1);
		}
	}

	if (remote_addr.family == AF_INET) {
		remote = convert_to_sockaddr_in(remote_addr);
		//printf("Sending \"%s\"\n", message);
		if (connect(sock, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
			perror("FAIL SND - Could not connect: ");
			return(-1);
		}
	} else {
		remote6 = convert_to_sockaddr_in6(remote_addr);
		//printf("Sending \"%s\"\n", message);
		if (connect(sock, (struct sockaddr *) &remote6, sizeof(remote6)) < 0) {
			perror("FAIL SND - Could not connect: ");
			return(-1);
		}
	}

	//printf("Sending \"%s\"\n", message);
	if (send(sock, message, strlen(message), 0) <= 0) {
		perror("FAIL SND - Send failed: ");
		return(-1);
	}
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return(0);
}

int send_icmp(char *message)
{
	int sock;
	struct sockaddr_in remote, local;
	struct icmphdr icmp_hdr;
	char packetdata[sizeof(icmp_hdr) + 4];


	if ((sock = socket(AF_INET | AF_INET6, SOCK_DGRAM, IPPROTO_ICMP)) < 0) {
		perror("FAIL SND - Could not open socket: ");
		return(-1);
	}

	const int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(int)) < 0)
		perror("FAIL SND - setsockopt(SO_REUSEADDR) failed");

	remote.sin_family = AF_INET;
	remote.sin_port = htons(atoi(net_info.remote_port));
	inet_aton(net_info.remote_ip, &remote.sin_addr);

	local.sin_family  = AF_INET;
	local.sin_port = htons(atoi(net_info.bind_port));
	inet_aton(net_info.bind_ip, &local.sin_addr);

	// Initialize the ICMP header
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	icmp_hdr.type = ICMP_ECHO;
	icmp_hdr.un.echo.id = 1234;
	icmp_hdr.un.echo.sequence = 1;

	// Initialize the packet data (header and payload)
	memcpy(packetdata, &icmp_hdr, sizeof(icmp_hdr));
	memcpy(packetdata + sizeof(icmp_hdr), message, strlen(message));

	if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("FAIL SND - Could not bind: ");
		return(-1);
	}

	//printf("Sending \"%s\"\n", message);

	// Send the packet
	if(sendto(sock, packetdata, sizeof(packetdata), 0, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
		perror("FAIL SND - Send failed: ");
		close(sock);
		return(-1);
	}

	//printf("Sent \"%s\"\n", message);

	/* if (send(sock, packetdata, strlen(packetdata), 0) <= 0) */
	/* { */
	/*         perror("FAIL SND - Send failed: "); */
	/*	close(sock); */
	/*         return(-1); */
	/* } */
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return(0);
}

int main(int argc, char *argv[])
{
	int send_ret;

	if (argc < 6) {
		printf("Usage: %s bind_ip bind_port remote_ip remote_port proto [interface]\n", argv[0]);
		exit(1);
	}

	net_info.bind_ip = argv[1];
	net_info.bind_port = argv[2];
	net_info.remote_ip = argv[3];
	net_info.remote_port = argv[4];
	net_info.protocol = argv[5];
	if (argc == 7)
		net_info.interface = argv[6];

	send_ret = -1;
	if (strcmp(net_info.protocol, "udp") == 0)
		send_ret = send_udp("test");
	else if (strcmp(net_info.protocol, "tcp") == 0)
		send_ret = send_tcp("test");
	else if (strcmp(net_info.protocol, "icmp") == 0)
		send_ret = send_icmp("test");
	else
		printf("FAIL SND - Unknown protocol.\n");

	if (send_ret == -1) {
		printf("FAIL SND - Send message failed.\n");
		exit(1);
	}

	exit(0);
}
