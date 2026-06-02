#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include "net_inet.h"

enum protocol {
	INVALID,
	UDP,
	TCP,
	ICMP
};

struct connection_info {
	char *bind_ip;
	char *bind_port;
	char *remote_ip;
	char *remote_port;
	char *protocol;
	enum protocol prot;
	int timeout;
	char *interface;
} net_info = {0};

int receive_bind()
{
	int sock;
	struct sockaddr_in local = {0};
	struct sockaddr_in6 local6 = {0};

	struct ip_address bind_addr = {0};

	if (!parse_ip(net_info.bind_ip, net_info.bind_port, &bind_addr)) {
		fprintf(stderr, "FAIL - could not parse bind ip address\n");
		return -1;
	}

	switch(net_info.prot) {
	case UDP:
		sock = socket(bind_addr.family, SOCK_DGRAM, 0);
		break;
	case TCP:
		sock = socket(bind_addr.family, SOCK_STREAM, 0);
		break;
	case ICMP:
		sock = socket(bind_addr.family, SOCK_DGRAM, IPPROTO_ICMP);
		break;
	default:
		fprintf(stderr, "FAIL - invalid protocol\n");
		return -1;
	}

	if (sock < 0) {
		perror("FAIL - Socket error: ");
		return -1;
	}

	const int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(int)) < 0)
		perror("FAIL - setsockopt(SO_REUSEADDR) failed");

	if (net_info.interface) {
		bind_addr.interface = net_info.interface;
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, net_info.interface, strlen(net_info.interface)) < 0)
			perror("FAIL - setsockopt(SO_BINDTODEVICE) failed");
	}

	if (bind_addr.family == AF_INET) {
		local = convert_to_sockaddr_in(bind_addr);
		if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
			perror("FAIL - Bind error: ");
			return -1;
		}
	} else {
		local6 = convert_to_sockaddr_in6(bind_addr);
		if (bind(sock, (struct sockaddr *) &local6, sizeof(local6)) < 0) {
			perror("FAIL - Bind error: ");
			return -1;
		}
	}

	if (net_info.prot == TCP) {
		if (listen(sock, 5) == -1) {
			perror("FAIL - Could not listen: ");
			return -1;
		}
	}

	return sock;
}

int receive_udp(int sock)
{

	char *buf;
	int ret = -1;
	int select_return;

	fd_set read_set, err_set;
	struct timeval timeout;

	buf = (char *) malloc(255);
	memset(buf, '\0', 255);

	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	FD_ZERO(&err_set);
	FD_SET(sock, &err_set);
	timeout.tv_sec = net_info.timeout;
	timeout.tv_usec = 0;

	select_return = select(sock + 1, &read_set, NULL, &err_set, &timeout);
	if (select_return < 0) {
		perror("FAIL - Select error: ");
		ret = -1;
	} else if (select_return == 0) {
		printf("FAIL - select timeout\n");
	} else if (select_return > 0 && FD_ISSET(sock, &read_set) && !FD_ISSET(sock, &err_set)) {
		if (recvfrom(sock, buf, 255, 0, NULL, NULL) >= 1) {
			//printf("MESSAGE: %s\n", buf);
			ret = 0;
		} else {
			printf("FAIL - recvfrom failed\n");
			ret = -1;
		}
	}

	free(buf);
	return(ret);

}

int receive_tcp(int sock)
{
	int cli_sock;
	char *buf;
	int ret = -1;
	int select_return;

	fd_set read_set, err_set;
	struct timeval timeout;

	buf = (char *) malloc(255);
	memset(buf, '\0', 255);

	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	FD_ZERO(&err_set);
	FD_SET(sock, &err_set);
	timeout.tv_sec = net_info.timeout;
	timeout.tv_usec = 0;

	select_return = select(sock + 1, &read_set, NULL, &err_set, &timeout);
	if (select_return < 0) {
		perror("FAIL - Select failed: ");
		ret = -1;
	} else if (select_return == 0) {
		printf("FAIL - select timeout\n");
	} else if (select_return > 0 && FD_ISSET(sock, &read_set) && !FD_ISSET(sock, &err_set)) {
		if ((cli_sock = accept(sock, NULL, NULL)) < 0) {
			perror("FAIL - Accept failed: ");
			ret = -1;
		} else {
			if (recv(cli_sock, buf, 255, 0) >= 1) {
				//printf("MESSAGE: %s\n", buf);
				ret = 0;
			} else {
				perror("FAIL - recv failure: ");
				ret = -1;
			}
		}
	}

	free(buf);
	return(ret);
}

int receive_icmp(int sock)
{
	char *buf;
	int ret = -1;
	int select_return;

	fd_set read_set, err_set;
	struct timeval timeout;

	buf = (char *) malloc(255);
	memset(buf, '\0', 255);

	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	FD_ZERO(&err_set);
	FD_SET(sock, &err_set);
	timeout.tv_sec = net_info.timeout;
	timeout.tv_usec = 0;

	select_return = select(sock + 1, &read_set, NULL, &err_set, &timeout);
	if (select_return < 0) {
		perror("FAIL - Select error: ");
		ret = -1;
	} else if (select_return == 0) {
		printf("FAIL - select timeout\n");
	} else if (select_return > 0 && FD_ISSET(sock, &read_set) && !FD_ISSET(sock, &err_set)) {
		if (recvfrom(sock, buf, 255, 0, NULL, NULL) >= 1) {
			//printf("MESSAGE: %s\n", buf);
			ret = 0;
		} else {
			printf("FAIL - recvfrom failed\n");
			ret = -1;
		}
	}

	free(buf);
	return(ret);

}

static void usage(char *prog_name, char *msg)
{
	if (msg != NULL)
		fprintf(stderr, "%s\n", msg);

	fprintf(stderr, "Usage: %s [options]\n", prog_name);
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "--bind_ip     local ip address\n");
	fprintf(stderr, "--bind_port   local port\n");
	fprintf(stderr, "--remote_ip   remote ip address\n");
	fprintf(stderr, "--remote_port remote port\n");
	fprintf(stderr, "--protocol    protocol: udp or tcp\n");
	fprintf(stderr, "--sender      path of the sender\n");
	fprintf(stderr, "--interface   connect to specified network interface\n");
	fprintf(stderr, "--timeout     timeout in seconds\n");
	exit(EXIT_FAILURE);
}


int main(int argc, char *argv[])
{
	int opt = 0;
	int pid, ret = -1;
	char *sender;

	static struct option long_options[] = {
		{"bind_ip",     required_argument, 0,  'i' },
		{"bind_port",   required_argument, 0,  'o' },
		{"remote_ip",   required_argument, 0,  'r' },
		{"remote_port", required_argument, 0,  'e' },
		{"protocol",    required_argument, 0,  'p' },
		{"timeout",     required_argument, 0,  't' },
		{"sender",      required_argument, 0,  's' },
		{"interface",   required_argument, 0,  'n' },
		{0,             0,                 0,  0   }
	};

	while ((opt = getopt_long(argc, argv,"i:o:r:e:p:t:s:n:", long_options, 0)) != -1) {
		switch (opt) {
		case 'i':
			net_info.bind_ip = optarg;
			break;
		case 'o':
			net_info.bind_port = optarg;
			break;
		case 'r':
			net_info.remote_ip = optarg;
			break;
		case 'e':
			net_info.remote_port = optarg;
			break;
		case 'p':
			net_info.protocol = optarg;
			if (strcmp(net_info.protocol, "udp") == 0)
				net_info.prot = UDP;
			else if (strcmp(net_info.protocol, "tcp") == 0)
				net_info.prot = TCP;
			else if (strcmp(net_info.protocol, "icmp") == 0)
				net_info.prot = ICMP;
			else
				printf("FAIL - Unknown protocol.\n");
			break;
		case 't':
			net_info.timeout = atoi(optarg);
			break;
		case 's':
			sender = optarg;
			break;
		case 'n':
			net_info.interface = optarg;
			break;
		default:
			usage(argv[0], "Unrecognized option\n");
		}
	}

	/* get the server to bind/listen, so the child has something
	 * to connect to if it wins the race. */
	int sockfd = receive_bind();
	if (sockfd == -1) {
		exit(1);
	}

	/* exec the sender */
	pid = fork();
	if (pid == -1) {
		perror("FAIL - could not fork");
		exit(EXIT_FAILURE);
	} else if (!pid) {
		if (sender == NULL) {
			usage(argv[0], "sender not specified");
			exit(EXIT_FAILURE);
			/* execution of the main thread continues
			 * in case the sender will be manually executed
			 */
		}
		/* invert remote x local ips to sender */
		execl(sender, sender, net_info.remote_ip, net_info.remote_port,
		      net_info.bind_ip, net_info.bind_port,
		      net_info.protocol, net_info.interface, NULL);
		printf("FAIL %d - execlp %s --bind_ip %s --bind_port %s "
		       "--remote_ip %s --remote_port %s --protocol %s --interface %s - %m\n",
		       getuid(), sender, net_info.bind_ip, net_info.bind_port,
		       net_info.remote_ip, net_info.remote_port, net_info.protocol,
		       net_info.interface);
		exit(EXIT_FAILURE);
	}

	switch(net_info.prot) {
	case UDP:
		ret = receive_udp(sockfd);
		break;
	case TCP:
		ret = receive_tcp(sockfd);
		break;
	case ICMP:
		ret = receive_icmp(sockfd);
		break;
	default:
		printf("FAIL - Invalid protocol.\n");
		exit(1);
	}

	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
	
	if (ret == -1) {
		printf("FAIL - Receive message failed.\n");
		exit(1);
	}

	printf("PASS\n");
	return 0;
}
