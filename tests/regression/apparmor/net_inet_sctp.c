/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Jérémy Jean <Jeremy.Jean@oss.cyber.gouv.fr> */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/sctp.h>

static void check(int ok, const char *operation)
{
	if (!ok) {
		printf("FAIL: %s (errno %d)\n", operation, errno);
		exit(1); /* Setup errors must not satisfy an expected EACCES. */
	}
}

int main(int argc, char *argv[])
{
	struct sockaddr_in in = {
		.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in6 in6 = {
		.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	struct sockaddr *addr;
	socklen_t addrlen;
	const char *mode;
	int family, client, listener;
	ssize_t ret;
	char payload = 'x', buffer[2];

	check(argc == 3, "usage: net_inet_sctp inet|inet6 MODE");
	check(!strcmp(argv[1], "inet") || !strcmp(argv[1], "inet6"), "family");
	mode = argv[2];
	family = strcmp(argv[1], "inet") == 0 ? AF_INET : AF_INET6;
	alarm(15);

	client = socket(family, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (client == -1 && !strcmp(mode, "probe") &&
	    (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT ||
	     errno == EAFNOSUPPORT))
		return 77;
	check(client >= 0, "client socket");
	if (!strcmp(mode, "probe")) {
		close(client);
		return 0;
	}

	/* Let the kernel choose a free loopback port for each test. */
	addr = family == AF_INET ? (struct sockaddr *)&in : (struct sockaddr *)&in6;
	addrlen = family == AF_INET ? sizeof(in) : sizeof(in6);
	listener = socket(family, SOCK_SEQPACKET, IPPROTO_SCTP);
	check(listener >= 0, "listener socket");
	check(bind(listener, addr, addrlen) == 0, "bind");
	check(getsockname(listener, addr, &addrlen) == 0, "getsockname");
	check(listen(listener, 1) == 0, "listen");

	if (!strcmp(mode, "connect")) {
		ret = connect(client, addr, addrlen);
	} else if (!strcmp(mode, "sendto")) {
		ret = sendto(client, &payload, 1, MSG_NOSIGNAL,
			     addr, addrlen);
	} else if (!strcmp(mode, "sendmsg")) {
		struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
		struct msghdr msg = {
			.msg_name = addr,
			.msg_namelen = addrlen,
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		ret = sendmsg(client, &msg, MSG_NOSIGNAL);
	} else if (!strcmp(mode, "connectx3")) {
		struct sctp_getaddrs_old args = {
			/* This ABI takes the address length in bytes. */
			.addr_num = addrlen,
			.addrs = addr,
		};
		socklen_t optlen = sizeof(args);

		ret = getsockopt(client, IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX3,
				 &args, &optlen);
	} else if (!strcmp(mode, "connectx_old") || !strcmp(mode, "connectx")) {
		int opt = !strcmp(mode, "connectx_old") ?
			SCTP_SOCKOPT_CONNECTX_OLD : SCTP_SOCKOPT_CONNECTX;

		/* CONNECTX can return a positive association ID on success. */
		ret = setsockopt(client, IPPROTO_SCTP, opt, addr, addrlen);
	} else {
		printf("FAIL: unknown operation %s\n", mode);
		return 1;
	}

	if (ret == -1) {
		int error = errno;

		printf("FAIL: %s: %s\n", mode, strerror(error));
		return error; /* Checked by runchecktest_errno. */
	}
	if (strcmp(mode, "sendto") && strcmp(mode, "sendmsg"))
		ret = sendto(client, &payload, 1, MSG_NOSIGNAL, addr, addrlen);
	check(ret == 1, "send payload");
	check(recv(listener, buffer, sizeof(buffer), 0) == 1 &&
	      buffer[0] == payload, "receive payload");

	close(client);
	close(listener);
	printf("PASS\n");
	return 0;
}
