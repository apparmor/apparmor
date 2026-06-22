/*
 *	Copyright (C) 2026 Canonical, Ltd.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */

/*
 * TCP Fast Open connect-mediation bypass regression test.
 *
 * Under an AppArmor profile that grants inet/inet6 stream "send" but DENIES
 * "connect", a plain connect(2) must be refused (EACCES/EPERM). Historically
 * the kernel's TFO fast path (sendto(..., MSG_FASTOPEN, ...), which performs
 * an implicit connect) only checked the send permission (AA_NET_SEND 0x02)
 * and skipped the connect permission (AA_NET_CONNECT 0x40), so a confined
 * task could open an outbound connection that connect(2) would have blocked.
 * The kernel fix mediates both producers: plain TCP and MPTCP (IPPROTO_MPTCP).
 *
 * This binary takes a mode and asserts the operation is DENIED:
 *   argv[1] = "connect"  -> baseline: connect(2) must be denied
 *   argv[1] = "fastopen" -> the bug: sendto(MSG_FASTOPEN) must be denied
 *   argv[2] = family: "inet"/"inet6" (TCP) or "minet"/"minet6" (MPTCP)
 *   argv[3] = port (the listener port, set up by this same process)
 *
 * Output contract (parsed by checktestfg in prologue.inc):
 *   "PASS\n"  -> the operation was DENIED as required (regression OK)
 *   "FAIL ..."-> the operation was ALLOWED (connect bypass) OR a setup error
 *
 * The .sh runs this with expected outcome "pass"; it also enables TCP Fast
 * Open first, so an EOPNOTSUPP here is a real setup error, not a skip.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

/* Map a family token to (AF_*, protocol). "minet"/"minet6" select MPTCP.
 * Returns 0 on success, -1 on an unknown token.
 */
static int parse_family(const char *tok, int *family, int *proto)
{
	*proto = 0;
	if (strcmp(tok, "inet") == 0) {
		*family = AF_INET;
	} else if (strcmp(tok, "inet6") == 0) {
		*family = AF_INET6;
	} else if (strcmp(tok, "minet") == 0) {
		*family = AF_INET;
		*proto = IPPROTO_MPTCP;
	} else if (strcmp(tok, "minet6") == 0) {
		*family = AF_INET6;
		*proto = IPPROTO_MPTCP;
	} else {
		return -1;
	}
	return 0;
}

/* Build a loopback sockaddr for the requested family. Returns addrlen. */
static socklen_t make_addr(int family, int port, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)ss;

		a->sin_family = AF_INET;
		a->sin_port = htons(port);
		inet_pton(AF_INET, "127.0.0.1", &a->sin_addr);
		return sizeof(*a);
	}
	{
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons(port);
		inet_pton(AF_INET6, "::1", &a->sin6_addr);
		return sizeof(*a);
	}
}

/* Start a plain TCP listener so the connect/TFO target exists. Returns the fd
 * or -1. A TCP listener accepts both TCP and MPTCP clients, which keeps the
 * test on the client-side mediation under examination. bind/listen perms are
 * granted by the profile so this must succeed.
 */
static int start_listener(int family, int port)
{
	int s, one = 1;
	struct sockaddr_storage ss;
	socklen_t len = make_addr(family, port, &ss);

	s = socket(family, SOCK_STREAM, 0);
	if (s < 0) {
		printf("FAIL - listener socket: %m\n");
		return -1;
	}
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	/* Enable TFO on the listener (qlen). Best-effort; the mediation check
	 * under test happens on the client side. */
	(void)setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&ss, len) < 0) {
		printf("FAIL - listener bind: %m\n");
		close(s);
		return -1;
	}
	if (listen(s, 5) < 0) {
		printf("FAIL - listener listen: %m\n");
		close(s);
		return -1;
	}
	return s;
}

/* Returns 1 if the kernel DENIED the operation (EACCES/EPERM) => regression OK.
 * Returns 0 if the operation was ALLOWED (connect bypass) => regression FAIL.
 * Returns -1 on a setup error.
 */
static int try_connect(int family, int proto, int port)
{
	int s, rc;
	struct sockaddr_storage ss;
	socklen_t len = make_addr(family, port, &ss);

	s = socket(family, SOCK_STREAM, proto);
	if (s < 0)
		return -1;
	rc = connect(s, (struct sockaddr *)&ss, len);
	if (rc == 0) {
		close(s);
		return 0;			/* allowed */
	}
	if (errno == EACCES || errno == EPERM) {
		close(s);
		return 1;			/* denied by AppArmor */
	}
	/* ECONNREFUSED/ETIMEDOUT mean it reached the network: mediation did not
	 * block it, so count as allowed. */
	close(s);
	return (errno == ECONNREFUSED || errno == ETIMEDOUT) ? 0 : -1;
}

static int try_fastopen(int family, int proto, int port)
{
	int s;
	ssize_t rc;
	char msg[] = "tfo";
	struct sockaddr_storage ss;
	socklen_t len = make_addr(family, port, &ss);

	s = socket(family, SOCK_STREAM, proto);
	if (s < 0)
		return -1;

	/* The bug: this implicit-connect send must be mediated as a connect. */
	rc = sendto(s, msg, sizeof(msg), MSG_FASTOPEN,
		    (struct sockaddr *)&ss, len);
	if (rc >= 0) {
		close(s);
		return 0;			/* allowed: connect bypass */
	}
	if (errno == EACCES || errno == EPERM) {
		close(s);
		return 1;			/* denied by AppArmor */
	}
	if (errno == EOPNOTSUPP || errno == EINVAL) {
		/* The .sh enabled TCP Fast Open before running, so this is a
		 * real setup error, not an expected condition. Fail loudly
		 * rather than masking it as a denial. */
		close(s);
		return -1;
	}
	close(s);
	return (errno == ECONNREFUSED || errno == ETIMEDOUT) ? 0 : -1;
}

int main(int argc, char *argv[])
{
	int family, proto, port, denied, listener;
	const char *mode;

	if (argc < 4) {
		printf("FAIL - usage: %s connect|fastopen inet|inet6|minet|minet6 port\n",
		       argv[0]);
		return 1;
	}
	mode = argv[1];
	if (parse_family(argv[2], &family, &proto) < 0) {
		printf("FAIL - unknown family '%s'\n", argv[2]);
		return 1;
	}
	port = atoi(argv[3]);

	signal(SIGPIPE, SIG_IGN);

	listener = start_listener(family, port);
	if (listener < 0)
		return 1;			/* FAIL already printed */

	if (strcmp(mode, "connect") == 0) {
		denied = try_connect(family, proto, port);
	} else if (strcmp(mode, "fastopen") == 0) {
		denied = try_fastopen(family, proto, port);
	} else {
		printf("FAIL - unknown mode '%s'\n", mode);
		close(listener);
		return 1;
	}

	close(listener);

	if (denied == 1) {
		printf("PASS\n");
		return 0;
	}
	if (denied == 0) {
		printf("FAIL - %s was ALLOWED despite deny connect "
		       "(connect-mediation bypass)\n", mode);
		return 1;
	}
	printf("FAIL - %s setup error: %m\n", mode);
	return 1;
}
