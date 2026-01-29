#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	pid_t pid;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return 1;
	}

	pid = atoi(argv[1]);
	if (pid <= 0) {
		fprintf(stderr, "Invalid PID: %s\n", argv[1]);
		return 1;
	}

	ret = kill(pid, SIGTERM);
	if (ret == 0)
		printf("PASS\n");
	else
		printf("FAIL - kill failed with errno %d (%s)\n", errno, strerror(errno));

	return !!ret;
}
