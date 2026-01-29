#include <unistd.h>

int main(void)
{
	/* Wait to be killed */
	sleep(10);

	/* We were not killed ==> Failure */
	return 1;
}
