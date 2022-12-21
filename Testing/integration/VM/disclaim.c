// Disclaim and exec the supplied command (and args), making the exec'd process "responsible" for
// itself (for the purposes of TCC and other security/privacy rules).
// See https://www.qt.io/blog/the-curious-case-of-the-responsible-process for reference

#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <err.h>

extern int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t attrs, int disclaim);

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s command [args...]\n", argv[0]);
		exit(1);
	}

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	responsibility_spawnattrs_setdisclaim(&attr, 1);

	int err = posix_spawnp(NULL, argv[1], NULL, &attr, &argv[1], envp);
	if (err) {
		errc(1, err, "posix_spawnp failed");
	}

	return 1;
}
