/*
 * Copyright 2014 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "private.h"

/* Defined as a magic value to avoid dependency on <zstd.h> */
#define AA_ZSTD_MAGICNUMBER 0xFD2FB528U

size_t _aa_compressed_cache_offset(const char *buf, size_t size)
{
	const size_t need = sizeof(struct compr_user_header) + sizeof(uint32_t);
	struct compr_user_header uh;
	uint32_t magic_nb;

	if (!buf || size < need)
		return 0;

	memcpy(&uh, buf, sizeof(uh));
	if (uh.version != COMPR_USER_HDR_VERSION)
		return 0;

	memcpy(&magic_nb, buf + sizeof(uh), sizeof(magic_nb));
	if (le32toh(magic_nb) != AA_ZSTD_MAGICNUMBER)
		return 0;

	return sizeof(uh);
}

size_t _aa_strip_compressed_cache_header(const char **buf, size_t *size)
{
	size_t hdr = _aa_compressed_cache_offset(*buf, *size);

	if (hdr) {
		*buf += hdr;
		*size -= hdr;
	}
	return hdr;
}

/**
 * Allow libapparmor to build on older systems where secure_getenv() is still
 * named __secure_getenv(). This snippet was taken from the glibc wiki
 * (https://sourceware.org/glibc/wiki/Tips_and_Tricks/secure_getenv).
 */
#ifndef HAVE_SECURE_GETENV
 #ifdef HAVE___SECURE_GETENV
  #define secure_getenv __secure_getenv
 #elif ENABLE_DEBUG_OUTPUT
  #error Debug output is not possible without a secure_getenv() implementation.
 #else
  #define secure_getenv(env) NULL
 #endif
#endif

/**
 * Allow libapparmor to build on older glibcs and other libcs that do
 * not support reallocarray.
 */
#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	return realloc(ptr, nmemb * size);
}
#endif

struct ignored_suffix_t {
	const char * text;
	int len;
	int silent;
};

static struct ignored_suffix_t ignored_suffixes[] = {
	/* Debian packaging files, which are in flux during install
           should be silently ignored. */
	{ ".dpkg-new", 9, 1 },
	{ ".dpkg-old", 9, 1 },
	{ ".dpkg-dist", 10, 1 },
	{ ".dpkg-bak", 9, 1 },
	{ ".dpkg-remove", 12, 1 },
	/* Archlinux packaging files */
	{ ".pacsave", 8, 1 },
	{ ".pacnew", 7, 1 },
	/* RPM packaging files have traditionally not been silently
           ignored */
	{ ".rpmnew", 7, 0 },
	{ ".rpmsave", 8, 0 },
	/* patch file backups/conflicts */
	{ ".orig", 5, 0 },
	{ ".rej", 4, 0 },
	/* Backup files should be mentioned */
	{ "~", 1, 0 },
	{ NULL, 0, 0 }
};

#define DEBUG_ENV_VAR	"LIBAPPARMOR_DEBUG"

void print_error(bool honor_env_var, const char *ident, const char *fmt, ...)
{
	va_list args;
	int openlog_options = 0;

	if (honor_env_var && secure_getenv(DEBUG_ENV_VAR))
		openlog_options |= LOG_PERROR;

	openlog(ident, openlog_options, LOG_ERR);
	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);
	closelog();
}

void print_debug(const char *fmt, ...)
{
	va_list args;

	if (!secure_getenv(DEBUG_ENV_VAR))
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void atomic_inc(unsigned int *v)
{
	__sync_add_and_fetch(v, 1);
}

bool atomic_dec_and_test(unsigned int *v)
{
	return __sync_sub_and_fetch(v, 1) == 0;
}

int _aa_is_blacklisted(const char *name)
{
	ssize_t name_len = strlen(name);
	struct ignored_suffix_t *suffix;

	/* skip dot files and files with no name */
	if (!name_len || *name == '.' || !strcmp(name, "README"))
		return 1;

	/* skip blacklisted suffixes */
	for (suffix = ignored_suffixes; suffix->text; suffix++) {
		char *found;
		if ( (found = strstr((char *) name, suffix->text)) &&
		     found - name + suffix->len == name_len ) {
			if (!suffix->silent)
				return -1;
			return 1;
		}
	}

	return 0;
}

/* automatically free allocated variables tagged with autofree on fn exit */
void _aa_autofree(void *p)
{
	void **_p = (void**)p;
	free(*_p);
}

void _aa_autoclose(int *fd)
{
	if (*fd != -1) {
		/* if close was interrupted retry */
		while(close(*fd) == -1 && errno == EINTR);
		*fd = -1;
	}
}

void _aa_autofclose(FILE **f)
{
	if (*f) {
		fclose(*f);
		*f = NULL;
	}
}

int _aa_asprintf(char **strp, const char *fmt, ...)
{
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vasprintf(strp, fmt, args);
	va_end(args);

	if (rc == -1)
		*strp = NULL;

	return rc;
}

/* stops on first error, can use errno or return value to communicate
 * the goal is to use this to replace _aa_dirat_for_each, but that will
 * be a different patch.
 */
int _aa_dirat_for_each2(int dirfd, const char *name, void *data,
			int (* cb)(int, const struct dirent *, void *))
{
	autoclose int cb_dirfd = -1;
	int fd_for_dir = -1;
	const struct dirent *ent;
	DIR *dir;
	int save, rc;

	if (!cb || !name) {
		errno = EINVAL;
		return -1;
	}
	save = errno;

	cb_dirfd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (cb_dirfd == -1) {
		PDEBUG("could not open directory fd '%d' '%s': %m\n", dirfd, name);
		return -1;
	}
	/* dup cd_dirfd because fdopendir has claimed the fd passed to it */
	fd_for_dir = dup(cb_dirfd);
	if (fd_for_dir == -1) {
		PDEBUG("could not dup directory fd '%s': %m\n", name);
		return -1;
	}
	dir = fdopendir(fd_for_dir);
	if (!dir) {
		PDEBUG("could not open directory '%s' from fd '%d': %m\n", name, fd_for_dir);
		close(fd_for_dir);
		return -1;
	}

	while ((ent = readdir(dir))) {
		if (cb) {
			rc = (*cb)(cb_dirfd, ent, data);
			if (rc) {
				PDEBUG("dir_for_each callback failed for '%s'\n",
				       ent->d_name);
				goto out;
			}
		}
	}
	errno = save;

out:
	closedir(dir);
	return rc;
}


#define max(a, b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#define CHUNK 32
struct overlaydir {
	int dirfd;
	struct dirent *dent;
};

static int insert(struct overlaydir **overlayptr, int *max_size, int *size,
		  int pos, int remaining, int dirfd, struct dirent *ent)
{
	struct overlaydir *overlay = *overlayptr;
	int i, chunk = max(remaining, CHUNK);

	if (size + 1 >= max_size) {
		struct overlaydir *tmp = reallocarray(overlay,
						      *max_size + chunk,
						      sizeof(*overlay));
		if (tmp == NULL)
			return -1;
		overlay = tmp;
	}
	*max_size += chunk;
	(*size)++;
	for (i = *size; i > pos; i--)
		overlay[i] = overlay[i - 1];
	overlay[pos].dirfd = dirfd;
	overlay[pos].dent = ent;

	*overlayptr = overlay;
	return 0;
}

#define merge(overlay, n_overlay, max_size, list, n_list, dirfd)	\
({									\
	int y, z;							\
	int rc = 0;							\
									\
	for (y = 0, z = 0; y < n_overlay && z < n_list; ) {		\
		int res = strcmp(overlay[y].dent->d_name, list[z]->d_name);\
		if (res < 0) {						\
			y++;						\
			continue;					\
		} else if (res == 0) {					\
			free(list[z]);					\
			list[z] = NULL;					\
			y++;						\
			z++;						\
		} else {						\
			if ((rc = insert(&overlay, &max_size, &n_overlay, y,\
					 n_list - z, dirfd, list[z])))	\
				goto fail;				\
			y++;						\
			list[z++] = NULL;				\
		}							\
	}								\
	while (z < n_list) {						\
		if ((rc = insert(&overlay, &max_size, &n_overlay, y,	\
				 n_list - z, dirfd,list[z])))		\
			goto fail;					\
		y++;							\
		list[z++] = NULL;					\
	}								\
									\
fail:									\
	rc;								\
})

static ssize_t readdirfd(int dirfd, struct dirent ***out,
			  int (*dircmp)(const struct dirent **, const struct dirent **))
{
	struct dirent **dents = NULL, *dent;
	ssize_t n = 0, i;
	int save;
	DIR *dir;

	*out = NULL;

	/*
	 * closedir(dir) will close the underlying fd, so we need
	 * to dup first
	 */
	if ((dirfd = dup(dirfd)) < 0) {
		PDEBUG("dup of dirfd failed: %m\n");
		return -1;
	}

	if ((dir = fdopendir(dirfd)) == NULL) {
		PDEBUG("fdopendir of dirfd failed: %m\n");
		close(dirfd);
		return -1;
	}

	/* Get number of directory entries */
	while ((dent = readdir(dir)) != NULL) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;
		n++;
	}
	rewinddir(dir);

	dents = calloc(n, sizeof(struct dirent *));
	if (!dents)
		goto fail;

	for (i = 0; i < n; ) {
		size_t len;
		if ((dent = readdir(dir)) == NULL) {
			PDEBUG("readdir of entry[%d] failed: %m\n", i);
			goto fail;
		}

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		len = offsetof(struct dirent, d_name) + strlen(dent->d_name) + 1;

		dents[i] = calloc(1, sizeof(*dents[i]));
		if (!dents[i])
			goto fail;
		memcpy(dents[i], dent, len);
		i++;
	}

	if (dircmp)
		qsort(dents, n, sizeof(struct dirent *), (int (*)(const void *, const void *))dircmp);

	*out = dents;
	closedir(dir);
	return n;

fail:
	save = errno;
	if (dents) {
		for (i = 0; i < n; i++)
			free(dents[i]);
	}
	free(dents);
	closedir(dir);
	errno = save;
	return -1;
}

int _aa_overlaydirat_for_each(int dirfd[], int n, void *data,
			int (* cb)(int, const char *, struct stat *, void *))
{
	autofree struct dirent **list = NULL;
	autofree struct overlaydir *overlay = NULL;
	int i;
	int n_list, size = 0, max_size = 0;
	int rc = 0;

	for (i = 0; i < n; i++) {
		n_list = readdirfd(dirfd[i], &list, alphasort);
		if (n_list == -1) {
			PDEBUG("scandirat of dirfd[%d] failed: %m\n", i);
			return -1;
		}
		if (merge(overlay, size, max_size, list, n_list, dirfd[i])) {
			for (i = 0; i < n_list; i++)
				free(list[i]);
			for (i = 0; i < size; i++)
				free(overlay[i].dent);
			return -1;
		}
	}

	for (rc = 0, i = 0; i < size; i++) {
		/* Must cycle through all dirs so that each one is autofreed */
		autofree struct dirent *dent = overlay[i].dent;
		struct stat my_stat;

		if (rc)
			continue;

		if (fstatat(overlay[i].dirfd, dent->d_name, &my_stat,
			    AT_SYMLINK_NOFOLLOW)) {
			PDEBUG("stat failed for '%s': %m\n", dent->d_name);
			rc = -1;
			continue;
		}

		if (cb(overlay[i].dirfd, dent->d_name, &my_stat, data)) {
			PDEBUG("dir_for_each callback failed for '%s'\n",
			       dent->d_name);
			rc = -1;
			continue;
		}
	}

	return rc;
}

/**
 * _aa_dirat_for_each: iterate over a directory calling cb for each entry
 * @dirfd: already opened directory
 * @name: name of the directory (NOT NULL)
 * @data: data pointer to pass to the callback fn (MAY BE NULL)
 * @cb: the callback to pass entry too (NOT NULL)
 *
 * Iterate over the entries in a directory calling cb for each entry.
 * The directory to iterate is determined by a combination of @dirfd and
 * @name.
 *
 * See the openat section of the open(2) man page for details on valid @dirfd
 * and @name combinations. This function does accept AT_FDCWD as @dirfd if
 * @name should be considered relative to the current working directory.
 *
 * Pass "." for @name if @dirfd is the directory to iterate over.
 *
 * The cb function is called with the DIR in use and the name of the
 * file in that directory.  If the file is to be opened it should
 * use the openat, fstatat, and related fns. If the file is a symlink
 * _aa_dirat_for_each currently tries to traverse it for the caller
 *
 * Returns: 0 on success, else -1 and errno is set to the error code
 */
int _aa_dirat_for_each(int dirfd, const char *name, void *data,
		       int (* cb)(int, const char *, struct stat *, void *))
{
	autofree struct dirent **namelist = NULL;
	autoclose int cb_dirfd = -1;
	int i, num_dirs, rc;

	if (!cb || !name) {
		errno = EINVAL;
		return -1;
	}

	cb_dirfd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (cb_dirfd == -1) {
		PDEBUG("could not open directory '%s': %m\n", name);
		return -1;
	}

	num_dirs = readdirfd(cb_dirfd, &namelist, alphasort);
	if (num_dirs == -1) {
		PDEBUG("scandirat of directory '%s' failed: %m\n", name);
		return -1;
	}

	for (rc = 0, i = 0; i < num_dirs; i++) {
		/* Must cycle through all dirs so that each one is autofreed */
		autofree struct dirent *dir = namelist[i];
		struct stat my_stat;

		if (fstatat(cb_dirfd, dir->d_name, &my_stat, AT_SYMLINK_NOFOLLOW)) {
			PDEBUG("stat failed for '%s': %m\n", dir->d_name);
			rc = -1;
			continue;
		}
		/* currently none of the callers handle symlinks, and this
		 * same basic code was applied to each. So for this patch
		 * just drop it here.
		 *
		 * Going forward we need to start handling symlinks as
		 * they have meaning.
		 * In the case of
		 * cache: they act as a place holder for files that have been
		 *        combined into a single binary. This enables the
		 *        file based cache lookup time find that relation
		 *        and dedup, so multiple loads aren't done.
		 * profiles: just a profile in an alternate location, but
		 *           should do dedup detection when doing dir reads
		 *           so we don't double process.
		 */
		if (S_ISLNK(my_stat.st_mode)) {
			/* just traverse the symlink */
			if (fstatat(cb_dirfd, dir->d_name, &my_stat, 0)) {
				PDEBUG("symlink target stat failed for '%s': %m\n", dir->d_name);
				rc = -1;
				continue;
			}
		}

		if (cb(cb_dirfd, dir->d_name, &my_stat, data)) {
			PDEBUG("dir_for_each callback failed for '%s'\n",
			       dir->d_name);
			rc = -1;
			continue;
		}
	}

	return rc;
}
