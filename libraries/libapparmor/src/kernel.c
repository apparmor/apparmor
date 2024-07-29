/*
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2010 Canonical Ltd.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <mntent.h>
#include <inttypes.h>
#include <pthread.h>

#include <sys/apparmor.h>
#include "private.h"

/* some non-Linux systems do not define a static value */
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#define symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@" #version)
#define default_symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@@" #version)
#define DLLEXPORT __attribute__((visibility("default"),externally_visible))

#define UNCONFINED		"unconfined"
#define UNCONFINED_SIZE		strlen(UNCONFINED)

/*
 * AppArmor kernel interfaces. Potentially used by this code to
 * implement the various library functions.
 *
 *
 * /sys/module/apparmor/parameters/ *
 *
 * Available on all kernels, some options may not be available and policy
 * may block access.
 *     audit                - normal,quiet_denied,quiet,noquiet,all
 *     debug (bool)         - turn on debug messages if enabled during compile
 *     hash_policy (bool)   - provide a hash of loaded policy
 *     logsyscall (bool)    - ignored
 *     paranoid_load (bool) - whether full policy checks are done. Should only
 *                            be disabled for embedded device kernels
 *     audit_header (bool)  - include "apparmor=<mode> in messages"
 *     enabled (bool)       - whether apparmor is enabled. This can be
 *                            different than whether apparmor is available.
 *                            See virtualization and LSM stacking.
 *     lock_policy (bool)   - one way trigger. Once set policy can not be
 *                            loaded, replace, removed.
 *      mode                - global policy namespace control of whether
 *                            apparmor is in "enforce", "complain"
 *      path_max            - maximum path size. Can always be read but
 *                            can only be set on some kernels.
 *
 * securityfs/apparmor - usually mounted at /sys/kernel/security/apparmor/ *
 *     .access    - transactional interface used to query kernel
 *     .ns_level  - RO policy namespace level of current task
 *     .ns_name   - RO current policy namespace of current task
 *     .ns_stacked - RO boolean if stacking is in use with the namespace
 *     .null - special device file used to redirect closed fds to
 *     profiles   - RO virtualized text list of visible loaded profiles
 *     .remove    - WO names of profiles to remove
 *     .replace   - WO binary policy to replace (will load if not present)
 *     .load      - WO binary policy to load (will fail if already present)
 *     revision   - RO unique incrementing revision number for policy
 *     .stacked   - RO boolean if label is currently stacked
 *     features/  - RO feature set supported by kernel
 *     policy/    - RO policy loaded into kernel
 *
 *
 * /proc/<tid>/attr/apparmor/ *
 * New proc attr interface compatible with LSM stacking. Available even
 * when LSM stacking is not in use.
 *     current    - see /proc/<tid>/attr/current
 *     exec       - see /proc/<tid>/attr/exec
 *     prev       - see /proc/<tid>/attr/prev
 *
 * /proc/<tid>/attr/ * Old proc attr interface shared between LSMs goes
 * to first registered LSM that wants the proc interface, but can be
 * virtualized by setting the display LSM. So if LSM stacking is in
 * use this interface may belong to another LSM. Use
 *    /proc/<tid>/attr/apparmor/ *
 * first if possible, and do NOT use if
 *    /sys/module/apparmor/parameters/enabled=N.
 * Note: older version of the library only used this interface and did not
 *       check if it was available. Which could lead to weird failures if
 *       another LSM has claimed it. This version of the library tries to
 *       fix this problem, but unfortunately it is impossible to completely
 *       address, because access to interfaces required to determine
 *       whether apparmor owns the interface may be restricted, either
 *       by existing apparmor policy that has not been updated to use the
 *       new interface or by another LSM.
 *     current    - current confinement
 *     display    - LSM stacking. Which LSM currently owns the interface.
 *     exec       - label to switch to at exec
 *     fscreate   - unused by apparmor
 *     keycreate  - unused by apparmor
 *     prev       - when in HAT set to parent label
 *     sockcreate - unused by apparmor
 *
 *
 * Below /proc/ interface combinations are documented on how the library
 * currently behaves and how it used to behave. This serves to document
 * known failure points as we can not entirely fix this mess.
 * Note: userspace applications using the interface directly have all
 *       the issues/failures of AppArmor 2.x unless they have specifically
 *       been updated to deal with this mess.
 *
 *
 * AppArmor 2.x Lib
 *
 * LSM   AA            sys      sys    proc/   proc/   user
 * Stk | Blt |  LSM  | enabl | avail |  aa/  |   *   | space |
 * ----+-----+-------+-------+-------+-------+-------+-------+--------+
 *  N  |  N  |   -   |   -   |   -   |   -   |   N   | AA2.x |   -    |
 *  N  |  N  | other |   -   |   -   |   -   |   N   | AA2.x |  FAIL  |
 *  N  |  N  | other |denied |   -   |   -   |   N   | AA2.x |  FAIL  |
 *  N  |  Y  |   -   |   N   |   -   |   -   |   N   | AA2.x |   -    |
 *  N  |  Y  | other |   -   |   -   |   -   |   N   | AA2.x |  FAIL  |
 *  N  |  Y  |  AA   |   -   |   -   |   -   |   Y   | AA2.x |  PASS  |
 *  Y  |  N  |   -   |   -   |   -   |   -   |   N   | AA2.x |   -    |
 *  Y  |  N  | other |   -   |   -   |   -   |   N   | AA2.x |  FAIL  |
 *  Y  |  Y  |   -   |   N   |   -   |   -   |   N   | AA2.x |   -    |
 *  Y  |  Y  | other |   -   |   -   |   -   |   N   | AA2.x |  FAIL  |
 *  Y  |  Y  |  AA   |   -   |   -   |   -   |   Y   | AA2.x |  PASS  |
 *  Y  |  Y  | major |   -   |   -   |   -   |   Y   | AA2.x |  PASS  |
 *  Y  |  Y  | minor |   -   |   -   |   -   |   N   | AA2.x |  FAIL  |
 *
 *
 * AppArmor 3.x Lib - adds stacking support.
 *
 * Will FAIL in a few cases because it can not determine if apparmor
 * is enabled and has control of the old interface. Not failing in these
 * cases where AppArmor is available will result in regressions where
 * the library will not work correctly with old kernels. In these
 * cases its better that apparmor userspace is not used.
 *
 * AppArmor 3.x will avoid the failure cases if any of enabled, avail
 * or the new proc interfaces are available to the task. AppArmor 3.x
 * will also automatically add permissions to access the new proc
 * interfaces so change_hat and change_profile won't experience these
 * failures, it will only happen for confined applications hitting the
 * interfaces and not using change_hat or change_profile.
 *
 * LSM   AA            sys      sys    proc/   proc/
 * Stk | Blt |  LSM  | enabl | avail |  aa/  |   *   |
 * ----+-----+-------+-------+-------+-------+-------+-----------------
 * Y/N |  N  | other | denied|   NA  |   NA  |   Y   | old interface avail
 * Y/N |  Y  | other | denied|   NA  |   NA  |   Y   | old interface avail
 *  Y  |  Y  | minor | denied|   NA  |   NA  |   Y   | old interface avail
 *  Y  |  Y  | minor | denied|   NA  | denied|   Y   | old interface avail
 * Y/N |  Y  | minor | denied| denied| denied|   Y   | old interface avail
 */

/**
 * aa_find_mountpoint - find where the apparmor interface filesystem is mounted
 * @mnt: returns buffer with the mountpoint string
 *
 * Returns: 0 on success else -1 on error
 *
 * NOTE: this function only supports versions of apparmor using securityfs
 */
int aa_find_mountpoint(char **mnt)
{
	struct stat statbuf;
	struct mntent *mntpt;
	FILE *mntfile;
	int rc = -1;

	if (!mnt) {
		errno = EINVAL;
		return -1;
	}

	mntfile = setmntent("/proc/mounts", "r");
	if (!mntfile)
		return -1;

	while ((mntpt = getmntent(mntfile))) {
		char *proposed = NULL;
		if (strcmp(mntpt->mnt_type, "securityfs") != 0)
			continue;

		if (asprintf(&proposed, "%s/apparmor", mntpt->mnt_dir) < 0)
			/* ENOMEM */
			break;

		if (stat(proposed, &statbuf) == 0) {
			*mnt = proposed;
			rc = 0;
			break;
		}
		free(proposed);
	}
	endmntent(mntfile);
	if (rc == -1)
		errno = ENOENT;
	return rc;
}

/**
 * pararm_check_base - return boolean value for PARAM
 * PARAM: parameter to check
 *
 * Returns: 1 == Y
 *          0 == N
 *         <0 == error
 *
 * done as a macro so we can paste the param
 */

#define param_check_base(PARAM)						\
({									\
	int rc, fd;							\
	fd = open("/sys/module/apparmor/parameters/" PARAM, O_RDONLY);	\
	if (fd == -1) {							\
		rc = -errno;						\
	} else {							\
		char buffer[2];						\
		int size = read(fd, &buffer, 2);			\
		rc = -errno;						\
		close(fd);						\
		errno = -rc;						\
		if (size > 0) {						\
			if (buffer[0] == 'Y')				\
				rc = 1;					\
			else						\
				rc = 0;					\
		}							\
	}								\
	(rc);								\
})

static pthread_once_t param_enabled_ctl = PTHREAD_ONCE_INIT;
static int param_enabled = 0;

static pthread_once_t param_private_enabled_ctl = PTHREAD_ONCE_INIT;
static int param_private_enabled = 0;

static void param_check_enabled_init_once(void)
{
	param_enabled = param_check_base("enabled");
}

static int param_check_enabled()
{
	if (pthread_once(&param_enabled_ctl, param_check_enabled_init_once) == 0 && param_enabled >= 0)
		return param_enabled;
	/* fallback if not initialized OR we recorded an error when
	 * initializing.
	 */
	return param_check_base("enabled");
}

static int is_enabled(void)
{
	return param_check_enabled() == 1;
}

static void param_check_private_enabled_init_once(void)
{
	param_private_enabled = param_check_base("available");
}

static int param_check_private_enabled()
{
	if (pthread_once(&param_private_enabled_ctl, param_check_private_enabled_init_once) == 0 && param_private_enabled >= 0)
		return param_private_enabled;
	/* fallback if not initialized OR we recorded an error when
	 * initializing.
	 */
	return param_check_base("available");
}

static int is_private_enabled(void)
{
	return param_check_private_enabled() == 1;
}

/**
 * aa_is_enabled - determine if apparmor is enabled
 *
 * Returns: 1 if enabled else reason it is not, or 0 on error
 *
 * ENOSYS - no indication apparmor is present in the system
 * ENOENT - enabled but interface could not be found
 * ECANCELED - disabled at boot
 * ENOMEM - out of memory
 */
int aa_is_enabled(void)
{
	int rc;
	char *mnt;
	bool private = false;

	rc = param_check_enabled();
	if (rc < 1) {
		if (!is_private_enabled()) {
			if (rc == 0)
				errno = ECANCELED;
			else if (rc == -ENOENT)
				errno = ENOSYS;
			else
				errno = -rc;

			return 0;
		}
		/* actually available but only on private interfaces */
		private = true;
	}

	/* if the interface mountpoint is available apparmor may not
	 * be locally enabled for older interfaces but still present
	 * so make sure to check after, checking available status
	 * also we don't cache the enabled status like available
	 * because the mount status can change.
	 */
	rc = aa_find_mountpoint(&mnt);
	if (rc == 0) {
		free(mnt);
		if (!private)
			return 1;
		/* provide an error code to indicate apparmor is available
		 * on private interfaces, but we can note that apparmor
		 * is enabled because some applications hit the low level
		 * interfaces directly and don't know about the new
		 * private interfaces
		 */
		errno = EBUSY;
		/* fall through to return 0 */
	}

	return 0;
}

static inline pid_t aa_gettid(void)
{
#ifdef SYS_gettid
	return syscall(SYS_gettid);
#else
	return getpid();
#endif
}

/*
 * Check for the new apparmor proc interface once on the first api call
 * and then reuse the result on all subsequent api calls. This avoids
 * a double syscall overhead on each api call if the interface is not
 * present.
 */
static pthread_once_t proc_attr_base_ctl = PTHREAD_ONCE_INIT;
static const char *proc_attr_base_old = "/proc/%d/attr/%s";
static const char *proc_attr_new_dir = "/proc/%d/attr/apparmor/";
static const char *proc_attr_base_stacking = "/proc/%d/attr/apparmor/%s";
static const char *proc_attr_base_unavailable = "/proc/%d/attr/apparmor/unavailable/%s";
static const char *proc_attr_base = NULL;
static int proc_stacking_present = -1;	/* unknown */

static void proc_attr_base_init_once(void)
{
	autofree char *tmp;

	/* if we fail we just fall back to the default value */
	if (asprintf(&tmp, proc_attr_new_dir, aa_gettid()) > 0) {
		struct stat sb;
		if (stat(tmp, &sb) == 0) {
			proc_attr_base = proc_attr_base_stacking;
			proc_stacking_present = 1;
			return;
		} else if (errno == ENOENT) {
			/* no stacking - try falling back */
			proc_stacking_present = 0;
		} else if (errno == EACCES) {
			/* the dir exists, but access is denied */
			proc_stacking_present = 1;
			proc_attr_base = proc_attr_base_stacking;
		} /* else
			   denied by policy, or other error try falling back */
	} else {
		/* failed allocation - proc_attr_base stays NULL */
		return;
	}
	/* check for new interface failed, see if we can fallback */
	if (param_check_enabled() == 0) {
		/* definate NO (not just an error) on enabled. Do not fall
		 * back to old shared proc interface
		 *
		 * First try an alternate check for private proc interface
		 */
		int enabled = param_check_private_enabled();
		if (enabled == 1) {
			/* the private interface exists and we can't
			 * fallback so just keep trying on the new
			 * interface.
			 */
			proc_attr_base = proc_attr_base_stacking;
		} else if (enabled == 0) {
			/* definite NO - no interface available */
			proc_attr_base = proc_attr_base_unavailable;
		} else {
			/* error can't determine, proc_attr_base stays NULL */
		}
	} else if (param_check_enabled() == 1) {
		/* apparmor is enabled, we can use the old interface */
		proc_attr_base = proc_attr_base_old;
	} else if (errno != EACCES) {
		/* this shouldn't happen unless apparmor is not builtin
		 * or proc isn't mounted
		 */
		proc_attr_base = proc_attr_base_unavailable;
	} /* else
		   denied by policy - proc_attr_base stays NULL */

	return;
}

static char *procattr_path(pid_t pid, const char *attr)
{
	char *path = NULL;
	const char *tmp;

	/* TODO: rework this with futex or userspace RCU so we can update
	 * the base value instead of continually using the same base
	 * after we have hit an error
	 */
	/* ignore failure, we just fallback to the default value */
	(void) pthread_once(&proc_attr_base_ctl, proc_attr_base_init_once);

	if (proc_attr_base)
		tmp = proc_attr_base;
	else if (proc_stacking_present)
		/* couldn't determine during init */
		tmp = proc_attr_base_stacking;
	else
		/* couldn't determine during init and no stacking */
		tmp = proc_attr_base_old;
	if (asprintf(&path, tmp, pid, attr) > 0)
		return path;
	return NULL;
}

static int procattr_open(pid_t tid, const char *attr, int flags)
{
	autofree char *tmp = NULL;
	int fd;

	tmp = procattr_path(tid, attr);
	if (!tmp) {
		return -1;
	}
	fd = open(tmp, flags);

	/* Test is we can fallback to the old interface (this is ugly).
	 * If we haven't tried the old interface already
	 *    proc_attr_base == proc_attr_base_old - no fallback
	 * else if is_enabled()
	 *    apparmor is available on the old interface
	 *    we do NOT use is_private_enabled() as
	 *    1. the new private interface would have been tried first above
	 *    2. that can be true even when another LSM is using the
	 *       old interface where is_enabled() is only successful if
	 *       the old interface is available to apparmor.
	 */
	if (fd == -1 && param_check_enabled() != 0 && strncmp(tmp, proc_attr_base_old, strlen(proc_attr_base_old)) != 0) {
		free(tmp);
		if (asprintf(&tmp, proc_attr_base_old, tid, attr) < 0) {
			/* tmp is undefined, make sure it is null for autofree*/
			tmp = NULL;
			return -1;
		}
		fd = open(tmp, flags);
	}

	return fd;
}

/**
 * parse_unconfined - check for the unconfined label
 * @con: the confinement context
 * @size: size of the confinement context (not including the NUL terminator)
 *
 * Returns: True if the con is the unconfined label or false otherwise
 */
static bool parse_unconfined(char *con, int size)
{
	return size == UNCONFINED_SIZE &&
	       strncmp(con, UNCONFINED, UNCONFINED_SIZE) == 0;
}

/**
 * splitcon - split the confinement context into a label and mode
 * @con: the confinement context
 * @size: size of the confinement context (not including the NUL terminator)
 * @strip_newline: true if a trailing newline character should be stripped
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *  on success
 *
 * Modifies the @con string to split it into separate label and mode strings.
 * If @strip_newline is true and @con contains a single trailing newline, it
 * will be stripped on success (it will not be stripped on error). The @mode
 * argument is optional. If @mode is NULL, @con will still be split between the
 * label and mode (if present) but @mode will not be set.
 *
 * Returns: a pointer to the label string or NULL on error
 */
static char *splitcon(char *con, int size, bool strip_newline, char **mode)
{
	char *label = NULL;
	char *mode_str = NULL;
	char *newline = NULL;

	if (size == 0)
		goto out;

	if (strip_newline && con[size - 1] == '\n') {
		newline = &con[size - 1];
		size--;
	}

	if (parse_unconfined(con, size)) {
		label = con;
		goto out;
	}

	if (size > 3 && con[size - 1] == ')') {
		int pos = size - 2;

		while (pos > 0 && !(con[pos] == ' ' && con[pos + 1] == '('))
			pos--;
		if (pos > 0) {
			con[pos] = 0; /* overwrite ' ' */
			con[size - 1] = 0; /* overwrite trailing ) */
			mode_str = &con[pos + 2]; /* skip '(' */
			label = con;
		}
	}
out:
	if (label && strip_newline && newline)
		*newline = 0; /* overwrite '\n', if requested, on success */
	if (mode)
		*mode = mode_str;
	return label;
}

/**
 * aa_splitcon - split the confinement context into a label and mode
 * @con: the confinement context
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *  on success
 *
 * Modifies the @con string to split it into separate label and mode strings. A
 * single trailing newline character will be stripped from @con, if found. The
 * @mode argument is optional. If @mode is NULL, @con will still be split
 * between the label and mode (if present) but @mode will not be set.
 *
 * Returns: a pointer to the label string or NULL on error
 */
char *aa_splitcon(char *con, char **mode)
{
	return splitcon(con, strlen(con), true, mode);
}

/**
 * aa_getprocattr_raw - get the contents of @attr for @tid into @buf
 * @tid: tid of task to query
 * @attr: which /proc/<tid>/attr/<attr> to query
 * @buf: buffer to store the result in
 * @len: size of the buffer
 * @mode: if non-NULL and a mode is present, will point to mode string in @buf
 *
 * Returns: size of data read or -1 on error, and sets errno
 */
int aa_getprocattr_raw(pid_t tid, const char *attr, char *buf, int len,
		       char **mode)
{
	int rc = -1;
	int fd, ret;
	char *tmp = NULL;
	int size = 0;

	if (!buf || len <= 0) {
		errno = EINVAL;
		goto out;
	}

	fd = procattr_open(tid, attr, O_RDONLY);
	if (fd == -1) {
		goto out;
	}

	tmp = buf;
	do {
		ret = read(fd, tmp, len);
		if (ret <= 0)
			break;
		tmp += ret;
		size += ret;
		len -= ret;
		if (len < 0) {
			errno = ERANGE;
			goto out2;
		}
	} while (ret > 0);

	if (ret < 0) {
		int saved;
		if (ret != -1) {
			errno = EPROTO;
		}
		saved = errno;
		(void)close(fd);
		errno = saved;
		goto out;
	} else if (size > 0 && buf[size - 1] != 0) {
		/* check for null termination */
		if (buf[size - 1] != '\n') {
			if (len == 0) {
				errno = ERANGE;
				goto out2;
			} else {
				buf[size] = 0;
				size++;
			}
		}

		if (splitcon(buf, size, true, mode) != buf) {
			errno = EINVAL;
			goto out2;
		}
	}
	rc = size;

out2:
	(void)close(fd);
out:
	return rc;
}

#define INITIAL_GUESS_SIZE 128

/**
 * aa_getprocattr - get the contents of @attr for @tid into @label and @mode
 * @tid: tid of task to query
 * @attr: which /proc/<tid>/attr/<attr> to query
 * @label: allocated buffer the label is stored in
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns: size of data read or -1 on error, and sets errno
 *
 * Guarantees that @label and @mode are null terminated.  The length returned
 * is for all data including both @label and @mode, and maybe > than
 * strlen(@label) even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @label.  @mode is
 * always contained within @label's buffer and so NEVER do free(@mode)
 */
int aa_getprocattr(pid_t tid, const char *attr, char **label, char **mode)
{
	int rc, size = INITIAL_GUESS_SIZE/2;
	char *buffer = NULL;

	if (!label) {
		errno = EINVAL;
		return -1;
	}

	do {
		char *tmp;

		size <<= 1;
		tmp = realloc(buffer, size);
		if (!tmp) {
			free(buffer);
			return -1;
		}
		buffer = tmp;
		memset(buffer, 0, size);

		rc = aa_getprocattr_raw(tid, attr, buffer, size, mode);
	} while (rc == -1 && errno == ERANGE);

	if (rc == -1) {
		free(buffer);
		*label = NULL;
		if (mode)
			*mode = NULL;
	} else
		*label = buffer;

	return rc;
}

#ifdef HAVE_LINUX_LSM_H
#include <linux/lsm.h>
#else
#define LSM_ATTR_CURRENT	100
#define LSM_ATTR_EXEC		101
#define LSM_ATTR_PREV		104
#endif

// #ifdef HAVE_LINUX_LSM_H is not enough as some custom <6.8 kernel cherrypicked a 'custom' lsm.h, without actually supporting lsm syscalls (e.g. Ubuntu Mantic's 6.5.0-x).
#if defined(HAVE_LINUX_LSM_H) && defined(__NR_lsm_get_self_attr) && defined(__NR_lsm_set_self_attr)

#ifndef lsm_get_self_attr
static inline int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,
				    __u32 *size, __u32 flags)
{
	return syscall(__NR_lsm_get_self_attr, attr, ctx, size, flags);
}
#endif

#ifndef lsm_set_self_attr
static inline int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,
				    __u32 size, __u32 flags)
{
	return syscall(__NR_lsm_set_self_attr, attr, ctx, size, flags);
}
#endif

static int get_apparmor_attr_raw(__u32 op_type, struct lsm_ctx *ctx, __u32 sz)
{
	__u32 req_sz = sz;
	int result;

	if (!ctx)
		return -1;

	result = lsm_get_self_attr(op_type, ctx, &req_sz, LSM_FLAG_SINGLE);
	if (result >= 0 || // Success
	    (result == -1 && errno == E2BIG) // Buffer too small
	)
		return (int)req_sz;
	else
		return result;
}

/**
 * aa_get_self_attr - gets an attribute for current process
 * @param op_type The lsm attribute to get
 * @label: pointer to returned buffer with the label
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns the int-aligned size of @label. On error, returns -1 and sets errno.
 *
 * The calling thread is responsible for freeing @label.
 * As @mode is always a substring of @label, it should NOT be freed manually
 */
int aa_get_self_attr(int op_type, char **label, char **mode)
{
	size_t total_size = INITIAL_GUESS_SIZE;
	struct lsm_ctx *ctx = malloc(total_size);
	struct lsm_ctx *tmp_ctx;
	int rc = -1;
	int size;

	if (!ctx)
		goto out;

	ctx->id = LSM_ID_APPARMOR;
	ctx->flags = 0;
	ctx->len = total_size;
	ctx->ctx_len = total_size - sizeof(struct lsm_ctx);
	rc = get_apparmor_attr_raw(op_type, ctx, total_size);
	if (rc <= (int)total_size)
		goto out;

	// Insufficient size: we try again with the good size
	tmp_ctx = realloc(ctx, rc);
	if (!tmp_ctx) {
		rc = -1;
		goto out;
	}
	ctx = tmp_ctx;
	size = get_apparmor_attr_raw(op_type, ctx, rc);
	if (size > rc) { // Insufficient size: Should never happen
		rc = -1;
		goto out;
	}
	rc = size;
out:
	if (rc > 0) {
		rc -= sizeof(struct lsm_ctx);
		*label = aa_splitcon((char *)ctx->ctx, mode);
	} else {
		*label = NULL;
		*mode = NULL;
	}
	free(ctx);
	return rc;
}

/**
 * aa_set_self_attr - sets an attribute for current process
 * @param op_type The lsm attribute to set
 * @operation: The buffer to set the attribute
 * @op_len: The length of @buf
 *
 * Returns 0 on success. On error, returns -1 and sets errno.
 */
int aa_set_self_attr(int op_type, char *operation, int op_len)
{
	size_t total_size = sizeof(struct lsm_ctx) + op_len;
	struct lsm_ctx *ctx = (struct lsm_ctx *)malloc(total_size);
	int ret;

	ctx->id = LSM_ID_APPARMOR;
	ctx->flags = LSM_FLAG_SINGLE;
	ctx->len = total_size;
	ctx->ctx_len = op_len;
	memcpy(ctx->ctx, operation, op_len);
	ret = lsm_set_self_attr(op_type, ctx, total_size, 0);
	free(ctx);
	return ret;
}

#else


/**
 * aa_get_self_attr - gets an attribute for current process
 * @param op_type The lsm attribute to get
 * @label: pointer to returned buffer with the label
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns the size of @label. On error, returns -1 and sets errno.
 *
 * The calling thread is responsible for freeing @label.
 * As @mode is always a substring of @label, it should NOT be freed manually
 */
int aa_get_self_attr(int op_type, char **label, char **mode)
{
	char *iface = get_iface_name(op_type);

	if (!iface) {
		errno = -EINVAL;
		return -1;
	}
	return aa_getprocattr(aa_gettid(), iface, label, mode);
}

static int setprocattr(pid_t tid, const char *attr, const char *buf, int len)
{
	int rc = -1;
	int fd, ret;

	if (!buf) {
		errno = EINVAL;
		goto out;
	}

	fd = procattr_open(tid, attr, O_WRONLY);
	if (fd == -1) {
		goto out;
	}

	ret = write(fd, buf, len);
	if (ret != len) {
		int saved;
		if (ret != -1) {
			errno = EPROTO;
		}
		saved = errno;
		(void)close(fd);
		errno = saved;
		goto out;
	}

	rc = 0;
	(void)close(fd);

out:
	return rc;
}

/**
 * aa_set_self_attr - sets an attribute for current process
 * @param op_type The lsm attribute to set
 * @buf: The buffer to set the attribute
 * @mode: The length of @buf
 *
 * Returns 0 on success. On error, returns -1 and sets errno.
 */
int aa_set_self_attr(int op_type, char *buf, int len)
{
	char *iface = get_iface_name(op_type);

	if (!iface) {
		errno = -EINVAL;
		return -1;
	}
	return setprocattr(aa_gettid(), iface, buf, len);
}

#endif

char *get_iface_name(int op)
{
	switch (op) {
	case LSM_ATTR_CURRENT:
		return "current";
	case LSM_ATTR_EXEC:
		return "exec";
	case LSM_ATTR_PREV:
		return "prev";
	default:
		return NULL;
	}
}

int aa_change_hat(const char *subprofile, unsigned long token)
{
	int rc = -1;
	int len = 0;
	char *buf = NULL;
	const char *fmt = "changehat %016lx^%s";

	/* both may not be null */
	if (!(token || subprofile)) {
		errno = EINVAL;
		goto out;
	}

	if (subprofile && strnlen(subprofile, PATH_MAX + 1) > PATH_MAX) {
		errno = EPROTO;
		goto out;
	}

	len = asprintf(&buf, fmt, token, subprofile ? subprofile : "");
	if (len < 0) {
		goto out;
	}

	rc = aa_set_self_attr(LSM_ATTR_CURRENT, buf, len);
out:
	if (buf) {
		/* clear local copy of magic token before freeing */
		memset(buf, '\0', len);
		free(buf);
	}
	return rc;
}

/* original change_hat interface */
int __change_hat(char *subprofile, unsigned int token)
{
	return aa_change_hat(subprofile, (unsigned long) token);
}

int aa_change_profile(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "changeprofile %s", profile);
	if (len < 0)
		return -1;

	rc = aa_set_self_attr(LSM_ATTR_CURRENT, buf, len);

	free(buf);
	return rc;
}

int aa_change_onexec(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "exec %s", profile);
	if (len < 0)
		return -1;

	rc = aa_set_self_attr(LSM_ATTR_EXEC, buf, len);

	free(buf);
	return rc;
}

/* create an alias for the old change_hat@IMMUNIX_1.0 symbol */
DLLEXPORT extern typeof((__change_hat)) __old_change_hat __attribute__((alias ("__change_hat")));
symbol_version(__old_change_hat, change_hat, IMMUNIX_1.0);
default_symbol_version(__change_hat, change_hat, APPARMOR_1.0);


int aa_change_hatv(const char *subprofiles[], unsigned long token)
{
	int size, totallen = 0, hatcount = 0;
	int rc = -1;
	const char **hats;
	char *pos, *buf = NULL;
	const char *cmd = "changehat";

	/* both may not be null */
	if (!token && !(subprofiles && *subprofiles)) {
		errno = EINVAL;
                goto out;
        }

	/* validate hat lengths and while we are at it count how many and
	 * mem required */
	if (subprofiles) {
		for (hats = subprofiles; *hats; hats++) {
			int len = strnlen(*hats, PATH_MAX + 1);
			if (len > PATH_MAX) {
				errno = EPROTO;
				goto out;
			}
			totallen += len + 1;
			hatcount++;
                }
	}

	/* allocate size of cmd + space + token + ^ + vector of hats */
	size = strlen(cmd) + 18 + totallen + 1;
	buf = malloc(size);
	if (!buf) {
                goto out;
        }

	/* setup command string which is of the form
	 * changehat <token>^hat1\0hat2\0hat3\0..\0
	 */
	sprintf(buf, "%s %016lx^", cmd, token);
	pos = buf + strlen(buf);
	if (subprofiles) {
		for (hats = subprofiles; *hats; hats++) {
			strcpy(pos, *hats);
			pos += strlen(*hats) + 1;
		}
	} else
		/* step pos past trailing \0 */
		pos++;

	rc = aa_set_self_attr(LSM_ATTR_CURRENT, buf, pos - buf);

out:
	if (buf) {
		/* clear local copy of magic token before freeing */
		memset(buf, '\0', size);
		free(buf);
	}

	return rc;
}

/**
 * change_hat_vargs - change_hatv but passing the hats as fn arguments
 * @token: the magic token
 * @nhat: the number of hats being passed in the arguments
 * ...: a argument list of const char * being passed
 *
 * change_hat_vargs can be called directly but it is meant to be called
 * through its macro wrapper of the same name.  Which automatically
 * fills in the nhats arguments based on the number of parameters
 * passed.
 * to call change_hat_vargs direction do
 * (change_hat_vargs)(token, nhats, hat1, hat2...)
 */
int (aa_change_hat_vargs)(unsigned long token, int nhats, ...)
{
	va_list ap;
	const char *argv[nhats+1];
	int i;

	va_start(ap, nhats);
	for (i = 0; i < nhats ; i++) {
		argv[i] = va_arg(ap, char *);
	}
	argv[nhats] = NULL;
	va_end(ap);
	return aa_change_hatv(argv, token);
}

int aa_stack_profile(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "stack %s", profile);
	if (len < 0)
		return -1;

	rc = aa_set_self_attr(LSM_ATTR_CURRENT, buf, len);

	free(buf);
	return rc;
}

int aa_stack_onexec(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "stack %s", profile);
	if (len < 0)
		return -1;

	rc = aa_set_self_attr(LSM_ATTR_EXEC, buf, len);

	free(buf);
	return rc;
}

/**
 * aa_gettaskcon - get the confinement context for task @target in an allocated buffer
 * @target: task to query
 * @label: pointer to returned buffer with the label
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns: length of confinement context or -1 on error and sets errno
 *
 * Guarantees that @label and @mode are null terminated.  The length returned
 * is for all data including both @label and @mode, and maybe > than
 * strlen(@label) even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @label.  @mode is
 * always contained within @label's buffer and so NEVER do free(@mode)
 */
int aa_gettaskcon(pid_t target, char **label, char **mode)
{
	return aa_getprocattr(target, "current", label, mode);
}

/**
 * aa_getcon - get the confinement context for current task in an allocated buffer
 * @label: pointer to return buffer with the label if successful
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns: length of confinement context or -1 on error and sets errno
 *
 * Guarantees that @label and @mode are null terminated.  The length returned
 * is for all data including both @label and @mode, and may > than
 * strlen(@label) even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @label.  @mode is
 * always contained within @label's buffer and so NEVER do free(@mode)
 */
int aa_getcon(char **label, char **mode)
{
	return aa_get_self_attr(LSM_ATTR_CURRENT, label, mode);
}


#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif

/**
 * aa_getpeercon_raw - get the confinement context of the socket's peer (other end)
 * @fd: socket to get peer confinement context for
 * @buf: buffer to store the result in
 * @len: initially contains size of the buffer, returns size of data read
 * @mode: if non-NULL and a mode is present, will point to mode string in @buf
 *
 * Returns: length of confinement context including null termination or -1 on
 *          error if errno == ERANGE then @len will hold the size needed
 */
int aa_getpeercon_raw(int fd, char *buf, socklen_t *len, char **mode)
{
	socklen_t optlen;
	int rc;

	if (*len <= 0 || buf == NULL) {
		errno = EINVAL;
		return -1;
	}
	optlen = *len;

	if (!is_enabled()) {
		errno = EINVAL;
		return -1;
	}
	/* TODO: add check for private_enabled when alternate interface
	 * is approved
	 */
	rc = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &optlen);
	if (rc == -1 || optlen <= 0)
		goto out;

	/* check for null termination */
	if (buf[optlen - 1] != 0) {
		if (optlen < *len) {
			buf[optlen] = 0;
			optlen++;
		} else {
			/* buf needs to be bigger by 1 */
			rc = -1;
			errno = ERANGE;
			optlen++;
			goto out;
		}
	}

	if (splitcon(buf, optlen - 1, false, mode) != buf) {
		rc = -1;
		errno = EINVAL;
		goto out;
	}

	rc = optlen;
out:
	*len = optlen;
	return rc;
}

/**
 * aa_getpeercon - get the confinement context of the socket's peer (other end)
 * @fd: socket to get peer confinement context for
 * @label: pointer to allocated buffer with the label
 * @mode: if non-NULL and a mode is present, will point to mode string in @label
 *
 * Returns: length of confinement context including null termination or -1 on error
 *
 * Guarantees that @label and @mode are null terminated.  The length returned
 * is for all data including both @label and @mode, and maybe > than
 * strlen(@label) even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @label.  @mode is
 * always contained within @label's buffer and so NEVER do free(@mode)
 */
int aa_getpeercon(int fd, char **label, char **mode)
{
	socklen_t last_size, size = INITIAL_GUESS_SIZE;
	int rc;
	char *buffer = NULL;

	if (!label) {
		errno = EINVAL;
		return -1;
	}

	do {
		char *tmp;

		last_size = size;
		tmp = realloc(buffer, size);
		if (!tmp) {
			free(buffer);
			return -1;
		}
		buffer = tmp;
		memset(buffer, 0, size);

		rc = aa_getpeercon_raw(fd, buffer, &size, mode);
		/* size should contain actual size needed if errno == ERANGE */
	} while (rc == -1 && errno == ERANGE && size > last_size);

	if (rc == -1) {
		free(buffer);
		*label = NULL;
		if (mode)
			*mode = NULL;
		size = -1;
	} else
		*label = buffer;

	return size;
}

static pthread_once_t aafs_access_control = PTHREAD_ONCE_INIT;
static char *aafs_access = NULL;

static void aafs_access_init_once(void)
{
	char *aafs;
	int ret;

	ret = aa_find_mountpoint(&aafs);
	if (ret < 0)
		return;

	ret = asprintf(&aafs_access, "%s/.access", aafs);
	if (ret < 0)
		aafs_access = NULL;

	free(aafs);
}

/* "allow 0x00000000\ndeny 0x00000000\naudit 0x00000000\nquiet 0x00000000\n" */
#define QUERY_LABEL_REPLY_LEN	67

/**
 * aa_query_label - query the access(es) of a label
 * @mask: permission bits to query
 * @query: binary query string, must be offset by AA_QUERY_CMD_LABEL_SIZE
 * @size: size of the query string must include AA_QUERY_CMD_LABEL_SIZE
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int query_label(uint32_t mask, char *query, size_t size, int *allowed,
		int *audited)
{
	char buf[QUERY_LABEL_REPLY_LEN];
	uint32_t allow, deny, audit, quiet;
	int fd, ret, saved;

	if (!mask || size <= AA_QUERY_CMD_LABEL_SIZE) {
		errno = EINVAL;
		return -1;
	}

	ret = pthread_once(&aafs_access_control, aafs_access_init_once);
	if (ret) {
		errno = EINVAL;
		return -1;
	} else if (!aafs_access) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(aafs_access, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT)
			errno = EPROTONOSUPPORT;
		return -1;
	}

	memcpy(query, AA_QUERY_CMD_LABEL, AA_QUERY_CMD_LABEL_SIZE);
	errno = 0;
	ret = write(fd, query, size);
	if (ret < 0 || ((size_t) ret != size)) {
		if (ret >= 0)
			errno = EPROTO;
		/* IMPORTANT: This is the only valid error path that can have
		 * errno set to ENOENT. It indicates that the subject label
		 * could not be found by the kernel.
		 */
		(void)close(fd);
		return -1;
	}

	ret = read(fd, buf, QUERY_LABEL_REPLY_LEN);
	saved = errno;
	(void)close(fd);
	errno = saved;
	if (ret != QUERY_LABEL_REPLY_LEN) {
		errno = EPROTO;
		return -1;
	}

	ret = sscanf(buf, "allow 0x%8" SCNx32 "\n"
			  "deny 0x%8"  SCNx32 "\n"
			  "audit 0x%8" SCNx32 "\n"
			  "quiet 0x%8" SCNx32 "\n",
		     &allow, &deny, &audit, &quiet);
	if (ret != 4) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	*allowed = mask & ~(allow & ~deny) ? 0 : 1;
	if (!(*allowed))
		audit = 0xFFFFFFFF;
	*audited = mask & ~(audit & ~quiet) ? 0 : 1;

	return 0;
}

/* export multiple aa_query_label symbols to compensate for downstream
 * releases with differing symbol versions. */
DLLEXPORT extern typeof((query_label)) __aa_query_label __attribute__((alias ("query_label")));
symbol_version(__aa_query_label, aa_query_label, APPARMOR_1.1);
default_symbol_version(query_label, aa_query_label, APPARMOR_2.9);


/**
 * aa_query_file_path_len - query access permissions for a file @path
 * @mask: permission bits to query
 * @label: apparmor label
 * @label_len: length of @label (does not include any terminating nul byte)
 * @path: file path to query permissions for
 * @path_len: length of @path (does not include any terminating nul byte)
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int aa_query_file_path_len(uint32_t mask, const char *label, size_t label_len,
			   const char *path, size_t path_len, int *allowed,
			   int *audited)
{
	autofree char *query = NULL;

	/* + 1 for null separator */
	size_t size = AA_QUERY_CMD_LABEL_SIZE + label_len + 1 + path_len;
	query = malloc(size + 1);
	if (!query)
		return -1;
	memcpy(query + AA_QUERY_CMD_LABEL_SIZE, label, label_len);
	/* null separator */
	query[AA_QUERY_CMD_LABEL_SIZE + label_len] = 0;
	query[AA_QUERY_CMD_LABEL_SIZE + label_len + 1] = AA_CLASS_FILE;
	memcpy(query + AA_QUERY_CMD_LABEL_SIZE + label_len + 2, path, path_len);
	return aa_query_label(mask, query, size , allowed, audited);
}

/**
 * aa_query_file_path - query access permissions for a file @path
 * @mask: permission bits to query
 * @label: apparmor label
 * @path: file path to query permissions for
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int aa_query_file_path(uint32_t mask, const char *label, const char *path,
		       int *allowed, int *audited)
{
	return aa_query_file_path_len(mask, label, strlen(label), path,
				      strlen(path), allowed, audited);
}

/**
 * aa_query_link_path_len - query access permissions for a hard link @link
 * @label: apparmor label
 * @label_len: length of @label (does not include any terminating nul byte)
 * @target: file path that hard link will point to
 * @target_len: length of @target (does not include any terminating nul byte)
 * @link: file path of hard link
 * @link_len: length of @link (does not include any terminating nul byte)
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int aa_query_link_path_len(const char *label, size_t label_len,
			   const char *target, size_t target_len,
			   const char *link, size_t link_len,
			   int *allowed, int *audited)
{
	autofree char *query = NULL;

	/* + 1 for null separators */
	size_t size = AA_QUERY_CMD_LABEL_SIZE + label_len + 1 + target_len +
		1 + link_len;
	size_t pos = AA_QUERY_CMD_LABEL_SIZE;

	query = malloc(size);
	if (!query)
		return -1;
	memcpy(query + pos, label, label_len);
	/* null separator */
	pos += label_len;
	query[pos] = 0;
	query[++pos] = AA_CLASS_FILE;
	memcpy(query + pos + 1, link, link_len);
	/* The kernel does the query in two parts; we could simulate this
	 * doing the following, however as long as policy is compiled
	 * correctly this isn't required, and it requires an extra round
	 * trip to the kernel and adds a race on policy replacement between
	 * the two queries.
	 *
	int rc = aa_query_label(AA_MAY_LINK, query, size, allowed, audited);
	if (rc || !*allowed)
		return rc;
	*/
	pos += 1 + link_len;
	query[pos] = 0;
	memcpy(query + pos + 1, target, target_len);
	return aa_query_label(AA_MAY_LINK, query, size, allowed, audited);
}

/**
 * aa_query_link_path - query access permissions for a hard link @link
 * @label: apparmor label
 * @target: file path that hard link will point to
 * @link: file path of hard link
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int aa_query_link_path(const char *label, const char *target, const char *link,
		       int *allowed, int *audited)
{
	return aa_query_link_path_len(label, strlen(label), target,
				      strlen(target), link, strlen(link),
				      allowed, audited);
}

static int alloc_substring(char ***v, char *s, char *p,
			   size_t max_size, size_t n, bool immutable)
{
	if (max_size) {
		if (n >= max_size) {
			errno = E2BIG;
			return -1;
		}
	} else {
		char ** tmpv;
		tmpv = (char **) realloc(*v, (n + 1) * sizeof(char *));
		if (tmpv == NULL) {
			errno = ENOMEM;
			return -1;
		}
		*v = tmpv;
	}
	if (immutable) {
		char *tmp;
		tmp = (char *) malloc(p - s + 1);
		if (tmp == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(tmp, s, p - s);
		tmp[p - s] = 0;
		(*v)[n] = tmp;
	} else {
		(*v)[n] = s;
		if (*p)
			*p = 0;
	}

	return 0;
}

/**
 * aa_split_overlay_str - split a string into potentially multiple strings
 * @str: the string to split
 * @vec: vector to put string pointers into, IF null will be allocated
 * @max_size: maximum number of ents to put in @vec, IF 0 dynamic
 * @immutable: true if @str should not be modified.
 *
 * Returns: the number of entries in vec on success. -1 on error and errno set.
 *
 * Split a comma or colon separated string into substrings.
 *
 * IF @vec == NULL
 *    the vec will be dynamically allocated
 * ELSE
 *    passed in @vec will be used, and NOT updated/extended
 *
 * IF @max_size == 0 && @vec == NULL
 *    @vec will be dynamically resized
 * ELSE
 *    @vec will be fixed at @max_size
 *
 * IF @immutable is true
 *    the substrings placed in @vec will be allocated copies.
 * ELSE
 *    @str will be updated in place and @vec[x] will point into @str
 */
int aa_split_overlay_str(char *str, char ***vec, size_t max_size, bool immutable)
{
	char *s = str;
	char *p = str;
	int rc, n = 0;
	char **v = *vec;

	if (!*vec) {
		if (max_size) {
			v = (char **) malloc(max_size * sizeof(char *));
			if (v == NULL) {
				rc = ENOMEM;
				goto err;
			}
		}
	}

	while (*p) {
		if (*p == '\\') {
			if (*(p + 1) != 0)
				p++;
		} else if (*p == ',' || *p == ':') {
			if (p != s) {
				if (alloc_substring(&v, s, p, max_size, n, immutable) == -1) {
					rc = errno;
					goto err;
				}
				n++;
			}
			p++;
			s = p;
		} else
			p++;
	}
	if (p != s) {
		if (alloc_substring(&v, s, p, max_size, n, immutable) == -1) {
			rc = errno;
			goto err;
		}
		n++;
	}

	*vec = v;
	return n;
err:
	if (immutable) {
		for (int i = 0; i < n; i++) {
			free(v[i]);
		}
	}
	if (!*vec)
		free(v);
	errno = rc;
	return -1;
}
