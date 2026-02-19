/*
 *   Copyright (C) 2020 Canonical Ltd.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/apparmor.h>

#include <libintl.h>
#define _(s) gettext(s)

/* TODO: implement config locations - value can change */
#define DEFAULT_CONFIG_LOCATIONS "/etc/apparmor/parser.conf"
#define DEFAULT_POLICY_LOCATIONS "/var/cache/apparmor:/etc/apparmor.d/cache.d:/etc/apparmor.d/cache"
#define CACHE_FEATURES_FILE ".features"

bool opt_debug = false;
bool opt_verbose = false;
bool opt_dryrun = false;
bool opt_force = false;
bool opt_config = false;

#define warning(fmt, args...) _error(_("aa-load: WARN: " fmt "\n"), ## args)
#define error(fmt, args...) _error(_("aa-load: ERROR: " fmt "\n"), ## args)
static void _error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

#define verbose(fmt, args...) _debug(opt_verbose, _(fmt "\n"), ## args)
#define debug(fmt, args...) _debug(opt_debug, _("aa-load: DEBUG: " fmt "\n"), ## args)
static void _debug(bool opt_displayit, const char *fmt, ...)
{
	va_list args;

	if (!opt_displayit)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static int have_enough_privilege(const char *command)
{
	uid_t uid, euid;

	uid = getuid();
	euid = geteuid();

	if (uid != 0 && euid != 0) {
		error("%s: Sorry. You need root privileges to run this program.\n",
		      command);
		return EPERM;
	}

	if (uid != 0 && euid == 0) {
		error("%s: Aborting! You've set this program setuid root.\n"
		      "Anybody who can run this program can update "
		      "your AppArmor profiles.\n", command);
		exit(EXIT_FAILURE);
	}

	return 0;
}


static int load_config(const char *file)
{
	/* TODO */
	return ENOENT;
}

/**
 * load a single policy cache file to the kernel
 */
static int load_policy_file(const char *file)
{
	int rc = 0;

	struct aa_kernel_interface *kernel_interface;

	// Todo: Check cache validity

	if (aa_kernel_interface_new(&kernel_interface, NULL, NULL)) {
		rc = -errno;
		error("Failed to open kernel interface '%s': %m", file);
		return rc;
	}
	if (!opt_dryrun &&
	    aa_kernel_interface_replace_policy_from_file(kernel_interface,
							 AT_FDCWD, file)) {
		rc = -errno;
		error("Failed to load policy into kernel '%s': %m", file);
	}
	aa_kernel_interface_unref(kernel_interface);

	return rc;
}

static void validate_features(const char *dir_path)
{
	aa_features *kernel_features;

	if (aa_features_new_from_kernel(&kernel_features) == -1) {
		error("Failed to obtain features: %m");
		return;
	}

	if (aa_features_check(AT_FDCWD, dir_path, kernel_features) == -1) {
		if (errno == ENOENT) {
			/* features file does not exist
			 * not an issue when loading cache policies from dir
			 */
		}
		else if (errno == EEXIST) {
			warning("Overlay features do not match kernel features");
		}
	}
	aa_features_unref(kernel_features);
}

/**
 * load a directory of policy cache files to the kernel
 * This does not do a subdir search to find the kernel match but
 * tries to load the dir regardless of whether its features match
 *
 * The hierarchy looks like
 *
 * dir/
 *     .features
 *     profile1
 *     ...
 */

static int load_policy_dir(const char *dir_path)
{
	DIR *d;
	struct dirent *dir;
	int rc = 0;
	char *file;
	size_t len;

	validate_features(dir_path);

	d = opendir(dir_path);
	if (!d) {
		rc = -errno;
		error("Failed to open directory '%s': %m", dir_path);
		return rc;
	}

	while ((dir = readdir(d)) != NULL) {
		/* Only check regular files for now */
		if (dir->d_type == DT_REG) {
			/* As per POSIX dir->d_name has at most NAME_MAX characters */
			len = strnlen(dir->d_name, NAME_MAX);
			/* Ignores .features */
			if (strncmp(dir->d_name, CACHE_FEATURES_FILE, len) == 0) {
				continue;
			}
			if (asprintf(&file, "%s/%s", dir_path, dir->d_name) == -1) {
				error("Failure allocating memory");
				closedir(d);
				return -1;
			}
			load_policy_file(file);
			free(file);
			file = NULL;
		}
	}
	closedir(d);
	return 0;
}


/**
 * load_hashed_policy - find policy hashed dir and load it
 *
 * load/replace all policy from a policy hierarchy directory
 *
 * Returns: 0 on success < -errno
 *
 * It will find the subdir that matches the kernel and load all
 * precompiled policy files from it.
 *
 * The hierarchy looks something like
 *
 * location/
 *          kernel_hash1.0/
 *                         .features
 *                         profile1
 *                         ...
 *          kernel_hash2.0/
 *                        .features
 *                        profile1
 *                        ...
 */
static int load_policy_by_hash(const char *location)
{
	aa_policy_cache *policy_cache = NULL;
	int rc;

	if ((rc = aa_policy_cache_new(&policy_cache, NULL, AT_FDCWD, location, 0))) {
		rc = -errno;
		error("Failed to open policy cache '%s': %m", location);
		return rc;
	}

	if (opt_debug) {
		/* show hash directory under location that matches the
		 * current kernel
		 */
		char *cache_loc = aa_policy_cache_dir_path_preview(NULL, AT_FDCWD, location);
		if (!cache_loc) {
			rc = -errno;
			error("Failed to find cache location '%s': %m", location);
			goto out;
		}
		debug("Loading cache from '%s'\n", cache_loc);
		free(cache_loc);
	}

	if (!opt_dryrun) {
		if ((rc = aa_policy_cache_replace_all(policy_cache, NULL)) < 0) {
			error("Failed to load policy cache '%s': %m", location);
		} else {
			verbose("Success - Loaded policy cache '%s'", location);
		}
	}

out:
	aa_policy_cache_unref(policy_cache);

	return rc;
}

/**
 * load_arg - calls specific load functions for files and directories
 *
 * load/replace all policy files/dir in arg
 *
 * Returns: 0 on success, 1 on failure.
 *
 * It will load by hash subtree first, and fallback to a cache dir
 * If not a directory, it will try to load it as a cache file
 */
static int load_arg(char *arg)
{
	char **location = NULL;
	int i, n, rc = 0;


	/* arg can specify an overlay of multiple cache locations */
	if ((n = aa_split_overlay_str(arg, &location, 0, true)) == -1) {
		error("Failed to parse overlay locations: %m");
		return 1;
	}

	for (i = 0; i < n; i++) {
		struct stat st;
		debug("Trying to open %s", location[i]);
		if (stat(location[i], &st) == -1) {
			error("Failed stat of '%s': %m", location[i]);
			rc = 1;
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			/* try hash dir subtree first */
			if (load_policy_by_hash(location[i]) < 0) {
				error("Failed load policy by hash '%s': %m", location[i]);
				rc = 1;
			}
			/* fall back to cache dir */
			if (load_policy_dir(location[i]) < 0) {
				error("Failed load policy by directory '%s': %m", location[i]);
				rc = 1;
			}

		} else if (load_policy_file(location[i]) < 0) {
			rc = 1;
		}
	}

	for (i = 0; i < n; i++)
		free(location[i]);
	free(location);
	return rc;
}

static void print_usage(const char *command)
{
	printf("Usage: %s [OPTIONS] (cache file|cache dir|cache base dir)+\n"
	       "Load precompiled AppArmor policy from cache location(s)\n\n"
	       "Options:\n"
	       "  -f, --force     load policy even if abi does not match the kernel\n"
	       "  -d, --debug     display debug messages\n"
	       "  -v, --verbose   display progress and error messages\n"
	       "  -n, --dry-run   do everything except actual load\n"
	       "  -h, --help      this message\n",
	       command);
}

static const char *short_options = "c:dfvnh";
struct option long_options[] = {
	{"config",	1, 0, 'c'},
	{"debug",	0, 0, 'd'},
	{"force",	0, 0, 'f'},
	{"verbose",	0, 0, 'v'},
	{"dry-run",	0, 0, 'n'},
	{"help",	0, 0, 'h'},
	{NULL, 0, 0, 0},
};

static int process_args(int argc, char **argv)
{
	int c, o;

	opterr = 1;
	while ((c = getopt_long(argc, argv, short_options, long_options, &o)) != -1) {
		switch(c) {
		case 0:
			error("error in argument processing\n");
			exit(1);
			break;
		case 'd':
			opt_debug = true;
			break;
		case 'f':
			opt_force = true;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 'n':
			opt_dryrun = true;
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
			break;
		case 'c':
			/* TODO: reserved config location,
			 *  act as a bad arg for now, when added update usage
			 */
			//opt_config = true; uncomment when implemented
			/* Fall through */
		default:
			error("unknown argument: '%s'\n\n", optarg);
			print_usage(argv[1]);
			exit(1);
			break;
		}
	}

	return optind;
}

int main(int argc, char **argv)
{
	int i, rc = 0;

	optind = process_args(argc, argv);

	if (!opt_dryrun && have_enough_privilege(argv[0]))
		return 1;

	/* if no location use the default one */
	if (optind == argc) {
		if (!opt_config && load_config(DEFAULT_CONFIG_LOCATIONS) == 0) {
			verbose("Loaded policy config");
		}
		if ((rc = load_arg(DEFAULT_POLICY_LOCATIONS)))
			verbose("Loading policy from default location '%s'", DEFAULT_POLICY_LOCATIONS);
		else
			debug("No policy specified, and no policy config or policy in default locations");
	}
	for (i = optind; i < argc; i++) {
		/* Try to load all policy locations even if one fails
		 * but always return an error if any fail
		 */

		int tmp = load_arg(argv[i]);
		if (!rc)
			rc = tmp;
	}

	return rc;
}
