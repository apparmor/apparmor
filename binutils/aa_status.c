/*
 *   Copyright (C) 2020 Canonical Ltd.
 *
 *   This program is free software; you can redistribute it and/or
 *    modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <regex.h>

#include <sys/apparmor.h>
#include <sys/apparmor_private.h>

#include "cJSON.h"

#define autofree __attribute((cleanup(_aa_autofree)))
#define autofclose __attribute((cleanup(_aa_autofclose)))

#define AA_EXIT_ENABLED 0
#define AA_EXIT_DISABLED 1
#define AA_EXIT_NO_POLICY 2
#define AA_EXIT_NO_CONTROL 3
#define AA_EXIT_NO_PERM 4
#define AA_EXIT_INTERNAL_ERROR 42

/* NOTE: Increment this whenever the JSON format changes */
static const unsigned char aa_status_json_version[] = "2";

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__ ((__unused__))

struct filter_set {
	regex_t mode;
	regex_t profile;
	regex_t pid;
	regex_t exe;
};

typedef struct {
	regex_t *mode;
	regex_t *profile;
	regex_t *pid;
	regex_t *exe;
} filters_t;

static void init_filters(filters_t *filters, struct filter_set *base) {
	filters->mode = &base->mode;
	filters->profile = &base->profile;
	filters->pid = &base->pid;
	filters->exe = &base->exe;
};

static void free_filters(filters_t *filters)
{
	if (filters->mode)
		regfree(filters->mode);
	if (filters->profile)
		regfree(filters->profile);
	if (filters->pid)
		regfree(filters->pid);
	if (filters->exe)
		regfree(filters->exe);
}

struct profile {
	char *name;
	char *status;
};

static void free_profiles(struct profile *profiles, size_t n) {
	if (!profiles)
		return;
	while (n > 0) {
		n--;
		free(profiles[n].name);
		free(profiles[n].status);
	}
	free(profiles);
}

struct process {
	char *pid;
	char *profile;
	char *exe;
	char *mode;
};

static void free_processes(struct process *processes, size_t n) {
	if (!processes)
		return;
	while (n > 0) {
		n--;
		free(processes[n].pid);
		free(processes[n].profile);
		free(processes[n].exe);
		free(processes[n].mode);
	}
	free(processes);
}

#define SHOW_PROFILES 1
#define SHOW_PROCESSES 2

static int verbose = 1;
static bool quiet = false;
int opt_show = SHOW_PROFILES | SHOW_PROCESSES;
bool opt_json = false;
bool opt_pretty = false;
bool opt_count = false;
const char *opt_mode = ".*";
const char *opt_profiles = ".*";
const char *opt_pid = ".*";
const char *opt_exe = ".*";

const char *profile_statuses[] = {"enforce", "complain", "prompt", "kill", "unconfined"};
const char *process_statuses[] = {"enforce", "complain", "prompt", "kill", "unconfined", "mixed"};

#define eprintf(...)                                                    \
do {									\
	if (!quiet)							\
	  fprintf(stderr, __VA_ARGS__);					\
} while (0)

#define dprintf(...)							\
do {									       \
	if (verbose && !opt_json)					       \
		printf(__VA_ARGS__);					       \
} while (0)

#define dfprintf(...)                                                          \
do {									       \
	if (verbose && !opt_json)					       \
		fprintf(__VA_ARGS__);					       \
} while (0)


static int open_profiles(FILE **fp)
{
	autofree char *apparmorfs = NULL;
	autofree char *apparmor_profiles = NULL;
	struct stat st;
	int ret;

	ret = stat("/sys/module/apparmor", &st);
	if (ret != 0) {
		eprintf("apparmor not present.\n");
		return AA_EXIT_DISABLED;
	}
	dprintf("apparmor module is loaded.\n");

	ret = aa_find_mountpoint(&apparmorfs);
	if (ret == -1) {
		eprintf("apparmor filesystem is not mounted.\n");
		return AA_EXIT_NO_CONTROL;
	}

	apparmor_profiles = malloc(strlen(apparmorfs) + 10); // /profiles\0
	if (apparmor_profiles == NULL) {
		return AA_EXIT_INTERNAL_ERROR;
	}
	sprintf(apparmor_profiles, "%s/profiles", apparmorfs);

	*fp = fopen(apparmor_profiles, "r");
	if (*fp == NULL) {
		if (errno == EACCES) {
			eprintf("You do not have enough privilege to read the profile set.\n");
		} else {
			eprintf("Could not open %s: %s", apparmor_profiles, strerror(errno));
		}
		return AA_EXIT_NO_PERM;
	}

	return 0;
}

/**
 * get_profiles - get a listing of profiles on the system
 * @fp: opened apparmor profiles file
 * @profiles: return: list of profiles
 * @n: return: number of elements in @profiles
 *
 * Return: 0 on success, shell error on failure
 */
static int get_profiles(FILE *fp, struct profile **profiles, size_t *n) {
	autofree char *line = NULL;
	size_t len = 0;

	*profiles = NULL;
	*n = 0;

	while (getline(&line, &len, fp) != -1) {
		struct profile *_profiles;
		autofree char *status = NULL;
		autofree char *name = NULL;
		char *tmpname = aa_splitcon(line, &status);

		if (!tmpname) {
			eprintf("Error: failed profile name split of '%s'.\n", line);
			// skip this entry and keep processing
			// else would be AA_EXIT_INTERNAL_ERROR;
			continue;
		}
		name = strdup(tmpname);

		if (status) {
			if (strcmp(status, "user") == 0)
				status = strdup("prompt");
			else
				status = strdup(status);
		}
		// give up if out of memory
		if (name == NULL || status == NULL)
			goto err;

		_profiles = realloc(*profiles, (*n + 1) * sizeof(**profiles));
		if (_profiles == NULL)
			goto err;

		// steal name and status
		_profiles[*n].name = name;
		_profiles[*n].status = status;
		name = NULL;
		status = NULL;
		*n = *n + 1;
		*profiles = _profiles;
	}

	return *n > 0 ? AA_EXIT_ENABLED : AA_EXIT_NO_POLICY;

err:
	free_profiles(*profiles, *n);
	*profiles = NULL;
	*n = 0;
	return AA_EXIT_INTERNAL_ERROR;
}

static int compare_profiles(const void *a, const void *b) {
	return strcmp(((struct profile *)a)->name,
		      ((struct profile *)b)->name);
}

/**
 * filter_profiles - create a filtered profile list
 * @profiles: list of profiles
 * @n: number of elements in @profiles
 * @filters: filters to apply
 * @filtered: return: new list of profiles that match the filter
 * @nfiltered: return: number of elements in @filtered
 *
 * Return: 0 on success, shell error on failure
 */
static int filter_profiles(struct profile *profiles,
			   size_t n,
			   filters_t *filters,
			   struct profile **filtered,
			   size_t *nfiltered)
{
	int ret = 0;
	size_t i;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (regexec(filters->mode, profiles[i].status, 0, NULL, 0) != 0)
			continue;
		if (regexec(filters->profile, profiles[i].name, 0, NULL, 0) == 0) {
			struct profile *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_profiles(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
			}
			_filtered[*nfiltered].name = strdup(profiles[i].name);
			_filtered[*nfiltered].status = strdup(profiles[i].status);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}
	if (*nfiltered != 0) {
		qsort(*filtered, *nfiltered, sizeof(*profiles), compare_profiles);
	}
	return ret;
}

/**
 * get_processes - get a list of processes that are confined
 * @profiles: list of profiles, used to filter out unconfined processes
 * @n: number of entries in @procfiles
 * @processes: return: list of confined processes
 * @nprocesses: return: number of entries in @processes
 *
 * Return: 0 on success, shell exit code on failure
 *
 * profiles is used to find prcesses that should be confined but aren't.
 */
static int get_processes(struct profile *profiles,
			 size_t n,
			 struct process **processes,
			 size_t *nprocesses)
{
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	int ret = 0;

	*processes = NULL;
	*nprocesses = 0;

	dir = opendir("/proc");
	if (dir == NULL) {
		ret = AA_EXIT_INTERNAL_ERROR;
		goto exit;
	}
	while ((entry = readdir(dir)) != NULL) {
		size_t i;
		int rc;
		int ispid = 1;
		autofree char *profile = NULL;
		autofree char *mode = NULL; /* be careful */
		autofree char *exe = NULL;
		autofree char *real_exe = NULL;
		autofclose FILE *fp = NULL;
		autofree char *line = NULL;

		// ignore non-pid entries
		for (i = 0; ispid && i < strlen(entry->d_name); i++) {
			ispid = (isdigit(entry->d_name[i]) ? 1 : 0);
		}
		if (!ispid) {
			continue;
		}

		rc = aa_getprocattr(atoi(entry->d_name), "current", &profile, &mode);
		if (rc == -1 && errno != ENOMEM) {
			/* fail to access */
			continue;
		} else if (rc == -1 ||
			   asprintf(&exe, "/proc/%s/exe", entry->d_name) == -1) {
			eprintf("ERROR: Failed to allocate memory\n");
			ret = AA_EXIT_INTERNAL_ERROR;
			goto exit;
		} else if (mode) {
			/* TODO: make this not needed. Mode can now be autofreed */
			if (strcmp(mode, "user") == 0)
				mode = strdup("prompt");
			else
				mode = strdup(mode);
		}
		// get executable - readpath can allocate for us but seems
		// to fail in some cases with errno 2 - no such file or
		// directory - whereas readlink() can succeed in these
		// cases - and readpath() seems to have the same behaviour
		// as in python with better canonicalized results so try it
		// first and fallack to readlink if it fails
		// coverity[toctou]
		real_exe = realpath(exe, NULL);
		if (real_exe == NULL) {
			int res;
			// ensure enough space for NUL terminator
			real_exe = calloc(PATH_MAX + 1, sizeof(char));
			if (real_exe == NULL) {
				eprintf("ERROR: Failed to allocate memory\n");
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			res = readlink(exe, real_exe, PATH_MAX);
			if (res == -1) {
				continue;
			}
			real_exe[res] = '\0';
		}


		if (mode == NULL) {
			// is unconfined so keep only if this has a
			// matching profile. TODO: fix to use attachment
			// ideally would walk process tree and apply
			// according to x rules and attachments
			for (i = 0; i < n; i++) {
				if (strcmp(profiles[i].name, real_exe) == 0) {
					profile = strdup(real_exe);
					mode = strdup("unconfined");
					break;
				}
			}
		}
		if (profile != NULL && mode != NULL) {
			struct process *_processes = realloc(*processes,
							     (*nprocesses + 1) * sizeof(**processes));
			if (_processes == NULL) {
				free_processes(*processes, *nprocesses);
				*processes = NULL;
				*nprocesses = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			_processes[*nprocesses].pid = strdup(entry->d_name);
			_processes[*nprocesses].profile = profile;
			_processes[*nprocesses].exe = strdup(real_exe);
			_processes[*nprocesses].mode = mode;
			*processes = _processes;
			*nprocesses = *nprocesses + 1;
			profile = NULL;
			mode = NULL;
			ret = AA_EXIT_ENABLED;
		}
	}

exit:
	if (dir != NULL) {
		closedir(dir);
	}
	return ret;
}

/**
 * filter_processes: create a new filtered process list by applying @filter
 * @processes: list of processes to filter
 * @n: number of entries in @processes
 * @filters: regex filters @processes against
 * @filtered: return: new list of processes matching filter
 * @nfiltered: number of entries in @filtered
 *
 * Return: 0 on success, shell exit value on failure
 */
static int filter_processes(struct process *processes,
			    size_t n,
			    filters_t *filters,
			    struct process **filtered,
			    size_t *nfiltered)
{
	size_t i;
	int ret = 0;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (regexec(filters->mode, processes[i].mode, 0, NULL, 0) != 0)
			continue;
		if (regexec(filters->pid, processes[i].pid, 0, NULL, 0) != 0)
			continue;
		if (regexec(filters->exe, processes[i].exe, 0, NULL, 0) != 0)
			continue;
		if (regexec(filters->profile, processes[i].profile, 0, NULL, 0) == 0)
		{
			struct process *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_processes(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
			}
			_filtered[*nfiltered].pid = strdup(processes[i].pid);
			_filtered[*nfiltered].profile = strdup(processes[i].profile);
			_filtered[*nfiltered].exe = strdup(processes[i].exe);
			_filtered[*nfiltered].mode = strdup(processes[i].mode);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}

	return ret;
}

/**
 * simple_filtered_count - count the number of profiles with mode == filter
 * @outf: output file destination
 * @filters: filters to filter profiles on
 * @profiles: profiles list to filter
 * @nprofiles: number of entries in @profiles
 *
 * Return: 0 on success, else shell error code
 */
static int simple_filtered_count(FILE *outf, filters_t *filters, bool json,
				 struct profile *profiles, size_t nprofiles)
{
	struct profile *filtered = NULL;
	size_t nfiltered;
	int ret;

	ret = filter_profiles(profiles, nprofiles, filters,
			      &filtered, &nfiltered);

	if (!json) {
		fprintf(outf, "%zd\n", nfiltered);
	} else {
		fprintf(outf, "\"profile_count\": %zd", nfiltered);
	}

	free_profiles(filtered, nfiltered);

	return ret;
}

/**
 * simple_filtered_process_count - count processes with mode == filter
 * @outf: output file destination
 * @filters: filters to filter processes on
 * @processes: process list to filter
 * @nprocesses: number of entries in @processes
 *
 * Return: 0 on success, else shell error code
 */
static int simple_filtered_process_count(FILE *outf, filters_t *filters, bool json,
					 struct process *processes, size_t nprocesses) {
	struct process *filtered = NULL;
	size_t nfiltered;
	int ret;

	ret = filter_processes(processes, nprocesses, filters, &filtered,
			       &nfiltered);
	if (!json) {
		fprintf(outf, "%zd\n", nfiltered);
	} else {
		fprintf(outf, "\"process_count\": %zd", nfiltered);
	}
	
	free_processes(filtered, nfiltered);

	return ret;
}


static int compare_processes_by_profile(const void *a, const void *b) {
	return strcmp(((struct process *)a)->profile,
		      ((struct process *)b)->profile);
}

static int compare_processes_by_executable(const void *a, const void *b) {
	return strcmp(((struct process *)a)->exe,
		      ((struct process *)b)->exe);
}

static void json_header(FILE *outf)
{
	fprintf(outf, "{\"version\": \"%s\"", aa_status_json_version);
}

static void json_seperator(FILE *outf)
{
	fprintf(outf, ", ");
}

static void json_footer(FILE *outf)
{
	fprintf(outf, "}\n");
}

/**
 * detailed_profiles - output a detailed listing of apparmor profile status
 * @outf: output file
 * @filters: filters to apply
 * @json: whether output should be in json format
 * @profiles: list of profiles to output
 * @nprofiles: number of profiles in @profiles
 *
 * Return: 0 on success, else shell error
 */
static int detailed_profiles(FILE *outf, filters_t *filters, bool json,
			     struct profile *profiles, size_t nprofiles) {
	int ret;
	size_t i;
	int is_first = 1;

	if (json) {
		fprintf(outf, "\"profiles\": {");
	} else {
		dfprintf(outf, "%zd profiles are loaded.\n", nprofiles);
	}

	for (i = 0; i < ARRAY_SIZE(profile_statuses); i++) {
		size_t nfiltered = 0, j;
		struct profile *filtered = NULL;
		filters_t subfilters = *filters;
		regex_t mode_filter;

		if (regexec(filters->mode, profile_statuses[i], 0, NULL, 0) == REG_NOMATCH)
			/* skip processing for entries that don't match filter*/
			continue;
		/* need subfilter as we want to split on matches to specific
		 * status
		 */
		subfilters.mode = &mode_filter;
		if (regcomp(&mode_filter, profile_statuses[i], REG_NOSUB) != 0) {
			eprintf("Error: failed to compile sub filter '%s'\n",
				 profile_statuses[i]);
			return AA_EXIT_INTERNAL_ERROR;
		}
		ret = filter_profiles(profiles, nprofiles, &subfilters, &filtered, &nfiltered);
		regfree(&mode_filter);
		if (ret != 0) {
			return ret;
		}
		if (!json) {
			dfprintf(outf, "%zd profiles are in %s mode.\n", nfiltered, profile_statuses[i]);
		}

		for (j = 0; j < nfiltered; j++) {
			if (json) {
				fprintf(outf, "%s\"%s\": \"%s\"",
				       is_first ? "" : ", ", filtered[j].name, profile_statuses[i]);
				is_first = 0;
			} else {
				dfprintf(outf, "   %s\n", filtered[j].name);
			}
		}

		free_profiles(filtered, nfiltered);
	}
	if (json)
		fprintf(outf, "}");

	return AA_EXIT_ENABLED;
}


/**
 * detailed_processses - output a detailed listing of apparmor process status
 * @outf: output file
 * @filters: filter regexs
 * @json: whether output should be in json format
 * @processes: list of processes to output
 * @nprocesses: number of processes in @processes
 *
 * Return: 0 on success, else shell error
 */
static int detailed_processes(FILE *outf, filters_t *filters, bool json,
			      struct process *processes, size_t nprocesses) {
	int ret = 0;
	size_t i;
	int need_finish = 0;

	if (json) {
		fprintf(outf, "\"processes\": {");
	} else {
		dfprintf(outf, "%zd processes have profiles defined.\n", nprocesses);
	}

	for (i = 0; i < ARRAY_SIZE(process_statuses); i++) {
		size_t nfiltered = 0, j;
		struct process *filtered = NULL;
		filters_t subfilters = *filters;
		regex_t mode_filter;
		if (regexec(filters->mode, process_statuses[i], 0, NULL, 0) == REG_NOMATCH)
			/* skip processing for entries that don't match filter*/
			continue;
		/* need sub_filter as we want to split on matches to specific
		 * status
		 */
		subfilters.mode = &mode_filter;
		if (regcomp(&mode_filter, process_statuses[i], REG_NOSUB) != 0) {
			eprintf("Error: failed to compile sub filter '%s'\n",
				 profile_statuses[i]);
			return AA_EXIT_INTERNAL_ERROR;
		}
		ret = filter_processes(processes, nprocesses, &subfilters, &filtered, &nfiltered);
		regfree(&mode_filter);
		if (ret != 0)
			goto exit;

		if (!json) {
			if (strcmp(process_statuses[i], "unconfined") == 0) {
				dfprintf(outf, "%zd processes are unconfined but have a profile defined.\n", nfiltered);
			} else {
				dfprintf(outf, "%zd processes are in %s mode.\n", nfiltered, process_statuses[i]);
			}
		}

		if (!json) {
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_profile);
			for (j = 0; j < nfiltered; j++) {
				dfprintf(outf, "   %s (%s) %s\n", filtered[j].exe, filtered[j].pid,
					// hide profile name if matches executable
					(strcmp(filtered[j].profile, filtered[j].exe) == 0 ?
					 "" :
					 filtered[j].profile));
			}
		} else {
			// json output requires processes to be grouped per executable
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_executable);
			for (j = 0; j < nfiltered; j++) {
				if (j > 0 && strcmp(filtered[j].exe, filtered[j - 1].exe) == 0) {
					// same executable
					fprintf(outf, ", {\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       filtered[j].profile, filtered[j].pid, filtered[j].mode);
				} else {
					fprintf(outf, "%s\"%s\": [{\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       // first element will be a unique executable
					       j == 0 && !need_finish ? "" : "], ",
					       filtered[j].exe, filtered[j].profile, filtered[j].pid, filtered[j].mode);
				}

				need_finish = 1;
			}

		}
		free_processes(filtered, nfiltered);
	}
	if (json) {
		if (need_finish > 0) {
			fprintf(outf, "]");
		}

		fprintf(outf, "}");
	}

exit:
	return ret;
}


static int print_legacy(const char *command)
{
	printf("Usage: %s [OPTIONS]\n"
	 "Legacy options and their equivalent command\n"
	 "  --profiled             --count --profiles\n"
	 "  --enforced             --count --profiles --mode=enforced\n"
	 "  --complaining          --count --profiles --mode=complain\n"
	 "  --kill                 --count --profiles --mode=kill\n"
	 "  --prompt               --count --profiles --mode=prompt\n"
	 "  --special-unconfined   --count --profiles --mode=unconfined\n"
	 "  --process-mixed        --count --ps --mode=mixed\n",
	command);

	exit(0);
	return 0;
}

static int usage_filters(void)
{
	long unsigned int i;

	printf("Usage of filters\n"
	 "Filters are used to reduce the output of information to only\n"
	 "those entries that will match the filter. Filters use posix\n"
	 "regular expression syntax. The possible values for exes that\n"
	 "support filters are below\n\n"
	 "  --filter.mode: regular expression to match the profile mode"
	 "                 modes: enforce, complain, kill, unconfined, mixed\n"
	 "  --filter.profiles: regular expression to match displayed profile names\n"
	 "  --filter.pid:  regular expression to match displayed processes pids\n"
	 "  --filter.exe:  regular expression to match executable\n"
	);
	for (i = 0; i < ARRAY_SIZE(process_statuses); i++) {
		printf("%s%s", i ? ", " : "", process_statuses[i]);
	}
	printf("\n");

	exit(0);
	return 0;
}

static int print_usage(const char *command, bool error)
{
	int status = EXIT_SUCCESS;

	if (error) {
		status = EXIT_FAILURE;
	}

	printf("Usage: %s [OPTIONS]\n"
	 "Displays various information about the currently loaded AppArmor policy.\n"
	 "Default if no options given\n"
	 "  --show=all\n\n"
	 "OPTIONS (one only):\n"
	 "  --enabled       returns error code if AppArmor not enabled\n"
	 "  --show=X        What information to show. {profiles,processes,all}\n"
	 "  --count         print the number of entries. Implies --quiet\n"
	 "  --filter.mode=filter      see filters\n"
	 "  --filter.profiles=filter  see filters\n"
	 "  --filter.pid=filter       see filters\n"
	 "  --filter.exe=filter       see filters\n"
	 "  --json          displays multiple data points in machine-readable JSON format\n"
	 "  --pretty-json   same data as --json, formatted for human consumption as well\n"
	 "  --verbose       (default) displays data points about loaded policy set\n"
	 "  --quiet         don't output error messages\n"
	 "  -h[(legacy|filters)]      this message, or info on the specified option\n"
	 "  --help[=(legacy|filters)] this message, or info on the specified option\n",
	 command);

	exit(status);

	return 0;
}


#define ARG_ENABLED	129
#define ARG_PROFILED	130
#define ARG_ENFORCED	131
#define ARG_COMPLAIN	132
#define ARG_KILL	133
#define ARG_UNCONFINED	134
#define ARG_PS_MIXED	135
#define ARG_JSON	136
#define ARG_PRETTY	137
#define ARG_COUNT	138
#define ARG_SHOW	139
#define ARG_MODE	140
#define ARG_PROFILES	141
#define ARG_PID		142
#define ARG_EXE		143
#define ARG_PROMPT	144
#define ARG_VERBOSE 'v'
#define ARG_QUIET 'q'
#define ARG_HELP 'h'

static int parse_args(int argc, char **argv)
{
	int opt;
	struct option long_opts[] = {
		{"enabled", no_argument, 0, ARG_ENABLED},
		{"profiled", no_argument, 0, ARG_PROFILED},
		{"enforced", no_argument, 0, ARG_ENFORCED},
		{"complaining", no_argument, 0, ARG_COMPLAIN},
		{"prompt", no_argument, 0, ARG_PROMPT},
		{"kill", no_argument, 0, ARG_KILL},
		{"special-unconfined", no_argument, 0, ARG_UNCONFINED},
		{"process-mixed", no_argument, 0, ARG_PS_MIXED},
		{"json", no_argument, 0, ARG_JSON},
		{"pretty-json", no_argument, 0, ARG_PRETTY},
		{"verbose", no_argument, 0, ARG_VERBOSE},
		{"quiet", no_argument, 0, ARG_QUIET},
		{"help", 2, 0, ARG_HELP},
		{"count", no_argument, 0, ARG_COUNT},
		{"show", 1, 0, ARG_SHOW},
		{"filter.profiles", 1, 0, ARG_PROFILES},
		{"filter.pid", 1, 0, ARG_PID},
		{"filter.exe", 1, 0, ARG_EXE},
		{"filter.mode", 1, 0, ARG_MODE},
		{NULL, 0, 0, 0},
	};

	// Using exit here is temporary
	while ((opt = getopt_long(argc, argv, "+vh::", long_opts, NULL)) != -1) {
		switch (opt) {
		case ARG_ENABLED:
			exit(aa_is_enabled() == 1 ? 0 : AA_EXIT_DISABLED);
			break;
		case ARG_VERBOSE:
			verbose = 1;
			/* default opt_mode */
			/* default opt_show */
			break;
		case ARG_QUIET:
			quiet = true;
			break;
		case ARG_HELP:
			if (!optarg) {
				print_usage(argv[0], false);
			} else if (strcmp(optarg, "legacy") == 0) {
				print_legacy(argv[0]);
			} else if (strcmp(optarg, "filters") == 0) {
				usage_filters();
			} else {
				eprintf("Error: Invalid --help option '%s'.\n", optarg);
				print_usage(argv[0], true);
				break;
			}
			break;
		case ARG_PROFILED:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			/* default opt_mode */
			break;
		case ARG_ENFORCED:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			opt_mode = "enforce";
			break;
		case ARG_COMPLAIN:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			opt_mode = "complain";
			break;
		case ARG_PROMPT:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			opt_mode = "prompt";
			break;
		case ARG_UNCONFINED:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			opt_mode = "unconfined";
			break;
		case ARG_KILL:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROFILES;
			opt_mode = "kill";
			break;
		case ARG_PS_MIXED:
			verbose = false;
			opt_count = true;
			opt_show = SHOW_PROCESSES;
			opt_mode = "mixed";
			break;
		case ARG_JSON:
			opt_json = true;
			/* default opt_show */
			break;
		case ARG_PRETTY:
			opt_pretty = true;
			opt_json = true;
			/* default opt_show */
			break;
		case ARG_COUNT:
			opt_count = true;
			/* default opt_show */
			break;
		case ARG_SHOW:
			if (strcmp(optarg, "all") == 0) {
				opt_show = SHOW_PROFILES | SHOW_PROCESSES;
			} else if (strcmp(optarg, "profiles") == 0) {
				opt_show = SHOW_PROFILES;
			} else if (strcmp(optarg, "processes") == 0) {
				opt_show = SHOW_PROCESSES;
			} else {
				eprintf("Error: Invalid --show option '%s'.\n", optarg);
				print_usage(argv[0], true);
				break;
			}
			break;
		case ARG_PROFILES:
			opt_profiles = optarg;
			/* default opt_mode */
			break;
		case ARG_PID:
			opt_pid = optarg;
			/* default opt_mode */
			break;
		case ARG_MODE:
			opt_mode = optarg;
			break;
		case ARG_EXE:
			opt_exe = optarg;
			/* default opt_mode */
			break;
			
		default:
			eprintf("Error: Invalid command.\n");
			print_usage(argv[0], true);
			break;
		}
	}

	return optind;
}

int main(int argc, char **argv)
{
	autofree char *buffer = NULL;	/* pretty print buffer */
	size_t buffer_size;
	autofclose FILE *fp = NULL;
	size_t nprofiles = 0;
	struct profile *profiles = NULL;
	int ret = EXIT_SUCCESS;
	const char *progname = argv[0];
	FILE *outf = stdout, *outf_save = NULL;
	struct filter_set filter_set;
	filters_t filters;

	if (argc > 1) {
		int pos = parse_args(argc, argv);
		if (pos < argc) {
			eprintf("Error: Unknown options.\n");
			print_usage(progname, true);
		}
	} else {
		verbose = 1;
		/* default opt_show */
		/* default opt_mode */
		/* default opt_json */
	}

	init_filters(&filters, &filter_set);
	if (regcomp(filters.mode, opt_mode, REG_NOSUB) != 0) {
		eprintf("Error: failed to compile mode filter '%s'\n",
			 opt_mode);
		return AA_EXIT_INTERNAL_ERROR;
	}
	if (regcomp(filters.profile, opt_profiles, REG_NOSUB) != 0) {
		eprintf("Error: failed to compile profiles filter '%s'\n",
			 opt_profiles);
		ret = AA_EXIT_INTERNAL_ERROR;
		goto out;
	}
	if (regcomp(filters.pid, opt_pid, REG_NOSUB) != 0) {
		eprintf("Error: failed to compile ps filter '%s'\n",
			 opt_pid);
		ret = AA_EXIT_INTERNAL_ERROR;
		goto out;
	}
	if (regcomp(filters.exe, opt_exe, REG_NOSUB) != 0) {
		eprintf("Error: failed to compile exe filter '%s'\n",
			 opt_exe);
		ret = AA_EXIT_INTERNAL_ERROR;
		goto out;
	}

	/* check apparmor is available and we have permissions */
	ret = open_profiles(&fp);
	if (ret != 0)
		goto out;

	if (opt_pretty) {
		outf_save = outf;
		outf = open_memstream(&buffer, &buffer_size);
		if (!outf) {
			eprintf("Failed to open memstream: %m\n");
			return AA_EXIT_INTERNAL_ERROR;
		}
	}

	/* always get policy even if not displayed because getting processes
	 * requires it to filter out unconfined tasks that don't or shouldn't
	 * have policy associated.
	 */
	ret = get_profiles(fp, &profiles, &nprofiles);
	if (ret != 0 && !opt_json) {
		eprintf("Failed to get profiles: %d....\n", ret);
		goto out;
	}

	if (opt_json)
		json_header(outf);
	if (opt_show & SHOW_PROFILES) {
		if (opt_json)
			json_seperator(outf);
		if (opt_count) {
			ret = simple_filtered_count(outf, &filters, opt_json,
						    profiles, nprofiles);
		} else {
			ret = detailed_profiles(outf, &filters, opt_json,
						profiles, nprofiles);
		}
		if (ret != 0)
			goto out;
	}

	if (opt_show & SHOW_PROCESSES) {
		if (opt_json)
			json_seperator(outf);

		struct process *processes = NULL;
		size_t nprocesses = 0;

		ret = get_processes(profiles, nprofiles, &processes, &nprocesses);
		if (ret != 0) {
			eprintf("Failed to get processes: %d....\n", ret);
		} else if (opt_count) {
			ret = simple_filtered_process_count(outf, &filters, opt_json,
							processes, nprocesses);
		} else {
			ret = detailed_processes(outf, &filters, opt_json,
						 processes, nprocesses);
		}
		free_processes(processes, nprocesses);

		if (ret != 0)
			goto out;
	}

	if (opt_json)
		json_footer(outf);

	if (opt_pretty) {
		autofree char *pretty = NULL;
		cJSON *json;

		/* explicit close to sync */
		fclose(outf);
		outf = outf_save;
		json = cJSON_Parse(buffer);
		if (!json) {
			eprintf("Failed to parse json output");
			ret = AA_EXIT_INTERNAL_ERROR;
			goto out;
		}

		pretty = cJSON_Print(json);
		if (!pretty) {
			eprintf("Failed to print pretty json");
			ret = AA_EXIT_INTERNAL_ERROR;
			goto out;
		}
		fprintf(outf, "%s\n", pretty);

		ret = AA_EXIT_ENABLED;
	}

out:
	free_profiles(profiles, nprofiles);
	free_filters(&filters);

	exit(ret);
}
