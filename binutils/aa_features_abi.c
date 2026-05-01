/*
 *   Copyright (c) 2020
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Canonical Ltd.
 */

#include <fcntl.h>
#include <getopt.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/apparmor.h>
#include <sys/apparmor_private.h>
#include <unistd.h>
#define _(s) gettext(s)

#include "../libraries/libapparmor/src/private.h"

static const char *progname = NULL;
static const char *opt_file = NULL;
static const char *opt_write = NULL;
static bool opt_debug = false;
static bool opt_verbose = false;
static bool opt_extract = false;

static void usage(const char *name, bool error)
{
	FILE *stream = stdout;
	int status = EXIT_SUCCESS;

	if (error) {
		stream = stderr;
		status = EXIT_FAILURE;
	}

	fprintf(stream,
		_("USAGE: %s [OPTIONS] <SOURCE> [OUTPUT OPTIONS]\n"
		  "\n"
		  "Output AppArmor feature abi from SOURCE to OUTPUT"
		  "\n"
		  "OPTIONS:\n"
#if 0
		  "  -d, --debug      show messages with debugging information\n"
		  "  -v, --verbose    show messages with stats\n"
#endif
		  "  -h, --help       display this help\n"
		  "SOURCE:\n"
		  "  -f F, --file=F   load features abi from file F\n"
		  "  -x, --extract    extract features abi from the kernel\n"
		  "OUTPUT OPTIONS:\n"
		  "  --stdout         default, write features to stdout\n"
		  "  -w F, --write=F  write features abi to the file F instead of stdout\n"
		  "\n"), name);
	exit(status);
}

#define error(fmt, args...) _error(_("%s: ERROR: " fmt " - %m\n"), progname, ## args)
static void _error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

#if 0
#define debug(fmt, args...) _debug(_("%s: DEBUG: " fmt "\n"), progname, ## args)
static void _debug(const char *fmt, ...)
{
	va_list args;

	if (!opt_debug)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

#define verbose(fmt, args...) _verbose(_(fmt "\n"), ## args)
static void _verbose(const char *fmt, ...)
{
	va_list args;

	if (!opt_verbose)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
#endif

#define ARG_STDOUT 128

static char **parse_args(int argc, char **argv)
{
	int opt;
	struct option long_opts[] = {
		{"debug", no_argument, 0, 'd'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{"extract", no_argument, 0, 'x'},
		{"file", required_argument, 0, 'f'},
		{"write", required_argument, 0, 'w'},
		{"stdout", no_argument, 0, ARG_STDOUT},
	};

	while ((opt = getopt_long(argc, argv, "+dvhxf:l:w:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			opt_debug = true;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 'h':
			usage(argv[0], false);
			break;
		case 'x':
			opt_extract = true;
			break;
		case 'f':
			opt_file = optarg;
			break;
		case 'w':
			opt_write = optarg;
			break;
		case ARG_STDOUT:
			opt_write = NULL;
			break;
		default:
			usage(argv[0], true);
			break;
		}
	}

	return argv + optind;
}


/* TODO: add features intersection and testing */

int main(int argc, char **argv)
{
	struct aa_features *features;
	autoclose int in = -1;
	autoclose int out = -1;
	int rc = 0;

	progname = argv[0];

	argv = parse_args(argc, argv);

	if (!opt_extract && !opt_file)
		usage(argv[0], true);
	if (opt_extract && opt_file) {
		error("options --extract and --file are mutually exclusive");
	}
	if (opt_extract) {
		rc = aa_features_new_from_kernel(&features);
		if (rc == -1)
			error("failed to extract features abi from the kernel");
	}
	if (opt_file) {
		in = open(opt_file, O_RDONLY);
		if (in == -1)
			error("failed to open file '%s'", opt_file);
		rc = aa_features_new_from_file(&features, in);
		if (rc == -1)
			error("failed to load features abi from file '%s'", opt_file);
	}
	

	if (opt_write) {
		out = open(opt_write, O_WRONLY | O_CREAT, 00600);
		if (out == -1)
			error("failed to open output file '%s'", opt_write);
	} else {
		out = fileno(stdout);
		if (out == -1)
			error("failed to get stdout");
	}	
	rc = aa_features_write_to_fd(features, out);
	if (rc == -1)
		error("failed to write features abi");

	return 0;
}
