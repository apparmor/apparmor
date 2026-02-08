/*
 *   Copyright (c) 2014
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#ifndef __AA_POLICY_CACHE_H
#define __AA_POLICY_CACHE_H

#include <stdio.h>

extern struct timespec cache_tstamp, mru_policy_tstamp;

/* returns true if time is more recent than mru_tstamp */
#define tstamp_cmp(a, b)						\
  (((a).tv_sec == (b).tv_sec) ?						\
   ((a).tv_nsec - (b).tv_nsec) :					\
   ((a).tv_sec - (b).tv_sec))
#define tstamp_is_null(a) ((a).tv_sec == 0 && (a).tv_nsec == 0)

extern int show_cache;
extern int skip_cache;
extern int skip_read_cache;
extern int write_cache;
extern int cond_clear_cache;		/* only applies if write is set */
extern int force_clear_cache;		/* force clearing regargless of state */
extern int create_cache_dir;		/* create the cache dir if missing? */
extern int mru_skip_cache;

struct aa_policy_cache;

void set_cache_tstamp(struct timespec t);
void update_mru_tstamp(FILE *file, const char *path);
bool valid_cached_file_version(const char *cachename);
zstd_compress_t is_valid_precompressed_profile(char* buffer, size_t buffer_size, uint8_t min_compr_level);
char *cache_filename(struct aa_policy_cache *pc, int dir, const char *basename);
void valid_read_cache(const char *cachename);
zstd_compress_t valid_compressed_cache(const char *cachename);
int cache_hit(const char *cachename);
int setup_cache_tmp(const char **cachetmpname, char *cachename, int create_compressed);
void install_cache(const char *cachetmpname, const char *cachename);

#endif /* __AA_POLICY_CACHE_H */
