/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010 - 2012
 *   Canonical Ltd. (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */

#include <algorithm>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <search.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/apparmor.h>

#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "parser_yacc.h"
#include "network.h"

/* #define DEBUG */
#ifdef DEBUG
#undef PDEBUG
#define PDEBUG(fmt, args...) fprintf(stderr, "Lexer: " fmt, ## args)
#else
#undef PDEBUG
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

using namespace std;

ProfileList policy_list;

const char *dfa_cacheloc = NULL;
int dfa_show_cache = false;

void add_to_list(Profile *prof)
{
	pair<ProfileList::iterator, bool> res = policy_list.insert(prof);
	if (!res.second) {
		PERROR("Multiple definitions for profile %s exist,"
		       "bailing out.\n", prof->name);
		exit(1);
	}
}

void add_hat_to_policy(Profile *prof, Profile *hat)
{
	hat->parent = prof;

	pair<ProfileList::iterator, bool> res = prof->hat_table.insert(hat);
	if (!res.second) {
		PERROR("Multiple definitions for hat %s in profile %s exist,"
		       "bailing out.\n", hat->name, prof->name);
		exit(1);
	}
}

int load_policy_list(ProfileList &list, int option,
		     aa_kernel_interface *kernel_interface, int cache_fd)
{
	int res = 0;

	for (ProfileList::iterator i = list.begin(); i != list.end(); i++) {
		res = load_profile(option, kernel_interface, *i, cache_fd);
		if (res != 0)
			break;
	}

	return res;
}

int load_flattened_hats(Profile *prof, int option,
			aa_kernel_interface *kernel_interface, int cache_fd)
{
	return load_policy_list(prof->hat_table, option, kernel_interface,
				cache_fd);
}

int load_policy(int option, aa_kernel_interface *kernel_interface, int cache_fd)
{
	return load_policy_list(policy_list, option, kernel_interface, cache_fd);
}

int load_hats(std::ostringstream &buf, Profile *prof)
{
	for (ProfileList::iterator i = prof->hat_table.begin(); i != prof->hat_table.end(); i++) {
		sd_serialize_profile(buf, *i, 0);
	}

	return 0;
}


void dump_policy(void)
{
	policy_list.dump();
}

void dump_policy_names(void)
{
	policy_list.dump_profile_names(true);
}

/* merge_hats: merges hat_table into hat_table owned by prof */
static void merge_hats(Profile *prof, ProfileList &hats)
{
	for (ProfileList::iterator i = hats.begin(); i != hats.end(); ) {
		ProfileList::iterator cur = i++;
		add_hat_to_policy(prof, *cur);
		hats.erase(cur);
	}

}

Profile *merge_policy(Profile *a, Profile *b)
{
	Profile *ret = a;
	struct cod_entry *last;

	if (!a) {
		ret = b;
		goto out;
	}
	if (!b)
		goto out;

	if (a->name || b->name) {
                PERROR("ASSERT: policy merges shouldn't have names %s %s\n",
		       a->name ? a->name : "",
		       b->name ? b->name : "");
		exit(1);
	}

	if (a->entries) {
		list_last_entry(a->entries, last);
		last->next = b->entries;
	} else {
		a->entries = b->entries;
	}
	b->entries = NULL;

	if (merge_profile_mode(a->flags.mode, b->flags.mode) == profile_mode::CONFLICT) {
		PERROR("ASSERT: policy merge with different modes 0x%x != 0x%x\n",
		       static_cast<unsigned int>(a->flags.mode),
		       static_cast<unsigned int>(b->flags.mode));
		exit(1);
	}

	a->flags.audit = a->flags.audit || b->flags.audit;

	a->caps.allow |= b->caps.allow;
	a->caps.audit |= b->caps.audit;
	a->caps.deny |= b->caps.deny;
	a->caps.quiet |= b->caps.quiet;

	if (a->net.allow) {
		size_t i;
		for (i = 0; i < get_af_max(); i++) {
			a->net.allow[i] |= b->net.allow[i];
			a->net.audit[i] |= b->net.audit[i];
			a->net.deny[i] |= b->net.deny[i];
			a->net.quiet[i] |= b->net.quiet[i];
		}
	}

	a->rule_ents.splice(a->rule_ents.end(), b->rule_ents);

	merge_hats(a, b->hat_table);
	delete b;
out:
	return ret;
}

/**
 * DFA blob cache: reuse compiled file DFA across profiles with identical
 * expanded file rules. Profiles that share the same template section
 * lead to the same DFA being recreated multiple times.
 *
 * The cache uses a directory on disk (set via --dfa-cache-loc argument) to
 * persist across fork() children and across parser invocations.
 *
 * Cache key: FNV-1a hash of all expanded cod_entry fields.
 * Cache file format: raw DFA blob followed by perms table.
 */
struct dfa_perms_header {
	uint32_t magic;
	uint32_t version;
	uint64_t dfa_size;
	uint32_t perms_count;
	uint32_t reserved;
};

#define DFA_CACHE_MAGIC 0x43414644  /* "DFAC" in little-endian */
#define DFA_CACHE_VERSION 1
/* FNV-1a add hash helper */
#define FNV1A_ADD_TO_HASH(hash, val) do { (hash) ^= (uint64_t)(val); (hash) *= 0x100000001b3ULL; } while (0)

/* Compute FNV-1a 64-bit hash of a profile's expanded file rules (cod_entry) */
static uint64_t hash_profile_file_rules(Profile *profile)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	struct cod_entry *entry;

	list_for_each(profile->entries, entry) {
		if (entry->name) {
			for (const char *p = entry->name; *p; p++)
				FNV1A_ADD_TO_HASH(hash, (unsigned char)*p);
		}
		FNV1A_ADD_TO_HASH(hash, entry->perms);
		FNV1A_ADD_TO_HASH(hash, entry->audit);
		FNV1A_ADD_TO_HASH(hash, entry->rule_mode);
		FNV1A_ADD_TO_HASH(hash, entry->priority);
		if (entry->link_name) {
			for (const char *p = entry->link_name; *p; p++)
				FNV1A_ADD_TO_HASH(hash, (unsigned char)*p);
		}
		if (entry->nt_name) {
			for (const char *p = entry->nt_name; *p; p++)
				FNV1A_ADD_TO_HASH(hash, (unsigned char)*p);
		}
	}

	return hash;
}

static bool dfa_cache_lookup_disk(Profile *profile, uint64_t key)
{
	if (!dfa_cacheloc)
		return false;

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%016llx.dfa", dfa_cacheloc,
		 (unsigned long long)key);

	FILE *f = fopen(path, "rb");
	if (!f)
		return false;

	struct dfa_perms_header hdr;
	if (fread(&hdr, sizeof(hdr), 1, f) != 1 ||
	    hdr.magic != DFA_CACHE_MAGIC ||
	    hdr.version != DFA_CACHE_VERSION) {
		fclose(f);
		return false;
	}

	/* Sanity-check sizes from the cache file to avoid OOM on corrupt
	 * or maliciously crafted files in a user-provided dfa_cacheloc.
	 * DFA cache files are usually between 50kB and 150kB.
	 * Check also for max permission count, resonable max 32k permissions */
#define DFA_CACHE_MAX_DFA_SIZE  (1024 * 1024)
#define DFA_CACHE_MAX_PERMS     (32 * 1024)
	if (hdr.dfa_size == 0 || hdr.dfa_size > DFA_CACHE_MAX_DFA_SIZE ||
	    hdr.perms_count > DFA_CACHE_MAX_PERMS) {
		fclose(f);
		return false;
	}

	void *dfa = malloc(hdr.dfa_size);
	if (!dfa) {
		fclose(f);
		return false;
	}

	if (fread(dfa, 1, hdr.dfa_size, f) != hdr.dfa_size) {
		free(dfa);
		fclose(f);
		return false;
	}

	std::vector<aa_perms> perms_table(hdr.perms_count);
	if (hdr.perms_count > 0 &&
	    fread(perms_table.data(), sizeof(aa_perms), hdr.perms_count, f) != hdr.perms_count) {
		free(dfa);
		fclose(f);
		return false;
	}

	/* Touch DFA cache file to update mtime for cache pruning purposes. */
	futimens(fileno(f), NULL);
	fclose(f);

	profile->dfa.dfa = dfa;
	profile->dfa.size = hdr.dfa_size;
	profile->dfa.perms_table = perms_table;

	return true;
}

static void dfa_cache_store_disk(Profile *profile, uint64_t key)
{
	if (!dfa_cacheloc || !profile->dfa.dfa || profile->dfa.size == 0)
		return;

	if (mkdir(dfa_cacheloc, 0700) == -1 && errno != EEXIST)
		return;

	char path[PATH_MAX];
	char tmp_path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%016llx.dfa", dfa_cacheloc,
		 (unsigned long long)key);
	snprintf(tmp_path, sizeof(tmp_path), "%s/%016llx.dfa.tmp.%d", dfa_cacheloc,
		 (unsigned long long)key, (int)getpid());

	int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return;
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		unlink(tmp_path);
		return;
	}

	struct dfa_perms_header hdr;
	hdr.magic = DFA_CACHE_MAGIC;
	hdr.version = DFA_CACHE_VERSION;
	hdr.dfa_size = profile->dfa.size;
	hdr.perms_count = profile->dfa.perms_table.size();
	hdr.reserved = 0;

	if (fwrite(&hdr, sizeof(hdr), 1, f) != 1 ||
	    fwrite(profile->dfa.dfa, 1, profile->dfa.size, f) != profile->dfa.size ||
	    (hdr.perms_count > 0 &&
	     fwrite(profile->dfa.perms_table.data(), sizeof(aa_perms),
		    hdr.perms_count, f) != hdr.perms_count)) {
		fclose(f);
		unlink(tmp_path);
		return;
	}

	fclose(f);
	if (rename(tmp_path, path) != 0)
		unlink(tmp_path);
}

int process_profile_rules(Profile *profile)
{
	int error;
	uint64_t cache_key = 0;
	bool file_dfa_cached = false;

	if (dfa_cacheloc) {
		cache_key = hash_profile_file_rules(profile);
		file_dfa_cached = dfa_cache_lookup_disk(profile, cache_key);
		if (dfa_show_cache)
			PERROR("DFA cache %s: %s\n",
			       file_dfa_cached ? "hit" : "miss",
			       profile->name);
	}

	if (!file_dfa_cached) {
		error = process_profile_regex(profile);
		if (error) {
			PERROR(_("ERROR processing regexs for profile %s, failed to load\n"), profile->name);
			exit(1);
			return error;
		}

		if (dfa_cacheloc)
			dfa_cache_store_disk(profile, cache_key);
	}

	error = process_profile_policydb(profile);
	if (error) {
		PERROR(_("ERROR processing policydb rules for profile %s, failed to load\n"),
		       (profile)->name);
		exit(1);
		return error;
	}

	return 0;
}

int post_process_policy_list(ProfileList &list, int debug_only);
int post_process_profile(Profile *profile, int debug_only)
{
	int error = 0;

	profile->add_implied_rules();

	error = process_profile_variables(profile);
	if (error) {
		PERROR(_("ERROR expanding variables for profile %s, failed to load\n"), profile->name);
		exit(1);
		return error;
	}

	error = replace_profile_aliases(profile);
	if (error) {
		PERROR(_("ERROR replacing aliases for profile %s, failed to load\n"), profile->name);
		return error;
	}

	error = profile_merge_rules(profile);
	if (error) {
		PERROR(_("ERROR merging rules for profile %s, failed to load\n"), profile->name);
		exit(1);
		return error;
	}

	if (!debug_only) {
		error = process_profile_rules(profile);
		if (error)
			return error;
	}

	error = post_process_policy_list(profile->hat_table, debug_only);

	if (prompt_compat_mode == prompt_compat_t::FLAG && profile->uses_prompt_rules)
		profile->flags.mode = profile_mode::PROMPT;

	return error;
}

int post_process_policy_list(ProfileList &list, int debug_only)
{
	int error = 0;
	for (ProfileList::iterator i = list.begin(); i != list.end(); i++) {
		error = post_process_profile(*i, debug_only);
		if (error)
			break;
	}

	return error;
}

int post_process_policy(int debug_only)
{
	return post_process_policy_list(policy_list, debug_only);
}

void free_policies(void)
{
	policy_list.clear();
}
