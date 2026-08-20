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
#ifdef USE_DFA_CACHE
#include <vector>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <search.h>
#include <string.h>
#include <errno.h>
#ifdef USE_DFA_CACHE
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#endif
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

#ifdef USE_DFA_CACHE
const char *dfa_cacheloc = NULL;
bool dfa_show_cache = false;
#endif

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

#ifdef USE_DFA_CACHE
/**
 * DFA blob cache: reuse compiled file DFA across profiles with identical
 * expanded file rules. Profiles that share the same template section
 * lead to the same DFA being recreated multiple times.
 *
 * The cache uses a directory on disk (set via --dfa-cache-loc argument) to
 * persist across fork() children and across parser invocations.
 *
 * Cache key: FNV-1a hash of all expanded cod_entry fields (filename addressing).
 * Cache validation: SHA-256 of the serialized rule input stored in the header.
 * Cache file format: header + raw DFA blob + perms table.
 */

/* Minimal self-contained SHA-256 implementation (FIPS 180-4) */
struct sha256_ctx {
	uint32_t state[8];
	uint64_t count;
	uint8_t buf[64];
};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t sha256_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
	uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
		       ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = sha256_rotr(w[i-15], 7) ^ sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = sha256_rotr(w[i-2], 17) ^ sha256_rotr(w[i-2], 19) ^ (w[i-2] >> 2);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];

	for (i = 0; i < 64; i++) {
		t1 = h + (sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25)) +
		     ((e & f) ^ (~e & g)) + sha256_k[i] + w[i];
		t2 = (sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22)) +
		     ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	size_t buffered = ctx->count % 64;
	ctx->count += len;

	if (buffered && buffered + len >= 64) {
		size_t fill = 64 - buffered;
		memcpy(ctx->buf + buffered, p, fill);
		sha256_transform(ctx->state, ctx->buf);
		p += fill;
		len -= fill;
		buffered = 0;
	}
	while (len >= 64) {
		sha256_transform(ctx->state, p);
		p += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buf + buffered, p, len);
}

static void sha256_final(struct sha256_ctx *ctx, uint8_t digest[32])
{
	uint64_t bits = ctx->count * 8;
	size_t buffered = ctx->count % 64;
	int i;

	ctx->buf[buffered++] = 0x80;
	if (buffered > 56) {
		memset(ctx->buf + buffered, 0, 64 - buffered);
		sha256_transform(ctx->state, ctx->buf);
		buffered = 0;
	}
	memset(ctx->buf + buffered, 0, 56 - buffered);
	for (i = 0; i < 8; i++)
		ctx->buf[56 + i] = (uint8_t)(bits >> (56 - i * 8));
	sha256_transform(ctx->state, ctx->buf);

	for (i = 0; i < 8; i++) {
		digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
		digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i*4+3] = (uint8_t)(ctx->state[i]);
	}
}
/* End of SHA-256 implementation */

struct dfa_perms_header {
	uint32_t magic;
	uint32_t version;
	uint64_t dfa_size;
	uint32_t perms_count;
	uint32_t reserved;
	uint8_t  content_sha256[32]; /* SHA-256 of serialized rule input */
};

#define DFA_CACHE_MAGIC 0x43414644  /* "DFAC" in little-endian */
#define DFA_CACHE_VERSION 1
/* FNV-1a add hash helper */
#define FNV1A_ADD_TO_HASH(hash, val) do { (hash) ^= (uint64_t)(val); (hash) *= 0x100000001b3ULL; } while (0)

/* Compute FNV-1a 64-bit hash of a profile's expanded file rules (cod_entry).
 * Used as the cache filename (fast addressing). */
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
		FNV1A_ADD_TO_HASH(hash, entry->audit.audit);
		FNV1A_ADD_TO_HASH(hash, entry->rule_mode);
		FNV1A_ADD_TO_HASH(hash, entry->priority);
		if (entry->link_name) {
			for (const char *p = entry->link_name; *p; p++)
				FNV1A_ADD_TO_HASH(hash, (unsigned char)*p);
			FNV1A_ADD_TO_HASH(hash, entry->subset);
		}
		if (entry->nt_name) {
			for (const char *p = entry->nt_name; *p; p++)
				FNV1A_ADD_TO_HASH(hash, (unsigned char)*p);
		}
	}

	/* Add global state info that affects DFA compilation so that caches
	 * built under different kernel ABI versions, parser ABI versions,
	 * parser control options, or permstable32 versions are not accidentallyreused. */
	FNV1A_ADD_TO_HASH(hash, kernel_abi_version);
	FNV1A_ADD_TO_HASH(hash, parser_abi_version);
	FNV1A_ADD_TO_HASH(hash, parseopts.control);
	FNV1A_ADD_TO_HASH(hash, kernel_supports_permstable32);

	return hash;
}

/* Compute SHA-256 content hash of a profile's file rules for cache validation.
 * This provides cryptographic-strength collision resistance (2^128 for
 * collision, 2^256 for preimage) independent of the FNV-1a filename hash. */
static void compute_content_hash(Profile *profile, uint8_t digest[32])
{
	struct sha256_ctx ctx;
	struct cod_entry *entry;
	uint8_t sep = 0xff; /* field separator */
	uint8_t null_marker = 0x00; /* marks a NULL field */

	sha256_init(&ctx);

	list_for_each(profile->entries, entry) {
		if (entry->name)
			sha256_update(&ctx, entry->name, strlen(entry->name) + 1);
		else
			sha256_update(&ctx, &null_marker, 1);
		sha256_update(&ctx, &sep, 1);

		sha256_update(&ctx, &entry->perms, sizeof(entry->perms));
		sha256_update(&ctx, &entry->audit.audit, sizeof(entry->audit.audit));
		sha256_update(&ctx, &entry->rule_mode, sizeof(entry->rule_mode));
		sha256_update(&ctx, &entry->priority, sizeof(entry->priority));
		sha256_update(&ctx, &sep, 1);

		if (entry->link_name) {
			sha256_update(&ctx, entry->link_name, strlen(entry->link_name) + 1);
			sha256_update(&ctx, &entry->subset, sizeof(entry->subset));
		} else {
			sha256_update(&ctx, &null_marker, 1);
		}
		sha256_update(&ctx, &sep, 1);

		if (entry->nt_name)
			sha256_update(&ctx, entry->nt_name, strlen(entry->nt_name) + 1);
		else
			sha256_update(&ctx, &null_marker, 1);
		sha256_update(&ctx, &sep, 1);
	}

	/* Include global state that affects DFA compilation */
	sha256_update(&ctx, &kernel_abi_version, sizeof(kernel_abi_version));
	sha256_update(&ctx, &parser_abi_version, sizeof(parser_abi_version));
	sha256_update(&ctx, &parseopts.control, sizeof(parseopts.control));
	sha256_update(&ctx, &kernel_supports_permstable32,
		      sizeof(kernel_supports_permstable32));

	sha256_final(&ctx, digest);
}

static bool dfa_cache_lookup_disk(Profile *profile, uint64_t key,
				  const uint8_t content_hash[32])
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

	/* Validate content hash to detect hash collisions or corruption */
	if (memcmp(hdr.content_sha256, content_hash, 32) != 0) {
		if (dfa_show_cache)
			PERROR("DFA cache collision detected for %016llx\n",
			       (unsigned long long)key);
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

	size_t save = ftell(f);
	fseek(f, 0L, SEEK_END);
	size_t sz = ftell(f);
	fseek(f, save, SEEK_SET);
	sz -= save;

	if (hdr.dfa_size > sz) {
		fclose(f);
		return false;
	}
	sz -= hdr.dfa_size;

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

	if ((sizeof(aa_perms) * hdr.perms_count) > sz) {
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

#define DFA_CACHE_TOUCH_DELTA_SECS (7 * 24 * 60 * 60)
	/* Touch DFA cache file to update mtime for cache pruning purposes,
	 * but only if the file is older than DFA_CACHE_TOUCH_DELTA_SECS to
	 * avoid unnecessary disk writes on every cache hit. */
	struct stat st;
	if (fstat(fileno(f), &st) == 0) {
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		if (now.tv_sec - st.st_mtim.tv_sec > DFA_CACHE_TOUCH_DELTA_SECS)
			futimens(fileno(f), NULL);
	}
	fclose(f);

	profile->dfa.dfa = dfa;
	profile->dfa.size = hdr.dfa_size;
	profile->dfa.perms_table = perms_table;

	return true;
}

static void dfa_cache_store_disk(Profile *profile, uint64_t key,
				 const uint8_t content_hash[32])
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
	memcpy(hdr.content_sha256, content_hash, 32);

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
#endif

int process_profile_rules(Profile *profile)
{
	int error;
	bool file_dfa_cached = false;
#ifdef USE_DFA_CACHE
	uint64_t cache_key = 0;

	uint8_t content_hash[32] = {0};

	if (dfa_cacheloc) {
		cache_key = hash_profile_file_rules(profile);
		compute_content_hash(profile, content_hash);
		file_dfa_cached = dfa_cache_lookup_disk(profile, cache_key, content_hash);
		if (dfa_show_cache)
			PERROR("DFA cache %s: %s\n",
			       file_dfa_cached ? "hit" : "miss",
			       profile->name);
	}
#endif

	/* xmatch is derived from profile name/attachment, not file rules,
	 * it must be always built, even on cache hit. */
	if (!process_profile_name_xmatch(profile)) {
		PERROR(_("ERROR processing xmatch for profile %s, failed to load\n"), profile->name);
		exit(1);
		return -1;
	}

	if (!file_dfa_cached) {
		error = process_profile_regex(profile);
		if (error) {
			PERROR(_("ERROR processing regexs for profile %s, failed to load\n"), profile->name);
			exit(1);
			return error;
		}

#ifdef USE_DFA_CACHE
		if (dfa_cacheloc)
			dfa_cache_store_disk(profile, cache_key, content_hash);
#endif
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
