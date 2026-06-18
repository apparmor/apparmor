/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#ifdef USE_DFA_CACHE
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#endif
#include <linux/limits.h>
#include <sys/apparmor.h>

#include <iomanip>
#include <string>
#include <sstream>


/* #define DEBUG */
#include "common_optarg.h"
#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "libapparmor_re/apparmor_re.h"
#include "libapparmor_re/aare_rules.h"
#include "policydb.h"
#include "rule.h"

enum class error_type {
	no_error,
	parse_error,
};


/* Filters out multiple slashes (except if the first two are slashes,
 * that's a distinct namespace in linux) and trailing slashes.
 * NOTE: modifies in place the contents of the path argument */

void filter_slashes(char *path)
{
	char *sptr, *dptr;
	bool seen_slash = false;

	if (!path || (strlen(path) < 2))
		return;

	sptr = dptr = path;

	/* special case for linux // namespace */
	if (sptr[0] == '/' && sptr[1] == '/' && sptr[2] != '/') {
		sptr += 2;
		dptr += 2;
	}

	while (*sptr) {
		if (*sptr == '/') {
			if (seen_slash) {
				++sptr;
			} else {
				*dptr++ = *sptr++;
				seen_slash = true;
			}
		} else {
			seen_slash = 0;
			if (dptr < sptr) {
				*dptr++ = *sptr++;
			} else {
				dptr++;
				sptr++;
			}
		}
	}
	*dptr = 0;
}

static error_type append_glob(std::string &pcre, int glob,
			      const char *default_glob, const char *null_glob)
{
	switch (glob) {
	case glob_default:
		pcre.append(default_glob);
		break;
	case glob_null:
		pcre.append(null_glob);
		break;
	default:
		PERROR(_("%s: Invalid glob type %d\n"), progname, glob);
		return error_type::parse_error;
		break;
	}
	return error_type::no_error;
}

/* converts the apparmor regex in aare and appends pcre regex output
 * to pcre string */
pattern_t convert_aaregex_to_pcre(const char *aare, int anchor, int glob,
				  std::string& pcre, int *first_re_pos)
{
#define update_re_pos(X) if (!(*first_re_pos)) { *first_re_pos = (X); }
#define MAX_ALT_DEPTH 50
	*first_re_pos = 0;

	int ret = 1;
	/* flag to indicate input error */
	error_type error;

	const char *sptr;
	pattern_t ptype;

	bool bEscape = false;	/* flag to indicate escape */
	int ingrouping = 0;	/* flag to indicate {} context */
	int incharclass = 0;	/* flag to indicate [ ] context */
	int grouping_count[MAX_ALT_DEPTH] = {0};

	error = error_type::no_error;
	ptype = pattern_t::Basic;	/* assume no regex */

	sptr = aare;

	if (parseopts.dump & DUMP_DFA_RULE_EXPR)
		fprintf(stderr, "aare: %s   ->   ", aare);

	if (anchor)
		/* anchor beginning of regular expression */
		pcre.append("^");

	while (error == error_type::no_error && *sptr) {
		switch (*sptr) {

		case '\\':
			/* concurrent escapes are allowed now and
			 * output as two consecutive escapes so that
			 * pcre won't interpret them
			 * \\\{...\\\} will be emitted as \\\{...\\\}
			 * for pcre matching.  For string matching
			 * and globbing only one escape is output
			 * this is done by stripping later
			 */
			if (bEscape) {
				pcre.append("\\\\");
			} else {
				bEscape = true;
				++sptr;
				continue;	/*skip turning bEscape off */
			}	/* bEscape */
			break;
		case '*':
			if (bEscape) {
				/* '*' is a PCRE special character */
				/* We store an escaped *, in case we
				 * end up using this regex buffer (i.e another
				 * non-escaped regex follows)
				 */
				pcre.append("\\*");
			} else {
				if ((pcre.length() > 0) && pcre[pcre.length() - 1]  == '/') {
					#if 0
					// handle comment containing use
					// of C comment characters
					// /* /*/ and /** to describe paths
					//
					// modify what is emitted for * and **
					// when used as the only path
					// component
					// ex.
					// /* /*/ /**/ /**
					// this prevents these expressions
					// from matching directories or
					// invalid paths
					// in these case * and ** must
					// match at least 1 character to
					// get a valid path element.
					// ex.
					// /foo/* -> should not match /foo/
					// /foo/*bar -> should match /foo/bar
					// /*/foo -> should not match //foo
					#endif
					const char *s = sptr;
					while (*s == '*')
						s++;
					if (*s == '/' || !*s)
						error = append_glob(pcre, glob, "[^/\\x00]", "[^/]");
				}
				if (*(sptr + 1) == '*') {
					/* is this the first regex form we
					 * have seen and also the end of
					 * pattern? If so, we can use
					 * optimised tail globbing rather
					 * than full regex.
					 */
					update_re_pos(sptr - aare);
					if (*(sptr + 2) == '\0' &&
					    ptype == pattern_t::Basic) {
						ptype = pattern_t::TailGlob;
					} else {
						ptype = pattern_t::Regex;
					}
					error = append_glob(pcre, glob, "[^\\x00]*", ".*");
					sptr++;
				} else {
					update_re_pos(sptr - aare);
					ptype = pattern_t::Regex;
					error = append_glob(pcre, glob, "[^/\\x00]*", "[^/]*");
				}	/* *(sptr+1) == '*' */
			}	/* bEscape */

			break;

		case '?':
			if (bEscape) {
				/* ? is not a PCRE regex character
				 * so no need to escape, just skip
				 * transform
				 */
				pcre.append(1, *sptr);
			} else {
				update_re_pos(sptr - aare);
				ptype = pattern_t::Regex;
				switch (glob) {
				case glob_default:
					pcre.append("[^/\\x00]");
					break;
				case glob_null:
					pcre.append("[^/]");
					break;
				default:
					PERROR(_("%s: Invalid glob type %d\n"), progname, glob);
					error = error_type::parse_error;
					break;
				}
			}
			break;

		case '[':
			if (bEscape) {
				/* [ is a PCRE special character */
				pcre.append("\\[");
			} else {
				update_re_pos(sptr - aare);
				incharclass = 1;
				ptype = pattern_t::Regex;
				pcre.append(1, *sptr);
			}
			break;

		case ']':
			if (bEscape) {
				/* ] is a PCRE special character */
				pcre.append("\\]");
			} else {
				if (incharclass == 0) {
					error = error_type::parse_error;
					PERROR(_("%s: Regex grouping error: Invalid close ], no matching open [ detected\n"), progname);
				}
				incharclass = 0;
				pcre.append(1, *sptr);
			}
			break;

		case '{':
			if (bEscape) {
				/* { is a PCRE special character */
				pcre.append("\\{");
			} else {
				if (incharclass) {
					/* don't expand inside [] */
					pcre.append("{");
				} else {
					update_re_pos(sptr - aare);
					ingrouping++;
					if (ingrouping >= MAX_ALT_DEPTH) {
						error = error_type::parse_error;
						PERROR(_("%s: Regex grouping error: Exceeded maximum nesting of {}\n"), progname);

					} else {
						grouping_count[ingrouping] = 0;
						ptype = pattern_t::Regex;
						pcre.append("(");
					}
				}	/* incharclass */
			}
			break;

		case '}':
			if (bEscape) {
				/* { is a PCRE special character */
				pcre.append("\\}");
			} else {
				if (incharclass) {
					/* don't expand inside [] */
					pcre.append("}");
				} else {
					if (grouping_count[ingrouping] == 0) {
						error = error_type::parse_error;
						PERROR(_("%s: Regex grouping error: Invalid number of items between {}\n"), progname);

					}
					ingrouping--;
					if (ingrouping < 0) {
						error = error_type::parse_error;
						PERROR(_("%s: Regex grouping error: Invalid close }, no matching open { detected\n"), progname);
						ingrouping = 0;
					}
					pcre.append(")");
				}	/* incharclass */
			}	/* bEscape */

			break;

		case ',':
			if (bEscape) {
				if (incharclass) {
					/* escape inside char class is a
					 * valid matching char for '\'
					 */
					pcre.append("\\,");
				} else {
					/* ',' is not a PCRE regex character
					 * so no need to escape, just skip
					 * transform
					 */
					pcre.append(1, *sptr);
				}
			} else {
				if (ingrouping && !incharclass) {
					grouping_count[ingrouping]++;
					pcre.append("|");
				} else {
					pcre.append(1, *sptr);
				}
			}
			break;

			/* these are special outside of character
			 * classes but not in them */
		case '^':
		case '$':
			if (incharclass) {
				pcre.append(1, *sptr);
			} else {
				pcre.append("\\");
				pcre.append(1, *sptr);
			}
			break;

			/*
			 * Not a subdomain regex, but needs to be
			 * escaped as it is a pcre metacharacter which
			 * we don't want to support. We always escape
			 * these, so no need to check bEscape
			 */
		case '.':
		case '+':
		case '|':
		case '(':
		case ')':
			pcre.append("\\");
			/* Fall through */

		default:
			if (bEscape) {
				const char *pos = sptr;
				int c;
				if ((c = str_escseq(&pos, "")) != -1) {
					/* valid escape we don't want to
					 * interpret here */
					pcre.append("\\");
					pcre.append(sptr, pos - sptr);
					sptr += (pos - sptr) - 1;
				} else {
					/* quoting mark used for something that
					 * does not need to be quoted; give a
					 * warning */
					pwarn(WARN_FORMAT, "Character %c was quoted"
					      "unnecessarily, dropped preceding"
					      " quote ('\\') character\n",
					      *sptr);
					pcre.append(1, *sptr);
				}
			} else
				pcre.append(1, *sptr);
			break;
		}	/* switch (*sptr) */

		bEscape = false;
		++sptr;
	}		/* while error == error_type::no_error && *sptr) */

	if (ingrouping > 0 || incharclass) {
		error = error_type::parse_error;

		PERROR(_("%s: Regex grouping error: Unclosed grouping or character class, expecting close }\n"),
		       progname);
	}

	if ((error == error_type::no_error) && bEscape) {
		/* trailing backslash quote */
		error = error_type::parse_error;
		PERROR(_("%s: Regex error: trailing '\\' escape character\n"),
		       progname);
	}
	/* anchor end and terminate pattern string */
	if ((error == error_type::no_error) && anchor) {
		pcre.append("$");
	}
	/* check error  again, as above STORE may have set it */
	if (error != error_type::no_error) {
		PERROR(_("%s: Unable to parse input line '%s'\n"),
		       progname, aare);

		ret = 0;
		goto out;
	}

out:
	if (ret == 0)
		ptype = pattern_t::Invalid;

	if (parseopts.dump & DUMP_DFA_RULE_EXPR)
		fprintf(stderr, "%s\n", pcre.c_str());

	return ptype;
}

const char *local_name(const char *name)
{
	const char *t;

	for (t = strstr(name, "//") ; t ; t = strstr(name, "//"))
		name = t + 2;

	return name;
}

/*
 * get_xattr_value returns the value of an xattr expression, performing NULL
 * checks along the way. The method returns NULL if the xattr match doesn't
 * have an xattrs (though this case currently isn't permitted by the parser).
 */
char *get_xattr_value(struct cond_entry *entry)
{
	if (entry->comp != cond_comp::EQ)
		return NULL;
	if (!entry->vals)
		return NULL;
	return entry->vals->value;
}

/* do we want to warn once/profile or just once per compile?? */
static void warn_once_xattr(const char *name)
{
	static const char *warned_name = NULL;
    common_warn_once(name, "xattr attachment conditional ignored", &warned_name);
}

bool process_profile_name_xmatch(Profile *prof)
{
	std::string tbuf;
	pattern_t ptype;
	char *name;

	struct cond_entry *entry;
	const char *xattr_value;

	if (prof->attachment) {
		name = prof->attachment;
	} else {
		/* don't filter_slashes for profile names, do on attachment */
		name = strdup(local_name(prof->name));
		if (!name)
			return false;
	}
	filter_slashes(name);
	ptype = convert_aaregex_to_pcre(name, 0, glob_default, tbuf,
					&prof->xmatch_len);
	if (ptype == pattern_t::Basic)
		prof->xmatch_len = strlen(name);

	if (ptype == pattern_t::Invalid) {
		PERROR(_("%s: Invalid profile name '%s' - bad regular expression\n"), progname, name);
		if (!prof->attachment)
			free(name);
		return false;
	}

	if (!prof->attachment)
		free(name);

	if (ptype == pattern_t::Basic && !(prof->altnames || prof->attachment || prof->xattrs.list)) {
		/* no regex so do not set xmatch */
		prof->xmatch = NULL;
		prof->xmatch_len = 0;
		prof->xmatch_size = 0;
	} else {
		/* build a dfa */
		aare_rules *rules = new aare_rules();
		if (!rules)
			return false;
		if (!rules->add_rule(tbuf.c_str(), 0, rule_mode_t::ALLOW,
				     AA_MAY_EXEC, 0, parseopts)) {
			delete rules;
			return false;
		}
		if (prof->altnames) {
			struct alt_name *alt;
			list_for_each(prof->altnames, alt) {
				int len;
				tbuf.clear();
				filter_slashes(alt->name);
				ptype = convert_aaregex_to_pcre(alt->name, 0,
								glob_default,
								tbuf, &len);
				if (!rules->add_rule(tbuf.c_str(), 0,
						rule_mode_t::ALLOW, AA_MAY_EXEC,
						0, parseopts)) {
					delete rules;
					return false;
				}
			}
		}
		if (prof->xattrs.list) {
			if (!(features_supports_domain_xattr && kernel_supports_oob)) {
				warn_once_xattr(prof->name);
				free_cond_entry_list(prof->xattrs);
				goto build;
			}

			for (entry = prof->xattrs.list; entry; entry = entry->next) {
				xattr_value = get_xattr_value(entry);
				if (!xattr_value)
					xattr_value = "**"; // Default to allowing any value.
				/* len is measured because it's required to
				 * convert the regex to pcre, but doesn't impact
				 * xmatch_len. The kernel uses the number of
				 * xattrs matched to prioritized in addition to
				 * xmatch_len.
				 */
				int len;
				tbuf.clear();
				/* prepend \x00 to every value. This is
				 * done to separate the existence of the
				 * xattr from a null value match.
				 *
				 * if an xattr exists, a single \x00 will
				 * be done before matching any of the
				 * xattr_value data.
				 *
				 * the pattern for a required xattr
				 *    \x00{value_match}\x-1
				 * optional xattr (null alternation)
				 *    {\x00{value_match},}\x-1
				 */
				tbuf.append("\\x00");
				convert_aaregex_to_pcre(xattr_value, 0,
							glob_null, tbuf,
							&len);
				if (!rules->append_rule(tbuf.c_str(), true, true, parseopts)) {
					delete rules;
					return false;
				}
			}
		}
build:
		/* xmatch doesn't use file dfa exec mode bits NOT the owner
		 * conditional and for just MAY_EXEC can be processed as
		 * none file perms
		 *
		 * we don't need to build xmatch for permstable32, so don't
		 */
		prof->xmatch = rules->create_dfablob(&prof->xmatch_size,
						    &prof->xmatch_len,
						    prof->xmatch_perms_table,
						    parseopts, false, -1);
		delete rules;
		if (!prof->xmatch)
			return false;
	}

	return true;
}

static int warn_change_profile = 1;

static bool is_change_profile_perms(perm32_t perms)
{
	/**
	 * A change_profile entry will have the AA_CHANGE_PROFILE bit set.
	 * It could also have the (AA_EXEC_BITS | ALL_AA_EXEC_UNSAFE) bits
	 * set by the frontend parser. That means that it is incorrect to
	 * identify change_profile modes using a test like this:
	 *
	 *   (perms & ~AA_CHANGE_PROFILE)
	 *
	 * The above test would incorrectly return true on a
	 * change_profile mode that has the
	 * (AA_EXEC_BITS | ALL_AA_EXEC_UNSAFE) bits set.
	 */
	return perms & AA_CHANGE_PROFILE;
}

bool process_dfa_entry(aare_rules *dfarules, struct cod_entry *entry)
{
	std::string tbuf;
	pattern_t ptype;
	int pos;

	if (!entry) 		/* shouldn't happen */
		return false;


	if (!is_change_profile_perms(entry->perms))
		filter_slashes(entry->name);
	ptype = convert_aaregex_to_pcre(entry->name, 0, glob_default, tbuf, &pos);
	if (ptype == pattern_t::Invalid)
		return false;

	entry->pattern_type = ptype;

	/* the link bit on the first pair entry should not get masked
	 * out by a deny rule, as both pieces of the link pair must
	 * match.  audit info for the link is carried on the second
	 * entry of the pair
	 *
	 * So if a deny rule only record it if there are permissions other
	 * than link in the entry.
	 * TODO: split link and change_profile entries earlier
	 */
	if (entry->rule_mode == rule_mode_t::DENY) {
		if ((entry->perms & ~AA_LINK_BITS) &&
		    !is_change_profile_perms(entry->perms) &&
		    !dfarules->add_rule(tbuf.c_str(), entry->priority,
					entry->rule_mode,
					entry->perms & ~(AA_LINK_BITS | AA_CHANGE_PROFILE),
					entry->audit == audit_t::FORCE ? entry->perms & ~(AA_LINK_BITS | AA_CHANGE_PROFILE) : 0,
					parseopts))
			return false;
	} else if (!is_change_profile_perms(entry->perms)) {
		if (!dfarules->add_rule(tbuf.c_str(), entry->priority,
				entry->rule_mode, entry->perms,
				entry->audit == audit_t::FORCE ? entry->perms : 0,
				parseopts))
			return false;
	}

	if (entry->perms & (AA_LINK_BITS)) {
		/* add the pair rule */
		std::string lbuf;
		int perms = AA_LINK_BITS & entry->perms;
		const char *vec[2];
		int pos;
		vec[0] = tbuf.c_str();
		if (entry->link_name) {
			filter_slashes(entry->link_name);
			ptype = convert_aaregex_to_pcre(entry->link_name, 0, glob_default, lbuf, &pos);
			if (ptype == pattern_t::Invalid)
				return false;
			if (entry->subset)
				perms |= LINK_TO_LINK_SUBSET(perms);
			vec[1] = lbuf.c_str();
		} else {
			perms |= LINK_TO_LINK_SUBSET(perms);
			vec[1] = "/[^/].*";
		}
		if (!dfarules->add_rule_vec(entry->priority,
				entry->rule_mode, perms,
				entry->audit == audit_t::FORCE ? perms & AA_LINK_BITS : 0,
				2, vec, parseopts, false))
			return false;
	}
	if (is_change_profile_perms(entry->perms)) {
		const char *vec[3];
		std::string lbuf, xbuf;
		autofree char *ns = NULL;
		autofree char *name = NULL;
		int index = 1;
		uint32_t onexec_perms = AA_ONEXEC;

		if ((parseopts.warn & WARN_RULE_DOWNGRADED) && entry->audit == audit_t::FORCE && warn_change_profile) {
			/* don't have profile name here, so until this code
			 * gets refactored just throw out a generic warning
			 */
			fprintf(stderr, "Warning kernel does not support audit modifier for change_profile rule.\n");
			warn_change_profile = 0;
		}

		if (entry->onexec) {
			ptype = convert_aaregex_to_pcre(entry->onexec, 0, glob_default, xbuf, &pos);
			if (ptype == pattern_t::Invalid)
				return false;
			vec[0] = xbuf.c_str();
		} else
			/* allow change_profile for all execs */
			vec[0] = "/[^/\\x00][^\\x00]*";

		if (!features_supports_stacking) {
			bool stack;

			if (!parse_label(&stack, &ns, &name,
					 tbuf.c_str(), false)) {
				return false;
			}

			if (stack) {
				fprintf(stderr,
					_("The current kernel does not support stacking of named transitions: %s\n"),
					tbuf.c_str());
				return false;
			}

			if (ns)
				vec[index++] = ns;
			vec[index++] = name;
		} else {
			vec[index++] = tbuf.c_str();
		}

		/* regular change_profile rule */
		if (!dfarules->add_rule_vec(entry->priority, entry->rule_mode,
					    AA_CHANGE_PROFILE | onexec_perms,
					    0, index - 1, &vec[1], parseopts, false))
			return false;

		/* onexec rules - both rules are needed for onexec */
		if (!dfarules->add_rule_vec(entry->priority, entry->rule_mode,
					    onexec_perms,
					    0, 1, vec, parseopts, false))
			return false;

		/**
		 * pick up any exec bits, from the frontend parser, related to
		 * unsafe exec transitions
		 */
		onexec_perms |= (entry->perms & (AA_EXEC_BITS | ALL_AA_EXEC_UNSAFE));
		if (!dfarules->add_rule_vec(entry->priority, entry->rule_mode,
					    onexec_perms, 0, index, vec,
					    parseopts, false))
			return false;
	}
	return true;
}

int process_profile_regex(Profile *prof)
{
	/* without usable permstable32 support we weld file and policydb together, so
	 * don't create the file blob here
	 */
	if (prof->dfa.rules->rule_count > 0) {
		int xmatch_len = 0;
		//fprintf(stderr, "Creating file DFA %d\n", kernel_supports_permstable32);
		prof->dfa.dfa = prof->dfa.rules->create_dfablob(&prof->dfa.size,
					&xmatch_len, prof->dfa.perms_table,
					parseopts, true,
					kernel_supports_permstable32_version);
		delete prof->dfa.rules;
		prof->dfa.rules = NULL;
		if (!prof->dfa.dfa)
			return -1;
	}

	return 0;
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

	list_for_each(profile->main_block->rules.entries, entry) {
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

	list_for_each(profile->main_block->rules.entries, entry) {
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

int process_profile_rules(Profile *prof)
{
	int err;
	bool file_dfa_cached = false;
#ifdef USE_DFA_CACHE
	uint64_t cache_key = 0;

	uint8_t content_hash[32] = {0};

	if (dfa_cacheloc) {
		cache_key = hash_profile_file_rules(prof);
		compute_content_hash(prof, content_hash);
		file_dfa_cached = dfa_cache_lookup_disk(prof, cache_key, content_hash);
		if (dfa_show_cache)
			PERROR("DFA cache %s: %s\n",
			       file_dfa_cached ? "hit" : "miss",
			       prof->name);
	}
#endif

	/* xmatch is derived from profile name/attachment, not file rules,
	 * it must be always built, even on cache hit. */
	if (!process_profile_name_xmatch(prof))
		goto xmatch_err;

	/* setup dfas */
	prof->dfa.rules = new aare_rules();
	if (!prof->dfa.rules)
		goto regex_err;

	prof->policy.rules = new aare_rules();
	if (!prof->policy.rules)
		goto policydb_err;

	/* compile rules */
	if (prof->main_block->gen_policy_re(*prof) != rule_result_t::OK) {
		exit(1);
	}


	if (!file_dfa_cached) {
		/* post policy process checks */
		err = process_profile_regex(prof);
		if (err)
			goto regex_err;

#ifdef USE_DFA_CACHE
	if (dfa_cacheloc)
		dfa_cache_store_disk(prof, cache_key, content_hash);
#endif
	}

	err = process_profile_policydb(prof);
	if (err)
		goto policydb_err;

	return 0;
xmatch_err:
	PERROR(_("ERROR processing xmatch for profile %s, failed to load\n"), prof->name);
	// TODO: convert to error return
	exit(1);
regex_err:
	PERROR(_("ERROR processing regexs for profile %s, failed to load\n"), prof->name);
	exit(1);
	return err;
policydb_err:
	PERROR(_("ERROR processing policydb rules for profile %s, failed to load\n"),
	       prof->name);
	exit(1);
	return err;

}

bool build_list_val_expr(std::string& buffer, struct value_list *list)
{
	struct value_list *ent;
	pattern_t ptype;
	int pos;

	if (!list) {
		buffer.append(default_match_pattern);
		return true;
	}

	buffer.append("(");

	ptype = convert_aaregex_to_pcre(list->value, 0, glob_default, buffer, &pos);
	if (ptype == pattern_t::Invalid)
		goto fail;

	list_for_each(list->next, ent) {
		buffer.append("|");
		ptype = convert_aaregex_to_pcre(ent->value, 0, glob_default, buffer, &pos);
		if (ptype == pattern_t::Invalid)
			goto fail;
	}
	buffer.append(")");

	return true;
fail:
	return false;
}

bool convert_entry(std::string& buffer, const char *entry)
{
	pattern_t ptype;
	int pos;

	if (entry) {
		ptype = convert_aaregex_to_pcre(entry, 0, glob_default, buffer, &pos);
		if (ptype == pattern_t::Invalid)
			return false;
	} else {
		buffer.append(default_match_pattern);
	}

	return true;
}

int clear_and_convert_entry(std::string& buffer, const char *entry)
{
	buffer.clear();
	return convert_entry(buffer, entry);
}

#define MAKE_STR(X) #X
#define CLASS_STR(X) "\\d" MAKE_STR(X)
#define MAKE_SUB_STR(X) "\\000" MAKE_STR(X)
#define CLASS_SUB_STR(X, Y) CLASS_STR(X) MAKE_SUB_STR(Y)

static const char *mediates_file = CLASS_STR(AA_CLASS_FILE);
static const char *mediates_mount = CLASS_STR(AA_CLASS_MOUNT);
static const char *mediates_dbus =  CLASS_STR(AA_CLASS_DBUS);
static const char *mediates_signal =  CLASS_STR(AA_CLASS_SIGNAL);
static const char *mediates_ptrace =  CLASS_STR(AA_CLASS_PTRACE);
static const char *mediates_socket_net = CLASS_STR(AA_CLASS_NET);	// socket af_family type
static const char *mediates_netv8 = CLASS_STR(AA_CLASS_NETV8);		// address on inet
static const char *mediates_netv9 = CLASS_STR(AA_CLASS_NETV9);
static const char *mediates_netv9_skb = CLASS_STR(AA_CLASS_NETV9_SKB);
static const char *mediates_net_unixv7 = CLASS_SUB_STR(AA_CLASS_NET, AF_UNIX);
static const char *mediates_net_unixv9 = CLASS_SUB_STR(AA_CLASS_NETV9, AF_UNIX);
static const char *mediates_ns = CLASS_STR(AA_CLASS_NS);
static const char *mediates_posix_mqueue = CLASS_STR(AA_CLASS_POSIX_MQUEUE);
static const char *mediates_sysv_mqueue = CLASS_STR(AA_CLASS_SYSV_MQUEUE);
static const char *mediates_io_uring = CLASS_STR(AA_CLASS_IO_URING);

/* Set the mediates priority to the maximum possible. This is to help
 * ensure that the mediates information is not wiped out by a rule
 * of higher priority. Which for allow rules isn't really a problem
 * in that these are only used as a place holder to ensure we have
 * a valid state at the mediates check, and an allow rule that wipes
 * these out would guarantee it. But a deny rule wiping these out
 * could result in the dfa allowing stuff as unmediated when it shouldn't
 *
 * Note: it turns out the above bug does exist for dbus rules in parsers
 * that do not support priority, and we don't have a way to fix it.
 * We fix it here by capping user specified priority to be less than
 * MAX_INTERNAL_PRIORITY.
 */
static int mediates_priority = MAX_INTERNAL_PRIORITY;

/* some rule types unfortunately encoded permissions on the class byte
 * to fix the above bug, they need a different solution. The generic
 * mediates rule will get encoded at the minimum priority, and then
 * for every rule of those classes a mediates rule of the same priority
 * will be added. This way the mediates rule never has higher priority,
 * which would wipe out the rule permissions encoded on the class state,
 * and it is guaranteed to have the same priority as the highest priority
 * rule.
 */
static int perms_onclass_mediates_priority = MIN_INTERNAL_PRIORITY;

int process_profile_policydb(Profile *prof)
{
	int error = -1;

	/* insert entries to show indicate what compiler/policy expects
	 * to be supported
	 */
	if (features_supports_userns &&
	    !prof->policy.rules->add_rule(mediates_ns, perms_onclass_mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
		goto out;

	/* don't add mediated classes to unconfined profiles */
	if (prof->flags.mode != profile_mode::UNCONFINED &&
	    prof->flags.mode != profile_mode::DEFAULT_ALLOW) {
		/* note: this activates fs based unix domain sockets mediation on connect */
		if (kernel_abi_version > 5 &&
		    !prof->policy.rules->add_rule(mediates_file, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_mount &&
		    !prof->policy.rules->add_rule(mediates_mount, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_dbus &&
		    !prof->policy.rules->add_rule(mediates_dbus, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_signal &&
		    !prof->policy.rules->add_rule(mediates_signal, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_ptrace &&
		    !prof->policy.rules->add_rule(mediates_ptrace, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_networkv8 &&
		    !prof->policy.rules->add_rule(mediates_netv8, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_networkv9_skb &&
		    !prof->policy.rules->add_rule(mediates_netv9_skb, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		/* v9 requires net and unix to be done together to avoid
		 * the problem that happened with v7/v8 unix/net
		 */
		if (features_supports_unixv9 &&
		    (!prof->policy.rules->add_rule(mediates_netv9,
						   mediates_priority,
						   rule_mode_t::ALLOW, AA_MAY_READ,
						   0, parseopts) ||
		     !prof->policy.rules->add_rule(mediates_net_unixv9,
						   mediates_priority,
						   rule_mode_t::ALLOW,  AA_MAY_READ,
						   0, parseopts)))
			goto out;
		else if (features_supports_unixv7 &&
		    (!prof->policy.rules->add_rule(mediates_socket_net,
						   mediates_priority,
						   rule_mode_t::ALLOW, AA_MAY_READ,
						   0, parseopts) ||
		     !prof->policy.rules->add_rule(mediates_net_unixv7,
						   mediates_priority,
						   rule_mode_t::ALLOW,  AA_MAY_READ,
						   0, parseopts)))
			goto out;
		if (features_supports_posix_mqueue &&
		    !prof->policy.rules->add_rule(mediates_posix_mqueue, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_sysv_mqueue &&
		    !prof->policy.rules->add_rule(mediates_sysv_mqueue, mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
		if (features_supports_io_uring &&
		    !prof->policy.rules->add_rule(mediates_io_uring, perms_onclass_mediates_priority, rule_mode_t::ALLOW, AA_MAY_READ, 0, parseopts))
			goto out;
	}

	if (prof->policy.rules->rule_count > 0) {
		int xmatch_len = 0;
		prof->policy.dfa = prof->policy.rules->create_dfablob(&prof->policy.size,
						&xmatch_len,
						prof->policy.perms_table,
						parseopts, false,
						kernel_supports_permstable32_version);
		delete prof->policy.rules;

		prof->policy.rules = NULL;
		if (!prof->policy.dfa)
			goto out;
	} else {
		delete prof->policy.rules;
		prof->policy.rules = NULL;
	}

	error = 0;

out:
	delete prof->policy.rules;
	prof->policy.rules = NULL;

	return error;
}

#ifdef UNIT_TEST

#include "unit_test.h"

#define MY_FILTER_TEST(input, expected_str)	\
	do {												\
		char *test_string = NULL;								\
		char *output_string = NULL;								\
													\
		test_string = strdup((input)); 								\
		filter_slashes(test_string); 								\
		asprintf(&output_string, "simple filter / conversion for '%s'\texpected = '%s'\tresult = '%s'", \
				(input), (expected_str), test_string);					\
		MY_TEST(strcmp(test_string, (expected_str)) == 0, output_string);			\
													\
		free(test_string);									\
		free(output_string);									\
	}												\
	while (0)

static int test_filter_slashes(void)
{
	int rc = 0;

	MY_FILTER_TEST("///foo//////f//oo////////////////", "/foo/f/oo/");
	MY_FILTER_TEST("/foo/f/oo", "/foo/f/oo");
	MY_FILTER_TEST("/", "/");
	MY_FILTER_TEST("", "");

	/* tests for "//" namespace */
	MY_FILTER_TEST("//usr", "//usr");
	MY_FILTER_TEST("//", "//");

	/* tests for not "//" namespace */
	MY_FILTER_TEST("///usr", "/usr");
	MY_FILTER_TEST("///", "/");

	MY_FILTER_TEST("/a/", "/a/");

	return rc;
}

#define MY_REGEX_EXT_TEST(glob, input, expected_str, expected_type)	\
	do {												\
		std::string tbuf;									\
		std::string tbuf2 = "testprefix";							\
		char *output_string = NULL;								\
		std::string expected_str2;								\
		pattern_t ptype;									\
		int pos;										\
													\
		ptype = convert_aaregex_to_pcre((input), 0, glob, tbuf, &pos); \
		asprintf(&output_string, "simple regex conversion for '%s'\texpected = '%s'\tresult = '%s'", \
				(input), (expected_str), tbuf.c_str());					\
		MY_TEST(strcmp(tbuf.c_str(), (expected_str)) == 0, output_string);			\
		MY_TEST(ptype == (expected_type), "simple regex conversion type check for '" input "'"); \
		free(output_string);									\
		/* ensure convert_aaregex_to_pcre appends only to passed ref string */			\
		expected_str2 = tbuf2;									\
		expected_str2.append((expected_str));							\
		ptype = convert_aaregex_to_pcre((input), 0, glob, tbuf2, &pos); \
		asprintf(&output_string, "simple regex conversion %sfor '%s'\texpected = '%s'\tresult = '%s'", \
			 glob == glob_null ? "with null allowed in glob " : "",\
				(input), expected_str2.c_str(), tbuf2.c_str());				\
		MY_TEST((tbuf2 == expected_str2), output_string);					\
		free(output_string);									\
	}												\
	while (0)

#define MY_REGEX_TEST(input, expected_str, expected_type) MY_REGEX_EXT_TEST(glob_default, input, expected_str, expected_type)


#define MY_REGEX_FAIL_TEST(input)						\
	do {												\
		std::string tbuf;									\
		pattern_t ptype;									\
		int pos;										\
													\
		ptype = convert_aaregex_to_pcre((input), 0, glob_default, tbuf, &pos); \
		MY_TEST(ptype == pattern_t::Invalid, "simple regex conversion invalid type check for '" input "'"); \
	}												\
	while (0)

static int test_aaregex_to_pcre(void)
{
	int rc = 0;

	MY_REGEX_TEST("/most/basic/test", "/most/basic/test", pattern_t::Basic);

	MY_REGEX_FAIL_TEST("\\");
	MY_REGEX_TEST("\\\\", "\\\\", pattern_t::Basic);
	MY_REGEX_TEST("\\blort", "blort", pattern_t::Basic);
	MY_REGEX_TEST("\\\\blort", "\\\\blort", pattern_t::Basic);
	MY_REGEX_FAIL_TEST("blort\\");
	MY_REGEX_TEST("blort\\\\", "blort\\\\", pattern_t::Basic);
	MY_REGEX_TEST("*", "[^/\\x00]*", pattern_t::Regex);
	MY_REGEX_TEST("blort*", "blort[^/\\x00]*", pattern_t::Regex);
	MY_REGEX_TEST("*blort", "[^/\\x00]*blort", pattern_t::Regex);
	MY_REGEX_TEST("\\*", "\\*", pattern_t::Basic);
	MY_REGEX_TEST("blort\\*", "blort\\*", pattern_t::Basic);
	MY_REGEX_TEST("\\*blort", "\\*blort", pattern_t::Basic);

	/* simple quoting */
	MY_REGEX_TEST("\\[", "\\[", pattern_t::Basic);
	MY_REGEX_TEST("\\]", "\\]", pattern_t::Basic);
	MY_REGEX_TEST("\\?", "?", pattern_t::Basic);
	MY_REGEX_TEST("\\{", "\\{", pattern_t::Basic);
	MY_REGEX_TEST("\\}", "\\}", pattern_t::Basic);
	MY_REGEX_TEST("\\,", ",", pattern_t::Basic);
	MY_REGEX_TEST("^", "\\^", pattern_t::Basic);
	MY_REGEX_TEST("$", "\\$", pattern_t::Basic);
	MY_REGEX_TEST(".", "\\.", pattern_t::Basic);
	MY_REGEX_TEST("+", "\\+", pattern_t::Basic);
	MY_REGEX_TEST("|", "\\|", pattern_t::Basic);
	MY_REGEX_TEST("(", "\\(", pattern_t::Basic);
	MY_REGEX_TEST(")", "\\)", pattern_t::Basic);
	MY_REGEX_TEST("\\^", "\\^", pattern_t::Basic);
	MY_REGEX_TEST("\\$", "\\$", pattern_t::Basic);
	MY_REGEX_TEST("\\.", "\\.", pattern_t::Basic);
	MY_REGEX_TEST("\\+", "\\+", pattern_t::Basic);
	MY_REGEX_TEST("\\|", "\\|", pattern_t::Basic);
	MY_REGEX_TEST("\\(", "\\(", pattern_t::Basic);
	MY_REGEX_TEST("\\)", "\\)", pattern_t::Basic);

	/* simple character class tests */
	MY_REGEX_TEST("[blort]", "[blort]", pattern_t::Regex);
	MY_REGEX_FAIL_TEST("[blort");
	MY_REGEX_FAIL_TEST("b[lort");
	MY_REGEX_FAIL_TEST("blort[");
	MY_REGEX_FAIL_TEST("blort]");
	MY_REGEX_FAIL_TEST("blo]rt");
	MY_REGEX_FAIL_TEST("]blort");
	MY_REGEX_TEST("b[lor]t", "b[lor]t", pattern_t::Regex);

	/* simple alternation tests */
	MY_REGEX_TEST("{alpha,beta}", "(alpha|beta)", pattern_t::Regex);
	MY_REGEX_TEST("baz{alpha,beta}blort", "baz(alpha|beta)blort", pattern_t::Regex);
	MY_REGEX_FAIL_TEST("{beta}");
	MY_REGEX_FAIL_TEST("biz{beta");
	MY_REGEX_FAIL_TEST("biz}beta");
	MY_REGEX_FAIL_TEST("biz{be,ta");
	MY_REGEX_FAIL_TEST("biz,be}ta");
	MY_REGEX_FAIL_TEST("biz{}beta");

	/* nested alternations */
	MY_REGEX_TEST("{{alpha,blort,nested},beta}", "((alpha|blort|nested)|beta)", pattern_t::Regex);
	MY_REGEX_FAIL_TEST("{{alpha,blort,nested}beta}");
	MY_REGEX_TEST("{{alpha,{blort,nested}},beta}", "((alpha|(blort|nested))|beta)", pattern_t::Regex);
	MY_REGEX_TEST("{{alpha,alpha{blort,nested}}beta,beta}", "((alpha|alpha(blort|nested))beta|beta)", pattern_t::Regex);
	MY_REGEX_TEST("{{alpha,alpha{blort,nested}}beta,beta}", "((alpha|alpha(blort|nested))beta|beta)", pattern_t::Regex);
	MY_REGEX_TEST("{{a,b{c,d}}e,{f,{g,{h{i,j,k},l}m},n}o}", "((a|b(c|d))e|(f|(g|(h(i|j|k)|l)m)|n)o)", pattern_t::Regex);
	/* max nesting depth = 50 */
	MY_REGEX_TEST("{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a,b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b}b,blort}",
			"(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a(a|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)|b)b|blort)", pattern_t::Regex);
	MY_REGEX_FAIL_TEST("{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a,b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b},b}b,blort}");

	/* simple single char */
	MY_REGEX_TEST("blor?t", "blor[^/\\x00]t", pattern_t::Regex);

	/* simple globbing */
	MY_REGEX_TEST("/*", "/[^/\\x00][^/\\x00]*", pattern_t::Regex);
	MY_REGEX_TEST("/blort/*", "/blort/[^/\\x00][^/\\x00]*", pattern_t::Regex);
	MY_REGEX_TEST("/*/blort", "/[^/\\x00][^/\\x00]*/blort", pattern_t::Regex);
	MY_REGEX_TEST("/*/", "/[^/\\x00][^/\\x00]*/", pattern_t::Regex);
	MY_REGEX_TEST("/**", "/[^/\\x00][^\\x00]*", pattern_t::TailGlob);
	MY_REGEX_TEST("/blort/**", "/blort/[^/\\x00][^\\x00]*", pattern_t::TailGlob);
	MY_REGEX_TEST("/**/blort", "/[^/\\x00][^\\x00]*/blort", pattern_t::Regex);
	MY_REGEX_TEST("/**/", "/[^/\\x00][^\\x00]*/", pattern_t::Regex);

	/* more complicated quoting */
	MY_REGEX_FAIL_TEST("\\\\[");
	MY_REGEX_FAIL_TEST("\\\\]");
	MY_REGEX_TEST("\\\\?", "\\\\[^/\\x00]", pattern_t::Regex);
	MY_REGEX_FAIL_TEST("\\\\{");
	MY_REGEX_FAIL_TEST("\\\\}");
	MY_REGEX_TEST("\\\\,", "\\\\,", pattern_t::Basic);
	MY_REGEX_TEST("\\\\^", "\\\\\\^", pattern_t::Basic);
	MY_REGEX_TEST("\\\\$", "\\\\\\$", pattern_t::Basic);
	MY_REGEX_TEST("\\\\.", "\\\\\\.", pattern_t::Basic);
	MY_REGEX_TEST("\\\\+", "\\\\\\+", pattern_t::Basic);
	MY_REGEX_TEST("\\\\|", "\\\\\\|", pattern_t::Basic);
	MY_REGEX_TEST("\\\\(", "\\\\\\(", pattern_t::Basic);
	MY_REGEX_TEST("\\\\)", "\\\\\\)", pattern_t::Basic);
	MY_REGEX_TEST("\\000", "\\000", pattern_t::Basic);
	MY_REGEX_TEST("\\x00", "\\x00", pattern_t::Basic);
	MY_REGEX_TEST("\\d000", "\\d000", pattern_t::Basic);

	/* more complicated character class tests */
	/*   -- embedded alternations */
	MY_REGEX_TEST("b[\\lor]t", "b[lor]t", pattern_t::Regex);
	MY_REGEX_TEST("b[{a,b}]t", "b[{a,b}]t", pattern_t::Regex);
	MY_REGEX_TEST("{alpha,b[{a,b}]t,gamma}", "(alpha|b[{a,b}]t|gamma)", pattern_t::Regex);

	/* pcre will ignore the '\' before '\{', but it should be okay
	 * for us to pass this on to pcre as '\{' */
	MY_REGEX_TEST("b[\\{a,b\\}]t", "b[\\{a,b\\}]t", pattern_t::Regex);
	MY_REGEX_TEST("{alpha,b[\\{a,b\\}]t,gamma}", "(alpha|b[\\{a,b\\}]t|gamma)", pattern_t::Regex);
	MY_REGEX_TEST("{alpha,b[\\{a\\,b\\}]t,gamma}", "(alpha|b[\\{a\\,b\\}]t|gamma)", pattern_t::Regex);

	/* test different globbing behavior conversion */
	MY_REGEX_EXT_TEST(glob_default, "/foo/**", "/foo/[^/\\x00][^\\x00]*", pattern_t::TailGlob);
	MY_REGEX_EXT_TEST(glob_null, "/foo/**", "/foo/[^/].*", pattern_t::TailGlob);
	MY_REGEX_EXT_TEST(glob_default, "/foo/f**", "/foo/f[^\\x00]*", pattern_t::TailGlob);
	MY_REGEX_EXT_TEST(glob_null, "/foo/f**", "/foo/f.*", pattern_t::TailGlob);

	MY_REGEX_EXT_TEST(glob_default, "/foo/*", "/foo/[^/\\x00][^/\\x00]*", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/*", "/foo/[^/][^/]*", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_default, "/foo/f*", "/foo/f[^/\\x00]*", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/f*", "/foo/f[^/]*", pattern_t::Regex);

	MY_REGEX_EXT_TEST(glob_default, "/foo/**.ext", "/foo/[^\\x00]*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/**.ext", "/foo/.*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_default, "/foo/f**.ext", "/foo/f[^\\x00]*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/f**.ext", "/foo/f.*\\.ext", pattern_t::Regex);

	MY_REGEX_EXT_TEST(glob_default, "/foo/*.ext", "/foo/[^/\\x00]*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/*.ext", "/foo/[^/]*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_default, "/foo/f*.ext", "/foo/f[^/\\x00]*\\.ext", pattern_t::Regex);
	MY_REGEX_EXT_TEST(glob_null, "/foo/f*.ext", "/foo/f[^/]*\\.ext", pattern_t::Regex);

	return rc;
}

int main(void)
{
	int rc = 0;
	int retval;

	// Default is parser_common.c, but it should be this source file instead
	progname = __FILE__;

	retval = test_filter_slashes();
	if (retval != 0)
		rc = retval;

	retval = test_aaregex_to_pcre();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
