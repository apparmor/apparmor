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

static bool process_dfa_entry(aare_rules *dfarules, struct cod_entry *entry)
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

bool post_process_entries(Profile *prof)
{
	int ret = true;
	struct cod_entry *entry;

	list_for_each(prof->entries, entry) {
		if (!process_dfa_entry(prof->dfa.rules, entry))
			ret = false;
	}

	return ret;
}

int process_profile_regex(Profile *prof)
{
	int error = -1;

	prof->dfa.rules = new aare_rules();
	if (!prof->dfa.rules)
		goto out;

	if (!post_process_entries(prof))
		goto out;

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
			goto out;
	}

	error = 0;

out:
	return error;
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

bool post_process_policydb_ents(Profile *prof)
{
	for (RuleList::iterator i = prof->rule_ents.begin(); i != prof->rule_ents.end(); i++) {
		if ((*i)->skip())
			continue;
		if ((*i)->gen_policy_re(*prof) == rule_result_t::ERROR)
			return false;
	}

	return true;
}


static bool gen_net_rule(Profile *prof, u16 family, unsigned int type_mask,
			 bool audit, rule_mode_t rmode) {
	std::ostringstream buffer;
	std::string buf;

	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_NETV8;
	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((family & 0xff00) >> 8);
	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (family & 0xff);
	if (type_mask > 0xffff) {
		buffer << "..";
	} else {
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << ((type_mask & 0xff00) >> 8);
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (type_mask & 0xff);
	}
	buf = buffer.str();
	if (!prof->policy.rules->add_rule(buf.c_str(), 0, rmode,
					  map_perms(AA_VALID_NET_PERMS),
					  audit ? map_perms(AA_VALID_NET_PERMS) : 0,
					  parseopts))
		return false;

	return true;
}

static bool gen_af_rules(Profile *prof, u16 family, unsigned int type_mask,
			  unsigned int audit_mask, rule_mode_t rmode)
{
	if (type_mask > 0xffff && audit_mask > 0xffff) {
		/* instead of generating multiple rules wild card type */
		return gen_net_rule(prof, family, type_mask, audit_mask, rmode);
	} else {
		int t;
		/* generate rules for types that are set */
		for (t = 0; t < 16; t++) {
			if (type_mask & (1 << t)) {
				if (!gen_net_rule(prof, family, t,
						  audit_mask & (1 << t),
						  rmode))
					return false;
			}
		}
	}

	return true;
}

bool post_process_policydb_net(Profile *prof)
{
	u16 af;

	/* no network rules defined so we don't have generate them */
	if (!prof->net.allow)
		return true;

	/* generate rules if the af has something set */
	for (af = AF_UNSPEC; af < get_af_max(); af++) {
		if (prof->net.allow[af] ||
		    prof->net.deny[af] ||
		    prof->net.audit[af] ||
		    prof->net.quiet[af]) {
			if (!gen_af_rules(prof, af, prof->net.allow[af],
					  prof->net.audit[af],
					  { rule_mode_t::ALLOW}))
				return false;
			if (!gen_af_rules(prof, af, prof->net.deny[af],
					  prof->net.quiet[af],
					  { rule_mode_t::DENY}))
				return false;
		}
	}

	return true;
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

	prof->policy.rules = new aare_rules();
	if (!prof->policy.rules)
		goto out;

	if (!post_process_policydb_ents(prof))
		goto out;

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
