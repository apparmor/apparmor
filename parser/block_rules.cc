/*
 *   Copyright (c) 2026
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
 *   along with this program; if not, contact Canonical Ltd.
 */

#include "block_rules.h"

void block_rules::add_rlimit(const char *id, const char *in_value, const char *unit)
{
	rlim_t value = RLIM_INFINITY;
	long long tmp;
	char *end;

	int limit = get_rlimit(id);
	if (limit == -1)
		yyerror("INVALID RLIMIT '%s'\n", id);

	if (strcmp(in_value, "infinity") == 0) {
		value = RLIM_INFINITY;
	} else {
		const char *kb = "KB";
		const char *mb = "MB";
		const char *gb = "GB";

		tmp = strtoll(in_value, &end, 0);
		switch (limit) {
		case RLIMIT_CPU:
			if (!end || in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s\n", id, in_value);
			tmp = convert_time_units(tmp, SECONDS_P_MS, unit);
			if (tmp == -1LL)
				yyerror("RLIMIT '%s %s' < minimum value of 1s\n", id, in_value);
			else if (tmp < 0LL)
				yyerror("RLIMIT '%s' invalid value %s\n", id, in_value);
			if (!unit)
				pwarn(WARN_MISSING, _("RLIMIT 'cpu' no units specified using default units of seconds\n"));
			value = tmp;
			break;
#ifdef RLIMIT_RTTIME
		case RLIMIT_RTTIME:
			/* RTTIME is measured in microseconds */
			if (!end || in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			tmp = convert_time_units(tmp, 1LL, unit);
			if (tmp < 0LL)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (!unit)
				pwarn(WARN_MISSING, _("RLIMIT 'rttime' no units specified using default units of microseconds\n"));
			value = tmp;
			break;
#endif
		case RLIMIT_NOFILE:
		case RLIMIT_NPROC:
		case RLIMIT_LOCKS:
		case RLIMIT_SIGPENDING:
#ifdef RLIMIT_RTPRIO
		case RLIMIT_RTPRIO:
#endif
			if (!end || in_value == end || unit || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			value = tmp;
			break;
#ifdef RLIMIT_NICE
		case RLIMIT_NICE:
			if (!end || in_value == end || unit)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (tmp < -20 || tmp > 19)
				yyerror("RLIMIT '%s' out of range (-20 .. 19) %lld\n", id, tmp);
			value = tmp + 20;
			break;
#endif
		case RLIMIT_FSIZE:
		case RLIMIT_DATA:
		case RLIMIT_STACK:
		case RLIMIT_CORE:
		case RLIMIT_RSS:
		case RLIMIT_AS:
		case RLIMIT_MEMLOCK:
		case RLIMIT_MSGQUEUE:
			if (in_value == end || tmp < 0)
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit ? unit : "");
			if (!unit) {
				; /* use default of bytes */
			} else if (strstr(kb, unit) == kb) {
				tmp *= 1024;
			} else if (strstr(mb, unit) == mb) {
				tmp *= 1024*1024;
			} else if (strstr(gb, unit) == gb) {
				tmp *= 1024*1024*1024;
			} else {
				yyerror("RLIMIT '%s' invalid value %s %s\n", id, in_value, unit);
			}
			value = tmp;
			break;
		default:
			yyerror("Unknown RLIMIT %s\n", id);
		}
	}
	rlimits.specified |= 1 << limit;
	rlimits.limits[limit] = value;
}

void block_rules::add_capabilities(struct prefixes prefix, uint64_t cap)
{
	/* priority is not supported on capability rules but this is
	 * currently not enforced */
	// if (prefix.priority != 0)
	// 	yyerror(_("priority prefix not allowed on capability rules"));

	if (prefix.owner != owner_t::UNSPECIFIED)
		yyerror(_("owner conditional not allowed on capability rules"));

	if (prefix.rule_mode == rule_mode_t::DENY && prefix.audit == audit_t::FORCE) {
		caps.deny |= cap;
	} else if (prefix.rule_mode == rule_mode_t::DENY) {
		caps.deny |= cap;
		caps.quiet |= cap;
	} else {
		caps.allow |= cap;
		if (prefix.audit != audit_t::UNSPECIFIED)
			caps.audit |= cap;
	}

}

void block_rules::merge_block_rules(block_rules *b)
{
	if (!b)
		return;

	caps.allow |= b->caps.allow;
	caps.audit |= b->caps.audit;
	caps.deny |= b->caps.deny;
	caps.quiet |= b->caps.quiet;

	if (rlimits.specified & b->rlimits.specified) {
		PERROR(_("Cannot merge rlimits, more than one value specified for a single rlimit\n"));
		exit(1);
	}
	rlimits.specified |= b->rlimits.specified;
	for (int i = 0; i <  RLIMIT_NLIMITS; i++) {
		if (b->rlimits.limits[i])
			rlimits.limits[i] = b->rlimits.limits[i];
	}
}
