/*
 *   Copyright (c) 2010
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

/**
 * The mount command, its mix of options and flags, its permissions and
 * mapping are a mess.
 *      mount [-lhV]
 *
 *      mount -a [-fFnrsvw] [-t vfstype] [-O optlist]
 *
 *      mount [-fnrsvw] [-o option[,option]...]  device|dir
 *
 *      mount [-fnrsvw] [-t vfstype] [-o options] device dir
 *
 *----------------------------------------------------------------------
 * Mount flags of no interest for apparmor mediation
 * -a, --all
 * -F fork for simultaneous mount
 * -f fake, do everything except that actual system call
 * -h --help
 * -i, --internal-only
 * -n mount without writing in /etc/mtab
 * -O <optlist> limits what is auto mounted
 * -p, --pass-fd num
 * -s     Tolerate sloppy mount options
 * -U uuid
 * -V --version
 * --no-canonicalize
 *
 *----------------------------------------------------------------------
 * what do we do with these
 * -l	list?
 * -L <label> label
 * -v --verbose		deprecated
 *
 *----------------------------------------------------------------------
 * Filesystem type
 * -t <vfstype>
 *    vfstype=<vfstype>
 *
 *----------------------------------------------------------------------
 * Mount Flags/options (-o --options)
 *  -o option[,option]
 * 
 * The Linux kernel has 32 fs - independent mount flags, that mount command
 * is responsible for stripping out and mapping to a 32 bit flags field.
 * The mount commands mapping is documented below.
 *
 * Unfortunately we can not directly use this mapping as we need to be able
 * represent, whether none, 1 or both options of a flag can be present for
 * example
 *    ro, and rw information is stored in a single bit.  But we need 2 bits
 *    of information.
 *    ro - the mount can only be readonly
 *    rw - the mount can only be rw
 *    ro/rw - the mount can be either ro/rw
 *    the fourth state of neither ro/rw does not exist, but still we need
 *    >1 bit to represent the possible choices
 *
 * The fs specific mount options are passed into the kernel as a string
 * to be interpreted by the filesystem.
 *
 *
 * #define MS_RDONLY	 1		Mount read-only
 *	ro -r --read-only	[source] dest
 *	rw -w
 * #define MS_NOSUID	 2		Ignore suid and sgid bits
 *	nosuid
 *	suid
 * #define MS_NODEV	 4		Disallow access to device special files
 *	nodev
 *	dev
 * #define MS_NOEXEC	 8		Disallow program execution
 *	noexec
 *	exec
 * #define MS_SYNCHRONOUS	16	Writes are synced at once
 *	sync
 *	async
 * #define MS_REMOUNT	32		Alter flags of a mounted FS
 *	remount			source dest
 * #define MS_MANDLOCK	64		Allow mandatory locks on an FS
 *	mand
 *	nomand
 * #define MS_DIRSYNC	128		Directory modifications are synchronous
 *	dirsync
 * #define MS_NOSYMFOLLOW	256 	Do not follow symlinks
 *	symfollow
 *	nosymfollow
 * #define MS_NOATIME	1024		Do not update access times
 *	noatime
 *	atime
 * #define MS_NODIRATIME	2048	Do not update directory access times
 *	nodiratime
 *	diratime
 * #define MS_BIND		4096
 *	--bind -B		source dest
 * #define MS_MOVE		8192
 *	--move -M		source dest
 * #define MS_REC		16384
 *	--rbind -R		source dest
 *	--make-rshared		dest
 *	--make-rslave		dest
 *	--make-rprivate		dest
 *	--make-runbindable	dest
 * #define MS_VERBOSE	32768		MS_VERBOSE is deprecated
 * #define MS_SILENT	32768
 *	silent
 *	load
 * #define MS_POSIXACL	(1<<16)		VFS does not apply the umask
 *	acl
 *	noacl
 * #define MS_UNBINDABLE	(1<<17)	change to unbindable
 *	--make-unbindable	dest
 * #define MS_PRIVATE	(1<<18)		change to private
 *	--make-private		dest
 * #define MS_SLAVE	(1<<19)		change to slave
 *	--make-slave		dest
 * #define MS_SHARED	(1<<20)		change to shared
 *	--make-shared		dest
 * #define MS_RELATIME	(1<<21)		Update atime relative to mtime/ctime
 *	relatime
 *	norelatime
 * #define MS_KERNMOUNT	(1<<22)		this is a kern_mount call
 * #define MS_I_VERSION	(1<<23)		Update inode I_version field
 *	iversion
 *	noiversion
 * #define MS_STRICTATIME	(1<<24)	Always perform atime updates
 *	strictatime
 *	nostrictatime
 * #define MS_LAZYTIME (1<<25)	Update the on-disk [acm]times lazily
 *	lazytime
 *	nolazytime
 * #define MS_NOSEC	(1<<28)
 * #define MS_BORN		(1<<29)
 * #define MS_ACTIVE	(1<<30)
 * #define MS_NOUSER	(1<<31)
 *	nouser
 *	user
 *
 * other mount options of interest
 *
 *   selinux
 *     context=<context>
 *     fscontext=<context>
 *     defcontext=<context>,
 *     rootcontext=<context>
 *
 *   defaults -> rw, suid,  dev,  exec,  auto,  nouser,  async
 *   owner -> implies nosuid  and  nodev
 *   users -> implies noexec, nosuid, and nodev
 *
 *----------------------------------------------------------------------
 * AppArmor mount rules
 *
 * AppArmor mount rules try to leverage mount syntax within apparmor syntax
 * this can not be done entirely but it is largely covered.
 *
 * The general mount syntax is
 * [audit] [deny] [owner] mount [conds]* [source] [ -> [conds] path],
 * [audit] [deny] remount [conds]* [path],
 * [audit] [deny] umount [conds]* [path],
 *
 * Note: leading owner option applies owner condition to both sours and dest
 *       path.
 *
 * where [conds] can be
 * fstype=<expr>
 * options=<expr>
 * owner[=<expr>]
 *
 * <expr> := <re> | '(' (<re>[,])+ ')'
 *
 * If a condition is not specified then it is assumed to match all possible
 * entries for it.  ie. a missing fstype means all fstypes are matched.
 * However if a condition is specified then the rule only grants permission
 * for mounts matching the specified pattern.
 *
 * Examples.
 * mount,		# allow any mount
 * mount /dev/foo,	# allow mounting of /dev/foo anywhere
 * mount options=ro /dev/foo,  #allow mounting /dev/foo as read only
 * mount options=(ro,foo) /dev/foo,
 * mount options=ro options=foo /dev/foo,
 * mount fstype=overlayfs options=(rw,upperdir=/tmp/upper/,lowerdir=/) overlay -> /mnt/
 *
 *----------------------------------------------------------------------
 * pivotroot
 *   pivotroot [oldroot=<value>] <path> -> <profile>
 *   pivotroot <path> -> {  }
 *
 *----------------------------------------------------------------------
 * chroot
 *   chroot <path> -> <profile>
 *   chroot <path> -> {  }
 *
 *----------------------------------------------------------------------
 * AppArmor mount rule encoding
 *
 * TODO:
 *   add semantic checking of options against specified filesystem types
 *   to catch mount options that can't be covered.
 *
 *
 */


#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "parser.h"
#include "policydb.h"
#include "profile.h"
#include "mount.h"

using namespace std;

struct mnt_keyword_table {
	const char *keyword;
	unsigned int set;
	unsigned int clear;
};

// keep in sync with utils/apparmor/rule/mount.py flags_keywords
static struct mnt_keyword_table mnt_opts_table[] = {
	{"ro",			MS_RDONLY, 0},
	{"r",			MS_RDONLY, 0},
	{"read-only",		MS_RDONLY, 0},
	{"rw",			0, MS_RDONLY},
	{"w",			0, MS_RDONLY},
	{"suid",		0, MS_NOSUID},
	{"nosuid",		MS_NOSUID, 0},
	{"dev",			0, MS_NODEV},
	{"nodev",		MS_NODEV, 0},
	{"exec",		0, MS_NOEXEC},
	{"noexec",		MS_NOEXEC, 0},
	{"sync",		MS_SYNCHRONOUS, 0},
	{"async",		0, MS_SYNCHRONOUS},
	{"remount",		MS_REMOUNT, 0},
	{"mand",		MS_MAND, 0},
	{"nomand",		0, MS_MAND},
	{"dirsync",		MS_DIRSYNC, 0},
	{"symfollow",		0, MS_NOSYMFOLLOW},
	{"nosymfollow",		MS_NOSYMFOLLOW, 0},
	{"atime",		0, MS_NOATIME},
	{"noatime",		MS_NOATIME, 0},
	{"diratime",		0, MS_NODIRATIME},
	{"nodiratime",		MS_NODIRATIME, 0},
	{"bind",		MS_BIND, 0},
	{"B",			MS_BIND, 0},
	{"move",		MS_MOVE, 0},
	{"M",			MS_MOVE, 0},
	{"rbind",		MS_RBIND, 0},
	{"R",			MS_RBIND, 0},
	{"verbose",		MS_VERBOSE, 0},
	{"silent",		MS_SILENT, 0},
	{"loud",		0, MS_SILENT},
	{"acl",			MS_ACL, 0},
	{"noacl",		0, MS_ACL},
	{"unbindable",		MS_UNBINDABLE, 0},
	{"make-unbindable",	MS_UNBINDABLE, 0},
	{"runbindable",		MS_RUNBINDABLE, 0},
	{"make-runbindable",	MS_RUNBINDABLE, 0},
	{"private",		MS_PRIVATE, 0},
	{"make-private",	MS_PRIVATE, 0},
	{"rprivate",		MS_RPRIVATE, 0},
	{"make-rprivate",	MS_RPRIVATE, 0},
	{"slave",		MS_SLAVE, 0},
	{"make-slave",		MS_SLAVE, 0},
	{"rslave",		MS_RSLAVE, 0},
	{"make-rslave",		MS_RSLAVE, 0},
	{"shared",		MS_SHARED, 0},
	{"make-shared",		MS_SHARED, 0},
	{"rshared",		MS_RSHARED, 0},
	{"make-rshared",	MS_RSHARED, 0},

	{"relatime",		MS_RELATIME, 0},
	{"norelatime",		0, MS_RELATIME},
	{"iversion",		MS_IVERSION, 0},
	{"noiversion",		0, MS_IVERSION},
	{"strictatime",		MS_STRICTATIME, 0},
	{"nostrictatime",	0, MS_STRICTATIME},
	{"lazytime",		MS_LAZYTIME, 0},
	{"nolazytime",		0, MS_LAZYTIME},
	{"user",		0, (unsigned int) MS_NOUSER},
	{"nouser",		(unsigned int) MS_NOUSER, 0},

	{NULL, 0, 0}
};

static struct mnt_keyword_table mnt_conds_table[] = {
	{"options", MNT_SRC_OPT, MNT_COND_OPTIONS},
	{"option", MNT_SRC_OPT, MNT_COND_OPTIONS},
	{"fstype", MNT_SRC_OPT | MNT_DST_OPT, MNT_COND_FSTYPE},
	{"vfstype", MNT_SRC_OPT | MNT_DST_OPT, MNT_COND_FSTYPE},

	{NULL, 0, 0}
};

static ostream &dump_flags(ostream &os,
			    pair <unsigned int, unsigned int> flags)
{
	bool is_first = true;
	for (int i = 0; mnt_opts_table[i].keyword; i++) {
		if ((flags.first & mnt_opts_table[i].set) ||
		    (flags.second & mnt_opts_table[i].clear)) {
			if (!is_first) {
				os << ", ";
			}
			is_first = false;
			os << mnt_opts_table[i].keyword;
		}
	}
	return os;
}

ostream &operator<<(ostream &os, pair<unsigned int, unsigned int> flags)
{
	return dump_flags(os, flags);
}

static int find_mnt_keyword(struct mnt_keyword_table *table, const char *name)
{
	int i;
	for (i = 0; table[i].keyword; i++) {
		if (strcmp(name, table[i].keyword) == 0)
			return i;
	}

	return -1;
}

int is_valid_mnt_cond(const char *name, int src)
{
	int i;
	i = find_mnt_keyword(mnt_conds_table, name);
	if (i != -1)
		return (mnt_conds_table[i].set & src);
	return -1;
}

static unsigned int extract_flags(struct value_list **list, unsigned int *inv)
{
	unsigned int flags = 0, invflags = 0;
	if (inv)
		*inv = 0;

	struct value_list *entry, *tmp, *prev = NULL;
	list_for_each_safe(*list, entry, tmp) {
		int i;
		i = find_mnt_keyword(mnt_opts_table, entry->value);
		if (i != -1) {
			flags |= mnt_opts_table[i].set;
			invflags |= mnt_opts_table[i].clear;
			PDEBUG(" extracting mount flag %s req: 0x%x inv: 0x%x"
			       " => req: 0x%x inv: 0x%x\n",
			       entry->value, mnt_opts_table[i].set,
			       mnt_opts_table[i].clear, flags, invflags);
			list_remove_at(*list, prev, entry);
			free_value_list(entry);
		} else
			prev = entry;
	}

	if (inv)
		*inv = invflags;

	return flags;
}

static bool conflicting_flags(unsigned int flags, unsigned int inv)
{
	if (flags & inv) {
		for (int i = 0; i < 31; i++) {
			unsigned int mask = 1 << i;
			if ((flags & inv) & mask) {
				cerr << "conflicting flag values = "
				     << flags << ", " << inv << "\n";
			}
		}
		return true;
	}
	return false;
}

static struct value_list *extract_fstype(struct cond_entry **conds)
{
	struct value_list *list = NULL;

	struct cond_entry *entry, *tmp, *prev = NULL;

	list_for_each_safe(*conds, entry, tmp) {
		if (entry->comp != cond_comp::EQ && entry->comp != cond_comp::IN)
			yyerror("only \"=\" and 'in' allowed in conditions of mount rules\n");

		if (strcmp(entry->name, "fstype") == 0 ||
		    strcmp(entry->name, "vfstype") == 0) {
			PDEBUG("  extracting fstype\n");
			list_remove_at(*conds, prev, entry);
			list_append(entry->vals, list);
			list = entry->vals;
			entry->vals = NULL;
			free_cond_entry(entry);
		} else
			prev = entry;
	}

	return list;
}

static struct cond_entry *extract_options(struct cond_entry **conds, cond_comp comp)
{
	struct cond_entry *list = NULL, *entry, *tmp, *prev = NULL;

	list_for_each_safe(*conds, entry, tmp) {
		if (entry->comp != cond_comp::EQ && entry->comp != cond_comp::IN)
			yyerror("only \"=\" and 'in' allowed in conditions of mount rules\n");

		if ((strcmp(entry->name, "options") == 0 ||
		     strcmp(entry->name, "option") == 0) &&
		    entry->comp == comp) {
			list_remove_at(*conds, prev, entry);
			PDEBUG("  extracting %s %s\n",
			       entry->name, entry->comp == cond_comp::EQ ? "=" : " in ");
			list_append(entry, list);
			list = entry;
		} else
			prev = entry;
	}

	return list;
}

static void perror_conds(const char *rule, struct cond_entry *conds)
{
	struct cond_entry *entry;

	list_for_each(conds, entry) {
		PERROR(  "unsupported %s condition '%s%s(...)'\n",
			 rule, entry->name, entry->comp == cond_comp::EQ ? "=" : " in ");
	}
}

static void perror_vals(const char *rule, struct value_list *vals)
{
	struct value_list *entry;

	list_for_each(vals, entry) {
		PERROR(  "unsupported %s value '%s'\n", rule, entry->value);
	}
}

static void process_one_option(struct cond_entry *&opts, unsigned int &flags,
			       unsigned int &inv_flags)
{
	struct cond_entry *entry;
	struct value_list *vals;

	entry = list_pop(opts);
	vals = entry->vals;
	entry->vals = NULL;
	/* fail if there are any unknown optional flags */
	if (opts) {
		PERROR("  unsupported multiple 'mount options %s(...)'\n",
		       entry->comp == cond_comp::EQ ? "=" : " in ");
		exit(1);
	}
	free_cond_entry(entry);

	flags = extract_flags(&vals, &inv_flags);
	if (vals) {
		perror_vals("mount option", vals);
		exit(1);
	}
}

mnt_rule::mnt_rule(struct cond_entry *src_conds, char *device_p,
		   struct cond_entry *dst_conds aa_unused, char *mnt_point_p,
		   perm32_t perms_p):
	perms_rule_t(AA_CLASS_MOUNT),
	mnt_point(mnt_point_p), device(device_p), trans(NULL), opts(NULL),
	flagsv(0), opt_flagsv(0)
{
	/* FIXME: dst_conds are ignored atm */
	dev_type = extract_fstype(&src_conds);

	if (src_conds) {
		/* move options in () to local list */
		struct cond_entry *opts_in = extract_options(&src_conds, cond_comp::IN);

		if (opts_in) {
			unsigned int tmpflags = 0, tmpinv_flags = 0;
			struct cond_entry *entry;

			while ((entry = list_pop(opts_in))) {
				process_one_option(entry, tmpflags,
						   tmpinv_flags);
				/* optional flags if set/clear mean the same
				 * thing and can be represented by a single
				 * bitset, also there is no need to check for
				 * conflicting flags when they are optional
				 */
				opt_flagsv.push_back(tmpflags | tmpinv_flags);
			}
		}

		/* move options=() to opts list */
		struct cond_entry *opts_eq = extract_options(&src_conds, cond_comp::EQ);
		if (opts_eq) {
			unsigned int tmpflags = 0, tmpinv_flags = 0;
			struct cond_entry *entry;

			while ((entry = list_pop(opts_eq))) {
				process_one_option(entry, tmpflags,
						   tmpinv_flags);
				/* throw away tmpinv_flags, only needed in
				 * consistancy check
				 */
				if (perms_p & AA_DUMMY_REMOUNT)
					tmpflags |= MS_REMOUNT;

				if (conflicting_flags(tmpflags, tmpinv_flags)) {
					PERROR("conflicting flags in the rule\n");
					exit(1);
				}

				flagsv.push_back(tmpflags);
			}
		}

		if (src_conds) {
			perror_conds("mount", src_conds);
			exit(1);
		}
	}

	if (!(flagsv.size() + opt_flagsv.size())) {
		/* no flag options, and not remount, allow everything */
		if (perms_p & AA_DUMMY_REMOUNT) {
			flagsv.push_back(MS_REMOUNT);
			opt_flagsv.push_back(MS_REMOUNT_FLAGS & ~MS_REMOUNT);
		} else {
			flagsv.push_back(MS_ALL_FLAGS);
			opt_flagsv.push_back(MS_ALL_FLAGS);
		}
	} else if (!(flagsv.size())) {
		/* no flags but opts set */
		if (perms_p & AA_DUMMY_REMOUNT)
			flagsv.push_back(MS_REMOUNT);
		else
			flagsv.push_back(0);
	} else if (!(opt_flagsv.size())) {
		opt_flagsv.push_back(0);
	}

	if (perms_p & AA_DUMMY_REMOUNT) {
		perms_p = AA_MAY_MOUNT;
	}
	perms = perms_p;
}

ostream &mnt_rule::dump(ostream &os)
{
	prefix_rule_t::dump(os);

	std::ios::fmtflags fmt(os.flags());

	if (perms & AA_MAY_MOUNT)
		os << "mount";
	else if (perms & AA_MAY_UMOUNT)
		os << "umount";
	else if (perms & AA_MAY_PIVOTROOT)
		os << "pivotroot";
	else
		os << "error: unknown mount perm";

	for (unsigned int i = 0; i < flagsv.size(); i++)
		os << " flags=(0x" << hex << flagsv[i] << ")";
	for (unsigned int i = 0; i < opt_flagsv.size(); i++)
		os << " flags in (0x" << hex << opt_flagsv[i] << ")";

	if (dev_type) {
		os << " type=";
		print_value_list(dev_type, os);
	}
	if (opts) {
		os << " options=";
		print_value_list(opts, os);
	}
	if (device)
		os << " " << device;
	if (mnt_point)
		os << " -> " << mnt_point;
	if (trans)
		os << " -> " << trans;


	os << " " << "(0x" << hex << perms << "/0x" << (audit != AUDIT_UNSPECIFIED ? perms : 0) << ")";
	os << ",\n";

	os.flags(fmt);
	return os;
}

/* does not currently support expansion of vars in options */
int mnt_rule::expand_variables(void)
{
	struct value_list *ent;
	int error = 0;

	error = expand_entry_variables(&mnt_point);
	if (error)
		return error;
	filter_slashes(mnt_point);
	error = expand_entry_variables(&device);
	if (error)
		return error;
	filter_slashes(device);
	error = expand_entry_variables(&trans);
	if (error)
		return error;

	list_for_each(dev_type, ent) {
		error = expand_entry_variables(&ent->value);
		if (error)
			return error;
	}
	list_for_each(opts, ent) {
		error = expand_entry_variables(&ent->value);
		if (error)
			return error;
	}

	return 0;
}

static int cmp_vec_int(std::vector<unsigned int> const &lhs,
		       std::vector<unsigned int> const &rhs)
{
	int res = lhs.size() - rhs.size();
	if (res)
		return res;

	for (unsigned long i = 0; i < lhs.size(); i++) {
		res = lhs[i] - rhs[i];
		if (res)
			return res;
	}

	return 0;
}

int mnt_rule::cmp(rule_t const &rhs) const {
		int res = perms_rule_t::cmp(rhs);
		if (res != 0)
			return res;
		mnt_rule const &rhs_mnt = rule_cast<mnt_rule const &>(rhs);
		res = null_strcmp(mnt_point, rhs_mnt.mnt_point);
		if (res)
			return res;
		res = null_strcmp(device, rhs_mnt.device);
		if (res)
			return res;
		res = null_strcmp(trans, rhs_mnt.trans);
		if (res)
			return res;

		res = cmp_value_list(dev_type, rhs_mnt.dev_type);
		if (res)
			return res;
		res = cmp_value_list(opts, rhs_mnt.opts);
		if (res)
			return res;

		res = cmp_vec_int(flagsv, rhs_mnt.flagsv);
		if (res)
			return res;
		return cmp_vec_int(opt_flagsv, rhs_mnt.opt_flagsv);
	}

static bool build_mnt_flags(char *buffer, int size, unsigned int flags,
			   unsigned int opt_flags)
{
	char *p = buffer;
	int i, len = 0;

	if (flags == MS_ALL_FLAGS) {
		/* all flags are optional */
		len = snprintf(p, size, "%s", default_match_pattern);
		if (len < 0 || len >= size)
			return false;
		return true;
	}
	for (i = 0; i <= 31; ++i) {
		if ((opt_flags) & (1 << i))
			len = snprintf(p, size, "(\\x%02x|)", i + 1);
		else if (flags & (1 << i))
			len = snprintf(p, size, "\\x%02x", i + 1);
		else	/* no entry = not set */
			continue;

		if (len < 0 || len >= size)
			return false;
		p += len;
		size -= len;
	}

	/* this needs to go once the backend is updated. */
	if (buffer == p) {
		/* match nothing - use impossible 254 as regex parser doesn't
		 * like the empty string
		 */
		if (size < 9)
			return false;

		strcpy(p, "(\\xfe|)");
	}

	return true;
}

static bool build_mnt_opts(std::string& buffer, struct value_list *opts)
{
	struct value_list *ent;
	pattern_t ptype;
	int pos;

	if (!opts) {
		buffer.append(default_match_pattern);
		return true;
	}

	list_for_each(opts, ent) {
		ptype = convert_aaregex_to_pcre(ent->value, 0, glob_default, buffer, &pos);
		if (ptype == ePatternInvalid)
			return false;

		if (ent->next)
			buffer.append(",");
	}

	return true;
}

void mnt_rule::warn_once(const char *name)
{
	rule_t::warn_once(name, "mount rules not enforce");
}


int mnt_rule::gen_policy_remount(Profile &prof, int &count,
				 unsigned int flags, unsigned int opt_flags)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	char flagsbuf[PATH_MAX + 3];
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* remount can't be conditional on device and type */
	/* rule class single byte header */
	mntbuf.assign(class_mount_hdr);
	if (mnt_point) {
		/* both device && mnt_point or just mnt_point */
		if (!convert_entry(mntbuf, mnt_point))
			goto fail;
		vec[0] = mntbuf.c_str();
	} else {
		if (!convert_entry(mntbuf, device))
			goto fail;
		vec[0] = mntbuf.c_str();
	}
	/* skip device */
	vec[1] = default_match_pattern;
	/* skip type */
	vec[2] = default_match_pattern;

	if (!build_mnt_flags(flagsbuf, PATH_MAX, flags & MS_REMOUNT_FLAGS,
			     opt_flags & MS_REMOUNT_FLAGS))
		goto fail;

	vec[3] = flagsbuf;

	perm32_t tmpperms, tmpaudit;
	if (opts) {
		tmpperms = AA_MATCH_CONT;
		tmpaudit = 0;
	} else {
		/* dependent on full expansion of any data match perms */
		tmpperms = perms;
		tmpaudit = audit == AUDIT_FORCE ? perms : 0;
	}
	/* match for up to but not including data
	 * if a data match is required this only has AA_MATCH_CONT perms
	 * else it has full perms
	 */
	if (!prof.policy.rules->add_rule_vec(priority, rule_mode, tmpperms,
					     tmpaudit, 4, vec, parseopts,
					     false))
		goto fail;
	count++;

	if (opts) {
		/* rule with data match required */
		optsbuf.clear();
		if (!build_mnt_opts(optsbuf, opts))
			goto fail;
		vec[4] = optsbuf.c_str();
		if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
						     (audit == AUDIT_FORCE ? perms : 0),
						     5, vec, parseopts, false))
			goto fail;
		count++;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}

int mnt_rule::gen_policy_bind_mount(Profile &prof, int &count,
				    unsigned int flags, unsigned int opt_flags)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	char flagsbuf[PATH_MAX + 3];
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* bind mount rules can't be conditional on dev_type or data */
	/* rule class single byte header */
	mntbuf.assign(class_mount_hdr);
	if (!convert_entry(mntbuf, mnt_point))
		goto fail;
	vec[0] = mntbuf.c_str();
	if (device && strcmp(device, "detached") == 0) {
		/* see note in move_mount. match nothing */
		devbuf.clear();
	} else if (!clear_and_convert_entry(devbuf, device)) {
		goto fail;
	}
	vec[1] = devbuf.c_str();
	/* skip type */
	vec[2] = default_match_pattern;

	if (!build_mnt_flags(flagsbuf, PATH_MAX, flags & MS_BIND_FLAGS,
			     opt_flags & MS_BIND_FLAGS))
		goto fail;
	vec[3] = flagsbuf;
	if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
					     audit == AUDIT_FORCE ? perms : 0,
					     4, vec,
					     parseopts, false))
		goto fail;
	count++;

	return RULE_OK;

fail:
	return RULE_ERROR;
}

int mnt_rule::gen_policy_change_mount_type(Profile &prof, int &count,
					   unsigned int flags,
					   unsigned int opt_flags)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	char flagsbuf[PATH_MAX + 3];
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];
	char *mountpoint = mnt_point;

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* change type base rules can specify the mount point by using
	 * the parser token position reserved to device. that's why if
	 * the mount point is not specified, we use device in its
	 * place. this is a deprecated behavior.
	 *
	 * change type base rules can not be conditional on device
	 * (source), device type or data
	 */
	/* rule class single byte header */
	mntbuf.assign(class_mount_hdr);
	if (flags && flags != MS_ALL_FLAGS && device && mnt_point) {
		PERROR("source and mount point cannot be used at the "
		       "same time for propagation type flags");
		goto fail;
	} else if (device && !mnt_point) {
		pwarn(WARN_DEPRECATED, _("The use of source as mount point for "
					 "propagation type flags is deprecated.\n"));
		mountpoint = device;
	}
	if (!convert_entry(mntbuf, mountpoint))
		goto fail;
	vec[0] = mntbuf.c_str();
	/* skip device and type */
	vec[1] = default_match_pattern;
	vec[2] = default_match_pattern;

	if (!build_mnt_flags(flagsbuf, PATH_MAX, flags & MS_MAKE_FLAGS,
			     opt_flags & MS_MAKE_FLAGS))
		goto fail;
	vec[3] = flagsbuf;
	if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
					     audit == AUDIT_FORCE ? perms : 0,
					     4, vec,
					     parseopts, false))
		goto fail;
	count++;

	return RULE_OK;

fail:
	return RULE_ERROR;
}

int mnt_rule::gen_policy_move_mount(Profile &prof, int &count,
				    unsigned int flags, unsigned int opt_flags)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	char flagsbuf[PATH_MAX + 3];
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* mount move rules can not be conditional on dev_type,
	 * or data
	 */
	/* rule class single byte header */
	mntbuf.assign(class_mount_hdr);
	if (!convert_entry(mntbuf, mnt_point))
		goto fail;
	vec[0] = mntbuf.c_str();
	if (device && strcmp(device, "detached") == 0) {
		/* see note in move_mount. match nothing */
		devbuf.clear();
	} else if (!clear_and_convert_entry(devbuf, device)) {
		goto fail;
	}
	vec[1] = devbuf.c_str();
	/* skip type */
	vec[2] = default_match_pattern;

	if (!build_mnt_flags(flagsbuf, PATH_MAX, flags & MS_MOVE_FLAGS,
			     opt_flags & MS_MOVE_FLAGS))
		goto fail;
	vec[3] = flagsbuf;
	if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
					     audit == AUDIT_FORCE ? perms : 0,
					     4, vec,
					     parseopts, false))
		goto fail;
	count++;

	return RULE_OK;

fail:
	return RULE_ERROR;
}

int mnt_rule::gen_policy_new_mount(Profile &prof, int &count,
				   unsigned int flags, unsigned int opt_flags)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	char flagsbuf[PATH_MAX + 3];
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* rule class single byte header */
	mntbuf.assign(class_mount_hdr);
	if (!convert_entry(mntbuf, mnt_point))
		goto fail;
	vec[0] = mntbuf.c_str();
	if (device && strcmp(device, "detached") == 0) {
		/* see note in move mount. match nothing */
		devbuf.clear();
	} else if (!clear_and_convert_entry(devbuf, device)) {
		goto fail;
	}
	vec[1] = devbuf.c_str();
	typebuf.clear();
	if (!build_list_val_expr(typebuf, dev_type))
		goto fail;
	vec[2] = typebuf.c_str();

	if (!build_mnt_flags(flagsbuf, PATH_MAX, flags & MS_NEW_FLAGS,
			     opt_flags & MS_NEW_FLAGS))
		goto fail;
	vec[3] = flagsbuf;

	perm32_t tmpperms, tmpaudit;
	if (opts) {
		tmpperms = AA_MATCH_CONT;
		tmpaudit = 0;
	} else {
		tmpperms = perms;
		tmpaudit = audit == AUDIT_FORCE ? perms : 0;
	}
	/* rule for match without required data || data MATCH_CONT */
	if (!prof.policy.rules->add_rule_vec(priority, rule_mode, tmpperms,
					     tmpaudit, 4, vec, parseopts,
					     false))
		goto fail;
	count++;

	if (opts) {
		/* rule with data match required */
		optsbuf.clear();
		if (!build_mnt_opts(optsbuf, opts))
			goto fail;
		vec[4] = optsbuf.c_str();
		if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
						     audit == AUDIT_FORCE ? perms : 0,
						     5, vec, parseopts, false))
			goto fail;
		count++;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}

int mnt_rule::gen_flag_rules(Profile &prof, int &count, unsigned int flags,
			     unsigned int opt_flags)
{
	/*
	 * XXX: added !flags to cover cases like:
	 * mount options in (bind) /d -> /4,
	 */
	if ((perms & AA_MAY_MOUNT) && (!flags || flags == MS_ALL_FLAGS)) {
		/* no mount flags specified, generate multiple rules */
		if (!device && !dev_type &&
		    gen_policy_remount(prof, count, flags, opt_flags) == RULE_ERROR)
			return RULE_ERROR;
		if (!dev_type && !opts &&
		    gen_policy_bind_mount(prof, count, flags, opt_flags) == RULE_ERROR)
			return RULE_ERROR;
		if ((!device || !mnt_point) && !dev_type && !opts &&
		    gen_policy_change_mount_type(prof, count, flags, opt_flags) == RULE_ERROR)
			return RULE_ERROR;
		if (!dev_type && !opts &&
		    gen_policy_move_mount(prof, count, flags, opt_flags) == RULE_ERROR)
			return RULE_ERROR;

		return gen_policy_new_mount(prof, count, flags, opt_flags);
	} else if ((perms & AA_MAY_MOUNT) && (flags & MS_REMOUNT)
		   && !device && !dev_type) {
		return gen_policy_remount(prof, count, flags, opt_flags);
	} else if ((perms & AA_MAY_MOUNT) && (flags & MS_BIND)
		   && !dev_type && !opts) {
		return gen_policy_bind_mount(prof, count, flags, opt_flags);
	} else if ((perms & AA_MAY_MOUNT) &&
		   (flags & (MS_MAKE_CMDS))
		   && (!device || !mnt_point) && !dev_type && !opts) {
		return gen_policy_change_mount_type(prof, count, flags, opt_flags);
	} else if ((perms & AA_MAY_MOUNT) && (flags & MS_MOVE)
		   && !dev_type && !opts) {
		return gen_policy_move_mount(prof, count, flags, opt_flags);
	} else if ((perms & AA_MAY_MOUNT) &&
		   ((flags | opt_flags) & ~MS_CMDS)) {
		/* generic mount if flags are set that are not covered by
		 * above commands
		 */
		return gen_policy_new_mount(prof, count, flags, opt_flags);
	} /* else must be RULE_OK for some rules */

	return RULE_OK;
}

int mnt_rule::gen_policy_re(Profile &prof)
{
	std::string mntbuf;
	std::string devbuf;
	std::string typebuf;
	std::string optsbuf;
	char class_mount_hdr[64];
	const char *vec[5];
	int count = 0;

	if (!features_supports_mount) {
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}

	sprintf(class_mount_hdr, "\\x%02x", AA_CLASS_MOUNT);

	/* a single mount rule may result in multiple matching rules being
	 * created in the backend to cover all the possible choices
	 */
	for (size_t i = 0; i < flagsv.size(); i++) {
		for (size_t j = 0; j < opt_flagsv.size(); j++) {
			if (gen_flag_rules(prof, count, flagsv[i], opt_flagsv[j]) == RULE_ERROR)
				goto fail;
		}
	}
	if (perms & AA_MAY_UMOUNT) {
		/* rule class single byte header */
		mntbuf.assign(class_mount_hdr);
		if (!convert_entry(mntbuf, mnt_point))
			goto fail;
		vec[0] = mntbuf.c_str();
		if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
					(audit == AUDIT_FORCE ? perms : 0), 1, vec,
					parseopts, false))
			goto fail;
		count++;
	}
	if (perms & AA_MAY_PIVOTROOT) {
		/* rule class single byte header */
		mntbuf.assign(class_mount_hdr);
		if (!convert_entry(mntbuf, mnt_point))
			goto fail;
		vec[0] = mntbuf.c_str();
		if (!clear_and_convert_entry(devbuf, device))
			goto fail;
		vec[1] = devbuf.c_str();
		if (!prof.policy.rules->add_rule_vec(priority, rule_mode, perms,
					(audit == AUDIT_FORCE ? perms : 0), 2, vec,
					parseopts, false))
			goto fail;
		count++;
	}

	if (!count)
		/* didn't actually encode anything */
		goto fail;

	return RULE_OK;

fail:
	PERROR("Encoding of mount rule failed\n");
	return RULE_ERROR;
}

void mnt_rule::post_parse_profile(Profile &prof aa_unused)
{
	if (trans) {
		/* TODO: pivot_root profile transition */
	}
}


