INCLUDES = $(all_includes)

# variables to set the library versions used by libtool
# Step through these rules IN ORDER to update the library version.
# 1. Update the version information only immediately before a public release
#    of your software. More frequent updates are unnecessary, and only
#    guarantee that the current interface number gets larger faster.
# 2. If the library source code has changed at all since the last update,
#    then
#    - increment AA_LIB_REVISION
# 3. If any interfaces have been added, removed, or changed since the last
#    update,
#    - increment AA_LIB_CURRENT
#      - by 1 if bugfix release
#      - by 5 on larger releases. This gives room to fix library interface
#        problems in the unlikely event where an interface has to break.
#    - set AA_LIB_REVISION to 0.
# 4. If any interfaces have been added since the last public release, then
#    - increment AA_LIB_AGE by the same amount that AA_LIB_CURRENT was
#      incremented.
# 5. If any interfaces have been removed or changed since the last public
#    release, then
#    - set AA_LIB_AGE to 0.
#
# The resulting library version triplet will be:
#   (AA_LIB_CURRENT - AA_LIB_AGE).AA_LIB_AGE.AA_LIB_REVISION
# and the SONAME will be:
#   libapparmor.so.(AA_LIB_CURRENT - AA_LIB_AGE)
#
# For more information, see:
# http://www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html
#
# After changing the AA_LIB_* variables, also update EXPECTED_SO_NAME.

AA_LIB_CURRENT = 25
AA_LIB_REVISION = 3
AA_LIB_AGE = 24
EXPECTED_SO_NAME = libapparmor.so.1.24.3

SUFFIXES = .pc.in .pc

COMMONDIR=$(top_srcdir)/../../common/
include $(COMMONDIR)/Make.rules

BUILT_SOURCES = grammar.h scanner.h af_protos.h
AM_LFLAGS = -v
AM_YFLAGS = -Wno-yacc -d -p aalogparse_
AM_CPPFLAGS = -D_GNU_SOURCE -I$(top_srcdir)/include/
scanner.h: scanner.l
	$(LEX) -v $<

scanner.c: scanner.l

af_protos.h:
	 echo '#include <netinet/in.h>' | $(CC) $(CPPFLAGS) -E -dD - | LC_ALL=C  sed  -n -e "/IPPROTO_MAX/d"  -e "s/^\#define[ \\t]\\+IPPROTO_\\([A-Z0-9_]\\+\\)\\(.*\\)$$/AA_GEN_PROTO_ENT(\\UIPPROTO_\\1, \"\\L\\1\")/p" > $@

lib_LTLIBRARIES = libapparmor.la
noinst_HEADERS = grammar.h parser.h scanner.h af_protos.h private.h PMurHash.h

libapparmor_la_SOURCES = grammar.y libaalogparse.c kernel.c scanner.c private.c features.c kernel_interface.c policy_cache.c PMurHash.c
libapparmor_la_LDFLAGS = -version-info $(AA_LIB_CURRENT):$(AA_LIB_REVISION):$(AA_LIB_AGE) -XCClinker -Bdynamic -pthread \
	-Wl,--version-script=$(top_srcdir)/src/libapparmor.map

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libapparmor.pc

CLEANFILES = libapparmor.pc

%.pc: %.pc.in $(top_builddir)/config.status
	$(AM_V_GEN)cd "$(top_builddir)" && \
	$(SHELL) ./config.status --file="src/$@"

tst_aalogmisc_SOURCES = tst_aalogmisc.c
tst_aalogmisc_LDADD = .libs/libapparmor.a

tst_aalogparse_cpp_SOURCES = tst_aalogparse_cpp.cpp
tst_aalogparse_cpp_LDADD = .libs/libapparmor.a

tst_aalogparse_oldname_SOURCES = tst_aalogparse_oldname.c
tst_aalogparse_oldname_LDADD = .libs/libapparmor.a

tst_aalogparse_reentrancy_SOURCES = tst_aalogparse_reentrancy.c
tst_aalogparse_reentrancy_LDADD = .libs/libapparmor.a
tst_aalogparse_reentrancy_LDFLAGS = -pthread

tst_features_SOURCES = tst_features.c
tst_features_LDADD = .libs/libapparmor.a

tst_kernel_SOURCES = tst_kernel.c
tst_kernel_LDADD = .libs/libapparmor.a
tst_kernel_LDFLAGS = -pthread

check_PROGRAMS = tst_aalogmisc tst_aalogparse_cpp tst_aalogparse_reentrancy tst_aalogparse_oldname tst_features tst_kernel
TESTS = $(check_PROGRAMS)

.PHONY: check-local
check-local:
	test -f ./.libs/$(EXPECTED_SO_NAME) || { echo '*** unexpected .so name/number for libapparmor (expected $(EXPECTED_SO_NAME), the actual filename is shown below) ***' ; ls -l ./.libs/libapparmor.so.*.* ; exit 1; }

EXTRA_DIST = grammar.y scanner.l libapparmor.map libapparmor.pc
