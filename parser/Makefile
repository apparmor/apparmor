# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007
#    NOVELL (All rights reserved)
#
#    Copyright (c) Christian Boltz 2018-2025
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, contact Novell, Inc.
# ----------------------------------------------------------------------
NAME=apparmor-parser
all:
COMMONDIR=../common/

include $(COMMONDIR)/Make.rules

DESTDIR=/
SBINDIR=${DESTDIR}/sbin
USR_SBINDIR=${DESTDIR}/usr/sbin
CONFDIR=/etc/apparmor
INSTALL_CONFDIR=${DESTDIR}${CONFDIR}
LOCALEDIR=/usr/share/locale
MANPAGES=apparmor.d.5 apparmor.7 apparmor_parser.8 apparmor_xattrs.7

# Test for bison version
# parse.error added in version 3.0
# default behavior changed in version 3.6
# parse.error=verbose supported from 3.0 so just test on that
# TODO move to autoconf
BISON_MAJOR:=$(shell bison --version |  ${AWK} '/^bison/ { print ($$NF) }'  | ${AWK} -F. '{print $$1 }')
USE_PARSE_ERROR:=$(shell test "${BISON_MAJOR}" -ge 3 && echo true)

YACC	:= bison
YFLAGS	:= -d
ifeq ($(USE_PARSE_ERROR),true)
YFLAGS+=--define=parse.error=verbose
endif
LEX	:= flex
LEXFLAGS = -B -v
ifndef DEBUG
LEXFLAGS += --noyy_top_state
endif

CPPFLAGS += -D_GNU_SOURCE

STDLIB_INCLUDE:="\#include <stdlib.h>"
HAVE_REALLOCARRAY:=$(shell echo $(STDLIB_INCLUDE) | ${CPP} ${CPPFLAGS} - - | grep -q reallocarray && echo true)

WARNINGS = -Wall
CXX_WARNINGS = ${WARNINGS} ${EXTRA_WARNINGS}

ifndef CXXFLAGS
CXXFLAGS	= -g -O2 -pipe

ifdef DEBUG
CXXFLAGS += -pg -D DEBUG
endif
ifdef COVERAGE
CXXFLAGS = -g -pg -fprofile-arcs -ftest-coverage
endif
endif #CXXFLAGS

HAVE_FLTO_PARTITION_NONE:=$(shell ${CC} -E -flto-partition=none /dev/null 1>/dev/null 2>&1 && echo true)
ifeq ($(HAVE_FLTO_PARTITION_NONE),true)
	CXXFLAGS += -flto-partition=none
endif

EXTRA_CXXFLAGS = ${CXXFLAGS} ${CPPFLAGS} ${CXX_WARNINGS} -std=gnu++0x

ifeq ($(HAVE_REALLOCARRAY),true)
EXTRA_CXXFLAGS+=-DHAVE_REALLOCARRAY=1
endif

ifdef DEBUG
LEXLIB	:= -lfl
endif


# Internationalization support. Define a package and a LOCALEDIR
EXTRA_CXXFLAGS+=-DPACKAGE=\"${NAME}\" -DLOCALEDIR=\"${LOCALEDIR}\"

# Config directory (default /etc/apparmor; overridable at build time for packaging)
EXTRA_CXXFLAGS+=-DCONFDIR=\"${CONFDIR}\"

SRCS = parser_common.c parser_include.c parser_interface.c parser_lex.c \
       parser_main.c parser_misc.c parser_merge.c parser_symtab.c \
       parser_yacc.c parser_regex.c parser_variable.c parser_policy.c \
       parser_alias.c common_optarg.c lib.c network.cc \
       mount.cc dbus.cc profile.cc rule.cc signal.cc ptrace.cc \
       af_rule.cc af_unix.cc policy_cache.c default_features.c userns.cc \
       mqueue.cc io_uring.cc all_rule.cc cond_expr.cc variable.cc symtab.cc
STATIC_HDRS = af_rule.h af_unix.h capability.h common_optarg.h dbus.h \
       file_cache.h immunix.h lib.h mount.h network.h parser.h \
       parser_include.h parser_version.h policy_cache.h policydb.h \
       profile.h ptrace.h rule.h signal.h userns.h mqueue.h io_uring.h \
       common_flags.h all_rule.h cond_expr.h variable.h symtab.h

SPECIAL_HDRS = parser_yacc.h unit_test.h base_cap_names.h
GENERATED_HDRS = af_names.h generated_af_names.h \
       cap_names.h generated_cap_names.h parser_version.h errnos.h
LIBAA_HDRS = libapparmor_re/apparmor_re.h libapparmor_re/aare_rules.h

TOOLS = apparmor_parser

OBJECTS = $(patsubst %.cc, %.o, $(SRCS:.c=.o))

AAREDIR= libapparmor_re
AAREOBJECT = ${AAREDIR}/libapparmor_re.a
AAREOBJECTS = $(AAREOBJECT)
AARE_LDFLAGS = -L. $(LDFLAGS)
ifdef WITH_STATIC_LINKING
  AARE_LDFLAGS += -static-libgcc -static-libstdc++
endif

ifdef WITH_STATIC_LINKING
  AALIB = -Wl,-Bstatic -lapparmor -lzstd -Wl,-Bdynamic -lpthread
else
  AALIB = -lapparmor -lzstd -lpthread
endif

ifdef WITH_LIBINTL
	AALIB += -lintl
endif

ifdef USE_SYSTEM
  # Using the system libapparmor so Makefile dependencies can't be used
  LIBAPPARMOR_A =
  INCLUDE_APPARMOR =
  APPARMOR_H =
  LD_LIBRARY_PATH?=
else
  ifdef USE_INTREE
    LIBAPPARMOR_SRC = $(realpath -f ../libraries/libapparmor)
  else
    LIBAPPARMOR_SRC = ../libraries/libapparmor
  endif

  LOCAL_LIBAPPARMOR_INCLUDE = $(LIBAPPARMOR_SRC)/include
  LOCAL_LIBAPPARMOR_LDPATH = $(LIBAPPARMOR_SRC)/src/.libs
  LD_LIBRARY_PATH:="$(LOCAL_LIBAPPARMOR_LDPATH)"

  ifdef WITH_STATIC_LINKING
    LIBAPPARMOR_A = $(LOCAL_LIBAPPARMOR_LDPATH)/libapparmor.a
  else
    LIBAPPARMOR_A = $(LOCAL_LIBAPPARMOR_LDPATH)/libapparmor.so
  endif

  INCLUDE_APPARMOR = -I$(LOCAL_LIBAPPARMOR_INCLUDE)
  APPARMOR_H = $(LOCAL_LIBAPPARMOR_INCLUDE)/sys/apparmor.h

  AARE_LDFLAGS += -L$(LOCAL_LIBAPPARMOR_LDPATH)
  ifdef USE_INTREE
    AARE_LDFLAGS += -Wl,-rpath,$(LOCAL_LIBAPPARMOR_LDPATH)
  endif
endif
EXTRA_CXXFLAGS += $(INCLUDE_APPARMOR)

LEX_C_FILES	= parser_lex.c
YACC_C_FILES	= parser_yacc.c parser_yacc.h

TESTS = tst_regex tst_misc tst_symtab tst_variable tst_lib tst_interface
TEST_CXXFLAGS = $(EXTRA_CXXFLAGS) -DUNIT_TEST -Wno-unused-result
TEST_OBJECTS = $(filter-out \
			parser_lex.o \
			parser_yacc.o \
			common_optarg.o \
			parser_main.o \
			policy_cache.o, ${OBJECTS}) \
               $(AAREOBJECTS)
TEST_LDFLAGS = $(AARE_LDFLAGS)
TEST_LDLIBS = $(AALIB)

ifdef V
  VERBOSE = 1
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  BUILD_OUTPUT =
  Q =
else
  BUILD_OUTPUT = > /dev/null 2>&1
  Q = @
endif
export Q VERBOSE BUILD_OUTPUT

HDRS=$(STATIC_HDRS) $(GENERATED_HDRS) parser_yacc.h $(LIBAA_HDRS) $(APPARMOR_H)


po/${NAME}.pot: ${SRCS} ${STATIC_HDRS}
	$(MAKE) -C po ${NAME}.pot NAME=${NAME} SOURCES="${SRCS} ${STATIC_HDRS}"

techdoc.pdf: techdoc.tex
	timestamp=$(shell date --utc "+%Y%m%d%H%M%S%z" -r $< );\
	while pdflatex "\def\fixedpdfdate{$$timestamp}\input $<" ${BUILD_OUTPUT} || exit 1 ; \
		grep -q "Label(s) may have changed" techdoc.log; \
	do :; done

techdoc/index.html: techdoc.pdf
	latex2html -show_section_numbers -split 0 -noinfo -nonavigation -noaddress techdoc.tex ${BUILD_OUTPUT}

techdoc.txt: techdoc/index.html
	w3m -dump $< > $@

# targets arranged this way so that people who don't want full docs can
# pick specific targets they want.
arch: 	$(TOOLS)

manpages:	$(MANPAGES)

htmlmanpages:	$(HTMLMANPAGES)

pdf:	techdoc.pdf

docs:	manpages htmlmanpages
extra_docs: pdf

indep: docs
	$(Q)$(MAKE) -C po all

all:	arch indep

.PHONY: coverage
coverage:
	$(MAKE) clean apparmor_parser COVERAGE=1

ifndef USE_SYSTEM
$(LIBAPPARMOR_A):
	@if [ ! -f $@ ]; then \
		echo "error: $@ is missing. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Build against the in-tree libapparmor by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Build against the system libapparmor by adding USE_SYSTEM=1 to your make command." 1>&2;\
		exit 1; \
	fi
endif

apparmor_parser: $(OBJECTS) $(AAREOBJECTS) $(LIBAPPARMOR_A)
	$(CXX) $(LDFLAGS) $(EXTRA_CXXFLAGS) -o $@ $(OBJECTS) $(LIBS) \
	      ${LEXLIB}  $(AAREOBJECTS) $(AARE_LDFLAGS) $(AALIB)

parser_yacc.c: parser_yacc.y $(STATIC_HDRS) $(GENERATED_HDRS)
	$(YACC) $(YFLAGS) -o parser_yacc.c parser_yacc.y

parser_yacc.h: parser_yacc.c

parser_lex.c: parser_lex.l $(HDRS)
	$(LEX) ${LEXFLAGS} -o$@ $<

parser_lex.o: parser_lex.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_misc.o: parser_misc.c $(HDRS) unit_test.h
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_yacc.o: parser_yacc.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_main.o: parser_main.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_interface.o: parser_interface.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_include.o: parser_include.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_merge.o: parser_merge.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_regex.o: parser_regex.c $(HDRS) unit_test.h
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_symtab.o: parser_symtab.c $(HDRS) unit_test.h
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_variable.o: parser_variable.c $(HDRS) unit_test.h
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_policy.o: parser_policy.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_alias.o: parser_alias.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

parser_common.o: parser_common.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

mount.o: mount.cc mount.h $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

common_optarg.o: common_optarg.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

policy_cache.o: policy_cache.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

lib.o: lib.c $(HDRS) unit_test.h
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

dbus.o: dbus.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

signal.o: signal.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

ptrace.o: ptrace.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

network.o: network.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

default_features.o: default_features.c $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

af_rule.o: af_rule.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

af_unix.o: af_unix.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

profile.o: profile.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

rule.o: rule.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

userns.o: userns.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

mqueue.o: mqueue.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

io_uring.o: io_uring.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

all_rule.o: all_rule.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

cond_expr.o: cond_expr.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

variable.o: variable.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<

symtab.o: symtab.cc $(HDRS)
	$(CXX) $(EXTRA_CXXFLAGS) -c -o $@ $<


parser_version.h: Makefile
	@echo \#define PARSER_VERSION \"$(VERSION)\" > .ver
	@mv -f .ver $@

# af_names and capabilities generation has moved to common/Make.rules,
# as well as the filtering that occurs for network protocols that
# apparmor should not mediate.

generated_af_names.h: ../common/list_af_names.sh
	../common/list_af_names.sh > $@

af_names.h: generated_af_names.h base_af_names.h
	@cat base_af_names.h | diff -u - generated_af_names.h | grep -v '^.AF_MAX' | grep '^+[^+]' ; \
	if [ $$? -eq 1 ] ; then \
		cat base_af_names.h | LC_ALL=C sed -n -e 's/[ \t]\?AF_MAX[ \t]\+[0-9]\+,//g'  -e 's/[ \t]\+\?AF_\([A-Z0-9_]\+\)[ \t]\+\([0-9]\+\),/#ifndef AF_\1\n#  define AF_\1 \2\n#endif\nAA_GEN_NET_ENT("\L\1", \UAF_\1)\n/pg' > $@ ; \
		cat base_af_names.h | LC_ALL=C sed -n -e 's/AF_MAX[ \t]\+\([0-9]\+\),\?.*/\n#define AA_AF_MAX \1\n/p' >> $@ ; \
	else \
		echo "Error: new AF names detected; please update base_af_names.h with values from generated_af_names.h" ; \
		exit 1 ; \
	fi

generated_cap_names.h: /usr/include/linux/capability.h
	../common/list_capabilities.sh | LC_ALL=C sed -n -e "s/[ \\t]\\?CAP_\\([A-Z0-9_]\\+\\)/\{\"\\L\\1\", \\UCAP_\\1, NO_BACKMAP_CAP, CAPFLAG_BASE_FEATURE\},\\n/pg" > $@

cap_names.h: generated_cap_names.h base_cap_names.h
	@LC_ALL=C sed -e 's/\([^,]*,[^,]*,\) CAP_[A-Z0-9_]\+,/\1 NO_BACKMAP_CAP,/g' base_cap_names.h | diff -u - generated_cap_names.h | grep '^+[^+]' ; \
	if [ $$? -eq 1 ] ; then \
		cp base_cap_names.h $@ ; \
	else \
		echo "Error: new capabilities detected please update base_cap_names.h with values from generated_cap_names.h" ; \
		LC_ALL=C sed -e 's/\([^,]*,[^,]*,\) CAP_[A-Z0-9_]\+,/\1 NO_BACKMAP_CAP,/g' base_cap_names.h | diff -u - generated_cap_names.h ; \
		exit 1; \
	fi

.PHONY: tst_binaries
tst_binaries: $(TESTS)

tst_lib: lib.c parser.h $(filter-out lib.o, ${TEST_OBJECTS})
	$(CXX) $(TEST_CXXFLAGS) -o $@ $< $(filter-out $(<:.c=.o), ${TEST_OBJECTS}) $(TEST_LDFLAGS) $(TEST_LDLIBS)
tst_%: parser_%.c parser.h $(filter-out parser_%.o, ${TEST_OBJECTS})
	$(CXX) $(TEST_CXXFLAGS) -o $@ $< $(filter-out $(<:.c=.o), ${TEST_OBJECTS}) $(TEST_LDFLAGS) $(TEST_LDLIBS)

errnos.h:
	echo '#include <errno.h>' > dump.c
	$(CC) $(CPPFLAGS) -E -dD dump.c | $(AWK) '/^#define E/ { printf "{ \"%s\", %s },\n", $$2, $$2 }' > errnos.h
	rm -f dump.c

.SILENT: check
.PHONY: check
check: check_pod_files tests

.SILENT: tests
tests: apparmor_parser ${TESTS}
	sh -e -c 'for test in ${TESTS} ; do echo "*** running $${test}" && LD_LIBRARY_PATH="$(LD_LIBRARY_PATH)" ./$${test}; done'
	$(Q)$(MAKE) -s -C tst tests

$(AAREOBJECT): FORCE
	$(MAKE) -C $(AAREDIR) CFLAGS="$(EXTRA_CXXFLAGS)"

.PHONY: install
install:
	$(MAKE) install-indep
	$(MAKE) install-arch

.PHONY: install-arch
install-arch: arch
	install -m 755 -d $(SBINDIR)
	install -m 755 ${TOOLS} $(SBINDIR)

.PHONY: install-indep
install-indep: indep
	install -m 755 -d $(INSTALL_CONFDIR)
	install -m 644 parser.conf $(INSTALL_CONFDIR)
	$(MAKE) -C po install NAME=${NAME} DESTDIR=${DESTDIR}
	$(MAKE) install_manpages DESTDIR=${DESTDIR}

ifndef VERBOSE
.SILENT: clean
endif
.PHONY: clean
clean: pod_clean
	rm -f core core.* *.o *.s *.a *~ *.gcda *.gcno
	rm -f gmon.out
	rm -f $(TOOLS) $(TESTS)
	rm -f $(LEX_C_FILES)
	rm -f $(YACC_C_FILES)
	rm -f $(NAME)*.tar.gz $(NAME)*.tgz
	rm -f $(GENERATED_HDRS)
	rm -rf techdoc.aux techdoc.out techdoc.log techdoc.pdf techdoc.toc techdoc.txt techdoc/
	$(MAKE) -s -C $(AAREDIR) clean
	$(MAKE) -s -C po clean
	$(MAKE) -s -C tst clean

FORCE:
