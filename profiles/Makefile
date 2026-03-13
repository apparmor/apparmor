# ------------------------------------------------------------------
#
#    Copyright (C) 2002-2009 Novell/SUSE
#    Copyright (C) 2010-2016 Canonical Ltd.
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
#
# ------------------------------------------------------------------

# Makefile for LSM-based AppArmor profiles

NAME=apparmor-profiles
all: docs
COMMONDIR=../common/

include $(COMMONDIR)/Make.rules

DESTDIR=/
PROFILES_DEST=${DESTDIR}/etc/apparmor.d
EXTRAS_DEST=${DESTDIR}/usr/share/apparmor/extra-profiles
PROFILES_SOURCE=./apparmor.d
ABSTRACTIONS_SOURCE=./apparmor.d/abstractions
EXTRAS_SOURCE=./apparmor/profiles/extras
EXTRAS_ABSTRACTIONS_SOURCE=./apparmor/profiles/extras/abstractions

ifdef USE_SYSTEM
    PYTHONPATH=
    PARSER?=apparmor_parser
    LOGPROF?=aa-logprof
else
    # PYTHON_DIST_BUILD_PATH based on libapparmor/swig/python/test/Makefile.am
    PYTHON_DIST_BUILD_PATH = ../libraries/libapparmor/swig/python/build/$$($(PYTHON) ../libraries/libapparmor/swig/python/test/buildpath.py)
    LIBAPPARMOR_PATH=../libraries/libapparmor/src/.libs/
    LD_LIBRARY_PATH=$(LIBAPPARMOR_PATH):$(PYTHON_DIST_BUILD_PATH)
    PYTHONPATH=../utils/:$(PYTHON_DIST_BUILD_PATH)
    PARSER?=../parser/apparmor_parser
    # use ../utils logprof
    LOGPROF?=LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) PYTHONPATH=$(PYTHONPATH) $(PYTHON) ../utils/aa-logprof --configdir ../utils/
endif

# $(PWD) is wrong when using "make -C profiles" - explicitly set it here to get the right value
PWD=$(shell pwd)

.PHONY: test-dependencies
test-dependencies: __parser __libapparmor


.PHONY: __parser __libapparmor
__parser:
ifndef USE_SYSTEM
	@if [ ! -f $(PARSER) ]; then \
		echo "error: $(PARSER) is missing. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Test using the in-tree parser by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Test using the system parser by adding USE_SYSTEM=1 to your make command." 1>&2; \
		exit 1; \
	fi
endif

__libapparmor:
ifndef USE_SYSTEM
	@if [ ! -f $(LIBAPPARMOR_PATH)libapparmor.so ]; then \
		echo "error: $(LIBAPPARMOR_PATH)libapparmor.so is missing. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Build against the in-tree libapparmor by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Build against the system libapparmor by adding USE_SYSTEM=1 to your make command." 1>&2; \
		exit 1; \
	fi
endif

local:
	for profile in $$(find ${PROFILES_SOURCE} -maxdepth 1 -type f) ; do \
		fn=$$(basename $$profile); \
		echo "# Site-specific additions and overrides for '$$fn'" > ${PROFILES_SOURCE}/local/$$fn; \
		grep "include[[:space:]]\\+if[[:space:]]\\+exists[[:space:]]\\+<local/$$fn>" "$$profile" >/dev/null || { echo "$$profile doesn't contain include if exists <local/$$fn>" ; exit 1; } ; \
	done

.PHONY: install
install:
	install -m 755 -d ${PROFILES_DEST}
	install -m 755 -d ${PROFILES_DEST}/disable
	for dir in $$(cd ${PROFILES_SOURCE} && find . -type d -printf '%P\n') ; do \
		install -m 755 -d "${PROFILES_DEST}/$${dir}" ; \
	done
	for file in $$(cd ${PROFILES_SOURCE} && find . -type f -printf '%P\n') ; do \
		install -m 644 "${PROFILES_SOURCE}/$${file}" "${PROFILES_DEST}/$$(dirname $${file})" ; \
	done
	install -m 755 -d ${EXTRAS_DEST}
	install -m 755 -d ${EXTRAS_DEST}/abstractions
	for file in $$(cd ${EXTRAS_SOURCE} && find . -type f -printf '%P\n') ; do \
		install -m 644 "${EXTRAS_SOURCE}/$${file}" "${EXTRAS_DEST}/$$(dirname $${file})" ; \
	done

LOCAL_ADDITIONS=$(filter-out ${PROFILES_SOURCE}/local/README, $(wildcard ${PROFILES_SOURCE}/local/*))
.PHONY: clean
clean:
	-rm -f ${LOCAL_ADDITIONS}

ifndef VERBOSE
  Q=@
else
  Q=
endif

.PHONY: docs
# docs: should we have some here?
docs:

.PHONY: check
check: check-parser check-logprof check-abstractions.d check-tunables.d check-local

.PHONY: check-parser
check-parser: test-dependencies
	@echo "*** Checking profiles from ${PROFILES_SOURCE} against apparmor_parser"
	$(Q)for profile in $$(find ${PROFILES_SOURCE} -maxdepth 1 -type f) ; do \
		[ -n "${VERBOSE}" ] && echo "Testing $${profile}" ; \
		${PARSER} --config-file=../parser/tst/parser.conf -S -b ${PROFILES_SOURCE} $${profile} > /dev/null || exit 1; \
	done

	@echo "*** Checking profiles from ${EXTRAS_SOURCE} against apparmor_parser"
	$(Q)for profile in $$(find ${EXTRAS_SOURCE} -maxdepth 1 -type f -not -name README) ; do \
		[ -n "${VERBOSE}" ] && echo "Testing $${profile}" ; \
		${PARSER} --config-file=../parser/tst/parser.conf -S -b ${EXTRAS_SOURCE} -I ${PROFILES_SOURCE} $${profile} > /dev/null || exit 1; \
	done

	@echo "*** Checking abstractions from ${ABSTRACTIONS_SOURCE} against apparmor_parser"
	$(Q)for abstraction in $$(find ${ABSTRACTIONS_SOURCE} -maxdepth 1 -type f -printf '%P\n') ; do \
		[ -n "${VERBOSE}" ] && echo "Testing ${ABSTRACTIONS_SOURCE}/$${abstraction}" ; \
		echo "abi <abi/4.0>, include <tunables/global> profile test { include <abstractions/$${abstraction}> }" \
		| ${PARSER} --config-file=../parser/tst/parser.conf -S -b ${PROFILES_SOURCE} > /dev/null \
		|| exit 1; \
	done

	@echo "*** Checking abstractions from ${EXTRAS_ABSTRACTIONS_SOURCE} against apparmor_parser"
	$(Q)for abstraction in $$(find ${EXTRAS_ABSTRACTIONS_SOURCE} -maxdepth 1 -type f -printf '%P\n') ; do \
		[ -n "${VERBOSE}" ] && echo "Testing ${EXTRAS_ABSTRACTIONS_SOURCE}/$${abstraction}" ; \
		echo "abi <abi/4.0>, include <tunables/global> profile test { include <abstractions/$${abstraction}> }" \
		| ${PARSER} --config-file=../parser/tst/parser.conf -S -b ${PROFILES_SOURCE} -I ${EXTRAS_SOURCE} > /dev/null \
		|| exit 1; \
	done

.PHONY: check-logprof
check-logprof: test-dependencies
	@echo "*** Checking profiles from ${PROFILES_SOURCE} against logprof"
	$(Q)${LOGPROF} -d ${PROFILES_SOURCE} -f /dev/null || exit 1

.PHONY: check-abstractions.d
check-abstractions.d:
	@echo "*** Checking if all abstractions (with a few exceptions) contain 'include if exists <abstractions/*.d>' and 'abi <abi/4.0>,'"
	$(Q)for file in $$(find ${ABSTRACTIONS_SOURCE} ${EXTRAS_ABSTRACTIONS_SOURCE} -maxdepth 1 -type f) ; do \
		case "$${file}" in */ubuntu-browsers | */ubuntu-helpers) continue ;; esac ; \
		include="include if exists <abstractions/$$(basename $${file}).d>" ; \
		grep -q "^  $${include}\$$" $${file} || { echo "$${file} does not contain '$${include}'"; exit 1; } ; \
		grep -q "^ *abi <abi/4.0>," $${file} || { echo "$${file} does not contain 'abi <abi/4.0>,'"; exit 1; } ; \
	done

.PHONY: check-tunables.d
check-tunables.d:
	@echo "*** Checking if all tunables (with a few exceptions) contain 'include if exists <tunables/*.d>'"
	$(Q)for file in $$(find ${PROFILES_SOURCE}/tunables -maxdepth 1 -type f) ; do \
		case "$${file}" in */sys) continue ;; esac ; \
		include="include if exists <tunables/$$(basename $${file}).d>" ; \
		grep -q "^$${include}\$$" $${file} || { echo "$${file} does not contain '$${include}'"; exit 1; } ; \
	done

.PHONY: check-local
check-local:
	@echo "*** Checking if all profiles contain 'include if exists <local/*>' and 'abi <abi/4.0>,'"
	$(Q)for file in $$(find ${PROFILES_SOURCE} ${EXTRAS_SOURCE} -maxdepth 1 -type f) ; do \
		case "$${file}" in */README) continue ;; esac ; \
		include="include if exists <local/$$(basename $${file})>" ; \
		grep -q "^  *$${include}\$$" $${file} || { echo "$${file} does not contain '$${include}'"; exit 1; } ; \
		grep -q "^ *abi <abi/4.0>," $${file} || { echo "$${file} does not contain 'abi <abi/4.0>,'"; exit 1; } ; \
	done
