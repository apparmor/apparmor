# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004-2009 NOVELL (All rights reserved)
#    Copyright (c) 2010-2014 Canonical Ltd.
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
NAME 		= apparmor-utils
all:
COMMONDIR=../../common/

include $(COMMONDIR)/Make.rules

# files that don't have 100% test coverage
INCOMPLETE_COVERAGE=libraries/libapparmor/swig/python/.*/LibAppArmor.py|utils/aa-logprof|utils/apparmor/aa.py|utils/apparmor/common.py|utils/apparmor/config.py|utils/apparmor/easyprof.py|utils/apparmor/fail.py|utils/apparmor/logparser.py|utils/apparmor/ui.py|minitools_test.py


ifdef USE_SYSTEM
    LD_LIBRARY_PATH?=
    PYTHONPATH?=
    CONFDIR=
    BASEDIR=
    PARSER=
else
    LIBAPPARMOR_BASEDIR?=../../libraries/libapparmor
    PYTHON_DIST_BUILD_PATH ?= $(LIBAPPARMOR_BASEDIR)/swig/python/build/$$($(PYTHON) $(LIBAPPARMOR_BASEDIR)/swig/python/test/buildpath.py)
    LIBAPPARMOR_PATH?=$(LIBAPPARMOR_BASEDIR)/src/.libs/
    LD_LIBRARY_PATH:=$(LD_LIBRARY_PATH):$(LIBAPPARMOR_PATH):$(PYTHON_DIST_BUILD_PATH)
    PYTHONPATH:=$(PYTHONPATH):..:$(PYTHON_DIST_BUILD_PATH)
    CONFDIR=$(CURDIR)
    BASEDIR=../../profiles/apparmor.d
    PARSER=../../parser/apparmor_parser
endif

.PHONY: __libapparmor __parser
__libapparmor:
ifndef USE_SYSTEM
	@if [ ! -d $(PYTHON_DIST_BUILD_PATH) ]; then \
		echo "error: $(PYTHON_DIST_BUILD_PATH) does not exist. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Build against the in-tree libapparmor by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Build against the system libapparmor by adding USE_SYSTEM=1 to your make command." 1>&2; \
		exit 1; \
	fi
	@if [ ! -f $(LIBAPPARMOR_PATH)libapparmor.so ]; then \
		echo "error: $(LIBAPPARMOR_PATH)libapparmor.so is missing. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Build against the in-tree libapparmor by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Build against the system libapparmor by adding USE_SYSTEM=1 to your make command." 1>&2; \
		exit 1; \
	fi
endif

__parser:
ifndef USE_SYSTEM
	@if [ ! -f $(PARSER) ]; then \
		echo "error: $(PARSER) is missing. Pick one of these possible solutions:" 1>&2; \
		echo "  1) Test using the in-tree parser by building it first and then trying again. See the top-level README for help." 1>&2; \
		echo "  2) Test using the system parser by adding USE_SYSTEM=1 to your make command." 1>&2; \
		exit 1; \
	fi
endif

COVERAGE_OMIT=test-*.py,common_test.py,*/dist-packages/*
ifneq ($(COVERAGE_OUT), )
HTML_COVR_ARGS=-d $(COVERAGE_OUT)
endif

# use   make COVERAGE_IGNORE_FAILURES=true coverage   to build coverage data even if some tests fail
ifeq ($(COVERAGE_IGNORE_FAILURES), true)
  COVERAGE_IGNORE_FAILURES_CMD=true
else
  COVERAGE_IGNORE_FAILURES_CMD=set -e
endif

.PHONY: clean check coverage coverage-report coverage-html
ifndef VERBOSE
.SILENT: clean check .coverage coverage coverage-report coverage-html
endif

clean:
	rm -rf __pycache__/ .coverage htmlcov coverage-report.txt

check: __libapparmor __parser
	export PYTHONPATH=$(PYTHONPATH) LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) LC_ALL=C __AA_CONFDIR=$(CONFDIR) __AA_BASEDIR=$(BASEDIR) __AA_PARSER=$(PARSER) ; $(foreach test, $(wildcard test-*.py), echo ; echo === $(test) === ; $(call pyalldo, $(test)))

# FIXME: passing -v to test-$*.py below makes some tests fail.
#
# This is a static pattern rule that allows running individual tests via the
# check-one-test-NAME target, where NAME matches an exciting file test-NAME.py.
# The way it is coded allows make <tab><tab> to complete it, making it easier
# to use interactively.
check-one-test-%: PYTHON ?= python3
$(foreach t,$(wildcard test-*.py),check-one-test-$(patsubst test-%.py,%,$t)): check-one-test-%: __libapparmor __parser
	PYTHONPATH=$(PYTHONPATH) LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) LC_ALL=C __AA_CONFDIR=$(CONFDIR) __AA_BASEDIR=$(BASEDIR) __AA_PARSER=$(PARSER) $(PYTHON) test-$*.py

.coverage: $(wildcard ../aa-* ../apparmor/*.py test-*.py) __libapparmor __parser
	export PYTHONPATH=$(PYTHONPATH) LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) LC_ALL=C __AA_CONFDIR=$(CONFDIR) __AA_BASEDIR=$(BASEDIR) __AA_PARSER=$(PARSER) ; $(COVERAGE_IGNORE_FAILURES_CMD) ; $(foreach test, $(wildcard test-*.py), echo ; echo === $(test) === ; $(PYTHON) -m coverage run --branch -p $(test); )
	$(PYTHON) -m coverage combine

coverage: .coverage

coverage-report: .coverage
	$(PYTHON) -m coverage report --omit="$(COVERAGE_OMIT)"

coverage-regression: .coverage
	$(PYTHON) -m coverage report --omit="$(COVERAGE_OMIT)" > coverage-report.txt
	$(PYTHON) -m coverage html --omit="$(COVERAGE_OMIT)" $(HTML_COVR_ARGS)
	cat coverage-report.txt
	@echo 'Checking for coverage changes...'
	@if grep -vE ' 100%$$|TOTAL|$(INCOMPLETE_COVERAGE)' coverage-report.txt  |grep '%$$' ; then echo "ERROR: Coverage regression - the files listed above are expected to have 100% test coverage"; exit 1; fi
	@if grep -E '($(INCOMPLETE_COVERAGE)).*100%$$' coverage-report.txt ; then echo 'ERROR: Coverage improvement - the files listed above now have 100% coverage. Please adjust INCOMPLETE_COVERAGE in the Makefile!'; exit 2; fi
	@echo '    ... unchanged'

coverage-html: .coverage
	$(PYTHON) -m coverage html --omit="$(COVERAGE_OMIT)" $(HTML_COVR_ARGS)
