# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007
#    NOVELL (All rights reserved)
#
#    Copyright (c) Christian Boltz 2018
#    Copyright (c) Canonical 2025
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
all:
COMMONDIR=../common/

include $(COMMONDIR)/Make.rules

DESTDIR=/
APPARMOR_BIN_PREFIX=${DESTDIR}/lib/apparmor
SBINDIR=${DESTDIR}/sbin
USR_SBINDIR=${DESTDIR}/usr/sbin
SYSTEMD_UNIT_DIR=${DESTDIR}/usr/lib/systemd/system
LOCALEDIR=/usr/share/locale
MANPAGES=aa-teardown.8

manpages:	$(MANPAGES)

htmlmanpages:	$(HTMLMANPAGES)

docs:	manpages htmlmanpages

indep: docs

all:	indep


.PHONY: install-redhat
install-redhat: install-systemd

.PHONY: install-suse
install-suse: install-systemd
	install -m 755 -d $(SBINDIR)
	ln -sf service $(SBINDIR)/rcapparmor

.PHONY: install-slackware
install-slackware:
	install -m 755 -d $(APPARMOR_BIN_PREFIX)/install
	install -m 755 frob_slack_rc $(APPARMOR_BIN_PREFIX)/install
	install -m 755 -d $(DESTDIR)/etc/rc.d
	install -m 755 rc.apparmor.$(subst install-,,$(@)) $(DESTDIR)/etc/rc.d/rc.apparmor

.PHONY: install-debian
install-debian:

.PHONY: install-unknown
install-unknown:

ifndef DISTRO
DISTRO=$(shell if [ -f /etc/slackware-version ] ; then \
	         echo slackware ; \
	       elif [ -f /etc/debian_version ] ; then \
	         echo debian ;\
	       elif which rpm > /dev/null ; then \
	         if [ "$$(rpm --eval '0%{?suse_version}')" != "0" ] ; then \
	             echo suse ;\
	         elif [ "$$(rpm --eval '%{_host_vendor}')" = redhat ] ; then \
	            echo redhat ;\
	         elif [ "$$(rpm --eval '0%{?fedora}')" != "0" ] ; then \
	            echo redhat ;\
	         else \
	            echo unknown ;\
	         fi ;\
	       else \
	          echo unknown ;\
	       fi)
endif

ifdef DISTRO
INSTALLDEPS+=install-$(DISTRO)
endif

.PHONY: install
install:
	$(MAKE) install-indep
	$(MAKE) install-arch

.PHONY: install-arch
install-arch: $(INSTALLDEPS)
	install -m 755 -d $(SBINDIR)

.PHONY: install-indep
install-indep: indep
	install -m 755 -d $(APPARMOR_BIN_PREFIX)
	install -m 755 rc.apparmor.functions $(APPARMOR_BIN_PREFIX)
	install -m 755 profile-load $(APPARMOR_BIN_PREFIX)
	$(MAKE) install_manpages DESTDIR=${DESTDIR}

.PHONY: install-systemd
install-systemd:
	install -m 755 -d $(SYSTEMD_UNIT_DIR)
	install -m 644 apparmor.service $(SYSTEMD_UNIT_DIR)
	install -m 755 apparmor.systemd $(APPARMOR_BIN_PREFIX)
	install -m 755 -d $(USR_SBINDIR)
	install -m 755 aa-teardown $(USR_SBINDIR)

ifndef VERBOSE
.SILENT: clean
endif
.PHONY: clean
clean: pod_clean
	rm -f core core.* *.o *.s *.a *~ *.gcda *.gcno
	rm -f gmon.out

FORCE:
