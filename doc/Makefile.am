## Makefile for the Micron documentation.
## Copyright (C) 2020-2021 Sergey Poznyakoff
##
## Micron is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 3 of the License, or (at your
## option) any later version.
##
## Micron is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with micron. If not, see <http://www.gnu.org/licenses/>. */
dist_man_MANS   = micrond.8 crontab.1 crontab.5
info_TEXINFOS   = micron.texi
micron_TEXINFOS = fdl.texi

GENDOCS = perl gendocs.pl
EXTRA_DIST = gendocs.pl webdoc.init otherdoc.texi.in

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
.PHONY: manual
manual:
	rm -rf manual
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS)" \
	 $(GENDOCS) -C manual -o otherdoc.texi $(PACKAGE) otherdoc.texi.in
	$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -DWEBDOC \
	   --html --init-file=webdoc.init $(info_TEXINFOS) -o manual

