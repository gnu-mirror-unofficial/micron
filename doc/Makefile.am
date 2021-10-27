# Makefile for the Micron documentation.
# Copyright (C) 2020-2021 Sergey Poznyakoff
# For copying conditions, see the file configure.ac in the parent directory.
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

