## Makefile for the GNU micron testsuite.
## Process this file with automake to produce Makefile.in.
## Copyright (C) 2020-2021 Sergey Poznyakoff
##
## GNU micron is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 3 of the License, or (at your
## option) any later version.
##
## GNU micron is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with GNU micron. If not, see <http://www.gnu.org/licenses/>. */
## 
EXTRA_DIST = $(TESTSUITE_AT) testsuite package.m4
DISTCLEANFILES       = atconfig $(check_SCRIPTS)
MAINTAINERCLEANFILES = Makefile.in $(TESTSUITE)

## ------------ ##
## package.m4.  ##
## ------------ ##

$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	{                                      \
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

#

## ------------ ##
## Test suite.  ##
## ------------ ##

TESTSUITE = $(srcdir)/testsuite
M4=m4

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AM_V_GEN)$(AUTOTEST) -I $(srcdir) testsuite.at -o $@.tmp
	$(AM_V_at)mv $@.tmp $@

atconfig: $(top_builddir)/config.status 
	cd $(top_builddir) && ./config.status tests/$@

clean-local:
	@test ! -f $(TESTSUITE) || $(SHELL) $(TESTSUITE) --clean

check-local: atconfig atlocal $(TESTSUITE)
	@$(SHELL) $(TESTSUITE)

# Run the test suite on the *installed* tree.
#installcheck-local:
#	$(SHELL) $(TESTSUITE) AUTOTEST_PATH=$(exec_prefix)/bin

TESTSUITE_AT = \
 testsuite.at\
 parser.at\
 next.at\
 min.at\
 hr.at\
 day.at\
 dom.at\
 dow.at\
 mail.at\
 vinput.at\
 syslog.at\
 outfile.at\
 maxinst.at\
 linecont.at\
 vscope.at

noinst_PROGRAMS = \
 parsetest\
 timetest\
 logger\
 mockmail\
 micronh\
 ftt

AM_CPPFLAGS = -I$(top_srcdir)/src $(PTHREAD_CFLAGS)

parsetest_LDADD = ../src/libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
timetest_LDADD = ../src/libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
logger_LDADD = ../src/libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
micronh_LDADD = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
ftt_LDADD = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
