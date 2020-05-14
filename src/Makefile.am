# micron - a minimal cron implementation
# Copyright (C) 2020 Sergey Poznyakoff
#
# Micron is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your
# option) any later version.
#
# Micron is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with micron. If not, see <http://www.gnu.org/licenses/>. */

sbin_PROGRAMS=micrond
micrond_SOURCES=\
 micrond.c\
 micrond.h\
 runner.c
if COND_INOTIFY
 micrond_SOURCES += watcher.c
endif

bin_PROGRAMS=crontab
crontab_SOURCES=crontab.c

noinst_LIBRARIES = libmicron.a
libmicron_a_SOURCES =\
 micron.c\
 micron.h\
 micron_log.c\
 micron_log.h\
 tempfile.c\
 progname.c\
 list.h

noinst_HEADERS = defs.h

LDADD = ./libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
AM_CPPFLAGS = $(PTHREAD_CFLAGS) -DCRONTAB_GID=\"$(CRONTAB_GID)\"

install-exec-hook:
	-chown root:$(CRONTAB_GID) $(DESTDIR)$(bindir)/crontab && \
	  chmod g+s $(DESTDIR)$(bindir)/crontab
