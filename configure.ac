# micron - a minimal cron implementation
# Copyright (C) 2020-2021 Sergey Poznyakoff
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

AC_PREREQ(2.63)
AC_INIT([micron],[1.1],[gray@gnu.org.ua])
AC_CONFIG_SRCDIR([src/micron.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([1.15 foreign tar-ustar silent-rules])
# Enable silent rules by default:
AM_SILENT_RULES([yes])
# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = no; then
  AC_MSG_ERROR([A C99 compiler is required])
fi  
AC_PROG_RANLIB
AC_USE_SYSTEM_EXTENSIONS
# Checks for libraries.
AC_CHECK_LIB(rt, clock_gettime)
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/inotify.h])
# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,
                 [#include <sys/types.h>
#include <time.h>
])
# Checks for library functions.
AC_CHECK_FUNCS([inotify_init])

# Check for POSIX threads support
AX_PTHREAD([],
 [AC_MSG_ERROR([POSIX threads support is required, but not available])])
# **********************	
# Inotify
# **********************	
AC_ARG_WITH(inotify,
	AC_HELP_STRING([--with-inotify],
	               [compile with inotify(7) support (Linux-specific)]),
	[status_inotify=${withval}],
	[status_inotify=probe])
if test $status_inotify != no; then
  if test "$ac_cv_header_sys_inotify_h" = yes &&
	     test "$ac_cv_func_inotify_init" = yes; then
    status_inotify=yes
  elif test $status_inotify = probe; then
    status_inotify=no
  else
    AC_MSG_FAILURE([Requested inotify(7) support is not available])
  fi
fi
if test $status_inotify = yes; then
  AC_DEFINE([WITH_INOTIFY],1,[Set to 1 if inotify(7) is to be used])
fi  
AM_CONDITIONAL([COND_INOTIFY],[test $status_inotify = yes])

# **********************	
# Select interface used to close file descriptors greater than or
# equal to the given one.
#
# Variants:
#  1. closefrom call    (FreeBSD)
#  2. F_CLOSEM fcntl (NetBSD, AIX, IRIX)
#  3. proc_pidinfo call (Darwin)
#  4. /proc/self/fd filesystem   (Linux)
#  5. Brute force
#
# The defines created here direct conditionalal compilation in
# src/closefds.c

AC_CHECK_FUNCS([closefrom])
AC_CHECK_DECL([F_CLOSEM],
              AC_DEFINE([HAVE_FCNTL_CLOSEM], [1],
	                [Use F_CLOSEM fcntl for mu_close_fds]),
	      [],
	      [#include <limits.h>
	       #include <fcntl.h>
])

AC_CHECK_HEADERS([libproc.h])
AC_CHECK_FUNCS([proc_pidinfo])

if test -d "/proc/self/fd" ; then
  AC_DEFINE([HAVE_PROC_SELF_FD], [1], [Define if you have /proc/self/fd])
fi  

#
AC_SUBST([CRONTAB_GID],[crontab])
AC_ARG_WITH([crontab-gid],
  [AC_HELP_STRING([--with-crontab-gid=GID],
                 [use this GID as owner of the crontab binary and user and group crontab directories])],
  [CRONTAB_GID=$withval],
  [CRONTAB_GID=crontab])

dnl # Initialize the test suite.
dnl AC_CONFIG_TESTDIR(tests)
dnl AC_CONFIG_FILES([tests/Makefile tests/atlocal tests/etc/Makefile])
dnl AM_MISSING_PROG([AUTOM4TE], [autom4te])
AC_CONFIG_FILES([Makefile
		 src/Makefile
		 doc/Makefile
		 tests/Makefile])
AC_OUTPUT
		 

