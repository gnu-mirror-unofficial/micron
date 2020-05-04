AC_PREREQ(2.63)
AC_INIT([micrond],[0.1],[gray@gnu.org.ua])
AC_CONFIG_SRCDIR([src/micron.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([1.15 foreign tar-ustar silent-rules])
# Enable silent rules by default:
AM_SILENT_RULES([yes])
# Checks for programs.
AC_PROG_CC
dnl AC_PROG_RANLIB
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

dnl # Initialize the test suite.
dnl AC_CONFIG_TESTDIR(tests)
dnl AC_CONFIG_FILES([tests/Makefile tests/atlocal tests/etc/Makefile])
dnl AM_MISSING_PROG([AUTOM4TE], [autom4te])
AC_CONFIG_FILES([Makefile
		 src/Makefile])
AC_OUTPUT
		 

