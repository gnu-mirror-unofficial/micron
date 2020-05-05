sbin_PROGRAMS=micrond
micrond_SOURCES=\
 micrond.c\
 micrond.h\
 runner.c
if COND_INOTIFY
 micrond_SOURCES += watcher.c
endif

noinst_LIBRARIES = libmicron.a
libmicron_a_SOURCES =\
 micron.c\
 micron.h\
 micron_log.c\
 micron_log.h\
 list.h

LDADD = ./libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
AM_CPPFLAGS = $(PTHREAD_CFLAGS) 
