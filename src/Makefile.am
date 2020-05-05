sbin_PROGRAMS=micrond
micrond_SOURCES=\
 micrond.c\
 micrond.h\
 runner.c\
 micron.c\
 micron.h\
 list.h
if COND_INOTIFY
 micrond_SOURCES += watcher.c
endif

LDADD = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
AM_CPPFLAGS = $(PTHREAD_CFLAGS) 
