noinst_PROGRAMS = parsetest timetest logger
LDADD = ../src/libmicron.a $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
AM_CPPFLAGS = -I$(top_srcdir)/src $(PTHREAD_CFLAGS)
check-local: $(noinst_PROGRAMS)
	@./parsetest
	@./timetest
