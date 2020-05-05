noinst_PROGRAMS = parsetest timetest
LDADD = micron.o
micron.o: $(top_srcdir)/src/micron.c $(top_srcdir)/src/micron.h
	$(AM_V_CC)$(COMPILE) -c -o $@ $<
AM_CPPFLAGS = -I$(top_srcdir)/src
check-local: $(noinst_PROGRAMS)
	@./parsetest
	@./timetest
