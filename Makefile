CFLAGS=-Wall -ggdb -DHAVE_STRUCT_TM_TM_GMTOFF=1
test: parsetest timetest
	./parsetest
	./timetest
parsetest: parsetest.c micron.c micron.h
	$(CC) $(CFLAGS) -oparsetest parsetest.c micron.c
timetest: timetest.c micron.c micron.h
	$(CC) $(CFLAGS) -otimetest timetest.c micron.c
clean:
	rm -f parsetest timetest *.o
