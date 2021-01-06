/* micron - a minimal cron implementation
   Copyright (C) 2020-2021 Sergey Poznyakoff

   Micron is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   Micron is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with micron. If not, see <http://www.gnu.org/licenses/>. */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

int
create_temp_file(int dirfd, char *filename, size_t suflen, int isdir)
{
    int fd;
    size_t len;
    char *carrybuf;
    char *p, *cp, *start, *end;
    static int first_call;
    static char randstate[256];
    static const unsigned char alphabet[] =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if (!first_call) {
	/* Initialize random number generator */
	struct timeval tv;
	gettimeofday (&tv, NULL);
	initstate(((unsigned long) tv.tv_usec << 16) ^ tv.tv_sec,
		  randstate, sizeof (randstate));
	first_call = 1;
    }
    setstate(randstate);
  
    /* Start with the last filename character before suffix */
    end = filename + strlen(filename) - suflen - 1;
    /* Fill X's with random characters */
    for (p = end; p >= filename && *p == 'X'; p--)
	*p = alphabet[random() % (sizeof(alphabet) - 1)];
    len = end - p;
    if (len == 0) {
	errno = EINVAL;
	return -1;
    }
    start = p + 1;
    
    carrybuf = malloc(len);
    if (!carrybuf)
	return -1;

    /* Fill in the carry buffer */
    memcpy(carrybuf, start, len);

    for (;;) {
	if (isdir) {
	    if (mkdirat(dirfd, filename, 0700) == 0 &&
		(fd = openat(dirfd, filename,
			     O_RDONLY | O_NONBLOCK | O_DIRECTORY)) >= 0) {
		break;
	    }
	} else if ((fd = open(filename, O_CREAT|O_EXCL|O_RDWR, 0600)) >= 0) {
	    break;
	}
      
	if (errno != EEXIST)
	    break;

	for (p = start, cp = carrybuf;; p++, cp++) {
	    char *q;
	  
	    if (p == end) {
		/* All permutation exhausted */
		errno = EEXIST;
		goto err;
	    }
	    q = strchr((char*)alphabet, *p);
	    if (!q)
		abort(); /* should not happen */
	    *p = (q[1] == 0) ? alphabet[0] : q[1];
	    if (*p != *cp)
		break;
	}
    }
err:
    free(carrybuf);
    return fd;
}
