/* This file is part of micron testsuite
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include "micron_log.h"

int
main(int argc, char **argv)
{
    int c;
    char buf[MICRON_LOG_BUF_SIZE];
    int line;
    
    while ((c = getopt(argc, argv, "s:")) != EOF) {
	switch (c) {
	case 's':
	    micron_log_dev = optarg;
	    break;

	default:
	    exit(1);
	}
    }

    line = 0;
    while (fgets(buf, sizeof(buf), stdin)) {
	size_t len = strlen(buf);
	buf[len-1] = 0;
	++line;
	micron_log_enqueue(LOG_CRON|LOG_INFO, buf, "micron_logger",
			   line);
    }
    micron_log_close();
}

