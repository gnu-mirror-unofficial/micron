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

