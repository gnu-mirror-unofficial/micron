/* GNU micron - a minimal cron implementation
   Copyright (C) 2020-2021 Sergey Poznyakoff

   GNU micron is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   GNU micron is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GNU micron. If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "micron.h"

#define PREV "-"

struct test_harness {
    char *spec;
    struct timepair {
	char *start;
	char *end;
    } times[120];
    int dsem;
    int enable;
} test[] = {
    { "* * * * *",
      {
	  { "2020-01-01T00:00:30", "2020-01-01T00:01:00" },
	  { PREV, "2020-01-01T00:02:00" },
	  { PREV, "2020-01-01T00:03:00" },
	  { PREV, "2020-01-01T00:04:00" },
	  { PREV, "2020-01-01T00:05:00" },
	  { PREV, "2020-01-01T00:06:00" },
	  { "2020-01-01T00:59:00", "2020-01-01T01:00:00" },
      },
    },
    { "15-30/3 * * * *",
      {
	  { "2020-01-01T00:00:30", "2020-01-01T00:15:00" },
	  { PREV, "2020-01-01T00:18:00" },
	  { PREV, "2020-01-01T00:21:00" },
	  { PREV, "2020-01-01T00:24:00" },
	  { PREV, "2020-01-01T00:27:00" },
	  { PREV, "2020-01-01T00:30:00" },
	  { PREV, "2020-01-01T01:15:00" },
      }
    },
    { "15-30/3 3,5 * * *",
      {
	  { "2020-01-01T00:00:30", "2020-01-01T03:15:00" },
	  { PREV, "2020-01-01T03:18:00" },
	  { PREV, "2020-01-01T03:21:00" },
	  { PREV, "2020-01-01T03:24:00" },
	  { PREV, "2020-01-01T03:27:00" },
	  { PREV, "2020-01-01T03:30:00" },
	  { PREV, "2020-01-01T05:15:00" },	
      }
    },
    { "0 15 1,15 jun-aug *",
      {
	  { "2020-01-01T00:00:30", "2020-06-01T15:00:00" },
	  { PREV, "2020-06-15T15:00:00" },
	  { PREV, "2020-07-01T15:00:00" },
	  { PREV, "2020-07-15T15:00:00" },
	  { PREV, "2020-08-01T15:00:00" },	
	  { PREV, "2020-08-15T15:00:00" },
	  { PREV, "2021-06-01T15:00:00" },
      }
    },
    { "0 12 * * *",
      {
	  { "2019-02-28T12:00:00", "2019-03-01T12:00:00" },
	  { "2020-02-29T12:00:00", "2020-03-01T12:00:00" }
      }
    },
    { "20 5 3-8 jan mon",
      {
	  { "2020-04-29T15:00:00", "2021-01-04T05:20:00" },
	  { PREV,                  "2022-01-03T05:20:00" },
	  { PREV,                  "2024-01-08T05:20:00" },
	  { PREV,                  "2025-01-06T05:20:00" },
	  { PREV,                  "2026-01-05T05:20:00" },
	  { PREV,                  "2027-01-04T05:20:00" }
      }
    },
    { "20 5 3-8 jan mon",
      {
	  { "2020-04-29T15:00:00", "2021-01-03T05:20:00" },
	  { PREV,                  "2021-01-04T05:20:00" },
	  { PREV,                  "2021-01-05T05:20:00" },
	  { PREV,                  "2021-01-06T05:20:00" },
	  { PREV,                  "2021-01-07T05:20:00" },
	  { PREV,                  "2021-01-08T05:20:00" },
	  { PREV,                  "2021-01-11T05:20:00" },
      },
      MICRON_DAY_VIXIE
    },
    { "20 5 3 jan mon",
      {
	  { "2020-04-29T15:00:00", "2022-01-03T05:20:00" },
	  { PREV,                  "2028-01-03T05:20:00" },
	  { PREV,                  "2033-01-03T05:20:00" },
      }
    },
    { "20 5 3 jan mon",
      {
	  { "2020-04-29T15:00:00", "2021-01-03T05:20:00" },
	  { PREV,                  "2021-01-04T05:20:00" },
	  { PREV,                  "2021-01-11T05:20:00" },
	  { PREV,                  "2021-01-18T05:20:00" },
	  { PREV,                  "2021-01-25T05:20:00" },
      },
      MICRON_DAY_VIXIE
    },
    { "20 5 3 jan mon",
      {
	  { "2020-04-29T15:00:00", "2021-01-18T05:20:00" },
	  { PREV,                  "2022-01-17T05:20:00" },
      },
      MICRON_DAY_DILLON
    },
    { "0 11 1,5 * mon-wed",
      {
	  { "2020-04-29T12:00:00", "2020-05-04T11:00:00" },
	  { PREV,                  "2020-05-05T11:00:00" },
	  { PREV,                  "2020-05-06T11:00:00" },
	  { PREV,                  "2020-05-25T11:00:00" },
	  { PREV,                  "2020-05-26T11:00:00" },
	  { PREV,                  "2020-05-27T11:00:00" },
	  { PREV,                  "2020-06-01T11:00:00" },
	  { PREV,                  "2020-06-02T11:00:00" },
	  { PREV,                  "2020-06-03T11:00:00" },
	  { PREV,                  "2020-06-24T11:00:00" },
      },
      MICRON_DAY_DILLON
    },      
    { NULL }
};

static int
tmeq(struct tm const *a, struct tm const *b)
{
    return a->tm_sec == b->tm_sec &&
	a->tm_min == b->tm_min &&
	a->tm_hour == b->tm_hour &&
	a->tm_mday == b->tm_mday &&
	a->tm_mon == b->tm_mon &&
	a->tm_year == b->tm_year;
}

static void
tmprint(struct tm const *t)
{
    printf("%4d-%02d-%02dT%02d:%02d:%02d",
	   t->tm_year + 1900,
	   t->tm_mon + 1,
	   t->tm_mday,
	   t->tm_hour,
	   t->tm_min,
	   t->tm_sec);
}

static int
tmscan(char const *str, struct tm *t)
{
    memset(t, 0, sizeof(*t));
    if (sscanf(str, "%4d-%02d-%02dT%02d:%02d:%02d\n",
	       &t->tm_year,
	       &t->tm_mon,
	       &t->tm_mday,
	       &t->tm_hour,
	       &t->tm_min,
	       &t->tm_sec) != 6)
	return -1;
    t->tm_year -= 1900;
    t->tm_mon--;
    mktime(t);
    return 0;
}

int
main(int argc, char **argv)
{
    int i;
    int rc;
    struct micronexp ent;
    char *endp;
    int status = 0;
    int print = 0;
    struct tm now, next;
    int dsem = MICRON_DAY_STRICT;
    time_t t;

    setenv("TZ", "UTC", 1);
    tzset();
    time(&t);
    localtime_r(&t, &now);
    while ((i = getopt(argc, argv, "t:ps:")) != EOF) {
	switch (i) {
	case 't':
	    if (tmscan(optarg, &now)) {
		fprintf(stderr, "bad time: %s\n", optarg);
		return 2;
	    }
	    break;
	case 'p':
	    print = 1;
	    break;
	case 's':
	    dsem = atoi(optarg);
	    break;
	default:
	    return 2;
	}
    }

    if (print) {
	for (i = optind; i < argc; i++) {
	    printf("%s:\n", argv[i]);
	    ent.dsem = dsem;
	    rc = micron_parse(argv[i], &endp, &ent);
	    if (rc) {
		fprintf(stderr, "%s at %s\n", micron_strerror(rc), endp);
		return 1;
	    }
	    micron_next(&ent, &now, &next);
	    tmprint(&next);
	    putchar('\n');
	    t = mktime(&next);
	    printf("%s", ctime(&t));
	}
	return 0;
    }

    if (optind < argc) {
	for (i = optind; i < argc; i++) {
	    int n = atoi(argv[i]);
	    assert(n >= 0 && n < sizeof(test)/sizeof(test[0]) - 1);
	    test[n].enable = 1;
	}
    } else
	for (i = 0; test[i].spec; i++)
	    test[i].enable = 1;
    
    for (i = 0; test[i].spec; i++) {
	int j;
	int pass;
	struct tm start_time, end_time;
	    
	if (!test[i].enable)
	    continue;
	
	printf("%02d %-6s %-24s ", i, micron_dsem_str[test[i].dsem],
	       test[i].spec);
	ent.dsem = test[i].dsem;
	rc = micron_parse(test[i].spec, &endp, &ent);
	if (rc) {
	    printf("FAIL (parse failed: %s at %s)\n",
		   micron_strerror(rc), endp);
	    status = 1;
	    continue;
	}
	pass = 1;
	for (j = 0; j < sizeof(test[0].times)/sizeof(test[0].times[0])
		 && test[i].times[j].start; j++) {
	    char *start = test[i].times[j].start;
	    if (j > 0 && strcmp(start, PREV) == 0)
		start = test[i].times[j-1].end;
	    assert(tmscan(start, &start_time) == 0);
	    assert(tmscan(test[i].times[j].end, &end_time) == 0);
	    micron_next(&ent, &start_time, &next);
	    if (!tmeq(&next, &end_time)) {
		pass = 0;
		break;
	    }
	}
	if (pass)
	    printf("OK\n");
	else {
	    printf("FAIL (%d: expect %s, got ", j,
		   test[i].times[j].end);
	    tmprint(&next);
	    printf(")\n");
	    status = 1;
	}
    }
    return status;
}
