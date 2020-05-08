/* micron - a minimal cron implementation
   Copyright (C) 2020 Sergey Poznyakoff

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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "micron.h"

struct test_harness {
    char *spec;
    int status;
    int end;
    struct micronexp entry;
    int enable;
} test[] = {
    { "* * * * *",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      },
    },
    { "*/3 * * * *",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..X..",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      },
    },
    { "15-30/3 * * * *",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "...............X..X..X..X..X..X.............................",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      }
    },
    { "1,5,15-30/3,40-47/2,59 * * * *",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  ".X...X.........X..X..X..X..X..X.........X.X.X.X............X",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      }
    },
    { "15-30 */3 1,15,20 4-7 6,0",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "...............XXXXXXXXXXXXXXXX.............................",
	  "X..X..X..X..X..X..X..X..",
	  "X.............X....X............",
	  "...XXXX.....",
	  "X.....X"
      }
    },
    { "15-30 */3 1,15,20 apr-jul sat,sun",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "...............XXXXXXXXXXXXXXXX.............................",
	  "X..X..X..X..X..X..X..X..",
	  "X.............X....X............",
	  "...XXXX.....",
	  "X.....X"
      }
    },
    { /* Sunday is 0 and 7 */
      "* * * * 7",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "X......"
      },
    },
    /* Errors */
    { "*",
      MICRON_E_EOF,
      1
    },
    { "* * 0 * *",
      MICRON_E_RANGE,
      4
    },
    { "* * * 0 *",
      MICRON_E_RANGE,
      6
    },
    { "5+ * * * *",
      MICRON_E_SYNT,
      1
    },
    /* Inverted ranges */
    { "50-20 * * * fri-sun",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "XXXXXXXXXXXXXXXXXXXXX.............................XXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "X....XX"
      }
    },
    { "@hourly",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "XXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      }
    },
    { "@daily",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      },
    },
    { "@midnight",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      },
    },
    { "@weekly",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	  "XXXXXXXXXXXX",
	  "X......"
      },
    },
    { "@monthly",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "X...............................",
	  "XXXXXXXXXXXX",
	  "XXXXXXX"
      },
    },
    { "@yearly",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "X...............................",
	  "X...........",
	  "XXXXXXX"
      },
    },
    { "@annually",
      MICRON_E_OK,
      0,
      {
        /* 0         1         2         3         4         5          */
	/* 012345678901234567890123456789012345678901234567890123456789 */
	  "X...........................................................",
	  "X.......................",
	  "X...............................",
	  "X...........",
	  "XXXXXXX"
      },
    },
    { NULL }
};

static struct micronexp *
micronexp_printable(struct micronexp const *ent, struct micronexp *res)
{
    int i;
#define PRT(f) \
    for (i = 0; i < sizeof(ent->f); i++)	\
	res->f[i] = ent->f[i] ? 'X' : '.';

    PRT(min);
    PRT(hrs);
    PRT(day);
    PRT(mon);
    PRT(dow);
    return res;
}

static void
print_header(int len)
{
    int i;

    if (len > 10) {
	for (i = 0; i < len; i++) {
	    if (i % 10 == 0)
		printf("%d", i / 10);
	    else
		putchar(' ');
	}
	putchar('\n');
	for (i = 0; i < 10; i++)
	    printf("%d", i);
	for (; i < len; i++)
	    printf("%d", i % 10);
    } else {
	for (i = 0; i < len; i++)
	    printf("%d", i);
    }	
    putchar('\n');
}

static void
micronexp_display(struct micronexp const *ent)
{
    struct micronexp prt;
    
    micronexp_printable(ent, &prt);
    print_header(60);
    printf("%.60s\n", prt.min);
    printf("%.24s\n", prt.hrs);
    printf("%.32s\n", prt.day);
    printf("%.12s\n", prt.mon);
    printf("%.7s\n", prt.dow); /* last byte is of no interest */
}

static int
micronexp_cmp(struct micronexp const *a, struct micronexp const *b)
{
    int rc;
    
    rc = memcmp(a->min, b->min, sizeof(a->min));
    if (rc == 0) {
	rc = memcmp(a->hrs, b->hrs, sizeof(a->hrs));
	if (rc == 0) {
	    rc = memcmp(a->day, b->day, sizeof(a->day));
	    if (rc == 0) {
		rc = memcmp(a->mon, b->mon, sizeof(a->mon));
		if (rc == 0) {
		    rc = memcmp(a->dow, b->dow, sizeof(a->dow)-1);
		}
	    }
	}
    }
    return rc;
}

int
main(int argc, char **argv)
{
    int i;
    int rc;
    struct micronexp ent, prt;
    char *endp;
    int status = 0;
    int print = 0;
    
    while ((i = getopt(argc, argv, "p")) != EOF) {
	switch (i) {
	case 'p':
	    print = 1;
	    break;
	default:
	    return 2;
	}
    }

    if (print) {
	for (i = optind; i < argc; i++) {
	    printf("%s:\n", argv[i]);
	    rc = micron_parse(argv[i], &endp, &ent);
	    if (rc) {
		printf("%s at %s\n", micron_strerror(rc), endp);
		return 1;
	    }
	    printf("Stopped at %s\n", endp);
	    micronexp_display(&ent);
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
	if (!test[i].enable)
	    continue;
	printf("%02d %-24s ", i, test[i].spec);
	rc = micron_parse(test[i].spec, &endp, &ent);
	if (rc != test[i].status) {
	    printf("FAIL (status %s)\n", micron_strerror(rc));
	    status = 1;
	} else if (endp-test[i].spec !=
		   (test[i].end == 0 ? strlen(test[i].spec) : test[i].end)) {
	    printf("FAIL (ends at \"%-.10s\")\n", endp);
	    status = 1;
	} else if (rc != MICRON_E_OK) {
	    printf("XFAIL\n");
	} else if (micronexp_cmp(micronexp_printable(&ent, &prt), &test[i].entry)) {
	    printf("FAIL\n");
	    micronexp_display(&ent);
	    status = 1;
	} else
	    printf("OK\n");
    }
    return status;
}
