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

#include <time.h>

enum {
    MICRON_E_OK,
    MICRON_E_EOF,
    MICRON_E_RANGE,
    MICRON_E_SYNT,
    MICRON_E_SYS,
    MICRON_E_BADCRON
};

struct micronent {
    char min[60];
    char hrs[24];
    char day[32];
    char mon[12];
    char dow[8];   /* 0 or 7 is Sun */
};

int micron_parse(char const *spec, char **endp, struct micronent *ent);
char const *micron_strerror(int ec);
void micron_next(struct micronent const *ent, struct tm const *now,
		struct tm *next);
int micron_next_time(struct micronent const *ent, struct timespec *ts);
