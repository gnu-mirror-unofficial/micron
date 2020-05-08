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
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "micron.h"

static char const *mon_names[] = {
    "jan", "feb", "mar",
    "apr", "may", "jun",
    "jul", "aug", "sep",
    "oct", "nov", "dec"
};

static char const *dow_names[] = {
    "sun", "mon", "tue", "wed", "thu", "fri", "sat"
};

static int
xlat_name(char const *xlat[], int n, char const *name, char const *allowed)
{
    int i;
    if (strlen(name) < 3 || (name[3] && strchr(allowed, name[3]) == 0))
	return -1;
    for (i = 0; i < n; i++)
	if (strncasecmp(xlat[i], name, 3) == 0)
	    return i;
    return -1;
}

static int
micron_parse_range(char const *spec, char **endp, char *map,
		   int len, int start,
		   char const **xlat)
{
    int r_min, r_max, r_step;
    unsigned long n;
    char *p;
    int list_ok;
    
    if (*spec == '*') {
	spec++;
	r_min = 0;
	r_max = len - 1;
	list_ok = 0;
    } else if (isdigit(*spec)) {
	errno = 0;
	n = strtoul(spec, &p, 10);
	if (errno || p == spec || n < start || n - start > len - 1) {
	    *endp = (char*) spec;
	    return MICRON_E_RANGE;
	}
	r_min = n - start;

	spec = p;

	if (*spec == '-') {
	    spec++;
	    errno = 0;
	    n = strtoul(spec, &p, 10);
	    if (errno || p == spec || n < start || n - start > len - 1) {
		*endp = (char*) spec;
		return MICRON_E_RANGE;
	    }
	    r_max = n - start;
	    spec = p;
	} else
	    r_max = r_min;
	list_ok = 1;
    } else if (xlat) {
	int d = xlat_name(xlat, len, spec, "-, ");
	if (d == -1)
	    goto esynt;
	spec += 3;
	r_min = d;
	
	if (*spec == '-') {
	    spec++;
	    d = xlat_name(xlat, len, spec, "/, ");
	    if (d == -1)
		goto esynt;
	    spec += 3;
	    r_max = d;
	} else
	    r_max = r_min;
	list_ok = 1;
    } else {
esynt:
	*endp = (char*) spec;
	return MICRON_E_SYNT;
    }

    if (r_max != r_min && *spec == '/') {
	spec++;
	errno = 0;
	n = strtoul(spec, &p, 10);
	if (errno || p == spec || n >= len) {
	    *endp = (char*) spec;
	    return MICRON_E_RANGE;
	}
	r_step = n;
	spec = p;
    } else
	r_step = 1;

    if (r_min > r_max) {
	for (; r_min < len; r_min += r_step)
	    map[r_min] = 1;
	r_min = 0;
    }
    
    for (; r_min <= r_max; r_min += r_step)
	map[r_min] = 1;

    *endp = (char*) spec;
    if (!list_ok && *spec == ',')
	return MICRON_E_SYNT;
    return MICRON_E_OK;
}

static int
micron_parse_field(char const *spec, char **endp, char *map,
		   int len, int start,
		   char const **xlat)
{
    int rc;
    char *p;
    
    while (*spec && isspace(*spec))
	spec++;
    if (!*spec) {
	*endp = (char*) spec;
	return MICRON_E_EOF;
    }
    memset(map, 0, len * sizeof(map[0]));
    do {
	rc = micron_parse_range(spec, &p, map, len, start, xlat);
	spec = p;
	if (*spec != ',')
	    break;
	spec++;
    } while (rc == MICRON_E_OK);
    *endp = (char*) spec;
    return rc;
}

#define PARSE_FIELD(spec,endp,fld,start,xlat)				\
    micron_parse_field(spec,						\
		       endp,						\
		       fld,						\
		       sizeof(fld)/sizeof((fld)[0]), start, xlat)

int
micron_parse_timespec(char const *spec, char **endp, struct micronexp *exp)
{
    char *p;
    int rc;

    if (exp->dsem < 0 || exp->dsem > MAX_MICRON_DAY)
	return MICRON_E_BADDSEM;
    
    rc = PARSE_FIELD(spec, &p, exp->min, 0, NULL);
    if (rc == 0) {
	rc = PARSE_FIELD(p, &p, exp->hrs, 0, NULL);
	if (rc == 0) {
	    rc = micron_parse_field(p, &p, exp->day,
				    exp->dsem == MICRON_DAY_DILLON
				      ? 5
				      : sizeof(exp->day)/sizeof(exp->day[0]),
				    1,
				    NULL);
	    if (rc == 0) {
		rc = PARSE_FIELD(p, &p, exp->mon, 1, mon_names);
		if (rc == 0) {
		    rc = PARSE_FIELD(p, &p, exp->dow, 0, dow_names);
		    if (rc == 0) {
			if (exp->dow[7]) {
			    exp->dow[0] = 1;
			    exp->dow[7] = 0;
			}
		    }
		}
	    }
	}
    }
    
    if (endp)
	*endp = p;
    return rc;
}

static struct micron_equiv {
    char const *name;
    int len;
    char const *equiv;
} micron_special[] = {
#define S(s) #s, sizeof(#s)-1
    { S(hourly),    "0 * * * *" },
    { S(daily),     "0 0 * * *" },
    { S(midnight),  "0 0 * * *" },
    { S(weekly),    "0 0 * * 0" },
    { S(monthly),   "0 0 1 * *" },
    { S(yearly),    "0 0 1 1 *" },
    { S(annually),  "0 0 1 1 *" },
    { NULL }
#undef S    
};

int
micron_parse(char const *spec, char **endp, struct micronexp *ent)
{
    while (*spec && isspace(*spec))
	spec++;
    if (!*spec) {
	*endp = (char*) spec;
	return MICRON_E_EOF;
    }

    if (*spec == '@') {
	struct micron_equiv *eqv;
	spec++;
	for (eqv = micron_special; eqv->name; eqv++) {
	    if (!strncmp(spec, eqv->name, eqv->len)
		&& (spec[eqv->len] == 0|| isspace(spec[eqv->len]))) {
		micron_parse_timespec(eqv->equiv, NULL, ent);
		if (endp)
		    *endp = (char*)spec + eqv->len;
		return MICRON_E_OK;
	    }
	}
	if (endp)
	    *endp = (char*) spec;
	return MICRON_E_SYNT;
    }

    return micron_parse_timespec(spec, endp, ent);
}

static char const *micron_error_str[] = {
    [MICRON_E_OK] = "no error",
    [MICRON_E_EOF] = "premature end of input",
    [MICRON_E_RANGE] = "value out of range",
    [MICRON_E_SYNT] = "syntax error",
    [MICRON_E_SYS] = "system error",
    [MICRON_E_BADCRON] = "malformed crontab entry",
    [MICRON_E_BADDSEM] = "bad day semantics"
};

char const *
micron_strerror(int ec)
{
    if (ec >= 0 && ec < sizeof(micron_error_str)/sizeof(micron_error_str[0]))
	return micron_error_str[ec];
    return "unknown error";
}

char const *micron_dsem_str[] = {
    "strict",
    "vixie",
    "dillon"
};

static int
julianday(struct tm *tm)
{
    int a = (13 - tm->tm_mon) / 12;
    int y = tm->tm_year + 6700 - a;
    int m = tm->tm_mon + 12*a - 2;

    return tm->tm_mday + (153*m + 2)/5 + 365*y + y/4 - y/100 + y/400 - 32045;
}

/* Compute day of week (0 - Sunday) */
static inline int
dayofweek(struct tm *tm)
{
    return (julianday(tm) + 1) % 7;
}

/* Day of week of the 1st day of the month */
static inline int
month_start_dayofweek(struct tm *tm)
{
    struct tm tm0 = *tm;
    tm0.tm_mday = 1;
    return dayofweek(&tm0);
}

/* Zero-based ordinal number of the day of week corresponding to
   TM (e.g. 1st Monday, 3rd Saturday, etc.)
*/
static inline int
downum(struct tm *tm)
{
    return (tm->tm_mday -
	    (tm->tm_wday - month_start_dayofweek(tm) + 7) % 7 + 1) / 7;
}

static int month_start[]=
    {    0,  31,  59,  90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };
    /* Jan  Feb  Mar  Apr  May  Jun  Jul  Aug  Sep  Oct  Nov  Dec */
    /*  31   28   31   30   31   30   31   31   30   31   30   31 */

static inline int
is_leap_year(int y)
{
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

static inline int
monthdays(struct tm *tm)
{
    return month_start[tm->tm_mon + 1] - month_start[tm->tm_mon]
	   + ((tm->tm_mon == 1) ? is_leap_year(tm->tm_year + 1900) : 0);
}

static inline void
next_month(struct tm *tm)
{
    if (++tm->tm_mon == 12) {
	tm->tm_mon = 0;
	tm->tm_year++;
    }
    tm->tm_mday = 1;
    tm->tm_hour = 0;
    tm->tm_min = 0;
    tm->tm_wday = dayofweek(tm);
}

static inline void
next_day(struct tm *tm)
{
    tm->tm_hour = 0;
    tm->tm_min = 0;
    tm->tm_wday = (tm->tm_wday + 1) % 7;
    if (++tm->tm_mday > monthdays(tm)) {
	tm->tm_mday = 1;
	next_month(tm);
    }
}

static inline void
next_hour(struct tm *tm)
{
    tm->tm_min = 0;
    if (++tm->tm_hour == 24) {
	tm->tm_hour = 0;
	next_day(tm);
    }
}

static inline void
next_minute(struct tm *tm)
{
    if (++tm->tm_min == 60) {
	tm->tm_min = 0;
	next_hour(tm);
    }
}

int
micron_next(struct micronexp const *ent, struct tm const *now, struct tm *next)
{
    *next = *now;
    next->tm_sec = 0;
    next_minute(next);
    
    while (1) {
	if (!ent->mon[next->tm_mon]) {
	    next_month(next);
	    continue;
	}

	switch (ent->dsem) {
	case MICRON_DAY_STRICT:
	    if (!(ent->day[next->tm_mday-1] && ent->dow[next->tm_wday])) {
		next_day(next);
		continue;
	    }
	    break;

	case MICRON_DAY_VIXIE:
	    /*
	     * DAY SEMANTICS ACCORDING TO VIXIE-STYLE CRONTABS:
	     *
	     * The day of a command's execution can be specified by two fields 
	     * day of month, and day of week.  If both fields are restricted
	     * (i.e., aren't *), the command will be run when either field
	     * matches the current time.  For example, ``30 4 1,15 * 5''
	     * would cause a command to be run at 4:30 am on the 1st and 15th
	     * of each month, plus every Friday.
	     */
	    if (!(ent->day[next->tm_mday-1] || ent->dow[next->tm_wday])) {
		next_day(next);
		continue;
	    }
	    break;

	case MICRON_DAY_DILLON:
	    /*
	     * DAY SEMANTICS ACCORDING OT DILLON-STYLE CRONTABS:
	     *
	     * If you specify both a day in the month and a day of week,
	     * it will be interpreted as the Nth such day in the month.
	     * ...
	     * To request the last Monday, etc. in a month, ask for the
	     * "5th" one.  This will always match the last Monday, etc.,
	     * even if there are only four Mondays in the month:
	     *
	     * # run at 11 am on the first and last Mon, Tue, Wed of each month
	     * 0 11 1,5 * mon-wed date
	     *
	     * When the fourth Monday in a month is the last, it will match
	     * against both the "4th" and the "5th" (it will only run once
	     * if both are specified).
	     */
	    if (!(ent->dow[next->tm_wday] &&
		  (ent->day[downum(next)] ||
		   (ent->day[4] && (monthdays(next) - next->tm_mday) < 7)))) {
		next_day(next);
		continue;
	    }
	    break;
	    
	default:
	    return MICRON_E_BADCRON;
	}

	if (!ent->hrs[next->tm_hour]) {
	    next_hour(next);
	    continue;
	}

	if (!ent->min[next->tm_min]) {
	    next_minute(next);
	    continue;
	}
	break;
    }
    return MICRON_E_OK;
}

int
micron_next_time_from(struct micronexp const *ent,
		      struct timespec *ts_from, struct timespec *ts)
{
    struct tm now, next;
    time_t t;
    int rc;
    
    if (!localtime_r(&ts_from->tv_sec, &now))
	return MICRON_E_SYS;
    rc = micron_next(ent, &now, &next);
    if (rc)
	return rc;
    t = mktime(&next);
    if (t == (time_t)-1)
	return MICRON_E_SYS;
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
    t += now.tm_gmtoff - next.tm_gmtoff;
#endif
    ts->tv_sec = t;
    ts->tv_nsec = 0;
    return MICRON_E_OK;
}

int
micron_next_time(struct micronexp const *ent, struct timespec *ts)
{
    struct timespec ts_now;

    clock_gettime(CLOCK_REALTIME, &ts_now);
    return micron_next_time_from(ent, &ts_now, ts);
}
