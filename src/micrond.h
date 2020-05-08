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
#include "micron.h"
#include "micron_log.h"
#include "list.h"

#define MAXCRONTABLINE 1024

enum {
    JOB_NORMAL,
    JOB_INTERNAL,
    JOB_REBOOT
};

struct cronjob {
    int type;                  /* Type of this job */
    struct micronexp schedule; /* Time schedule expression */
    char *command;             /* Command to be run */
    uid_t uid;                 /* Run as this UID */ 
    gid_t gid;                 /* ... and GID */
    unsigned allow_multiple;   /* Allow that many instances to run
				  simultaneously */
    struct micron_environ *env;/* Execution environment */ 
    struct timespec next_time; /* Next time this entry is to be run */
    struct list_head list;     /* Links to the next and prev crontab entries */
    struct list_head runq;     /* Links to the next and prev runqueue
				  entries */
    int fileid;                /* Crontab identifier */
    unsigned line;             /* Line in file where it is defined */
    unsigned refcnt;           /* Number of times this entry is referenced */
};

static inline void
cronjob_ref(struct cronjob *cp)
{
    cp->refcnt++;
}

static inline struct cronjob *
cronjob_unref(struct cronjob *cp)
{
    if (--cp->refcnt == 0) {
	LIST_REMOVE(cp, list);
	LIST_REMOVE(cp, runq);
	free(cp);
	cp = NULL;
    }
    return cp;
}

static inline int
timespec_cmp(struct timespec const *a, struct timespec const *b)
{
    if (a->tv_sec < b->tv_sec)
	return -1;
    if (a->tv_sec > b->tv_sec)
	return 1;
    if (a->tv_nsec < b->tv_nsec)
	return -1;
    if (a->tv_nsec > b->tv_nsec)
	return 1;
    return 0;
}

extern void (*micron_logger)(int prio, char const *, ...)
    ATTR_PRINTFLIKE(2,3);

#define micron_log(pri, ...)			\
    do {					\
	if ((pri & 0x7) <= log_level) {		\
	    micron_logger(pri, __VA_ARGS__);	\
	}					\
    } while(0)

enum {
    CRONID_MASTER,
    CRONID_SYSTEM,
    CRONID_USER,
    NCRONID
};

#define CDF_DEFAULT  0
#define CDF_SINGLE   0x1
#define CDF_DISABLED 0x2

struct crongroup {
    char const *id;
    char *dirname;
    int dirfd;
    char *pattern;
    char const **exclude;
    int flags;
};

extern struct crongroup crongroups[];
extern char *mailer_command;
extern int syslog_enable;
extern int syslog_facility;
extern int log_level;

enum {
    EXIT_OK,
    EXIT_FATAL,
    EXIT_USAGE
};

void crontab_deleted(int cid, char const *name);
void crontab_updated(int cid, char const *name);
void *cron_thr_watcher(void *ptr);

void crontab_scanner_schedule(void);

void *cron_thr_runner(void *ptr);
void *cron_thr_cleaner(void *ptr);

void runner_enqueue(struct cronjob *job);

char *catfilename(char const *dir, char const *file);
int parsefilename(char const *filename, char **dirname, char **basename);
void *memrealloc(void *p, size_t *pn, size_t s);

char **cronjob_mkenv(struct cronjob *job);
void env_free(char **env);
char const *env_get(char *name, char **env);


