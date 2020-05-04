#include <time.h>
#include "micron.h"
#include "list.h"

#define MAXCRONTABLINE 1024

struct micron_entry {
    struct micronent schedule;   /* Time schedule entry */
    char *command;               /* Command to be run */
    uid_t uid;
    gid_t gid;
    struct timespec next_time;   /* Next time this entry is to be run */
    struct list_head list;       /* Link to the next and prev elements */
    int fileid;                  /* Crontab identifier */
    int internal;                /* True if this is internal entry */
};

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

extern void (*micron_log)(int prio, char const *, ...);

enum {
    CRONID_MASTER,
    CRONID_SYSTEM,
    CRONID_USER,
    NCRONID
};

#define CDF_DEFAULT  0
#define CDF_SINGLE   0x1
#define CDF_DISABLED 0x2

struct crondef {
    char *dirname;
    int dirfd;
    char *pattern;
    char const **exclude;
    int flags;
};

extern struct crondef crondefs[];

void crontab_deleted(int cid, char const *name);
void crontab_updated(int cid, char const *name);
void *cron_thr_watcher(void *ptr);

void crontab_scanner_schedule(void);
