#include <time.h>
#include "micron.h"
#include "micron_log.h"
#include "list.h"

#define MAXCRONTABLINE 1024

struct micron_entry {
    struct micronent schedule; /* Time schedule entry */
    char *command;             /* Command to be run */
    uid_t uid;
    gid_t gid;
    struct micron_environ *env;
    struct timespec next_time; /* Next time this entry is to be run */
    struct list_head list;     /* Links to the next and prev crontab entries */
    struct list_head runq;     /* Links to the next and prev runqueue entries */
    int fileid;                /* Crontab identifier */
    int internal;              /* True if this is internal entry */
    unsigned refcnt;           /* Number of times this entry is referenced */
};

static inline void
micron_entry_ref(struct micron_entry *cp)
{
    cp->refcnt++;
}

static inline struct micron_entry *
micron_entry_unref(struct micron_entry *cp)
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

void runner_enqueue(struct micron_entry *entry);

char *catfilename(char const *dir, char const *file);
int parsefilename(char const *filename, char **dirname, char **basename);
void *memrealloc(void *p, size_t *pn, size_t s);

char **micron_entry_env(struct micron_entry *ent);
void env_free(char **env);
char const *env_get(char *name, char **env);


