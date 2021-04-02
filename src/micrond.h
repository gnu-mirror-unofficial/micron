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

#include <time.h>
#include "micron.h"
#include "micron_log.h"
#include "list.h"
#include "defs.h"

#define MAXCRONTABLINE 1024

enum {
    JOB_NORMAL,
    JOB_INTERNAL,
    JOB_REBOOT
};

struct cronjob_options {
    int perjob;
    int dsem;
    unsigned maxinstances;
    int syslog_facility;
    String syslog_tag;
    String mailto;
    struct cronjob_options *prev;
};

struct cronjob {
    int type;                  /* Type of this job */
    struct micronexp schedule; /* Time schedule expression */
    char *command;             /* Command to be run */
    char *input;               /* Standard input */
    uid_t uid;                 /* Run as this UID */ 
    gid_t gid;                 /* ... and GID */
    unsigned maxinstances;     /* Allow that many instances to run
				  simultaneously */
    struct micron_environ *env;/* Execution environment */ 
    struct timespec next_time; /* Next time this entry is to be run */
    struct list_head list;     /* Links to the next and prev crontab entries */
    struct list_head runq;     /* Links to the next and prev runqueue
				  entries */
    unsigned fileid;           /* Crontab identifier */
    int syslog_facility;
    char *syslog_tag; 
    char *mailto;
    unsigned refcnt;           /* Number of times this entry is referenced */
    unsigned runcnt;           /* Number of instances running */
};

void cronjob_ref(struct cronjob *cp);
void cronjob_unref(struct cronjob *cp);

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

/* Crongroup types */
enum {
    /*
     * Default crongroup file: must be owned by root and may not be
     * writable by anyone else, except root.
     * File format includes username after the cron expression.
     */
    CGTYPE_DEFAULT,

    /*
     * A single cron file.  The rules are the same as for CGF_DEFAULT,
     * except that the .pattern member of struct crongroup is treated as
     * the file name.  Used to define main /etc/crontab.
     */
    CGTYPE_SINGLE,

    /*
     * Per-user crontabs.  Must be owned by the corresponding users
     * (owner name same as the name of the file), and be writable only
     * by these.  File format does not include username field.
     */
    CGTYPE_USER,

    /*
     * Storage directory for user crongroups.  This directory hosts
     * subdirectories named after the owner users.  Ownership and attributes
     * are the same as for CGF_DEFAULT.
     */
    CGTYPE_GROUPHOST,

    /*
     * User crongroup.  This directory is stored in the CGF_GROUPHOST
     * crongroup.  It must be named after the user it belongs to and
     * must be writable by this user and his primary group.  Crontabs in
     * this directory must be owned by users who are members of the owner's
     * primary group, which group must be also their owner group.
     * Write permission for group is allowed.
     */
    CGTYPE_GROUP
};

/* Crongroup flags */
/* If this bit is set, the crongroup will not be used. */
#define CGF_DISABLED 0x1
/* Group is declared unsafe. */
#define CGF_UNSAFE   0x2

struct crongroup {
    char const *id;      /* Group ID. */
    char *dirname;       /* Directory name. */
    int dirfd;           /* Directory descriptor. */
    char *pattern;       /* For CGTYPE_SINGLE - name of the file in
			    dirname. For another types - a glob(7) pattern
			    of files to look for in dirname.  NULL means
			    "*".
			 */
    char const **exclude;/* Exclude patterns. */
    int type;            /* Crongroup type (see CGTYPE_ constants above). */ 
    int flags;           /* See CGF_ constants above. */
    int wd;              /* Inotify(7) watch descriptor. */

    /* Ownership and privileges */
    char const *owner_name;
    char const *owner_group;
    gid_t owner_gid;     /* This is set only for CGTYPE_GROUP types */
    int mode;
    int mask;            /* For future use */
    
    struct list_head list;
};

extern struct list_head crongroup_head;
extern char *mailer_command;
extern int log_level;
extern mode_t saved_umask;
extern unsigned micron_termination_timeout;

/* Return values from crontab safety checking and parsing functions */
enum {
    CRONTAB_SUCCESS,
    CRONTAB_NEW,
    CRONTAB_MODIFIED,
    CRONTAB_UNSAFE,
    CRONTAB_FAILURE
};

/* Built-in variable names */
#define BUILTIN_SYSLOG_FACILITY "SYSLOG_FACILITY"
#define BUILTIN_SYSLOG_TAG "SYSLOG_TAG"
#define BUILTIN_MAXINSTANCES "MAXINSTANCES"
#define BUILTIN_DAY_SEMANTICS "DAY_SEMANTICS"
#define BUILTIN_MAILTO "MAILTO"

/* Important environment variables */
#define ENV_LOGNAME "LOGNAME"
#define ENV_USER "USER"
#define ENV_HOME "HOME"
#define ENV_SHELL "SHELL"
#define ENV_MAILTO "MAILTO"
#define ENV_PATH "PATH"

void crongroups_parse_all(int ifmod);

void crontab_deleted(struct crongroup *cgrp, char const *name);
void crontab_updated(struct crongroup *cgrp, char const *name);
void crontab_chattr(struct crongroup *cgrp, char const *name);
void crongroup_chattr(struct crongroup *cgrp);
int crongroup_skip_name(struct crongroup *cgrp, char const *name);

void *cron_thr_watcher(void *ptr);

void crontab_scanner_schedule(void);
int usercrongroup_add(struct crongroup *host, char const *name);
void usercrongroup_delete(struct crongroup *host, char const *name);

void *cron_thr_runner(void *ptr);
void *cron_thr_cleaner(void *ptr);
void stop_thr_cleaner(pthread_t tid);
void default_stop_thread(pthread_t tid);
void restore_default_signals(void);

void runner_enqueue(struct cronjob *job);

char *catfilename(char const *dir, char const *file);
int parsefilename(char const *filename, char **dirname, char **basename);
void *memrealloc(void *p, size_t *pn, size_t s);

char **cronjob_mkenv(struct cronjob *job);
void env_free(char **env);
char const *env_get(char *name, char **env);


