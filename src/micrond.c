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
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <fnmatch.h>
#include <pthread.h>
#include <ctype.h>
#include "micrond.h"

static char const *backup_file_table[] = {
    ".#*",
    "*~",
    "#*#",
    NULL
};

struct crongroup crongroups[] = {
    {   /*
	 * The master crongroup consists of a single /etc/crontab file.
	 * The .pattern will be split into directory prefix and a file
	 * name in main.
	 */
	.id = "master",
	.dirfd = -1,
	.pattern = "/etc/crontab",
	.flags = CGF_SINGLE
    },
    {   /*
	 * The system crongroup comprises multiple files stored in
	 * /etc/cron.d
	 */
	.id = "system",
	.dirname = "/etc/cron.d",
	.dirfd = -1,
	.exclude = backup_file_table,
	.flags = CGF_DEFAULT
    },
    {   /*
	 * The user crongroup contains personal user crontabs.  The
	 * crontabs should not contain the user field.  It is deduced
	 * from the file name itself.
	 */
	.id = "user",
	.dirname = "/var/spool/cron/crontabs",
	.dirfd = -1,
	.exclude = backup_file_table,
	.flags = CGF_USER
    }
};

/* Mode argument for crontab parsing founctions */
enum {
    PARSE_ALWAYS      = 0x00, /* Always parse the file(s) */
    PARSE_IF_MODIFIED = 0x01, /* Parse the file only if mtime changed or
				 if it is a new file */
    PARSE_APPLY_NOW   = 0x02  /* Used together with any of the above means
				 that the changes must be applied to the
				 current minute. */
};

/* Return values from crontab safety checking and parsing functions */
enum {
    CRONTAB_SUCCESS,
    CRONTAB_NEW,
    CRONTAB_MODIFIED,
    CRONTAB_FAILURE
};

int foreground;
char *progname;
int no_safety_checking;
char *mailer_command = "/usr/sbin/sendmail -oi -t";
int syslog_enable;
int syslog_facility = LOG_CRON;
int log_level = LOG_INFO;

/* Boolean flag used to filter out @reboot jobs when rescanning. */
static int running;

int crongroup_parse(int cid, int ifmod);
void *cron_thr_main(void *);

void
stderr_log(int prio, char const *fmt, ...)
{
    va_list ap;
    char const *priname;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", progname);
    if ((priname = micron_log_pri_to_str(prio & 0x7)) != NULL)
	fprintf(stderr, "[%s] ", priname);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    fflush(stderr);
}

void (*micron_logger)(int prio, char const *, ...) = stderr_log;

int fatal_signals[] = {
    SIGHUP,
    SIGINT,
    SIGQUIT,
    SIGTERM,
    0
};

static void
signull(int sig)
{
}

static void
nomem_exit(void)
{
    micron_log(LOG_ERR, "out of memory");
    exit(EXIT_FATAL);
}

static void
crongroup_option(char const *arg)
{
    int neg = 0;
    size_t len = strcspn(arg, "=");
    int i;
    
    if (strncmp(arg, "no", 2) == 0) {
	if (arg[len]) {
	    micron_log(LOG_CRIT, "%s: assignment and negation used together",
		       arg);
	    exit(EXIT_USAGE);
	}
	arg += 2;
	len -= 2;
	neg = 1;
    } else if (arg[len] == 0) {
	micron_log(LOG_CRIT, "%s: expected ID=NAME", arg);
	exit(EXIT_USAGE);
    }

    for (i = 0; i < NCRONID; i++) {
	if (strncmp(crongroups[i].id, arg, len) == 0) {
	    if (neg)
		crongroups[i].flags |= CGF_DISABLED;
	    else {
		char *filename = (char *) (arg + len + 1);
		struct stat st;

		if (stat(filename, &st)) {
		    micron_log(LOG_CRIT, "%s: can't stat %s: %s",
			       arg, filename, strerror(errno));
		    exit(EXIT_FATAL);
		}
		if (S_ISDIR(st.st_mode)) {
		    crongroups[i].dirname = filename;
		    if (i == CRONID_MASTER)
			crongroups[i].pattern = "crontab";
		} else
		    crongroups[i].pattern = filename;
		crongroups[i].flags &= ~CGF_DISABLED;
	    }
	    return;
	}
    }

    micron_log(LOG_CRIT, "%s: unknown group name", arg);
    exit(EXIT_USAGE);
}   

int
main(int argc, char **argv)
{
    int c;
    int i;
    struct sigaction act;
    sigset_t sigs;
    pthread_t tid;
    
    progname = strrchr(argv[0], '/');
    if (progname)
	progname++;
    else
	progname = argv[0];
    
    while ((c = getopt(argc, argv, "g:F:fNl:m:p:s")) != EOF) {
	switch (c) {
	case 'g':
	    crongroup_option(optarg);
	    break;

	case 'l':
	    log_level = micron_log_str_to_pri(optarg);
	    if (log_level == -1) {
		micron_logger(LOG_CRIT, "unrecognized log level: %s", optarg);
		exit(EXIT_USAGE);
	    }
	    break;
		
	case 'm':
	    mailer_command = optarg;
	    break;
	    
	case 'N':
	    no_safety_checking = 1;
	    break;
	    
	case 'f':
	    foreground = 1;
	    break;

	case 'p':
	    micron_log_dev = optarg;
	    break;
	    
	case 's':
	    syslog_enable = 1;
	    break;

	case 'F':
	    syslog_facility = micron_log_str_to_fac(optarg);
	    if (syslog_facility == -1) {
		micron_log(LOG_CRIT, "unknown syslog facility %s", optarg);
		exit(EXIT_USAGE);
	    }
	    break;
	    
	default:
	    exit(EXIT_USAGE);
	}
    }

    for (i = 0; i < NCRONID; i++) {
	if (crongroups[i].flags & CGF_DISABLED)
	    continue;
	if (!crongroups[i].dirname) {
	    if (crongroups[i].pattern) {
		if (parsefilename(crongroups[i].pattern,
				  &crongroups[i].dirname,
				  &crongroups[i].pattern))
		    nomem_exit();
	    } else
		crongroups[i].flags |= CGF_DISABLED;
	}
    }

    if (!foreground) {
	if (daemon(0, 0)) {
	    micron_log(LOG_CRIT, "daemon failed: %s", strerror(errno));
	    exit(EXIT_FATAL);
	}
	micron_log_open(progname, LOG_CRON);
	micron_logger = micron_syslog;
    } else if (syslog_enable)
	micron_log_open(progname, LOG_CRON);

    umask(077);
    
    for (i = 0; i < NCRONID; i++)
	crongroup_parse(i, PARSE_ALWAYS);

    sigemptyset(&sigs);

    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    act.sa_handler = signull;
    
    for (i = 0; fatal_signals[i]; i++) {
	sigaddset(&sigs, fatal_signals[i]);
	sigaction(fatal_signals[i], &act, NULL);
    }
    sigaddset(&sigs, SIGPIPE);
    sigaddset(&sigs, SIGALRM);
    sigaddset(&sigs, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    micron_log(LOG_NOTICE, "cron (%s) started", PACKAGE_STRING);

    /* Start worker threads */
    // Program cleaner
    pthread_create(&tid, NULL, cron_thr_cleaner, NULL);
    // Program runner 
    pthread_create(&tid, NULL, cron_thr_runner, NULL);
    // Scheduler
    pthread_create(&tid, NULL, cron_thr_main, NULL);
    // Crontab watcher
#ifdef WITH_INOTIFY
    pthread_create(&tid, NULL, cron_thr_watcher, NULL);
#else
    crontab_scanner_schedule();
#endif

    /* Unblock only the fatal signals */
    sigemptyset(&sigs);
    for (i = 0; fatal_signals[i]; i++) {
	sigaddset(&sigs, fatal_signals[i]);
    }
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    /* Wait for signal to arrive */
    sigwait(&sigs, &i);
    micron_log(LOG_NOTICE, "cron shutting down on signal \"%s\"",
	       strsignal(i));

    return EXIT_OK;
}

void *
memrealloc(void *p, size_t *pn, size_t s)
{
    size_t n = *pn;
    char *newp;
	
    if (!p) {
	if (!n) {
	    n = 64 / s;
	    n += !n;
	}
    } else {
	if ((size_t) -1 / 3 * 2 / s <= n) {
	    errno = ENOMEM;
	    return NULL;
	}
	n += (n + 1) / 2;
    }

    newp = realloc(p, n * s);
    if (!newp)
	return NULL;
    *pn = n;
    return newp;
}

int
parsefilename(char const *filename, char **dirname, char **basename)
{
    char *p;
    size_t len;
    char *dir, *base;
    
    p = strrchr(filename, '/');
    if (p) {
	len = p - filename;
	dir = malloc(len + 1);
	if (!dir)
	    return -1;
	memcpy(dir, filename, len);
	dir[len] = 0;
	base = strdup(p+1);
    } else {
	dir = NULL;
	len = 0;
	while (1) {
	    if ((p = memrealloc(dir, &len, 1)) == NULL) {
		free(dir);
		return -1;
	    }
	    dir = p;
	    if (getcwd(dir, len))
		break;
	    if (errno != ERANGE) {
		micron_log(LOG_ERR, "getcwd: %s", strerror(errno));
		return -1;
	    }
	}
	base = strdup(filename);
    }
    if (!base) {
	free(dir);
	return -1;
    }
    *dirname = dir;
    *basename = base;
    return 0;
}

char *
catfilename(char const *dir, char const *file)
{
    char *buf;
    size_t dlen = strlen(dir);
    size_t len;

    while (dlen > 0 && dir[dlen-1] == '/')
	--dlen;

    while (*file && *file == '/')
	++file;

    if (dlen == 0) {
	errno = EINVAL;
	return NULL;
    }
    
    len = dlen + 1 + strlen(file);

    buf = malloc(len + 1);
    if (buf) {
	strcpy(buf, dir);
	strcat(buf, "/");
	strcat(buf, file);
    }
    return buf;
}

char const *
env_get(char *name, char **env)
{
    size_t i;
    size_t len = strlen(name);
    
    for (i = 0; env[i]; i++) {
	if (strlen(env[i]) > len
	    && memcmp(env[i], name, len) == 0
	    && env[i][len] == '=')
	    return env[i] + len + 1;
    }
    return NULL;
}

void
env_free(char **env)
{
    size_t i;
    for (i = 0; env[i]; i++)
	free(env[i]);
    free(env);
}

void
envc_free(int enc, char **env)
{
    size_t i;
    for (i = 0; i < enc; i++)
	free(env[i]);
    free(env);
}

/*
 * Incremental environments.
 *
 * An incremental environment structure modifies a basic environment
 * (its parent) avoiding unnecessary memory bloat. Another incremental
 * environment object can use it as its parent, and so on.
 *
 * When necessary, incremental environment can be flattened to a simple
 * environment array.
 */

struct micron_environ {
    size_t varc;     /* Number of variable settings in this environment */
    size_t varmax;   /* Max. count of variables */
    char **varv;     /* Variable settings */
    struct list_head link; /* Links to parent and child environments */
};

#define MICRON_ENVIRON_INITIALIZER(n) \
    { 0, 0, NULL, LIST_HEAD_INITIALIZER(n.link) }

static int micron_environ_set(struct micron_environ **ebuf, char const *name,
			      const char *value);

static void
micron_environ_init(struct micron_environ *ebuf)
{
    ebuf->varc = ebuf->varmax = 0;
    ebuf->varv = NULL;
    list_head_init(&ebuf->link);
}

static struct micron_environ *
micron_environ_alloc(struct list_head *head)
{
    struct micron_environ *ebuf = malloc(sizeof(*ebuf));
    if (ebuf)
	micron_environ_init(ebuf);
    LIST_HEAD_PUSH(head, ebuf, link);
    return ebuf;
}

static void
micron_environ_free(struct micron_environ *ebuf)
{
    envc_free(ebuf->varc, ebuf->varv);
    free(ebuf);
}    

/*
 * Find a variable NAME in environment EBUF (non-recursive).
 * On success, store the pointer to its definition in *ret and return 0.
 * Otherwise, return -1.
 */
static int
micron_environ_find(struct micron_environ const *ebuf, char const *name,
		    char ***ret)
{
    size_t len = strcspn(name, "=");
    size_t i;

    for (i = 0; i < ebuf->varc; i++) {
	if (strlen(ebuf->varv[i]) > len
	    && memcmp(ebuf->varv[i], name, len) == 0
	    && ebuf->varv[i][len] == '=') {
	    if (ret)
		*ret = &ebuf->varv[i];
	    return 0;
	}
    }
    return -1;
}

/*
 * Append variable definition VAR to the environment EBUF.
 * Return 0 on success, -1 on failure (not enough memory).
 */
static int
micron_environ_append_var(struct micron_environ *ebuf, char *var)
{
    if (ebuf->varc == ebuf->varmax) {
	char **p;
	p = memrealloc(ebuf->varv, &ebuf->varmax, sizeof(ebuf->varv[0]));
	if (!p)
	    return -1;
	ebuf->varv = p;
    }
    ebuf->varv[ebuf->varc] = var;
    if (var)
	ebuf->varc++;
    return 0;
}

static int
micron_environ_set_var(struct micron_environ **ebuf, char *var)
{
    char **vptr;
    if (micron_environ_find(*ebuf, var, &vptr) == 0) {
	*ebuf = micron_environ_alloc((*ebuf)->link.prev);
    }
    return micron_environ_append_var(*ebuf, var);
}

#define SIZE_MAX ((size_t)-1)

/*
 * Copy plain environment ENV to incremental environment EBUF.
 * Return 0 on success, -1 on failure (not enough memory).
 */
static int
micron_environ_copy(struct micron_environ *ebuf, size_t envc, char **env)
{
    size_t i;

    for (i = 0; i < envc; i++) {
	if (env[i] == NULL)
	    break;
	if (micron_environ_find(ebuf, env[i], NULL)) {
	    char *s;

	    if ((s = strdup(env[i])) == NULL)
		return -1;
	    if (micron_environ_append_var(ebuf, s)) {
		free(s);
		return -1;
	    }
	}
    }
    return 0;
}

/*
 * Given the incremental environment EBUF and the root of environment
 * list HEAD, look up the variable NAME in it and all its parents.
 * Return the value, or NULL if not found.
 */
static char const *
micron_environ_get(struct micron_environ const *ebuf,
		   struct list_head const *head,
		   char const *name)
{
    struct micron_environ const *envp;
    
    LIST_FOREACH_FROM(envp, ebuf, head, link) {
	char **pp;
	if (micron_environ_find(envp, name, &pp) == 0) {
	    return strchr(*pp, '=') + 1;
	}
    }
    return NULL;
}

/*
 * Set the variable NAME to VALUE in the environment EBUF.
 */
static int
micron_environ_set(struct micron_environ **ebuf, char const *name,
		   const char *value)
{
    size_t len = strlen(name) + strlen(value) + 1;
    char *var = malloc(len + 1);
    if (!var)
	return -1;
    strcpy(var, name);
    strcat(var, "=");
    strcat(var, value);
    if (micron_environ_set_var(ebuf, var)) {
	free(var);
	return -1;
    }
    return 0;
}

/*
 * Build a plain environment out of incremental one.
 */
static char **
micron_environ_build(struct micron_environ *micron_env, struct list_head *head)
{
    struct micron_environ ebuf = MICRON_ENVIRON_INITIALIZER(ebuf);
    struct micron_environ *p;
    extern char **environ;

    if (micron_environ_copy(&ebuf, SIZE_MAX, environ))
	goto err;

    LIST_FOREACH_FROM(p, micron_env, head, link) {
	if (micron_environ_copy(&ebuf, p->varc, p->varv))
	    goto err;
    }

    if (micron_environ_append_var(&ebuf, NULL))
	goto err;
    
    return ebuf.varv;

err:
    env_free(ebuf.varv);
    return NULL;
}

static struct list_head cronjob_head = LIST_HEAD_INITIALIZER(cronjob_head);
static pthread_mutex_t cronjob_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cronjob_cond = PTHREAD_COND_INITIALIZER;

static void
cronjob_head_remove(int fileid)
{
    struct cronjob *cp, *prev;
    LIST_FOREACH_SAFE(cp, prev, &cronjob_head, list) {
	if (cp->fileid == fileid) {
	    LIST_REMOVE(cp, list);
	    cronjob_unref(cp);
	}
    }
}

static struct cronjob *
cronjob_alloc(int fileid, int type,
	      struct micronexp const *schedule,
	      struct passwd const *pwd,
	      char const *command, struct micron_environ *env)
{
    struct cronjob *job;
    size_t size = sizeof(*job) + strlen(command) + 1;
    
    job = calloc(1, size);
    if (job) {
	memset(job, 0, size);
	job->type = type;
	job->fileid = fileid;
	job->schedule = *schedule;
	job->command = (char*)(job + 1);
	strcpy(job->command, command);
	if (pwd) {
	    job->uid = pwd->pw_uid;
	    job->gid = pwd->pw_gid;
	} else {
	    job->uid = 0;
	    job->gid = 0;
	}
	list_head_init(&job->list);
	list_head_init(&job->runq);
	job->env = env;
	cronjob_ref(job);
    }
    return job;
}

void
cronjob_arm(struct cronjob *job, int apply_now)
{
    struct cronjob *p;
    
    LIST_REMOVE(job, list);

    if (job->type == JOB_REBOOT) {
	job->next_time.tv_sec = 0;
	job->next_time.tv_nsec = 0;
	LIST_FOREACH(p, &cronjob_head, list) {
	    if (p->type != JOB_REBOOT)
		break;
	}
    } else {
	if (apply_now) {
	    struct timespec now;
	    clock_gettime(CLOCK_REALTIME, &now);
	    now.tv_sec -= 60;
	    micron_next_time_from(&job->schedule, &now, &job->next_time);
	} else {
	    micron_next_time(&job->schedule, &job->next_time);
	}
    
	LIST_FOREACH(p, &cronjob_head, list) {
	    int c;
	    /* Insert entries in their natural order (FIFO) ... */
	    if ((c = timespec_cmp(&job->next_time, &p->next_time)) < 0
		/* except for internal entries, which are fired first */
		|| (c == 0 && job->type == JOB_INTERNAL))
		break;
	}
    }
    
    LIST_INSERT_BEFORE(p, job, list);
}

struct crontab {
    int fileid;
    int cid;
    char *filename;
    struct list_head list;
    time_t mtime;
    struct list_head env_head;
};

static struct list_head crontabs = LIST_HEAD_INITIALIZER(crontabs);
static int next_fileid;

static struct crontab *
crontab_find(int cid, char const *filename, int alloc)
{
    struct crontab *cp;
    struct micron_environ *env;
    
    LIST_FOREACH(cp, &crontabs, list) {
	if (cp->cid == cid && strcmp(cp->filename, filename) == 0)
	    return cp;
    }

    if (!alloc)
	return NULL;
    cp = malloc(sizeof(*cp) + strlen(filename) + 1);
    if (!cp)
	nomem_exit();
    cp->fileid = next_fileid++;
    cp->cid = cid;
    cp->filename = (char*)(cp + 1);
    strcpy(cp->filename, filename);
    cp->mtime = (time_t) -1;
    list_head_init(&cp->env_head);
    env = micron_environ_alloc(&cp->env_head);
    if (syslog_enable)
	// Note: The following call won't update the ebuf value, since
	// the environment is still empty.
	micron_environ_set(&env, "SYSLOG",
			   micron_log_fac_to_str(syslog_facility));    
    LIST_HEAD_PUSH(&crontabs, cp, list);
    
    return cp;
}

void
crontab_clear(struct crontab *cp, int reset)
{
    struct micron_environ *env;
    cronjob_head_remove(cp->fileid);
    while ((env = LIST_HEAD_POP(&cp->env_head,env,link)) != NULL) {
	if (reset && list_head_is_empty(&cp->env_head)) {
	    LIST_HEAD_PUSH(&cp->env_head,env,link);
	    break;
	}
	micron_environ_free(env);
    }
}

void
crontab_forget(struct crontab *cp)
{
    crontab_clear(cp, 0);
    LIST_REMOVE(cp, list);
    free(cp);
}

char **
cronjob_mkenv(struct cronjob *job)
{
    struct crontab *cp;
    LIST_FOREACH(cp, &crontabs, list) {
	if (cp->fileid == job->fileid)
	    return micron_environ_build(job->env, &cp->env_head);
    }
    micron_log(LOG_ERR, "crontab fileid not found; please report");
    return NULL;
}

#define PRsCRONTAB "%s%s%s"
#define ARGCRONTAB(cid, filename)\
    crongroups[cid].dirname ? crongroups[cid].dirname : "", \
    crongroups[cid].dirname ? "/" : "",		        \
    filename

static inline int
isws(int c)
{
    return c == ' ' || c == '\t';
}

static pthread_key_t pwdbuf_key;
static pthread_once_t pwdbuf_key_once = PTHREAD_ONCE_INIT;

struct pwdbuf {
    struct passwd pwd;
    char *buf;
    size_t size;
};

static void
pwdbuf_free(void *f)
{
    struct pwdbuf *sb = f;
    free(sb->buf);
    free(sb);
}

static void
make_pwdbuf_key(void)
{
    pthread_key_create(&pwdbuf_key, pwdbuf_free);
}

static struct pwdbuf *
priv_expand_pwdbuf(struct pwdbuf *sb)
{
    size_t n;
    char *p;
    
    if (sb->size == 0) 
	n = 64;
    else {
	n = sb->size;
	if ((size_t) -1 / 3 * 2 <= n) {
	    micron_log(LOG_ERR, "out of memory");
	    return NULL;
	}
	n += (n + 1) / 2;
    }
    p = realloc(sb->buf, n);
    if (!p) {
	micron_log(LOG_ERR, "out of memory");
	return NULL;
    }
    sb->size = n;
    sb->buf = p;
    return sb;
}

static struct pwdbuf *
priv_get_pwdbuf(void)
{
    struct pwdbuf *sb;
    pthread_once(&pwdbuf_key_once, make_pwdbuf_key);
    if ((sb = pthread_getspecific(pwdbuf_key)) == NULL) {
	sb = calloc(1, sizeof(*sb));
	if (sb == NULL)
	    micron_log(LOG_ERR, "out of memory");
	else if (priv_expand_pwdbuf(sb) == NULL) {
	    free(sb);
	    sb = NULL;
	}
	pthread_setspecific(pwdbuf_key, sb);
    }
    return sb;
}

static struct passwd *
priv_get_passwd(char const *username)
{
    struct passwd *pwd;
    struct pwdbuf *sb = priv_get_pwdbuf();
    while (getpwnam_r(username, &sb->pwd, sb->buf, sb->size, &pwd) == ERANGE) {
	if (!priv_expand_pwdbuf(sb))
	    return NULL;
    }
    return pwd;
}

static int
crontab_check_file(int cid, char const *filename,
		   struct crontab **pcp, struct passwd **ppwd)
{
    char const *username;
    struct crontab *cp;
    struct passwd *pwd;
    int rc;
    struct stat st;
    
    if (fstatat(crongroups[cid].dirfd, filename, &st, AT_SYMLINK_NOFOLLOW)) {
	micron_log(LOG_ERR, "can't stat file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cid, filename),
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    if (!S_ISREG(st.st_mode)) {
	micron_log(LOG_ERR, PRsCRONTAB ": not a regular file",
		   ARGCRONTAB(cid, filename));
	return CRONTAB_FAILURE;
    }
    if (crongroups[cid].flags & CRONID_USER) {
	username = filename;
    } else {
	username = "root";
    }
    pwd = priv_get_passwd(username);
    if (!pwd) {
	micron_log(LOG_ERR, PRsCRONTAB ": ignored; no such username",
		   ARGCRONTAB(cid, filename));
	return CRONTAB_FAILURE;
    }
    if (st.st_uid != pwd->pw_uid) {
	micron_log(LOG_ERR, PRsCRONTAB " not owned by %s; ignored",
		   ARGCRONTAB(cid, filename), username);
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
	micron_log(LOG_ERR, PRsCRONTAB ": unsafe permissions",
		   ARGCRONTAB(cid, filename));
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }

    *ppwd = pwd;

    rc = CRONTAB_SUCCESS;
    cp = crontab_find(cid, filename, 1);
    if (cp->mtime == (time_t) -1)
	rc = CRONTAB_NEW;
    else if (cp->mtime < st.st_mtime)
	rc = CRONTAB_MODIFIED;
    cp->mtime = st.st_mtime;
    *pcp = cp;
    return rc;
}

static inline int
is_var_start(int c)
{
    return isalpha(c);
}

static inline int
is_var_part(int c)
{
    return isalnum(c) || c=='_';
}

/*
 * If the current line S looks like a environment variable assignment,
 * return 0 and set *NAME_END to the length of the name portion, and
 * VAL_START to the offset of the value portion.
 */
static int
is_env(char const *s, int *name_end, int *val_start)
{
    int ne, vs;
    if (!is_var_start(*s))
	return 0;
    for (ne = 0; s[ne] && is_var_part(s[ne]); ne++)
	;
    if (!s[ne])
	return 0;
    vs = ne;
    while (s[vs] && isws(s[vs]))
	vs++;
    if (s[vs] != '=')
	return 0;
    vs++;
    while (s[vs] && isws(s[vs]))
	vs++;
    *name_end = ne;
    *val_start = vs;
    return 1;
}

static int
copy_quoted(char *dst, char const *src, int delim)
{
    while (*src != delim) {
	if (!*src)
	    return -1;
	if (*src == '\\') {
	    if (src[1] == 0)
		return -1;
	    src++;
	}
	*dst++ = *src++;
    }
    *dst = 0;
    return 0;
}

static int
copy_unquoted(char *dst, char const *src)
{
    while (*src) {
	if (isws(*src))
	    return -1;
	*dst++ = *src++;
    }
    *dst = 0;
    return 0;
}

static int
check_var(char const *def)
{
    if (strncmp(def, "SYSLOG=", 7) == 0) {
	def += 7;
	if (strcasecmp(def, "off") == 0
	    || strcasecmp(def, "none") == 0
	    || strcasecmp(def, "default") == 0
	    || micron_log_str_to_fac(def) != -1)
	    return 0;
	else
	    return 1;
    }
    return 0;
}

static inline int
is_reboot(char const *s, char **endp)
{
    static char reboot_str[] = "@reboot";
    static int reboot_len = sizeof(reboot_str) - 1;
    
    if (strncmp(s, reboot_str, reboot_len) == 0
	&& (!s[reboot_len] || isws(s[reboot_len]))) {
	*endp = (char*) (s + reboot_len);
	return 1;
    }
    return 0;
}

static int
get_day_semantics(struct crontab const *cp)
{
    char const *str;
    struct micron_environ const *env = LIST_FIRST_ENTRY(&cp->env_head, env, link);

    str = micron_environ_get(env, &cp->env_head, "CRON_DAY_SEMANTICS");
    if (str) {
	int i;
	for (i = 0; i < MAX_MICRON_DAY; i++) {
	    if (strcasecmp(str, micron_dsem_str[i]) == 0)
		return i;
	}
	return -1;
    }
    return MICRON_DAY_STRICT;
}

static int
crontab_parse(int cid, char const *filename, int ifmod)
{
    int fd;
    struct crontab *cp;
    FILE *fp;
    char buf[MAXCRONTABLINE+1];
    size_t off;
    unsigned line = 0;
    struct cronjob *job;
    struct passwd *pwd;
    int env_cont = 1;
    struct micron_environ *env;
    
    /* Do nothing if this crongroup is disabled */
    if (crongroups[cid].flags & CGF_DISABLED)
	return CRONTAB_SUCCESS;
    /* Do nothing if we're not interested in this file */
    if ((crongroups[cid].flags & CGF_SINGLE) &&
	strcmp(crongroups[cid].pattern, filename))
	return CRONTAB_SUCCESS;
    
    switch (crontab_check_file(cid, filename, &cp, &pwd)) {
    case CRONTAB_SUCCESS:
	if (ifmod & PARSE_IF_MODIFIED)
	    return CRONTAB_SUCCESS;
	crontab_clear(cp, 1);
	break;

    case CRONTAB_NEW:
	break;
	
    case CRONTAB_MODIFIED:
	micron_log(LOG_INFO, "re-reading " PRsCRONTAB,
		   ARGCRONTAB(cid, filename));
	crontab_clear(cp, 1);
	break;
	
    case CRONTAB_FAILURE:
	if ((cp = crontab_find(cid, filename, 0)) != NULL) {
	    crontab_forget(cp);
	    return CRONTAB_MODIFIED;
	}
	return CRONTAB_FAILURE;
    }
	
    fd = openat(crongroups[cid].dirfd, filename, O_RDONLY);
    if (fd == -1) {
	micron_log(LOG_ERR, "can't open file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cid, filename),
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    fp = fdopen(fd, "r");
    if (!fp) {
	micron_log(LOG_ERR, "can't fdopen file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cid, filename),
		   strerror(errno));
	close(fd);
	return CRONTAB_FAILURE;
    }

    /* Create initial environment */
    micron_environ_alloc(&cp->env_head);
    
    off = 0;
    while (1) {
	size_t len;
	int type;
	struct micronexp schedule;
	char *p;
	char *user = NULL;
	char const *ep;
	int rc;
	int name_len, val_start;
	
	if (off >= MAXCRONTABLINE)
	    goto toolong;
	else if (fgets(buf + off, sizeof(buf) - off, fp) == NULL)
	    break;
	++line;
	len = strlen(buf + off);
	if (len == 0)
	    continue;
	switch (buf[strspn(buf, " \t")]) {
	case 0:
	case '\n':
	case '#':
	    continue;
	}
	if (buf[off+len-1] != '\n') {
	    int c;
	toolong:
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: line too long",
		       ARGCRONTAB(cid, filename), line);
	    off = 0;
	    while ((c = fgetc(fp)) != EOF) {
		if (c == '\n') {
		    ++line;
		    break;
		}
	    }
	    continue;
	}
	buf[off+len-1] = 0;
	--len;
	if (buf[off+len-1] == '\\') {
	    buf[off+len-1] = 0;
	    --len;
	    off += len;
	    continue;
	} else {
	    len += off;
	    off = 0;
	}

	/* Trim trailing whitespace */
	while (len > 0 && isws(buf[len-1]))
	    len--;
	if (len == 0)
	    continue;
	buf[len] = 0;

	/* Skip initial whitespace */
	for (p = buf; *p && isws(*p); p++)
	    ;

	if (is_env(p, &name_len, &val_start)) {
	    char *var = malloc(len+1);
	    if (!var) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
			   ARGCRONTAB(cid, filename), line);
		break;
	    }
	    memcpy(var, p, name_len);
	    var[name_len] = '=';

	    p += val_start;
	    if (*p == '"' || *p == '\'')
		rc = copy_quoted(var + name_len + 1, p + 1, *p);
	    else
		rc = copy_unquoted(var + name_len + 1, p);
	    if (rc) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: syntax error",
			   ARGCRONTAB(cid, filename), line);
		free(var);
		continue;
	    }

	    if (check_var(var) == 0) {
		env = LIST_FIRST_ENTRY(&cp->env_head, env, link);
		if (!env_cont) {
		    env = micron_environ_alloc(&cp->env_head);
		}
		if (micron_environ_set_var(&env, var)) {
		    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
			       ARGCRONTAB(cid, filename), line);
		    free(var);
		    break;
		}
	    } else {
		micron_log(LOG_ERR,
			   PRsCRONTAB ":%u: invalid builtin variable assignment",
			   ARGCRONTAB(cid, filename), line);
		free(var);
	    }
	    
	    env_cont = 1;
	    continue;
	} else
	    env_cont = 0;

	if (is_reboot(p, &p)) {
	    type = JOB_REBOOT;
	} else {
	    schedule.dsem = get_day_semantics(cp);
	    rc = micron_parse(p, &p, &schedule);
	    if (rc) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: %s near %s",
			   ARGCRONTAB(cid, filename), line,
			   micron_strerror(rc), p);
		continue;
	    }
	    type = JOB_NORMAL;
	}

	while (*p && isws(*p))
	    p++;

	if (!*p) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: premature end of line",
		       ARGCRONTAB(cid, filename), line);
	    continue;
	}

	if (!(crongroups[cid].flags & CGF_USER)) {
	    user = p;
	    
	    while (*p && !isws(*p))
		p++;

	    if (!*p) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: premature end of line",
			   ARGCRONTAB(cid, filename), line);
		continue;
	    }

	    *p++ = 0;

	    pwd = priv_get_passwd(user);
	    if (!pwd) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: no such user %s",
			   ARGCRONTAB(cid, filename), line, user);
		continue;
	    }

	    while (*p && isws(*p))
	        p++;
        }

	if (running && type == JOB_REBOOT) {
	    /* Ignore @reboot entries when running */
	    micron_log(LOG_DEBUG, PRsCRONTAB ":%u: ignoring @reboot",
			   ARGCRONTAB(cid, filename), line);
	    continue;
	}
	
	/* Finalize environment */
	env = LIST_FIRST_ENTRY(&cp->env_head, env, link);
	
	if (!micron_environ_get(env, &cp->env_head, "HOME")) 
	    micron_environ_set(&env, "HOME", pwd->pw_dir);
	if (!micron_environ_get(env, &cp->env_head, "SHELL")) 
	    micron_environ_set(&env, "SHELL", "/bin/sh");
    
	if (micron_environ_set(&env, "LOGNAME", pwd->pw_name)) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}
	if (micron_environ_set(&env, "USER", pwd->pw_name)) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}
	    
	job = cronjob_alloc(cp->fileid, type, &schedule, pwd, p, env);
	if (!job) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}

	ep = micron_environ_get(env, &cp->env_head, "JOB_ALLOW_MULTIPLE");
	if (ep) {
	    char *endp;
	    unsigned long n;
	    errno = 0;
	    n = strtoul(ep, &endp, 2);
	    if (errno || *endp) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: unrecognized value",
			   ARGCRONTAB(cid, filename), line);
	    } else
		job->allow_multiple = (int) n;
	}
	cronjob_arm(job, ifmod & PARSE_APPLY_NOW);
    }
    fclose(fp);
    return CRONTAB_MODIFIED;
}

void
crontab_scanner_schedule(void)
{
    struct micronexp schedule;
    struct cronjob *cp;
    LIST_FOREACH(cp, &cronjob_head, list) {
	if (cp->type == JOB_INTERNAL)
	    return;
    }
    micron_parse("* * * * *", NULL, &schedule);
    cp = cronjob_alloc(-1, JOB_INTERNAL, &schedule,
		       NULL, "<internal scanner>", NULL);
    if (!cp) {
	micron_log(LOG_ERR, "out of memory while installing internal scanner");
	/* Try to continue anyway */
	return;
    }
    cronjob_arm(cp, 0);
}

static int
patmatch(char const **patterns, const char *name)
{
    int i;
    for (i = 0; patterns[i]; i++)
	if (fnmatch(name, patterns[i], 0) == 0)
	    return 1;
    return 0;
}

int
crongroup_parse(int cid, int ifmod)
{
    struct crongroup const *cdef = &crongroups[cid];
    int dirfd;
    struct stat st;
    int rc;
    
    if (cdef->flags & CGF_DISABLED)
	return CRONTAB_SUCCESS;

    if (fstatat(AT_FDCWD, cdef->dirname, &st, AT_SYMLINK_NOFOLLOW)) {
	micron_log(LOG_ERR, "can't stat file %s: %s",
		   cdef->dirname,
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    if (st.st_uid != 0) {
	micron_log(LOG_ERR, "%s not owned by root; ignored",
		   cdef->dirname);
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }
    if (st.st_mode & S_IWOTH) {
	micron_log(LOG_ERR, "%s: unsafe permissions",
		   cdef->dirname);
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }
    if (!S_ISDIR(st.st_mode)) {
	micron_log(LOG_ERR, "%s: not a directory", cdef->dirname);
	return CRONTAB_FAILURE;
    }

    if (crongroups[cid].dirfd == -1) {
	dirfd = openat(AT_FDCWD, cdef->dirname,
		       O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (dirfd == -1) {
	    micron_log(LOG_ERR, "can't open directory %s: %s",
		       cdef->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}

	crongroups[cid].dirfd = dirfd;
    }
    
    if (cdef->flags & CGF_SINGLE) {
	rc = crontab_parse(cid, crongroups[cid].pattern, ifmod);
    } else {
	DIR *dir;
	struct dirent *ent;
	
	dirfd = dup(crongroups[cid].dirfd);
	if (dirfd == -1) {
	    micron_log(LOG_ERR, "dup: %s", strerror(errno));
	    return CRONTAB_FAILURE;
	}
	
	dir = fdopendir(dirfd);
	if (!dir) {
	    micron_log(LOG_ERR, "can't open directory %s: %s",
		       cdef->dirname,
		       strerror(errno));
	    close(dirfd);
	    return CRONTAB_FAILURE;
	}

	rc = CRONTAB_SUCCESS;
	while ((ent = readdir(dir))) {
	    if (strcmp(ent->d_name, ".") == 0 ||
		strcmp(ent->d_name, "..") == 0 ||
		(cdef->pattern && !fnmatch(cdef->pattern, ent->d_name, 0)) ||
		patmatch(cdef->exclude, ent->d_name))
		continue;
	    if (crontab_parse(cid, ent->d_name, ifmod) != CRONTAB_SUCCESS)
		rc = CRONTAB_MODIFIED;
	}
	closedir(dir);
    }
    return rc;
}

void
crontab_deleted(int cid, char const *name)
{
    struct crontab *cp = crontab_find(cid, name, 1);
    pthread_mutex_lock(&cronjob_mutex);
    cronjob_head_remove(cp->fileid);
    pthread_cond_broadcast(&cronjob_cond);
    pthread_mutex_unlock(&cronjob_mutex);
}

void
crontab_updated(int cid, char const *name)
{
    struct timespec ts;
    pthread_mutex_lock(&cronjob_mutex);
    clock_gettime(CLOCK_REALTIME, &ts);
    crontab_parse(cid, name, PARSE_ALWAYS |
		             (ts.tv_sec == 0 ? PARSE_APPLY_NOW : 0));
    pthread_cond_broadcast(&cronjob_cond);
    pthread_mutex_unlock(&cronjob_mutex);
}

void *
cron_thr_main(void *ptr)
{
    struct cronjob *job;

    pthread_mutex_lock(&cronjob_mutex);

    micron_log(LOG_INFO, "running reboot jobs");
    while (!list_head_is_empty(&cronjob_head)) {
	job = LIST_FIRST_ENTRY(&cronjob_head, job, list);
	if (job->type != JOB_REBOOT)
	    break;
	LIST_REMOVE(job, list);
	runner_enqueue(job);
	cronjob_unref(job);
    }
    running = 1;
    
    while (1) {
	int rc;
	
	if (list_head_is_empty(&cronjob_head)) {
	    pthread_cond_wait(&cronjob_cond, &cronjob_mutex);
	    continue;
	}
	
	job = LIST_FIRST_ENTRY(&cronjob_head, job, list);
	rc = pthread_cond_timedwait(&cronjob_cond, &cronjob_mutex,
				    &job->next_time);
	if (rc == 0)
	    continue;
	if (rc != ETIMEDOUT) {
	    micron_log(LOG_CRIT,
		       "unexpected error from pthread_cond_timedwait: %s",
		       strerror(errno));
	    exit(EXIT_FATAL);
	}

	if (job != LIST_FIRST_ENTRY(&cronjob_head, job, list)) {
	    /* Just in case... */
	    continue;
	}
	
	LIST_REMOVE(job, list);

	if (job->type == JOB_INTERNAL) {
	    int cid;

	    micron_log(LOG_DEBUG, "rescanning crontabs");
	    for (cid = 0; cid < NCRONID; cid++)
		crongroup_parse(cid, PARSE_IF_MODIFIED | PARSE_APPLY_NOW);
	} else {
	    runner_enqueue(job);
	}
	cronjob_arm(job, 0);
    }
}

