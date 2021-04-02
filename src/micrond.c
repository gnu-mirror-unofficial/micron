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
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <fnmatch.h>
#include <pthread.h>
#include <ctype.h>
#include "micrond.h"

struct crongroup crongroups[] = {
    {   /*
	 * The master crongroup consists of a single /etc/crontab file.
	 * The .pattern will be split into directory prefix and a file
	 * name in main.
	 */
	.id = "master",
	.type = CGTYPE_SINGLE,
	.dirfd = -1,
	.pattern = MICRON_CRONTAB_MASTER,

	.owner_name = "root",
	.owner_group = "root",
	.mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, // 0755
	.mask = S_IWGRP | S_IWOTH
    },
    {   /*
	 * The system crongroup comprises multiple files stored in
	 * /etc/cron.d
	 */
	.id = "system",
	.type = CGTYPE_DEFAULT,
	.dirname = MICRON_CRONDIR_SYSTEM,
	.dirfd = -1,
	.exclude = ignored_file_patterns,

	.owner_name = "root",
	.owner_group = "root",
	.mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, // 0755
	.mask = S_IWGRP | S_IWOTH
    },
    {   /*
	 * The user crongroup contains personal user crontabs.  The
	 * crontabs should not contain the user field.  It is deduced
	 * from the file name itself.
	 */
	.id = "user",
	.type = CGTYPE_USER,
	.dirname = MICRON_CRONDIR_USER,
	.dirfd = -1,
	.exclude = ignored_file_patterns,

	.owner_name = "root",
	.owner_group = CRONTAB_GID,
	.mode = S_IRWXU | S_IRWXG | S_ISVTX,
	.mask = S_IWOTH
    },
    {   /*
	 * The group crongroup contains personal user crontabs stored
	 * in directories named after the user login name.  Each directory
	 * is added to the crongroup_head as a separate crongroup of type
	 * CGTYPE_GROUP and can contain multiple crontabs.  They can be
	 * owned by different users the only requirement being that their
	 * owner is a member of the primary group of the user in whose
	 * directory they reside.  This provides a convenient way for
	 * maintaining crontabs for certain services, e.g. httpd.
	 */
	.id = "group",
	.type = CGTYPE_GROUPHOST,
	.dirname = MICRON_CRONDIR_GROUP,
	.dirfd = -1,
	.exclude = ignored_file_patterns,
	.flags = CGF_DISABLED,

	.owner_name = "root",
	.owner_group = CRONTAB_GID,
	.mode = S_IRWXU | S_IRWXG | S_ISVTX,
	.mask = S_IWOTH
    }
};

#define NCRONID (sizeof(crongroups)/sizeof(crongroups[0]))

struct list_head crongroup_head = LIST_HEAD_INITIALIZER(crongroup_head);

/* Mode argument for crontab parsing founctions */
enum {
    PARSE_ALWAYS      = 0x00, /* Always parse the file(s) */
    PARSE_IF_MODIFIED = 0x01, /* Parse the file only if mtime changed or
				 if it is a new file */
    PARSE_CHATTR      = 0x02, /* (Only for crongroups) Parse only if directory
				 permissions changed to safe state. */
    PARSE_APPLY_NOW   = 0x10  /* Used together with any of the above means
				 that the changes must be applied to the
				 current minute. */
};

int foreground;
int no_safety_checking;
char *mailer_command = "/usr/sbin/sendmail -oi -t";
int log_level = LOG_INFO;
mode_t saved_umask;
/* Time to wait for all cronjobs to terminate before stopping micrond. */
unsigned micron_termination_timeout = 60;
    
/* Boolean flag used to filter out @reboot jobs when rescanning. */
static int running;
static struct cronjob_options micron_options = {
    .dsem = MICRON_DAY_STRICT,
    .maxinstances = 1,
    .syslog_facility = 0
};    

static void set_crontab_options(char *str);

static int crongroup_init(struct crongroup *cgrp);
static int crongroup_parse(struct crongroup *cgrp, int ifmod);
static void crongroup_forget_crontabs(struct crongroup *cgrp);

static void *cron_thr_main(void *);
static void stop_thr_main(pthread_t tid);

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

/* Restore default signal handlers */
void
restore_default_signals(void)
{
    int i;
    struct sigaction act;
    sigset_t sigs;
    
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    for (i = 0; fatal_signals[i]; i++) {
	sigaction(fatal_signals[i], &act, NULL);
    }

    sigfillset(&sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
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
    }

    for (i = 0; i < NCRONID; i++) {
	if (strncmp(crongroups[i].id, arg, len) == 0) {
	    if (neg)
		crongroups[i].flags |= CGF_DISABLED;
	    else {
		if (arg[len]) {
		    char *filename = (char *) (arg + len + 1);
		    struct stat st;

		    if (stat(filename, &st)) {
			micron_log(LOG_CRIT, "%s: can't stat %s: %s",
				   arg, filename, strerror(errno));
			exit(EXIT_FATAL);
		    }
		    if (S_ISDIR(st.st_mode)) {
			crongroups[i].dirname = filename;
			if (crongroups[i].type == CGTYPE_SINGLE)
			    crongroups[i].pattern = "crontab";
		    } else
			crongroups[i].pattern = filename;
		}
		crongroups[i].flags &= ~CGF_DISABLED;
	    }
	    return;
	}
    }

    micron_log(LOG_CRIT, "%s: unknown group name", arg);
    exit(EXIT_USAGE);
}   

static void
usage(void)
{
    printf("usage: %s [-fhNSsv] [-g [no]GROUP[=DIR]] [-l PRI] [-m MAILER] [-o OPTS] [-p DEV]\n", progname);
    printf("A cron deamon\n");
    printf("\nOPTIONS:\n\n");
    printf("    -F FACILITY     log cronjobs output to this facility (implies -s)\n");
    printf("    -f              remain in foreground\n");
    printf("    -g GROUP=DIR    set directory or file name for crontab group GROUP\n");
    printf("    -g [no]GROUP    enable or disable crontab group GROUP\n");
    printf("    -l PRI          log only messages with syslog priority PRI or higher\n");
    printf("    -m MAILER       set mailer command\n");
    printf("    -N              disable safety checking (for debugging only!)\n");
    printf("    -o OPTS         set crontab options\n");
    printf("    -p SOCKET       send messages to syslog via this SOCKET\n");
    printf("    -S              log to syslog even if running in foreground\n");
    printf("    -s              log output from cronjobs to syslog\n");
    printf("    -t SECONDS      time to wait for the cronjobs to terminate after\n"
	   "                    sending them the SIGTERM signal before stopping\n"
	   "                    micrond\n");
    printf("\n");
    printf("    -h              print this help text\n");
    printf("    -v              print program version and exit\n");
    printf("\n");
    printf("Valid crontab groups are: master, system, user, and group.\n\n");
    printf("OPTS is a comma-separated list of crontab options.\n\n");
    printf("Syslog SOCKET can be either an absolute name of a UNIX socket or\n");
    printf("a host name or IPv4 address optionally followed by a colon and port\n");
    printf("number or service name.\n");
    printf("\n");
}

void
default_stop_thread(pthread_t tid)
{
    void *res;
    pthread_cancel(tid);
    pthread_join(tid, &res);
}

int
main(int argc, char **argv)
{
    int c;
    int i;
    struct sigaction act;
    sigset_t sigs;
    int log_to_syslog = 0;

    struct thread_info {
	pthread_t tid;              /* Thread handle. Gets filled when the
				       thread is created. */
	/* Each of the function pointers below can be NULL. */
	void (*init)(void);         /* Initialization funtion.  Called at
				       startup before creating the thread. */
	void *(*start)(void *ptr);  /* Thread start routine. */
	void (*stop) (pthread_t);   /* Function to stop the thread */
    };

    /*
     * Threads are started in the order they are listed in the thread_info
     * array and terminated in the reverse order.
     */
    static struct thread_info thread_info[] = {
	// Program cleaner
	{
	    .start = cron_thr_cleaner,
	    .stop = stop_thr_cleaner
	},
	// Program runner 
	{
	    .start = cron_thr_runner,
	    .stop = default_stop_thread
	},
	// Scheduler
	{
	    .start = cron_thr_main,
	    .stop = stop_thr_main
	},
	// Crontab watcher
	{
#ifdef WITH_INOTIFY
	    .start = cron_thr_watcher,
	    .stop = default_stop_thread
#else
	    .init = crontab_scanner_schedule
#endif
	}
    };
    static int nthr = sizeof(thread_info) / sizeof(thread_info[0]);

    
    set_progname(argv[0]);
    
    while ((c = getopt(argc, argv, "hg:fNl:m:o:p:Sst:v")) != EOF) {
	switch (c) {
	case 'h':
	    usage();
	    exit(EXIT_OK);
	    
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

	case 'o':
	    set_crontab_options(optarg);
	    break;

	case 'p':
	    micron_log_dev = optarg;
	    break;

	case 'S':
	    log_to_syslog = 1;
	    break;
	    
	case 's':
	    micron_options.syslog_facility = LOG_CRON;
	    break;

	case 't': {
	    unsigned long n;
	    char *endp;
	    
	    n = strtoul(optarg, &endp, 10);
	    if (*endp || (n == ULONG_MAX && errno == ERANGE) || n <= 0) {
		micron_logger(LOG_CRIT, "not a valid timeout value: %s", optarg);
		exit(EXIT_USAGE);
	    }
	    micron_termination_timeout = n;
	    break;
	}
	    
	case 'v':
	    version();
	    exit(EXIT_OK);
	    
	default:
	    exit(EXIT_USAGE);
	}
    }

    for (i = 0; i < NCRONID; i++) {
	list_head_init(&crongroups[i].list);
	if (crongroups[i].flags & CGF_DISABLED)
	    continue;
	if (!crongroups[i].dirname) {
	    if (crongroups[i].pattern) {
		if (parsefilename(crongroups[i].pattern,
				  &crongroups[i].dirname,
				  &crongroups[i].pattern))
		    nomem_exit();
	    } else {
		crongroups[i].flags |= CGF_DISABLED;
		continue;
	    }
	}

	if (crongroup_init(&crongroups[i]))
	    exit(EXIT_FATAL);
	
	LIST_HEAD_INSERT_LAST(&crongroup_head, &crongroups[i], list);
    }

    if (foreground) {
	/*
	 * Make sure stdin is disconnected from the terminal.  This setting
	 * will be inherited by all forked processes.  The remaining two
	 * standard descriptors will be set for each child individually.
	 */
	close(0);
	if (open("/dev/null", O_RDONLY) == -1) {
	    micron_log(LOG_CRIT, "can't open /dev/null: %s", strerror(errno));
	    exit(EXIT_FATAL);
	}
    } else {
	if (daemon(0, 0)) {
	    micron_log(LOG_CRIT, "daemon failed: %s", strerror(errno));
	    exit(EXIT_FATAL);
	}
	log_to_syslog = 1;
    }

    if (log_to_syslog) {
	micron_log_open(progname, LOG_CRON);
	micron_logger = micron_syslog;
    } else if (micron_options.syslog_facility)
	micron_log_open(progname, LOG_CRON);

    saved_umask = umask(077);
    crongroups_parse_all(PARSE_ALWAYS);

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
    for (i = 0; i < nthr; i++) {
	if (thread_info[i].init)
	    thread_info[i].init();
	if (thread_info[i].start)
	    pthread_create(&thread_info[i].tid, NULL,
			   thread_info[i].start, NULL);
    }
    
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

    /* Stop the threads in reverse order. */
    for (i = nthr - 1; i >= 0; i--) {
	if (thread_info[i].stop)
	    thread_info[i].stop(thread_info[i].tid);
    }

    micron_log_close();
    
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

/*
 * String support for cronjob_options.
 */

/* Return a pointer to the string value of S. */
static inline char const *
string_value(String s)
{
    return s ? s->str : NULL;
}

/*
 * Compute size of the String object able to store nul-terminated string of
 * length LEN.
*/
static inline size_t
string_reference_size(size_t len)
{
    return sizeof(struct string_reference) + len + 1;
}

/* Increase reference counter of S. */
static inline void
string_ref(String s)
{
    if (s)
	s->refcnt++;
}

/*
 * Allocate a String object able to store nul-terminated string of
 * length LEN.
 */
static String
string_alloc(size_t len)
{
    struct string_reference *ref;
    ref = malloc(string_reference_size(len));
    if (ref) {
	ref->refcnt = 1;
	ref->str[0] = 0;
    }
    return ref;
}

/*
 * Allocate a String object and initialize it with the first LEN bytes from
 * the string STR.  Terminate allocated string with \0.
 */
static String
string_init(char const *str, size_t len)
{
    String ref = string_alloc(len);
    if (ref) {
	memcpy(ref->str, str, len);
	ref->str[len] = 0;
    }
    return ref;
}

/*
 * Allocate a String object and initialize it to characters from S
 * (terminating \0 included).
 */
static String
string_copy(char const *s)
{
    if (!s)
	return NULL;
    return string_init(s, strlen(s));
}

/*
 * Decrement reference counter of S.  Free the object if the counter is 0.
 */
void
string_free(String s)
{
    if (s) {
	if (--s->refcnt == 0)
	    free(s);
    }
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
    int detached;    /* If true, this environment is detached from its
			parent. This means that eventual flattening of any
			of its children will stop at it. */
    struct list_head link; /* Links to parent and child environments */
};

#define MICRON_ENVIRON_INITIALIZER(n) \
    { 0, 0, NULL, 0, LIST_HEAD_INITIALIZER((n).link) }

static int micron_environ_set(struct micron_environ **ebuf, char const *name,
			      const char *value);
static int micron_environ_clone(struct micron_environ *dst,
				struct micron_environ *src,
				struct list_head *head);

static void
micron_environ_init(struct micron_environ *ebuf)
{
    ebuf->varc = ebuf->varmax = 0;
    ebuf->varv = NULL;
    ebuf->detached = 0;
    list_head_init(&ebuf->link);
}

static struct micron_environ *
micron_environ_create(void)
{
    struct micron_environ *ebuf = malloc(sizeof(*ebuf));
    if (ebuf)
	micron_environ_init(ebuf);
    return ebuf;
}

static struct micron_environ *
micron_environ_alloc(struct list_head *head)
{
    struct micron_environ *ebuf = micron_environ_create();
    if (ebuf) {
	LIST_HEAD_PUSH(head, ebuf, link);
    }
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
micron_environ_find(struct micron_environ const *ebuf,
		      char const *name,
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

static int
micron_environ_unset(struct list_head *head, char const *name)
{
    struct micron_environ *env = LIST_FIRST_ENTRY(head, env, link);
    char **vptr;
    
    if (!env->detached) {
	if (micron_environ_get(env, head, name)) {
	    struct micron_environ *denv = micron_environ_create();
	    if (!denv)
		return -1;
	    if (micron_environ_clone(denv, env, head)) {
		micron_environ_free(denv);
		return -1;
	    }
	    denv->detached = 1;
	    LIST_HEAD_PUSH(head, denv, link);
	    env = denv;
	}
    }

    if (micron_environ_find(env, name, &vptr) == 0) {
	size_t n;
	
	free(*vptr);
	if ((n = env->varc - (vptr - env->varv) - 1) > 0)
	    memmove(vptr, vptr + 1, n * sizeof(env->varv[0]));
	env->varc--;
    }
    return 0;
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

static int
micron_environ_clone(struct micron_environ *dst,
		     struct micron_environ *src, struct list_head *head)
{
    struct micron_environ *p;

    LIST_FOREACH_FROM(p, src, head, link) {
	if (micron_environ_copy(dst, p->varc, p->varv))
	    return -1;
	if (p->detached)
	    break;
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
    extern char **environ;

    if (micron_environ_clone(&ebuf, micron_env, head) == 0 &&
	micron_environ_copy(&ebuf, SIZE_MAX, environ) == 0 &&
	micron_environ_append_var(&ebuf, NULL) == 0)
	return ebuf.varv;

    env_free(ebuf.varv);
    return NULL;
}

static pthread_mutex_t cronjob_ref_mutex = PTHREAD_MUTEX_INITIALIZER;

void
cronjob_ref(struct cronjob *cp)
{
    pthread_mutex_lock(&cronjob_ref_mutex);
    cp->refcnt++;
    pthread_mutex_unlock(&cronjob_ref_mutex);
}

void
cronjob_unref(struct cronjob *cp)
{
    pthread_mutex_lock(&cronjob_ref_mutex);
    if (--cp->refcnt == 0) {
	free(cp);
    }
    pthread_mutex_unlock(&cronjob_ref_mutex);
}

static struct list_head cronjob_head = LIST_HEAD_INITIALIZER(cronjob_head);
static pthread_mutex_t cronjob_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cronjob_cond = PTHREAD_COND_INITIALIZER;

static void
cronjob_head_remove(unsigned fileid)
{
    struct cronjob *cp, *prev;
    LIST_FOREACH_SAFE(cp, prev, &cronjob_head, list) {
	if (cp->fileid == fileid) {
	    LIST_REMOVE(cp, list);
	    cronjob_unref(cp);
	}
    }
}

static char *
find_percent(char *p)
{
    enum { S_INIT, S_QUOTE, S_DQUOTE } state = S_INIT;

    while (*p) {
	switch (state) {
	case S_INIT:
	    switch (*p) {
	    case '\\':
		p++;
		if (*p == 0)
		    return NULL;
		break;
	    case '\'':
		state = S_QUOTE;
		break;
	    case '"':
		state = S_DQUOTE;
		break;
	    case '%':
		return p;
	    }
	    break;

	case S_QUOTE:
	    if (*p == '\'')
		state = S_INIT;
	    break;

	case S_DQUOTE:
	    switch (*p) {
	    case '\\':
		p++;
		if (*p == 0)
		    return NULL;
		break;
	    case '"':
		state = S_INIT;
	    }
	    break;
	}
	p++;
    }
    return NULL;
}

static struct cronjob *
cronjob_alloc(struct cronjob_options const *opt,
	      unsigned fileid, int type,
	      struct micronexp const *schedule,
	      struct passwd const *pwd,
	      char const *command, struct micron_environ *env)
{
    struct cronjob *job;
    char const *tag = (opt && opt->syslog_facility)
	               ? string_value(opt->syslog_tag) : NULL;
    char const *mailto = opt ? string_value(opt->mailto) : NULL;
    size_t size = sizeof(*job) + strlen(command) + 1 +
	            (tag ? strlen(tag) + 1 : 0) +
	            (mailto ? strlen(mailto) + 1 : 0);
    char *p;
    
    job = calloc(1, size);
    if (job) {
	memset(job, 0, sizeof(*job));

	if (opt) {
	    job->maxinstances = opt->maxinstances;
	    job->syslog_facility = opt->syslog_facility;
	}
	
	job->type = type;
	job->fileid = fileid;
	job->schedule = *schedule;
	p = (char*)(job + 1);
	job->command = p;
	strcpy(job->command, command);

	if ((p = find_percent(job->command)) != NULL) {
	    char *q;
	    *p++ = 0;
	    job->input = q = p;
	    /*
	     * Translate unescaped % to \n.
	     * Strip off backslashes.
	     */
	    while (*q) {
		if (*p == '%')
		    *q = '\n';
		else {
		    if (*p == '\\')
			p++;
		    if (q != p)
			*q = *p;
		}
		p++;
		q++;
	    }
	} else {
	    job->input = NULL;
	    p = job->command + strlen(job->command);
	}
	p++; /* skip past the terminating nul */
	
	if (tag) {
	    job->syslog_tag = p;
	    strcpy(job->syslog_tag, tag);
	    p += strlen(tag) + 1;
	}
	if (mailto) {
	    job->mailto = p;
	    strcpy(job->mailto, mailto);
	}
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
    unsigned fileid;
    struct crongroup *crongroup;
    char *filename;
    struct list_head list;
    time_t mtime;
    struct list_head env_head;
};

static struct list_head crontabs = LIST_HEAD_INITIALIZER(crontabs);
static unsigned next_fileid;

static struct crontab *
crontab_find(struct crongroup *cgrp, char const *filename, int alloc)
{
    struct crontab *cp;
    
    LIST_FOREACH(cp, &crontabs, list) {
	if (cp->crongroup == cgrp && strcmp(cp->filename, filename) == 0)
	    return cp;
    }

    if (!alloc)
	return NULL;
    cp = malloc(sizeof(*cp) + strlen(filename) + 1);
    if (!cp)
	nomem_exit();
    cp->fileid = next_fileid++;
    cp->crongroup = cgrp;
    cp->filename = (char*)(cp + 1);
    strcpy(cp->filename, filename);
    cp->mtime = (time_t) -1;
    list_head_init(&cp->env_head);
    micron_environ_alloc(&cp->env_head);
    LIST_HEAD_PUSH(&crontabs, cp, list);
    
    return cp;
}

static void
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

static void
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

#define PRsCRONTAB "%s/%s"
#define ARGCRONTAB(cgr, filename) cgr->dirname, filename

static inline int
isws(int c)
{
    return c == ' ' || c == '\t';
}

static pthread_key_t pwdbuf_key;
static pthread_once_t pwdbuf_key_once = PTHREAD_ONCE_INIT;

struct pwdbuf {
    struct passwd pwd;
    struct group grp;
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
priv_getpwnam(char const *username)
{
    struct passwd *pwd;
    struct pwdbuf *sb = priv_get_pwdbuf();
    while (getpwnam_r(username, &sb->pwd, sb->buf, sb->size, &pwd) == ERANGE) {
	if (!priv_expand_pwdbuf(sb))
	    return NULL;
    }
    return pwd;
}

static struct passwd *
priv_getpwuid(uid_t uid)
{
    struct passwd *pwd;
    struct pwdbuf *sb = priv_get_pwdbuf();
    while (getpwuid_r(uid, &sb->pwd, sb->buf, sb->size, &pwd) == ERANGE) {
	if (!priv_expand_pwdbuf(sb))
	    return NULL;
    }
    return pwd;
}

struct group *
priv_getgrgid(gid_t gid)
{
    struct group *grp;
    struct pwdbuf *sb = priv_get_pwdbuf();
    while (getgrgid_r(gid, &sb->grp, sb->buf, sb->size, &grp) == ERANGE) {
	if (!priv_expand_pwdbuf(sb))
	    return NULL;
    }
    return grp;
}

static int
crontab_stat(struct crongroup *cgrp, char const *filename, struct stat *pst,
	     struct passwd **ppwd)
{
    char const *username;
    struct passwd *pwd;
    struct stat st;
    
    if (fstatat(cgrp->dirfd, filename, &st, AT_SYMLINK_NOFOLLOW)) {
	micron_log(LOG_ERR, "can't stat file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cgrp, filename),
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    if (!S_ISREG(st.st_mode)) {
	micron_log(LOG_ERR, PRsCRONTAB ": not a regular file",
		   ARGCRONTAB(cgrp, filename));
	return CRONTAB_FAILURE;
    }

    switch (cgrp->type) {
    case CGTYPE_USER:
	username = filename;
	break;
	
    case CGTYPE_GROUP:
	if (st.st_gid != cgrp->owner_gid) {
	    micron_log(LOG_ERR, PRsCRONTAB ": wrong owner group",
		       ARGCRONTAB(cgrp, filename));
	    if (!no_safety_checking)
		return CRONTAB_UNSAFE;
	}
	pwd = priv_getpwuid(st.st_uid);
	if (!pwd) {
	    micron_log(LOG_ERR, PRsCRONTAB ": no user with uid %lu",
		       ARGCRONTAB(cgrp, filename),
		       (unsigned long)st.st_uid);
	    return CRONTAB_FAILURE;
	}
	if (pwd->pw_uid != 0 && pwd->pw_gid != cgrp->owner_gid) {
	    struct group *grp;
	    int i;
	    char *user;
	    
	    user = strdup(pwd->pw_name);
	    if (!user) {
		micron_log(LOG_ERR, "out of memory");
		return CRONTAB_FAILURE;
	    }
	    grp = priv_getgrgid(cgrp->owner_gid);
	    if (!grp) {
		micron_log(LOG_ERR,
			   PRsCRONTAB ": can't get group of user %s: %s",
			   ARGCRONTAB(cgrp, filename),
			   cgrp->owner_name,
			   strerror(errno));
		free(user);
		return CRONTAB_FAILURE;
	    }
	    for (i = 0; grp->gr_mem[i]; i++)
		if (strcmp(grp->gr_mem[i], user) == 0)
		    break;
	    if (grp->gr_mem[i] == NULL) {
		micron_log(LOG_ERR,
			   PRsCRONTAB ": file owner %s is not member of "
			   "the crontab owner group %s",
			   ARGCRONTAB(cgrp, filename),
			   user,
			   grp->gr_name);
		if (!no_safety_checking) {
		    free(user);
		    return CRONTAB_UNSAFE;
		}
	    }
	    free(user);
	}
	username = cgrp->owner_name;
	break;

    default:
	username = "root";
    }

    pwd = priv_getpwnam(username);
    if (!pwd) {
	micron_log(LOG_ERR, PRsCRONTAB ": ignored; no such username: %s",
		   ARGCRONTAB(cgrp, filename), username);
	return CRONTAB_FAILURE;
    }

    if (cgrp->type != CGTYPE_GROUP) {
	if (st.st_uid != pwd->pw_uid) {
	    micron_log(LOG_ERR, PRsCRONTAB " not owned by %s; ignored",
		       ARGCRONTAB(cgrp, filename), username);
	    if (!no_safety_checking)
		return CRONTAB_UNSAFE;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH)) {
	    micron_log(LOG_ERR, PRsCRONTAB ": unsafe permissions",
		       ARGCRONTAB(cgrp, filename));
	    if (!no_safety_checking)
		return CRONTAB_UNSAFE;
	}
    }
    if (ppwd)
	*ppwd = pwd;
    if (pst)
	*pst = st;
    return CRONTAB_SUCCESS;
}
    
static int
crontab_check_file(struct crongroup *cgrp, char const *filename,
		   struct crontab **pcp, struct passwd **ppwd)
{
    int rc;
    struct stat st;
    struct crontab *cp;
    
    rc = crontab_stat(cgrp, filename, &st, ppwd);
    if (rc != CRONTAB_SUCCESS)
	return rc;

    rc = CRONTAB_SUCCESS;
    cp = crontab_find(cgrp, filename, 1);
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
    return isalpha(c) || c=='_';
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
    while ((*dst++ = *src++) != 0)
	;
    return 0;
}

static int
cronjob_options_ref(struct cronjob_options **popt)
{
    if (!(*popt)->perjob) {
	struct cronjob_options *opt = calloc(1, sizeof(*opt));
	if (!opt) {
	    micron_log(LOG_ERR, "out of memory");
	    return -1;
	}
	*opt = **popt;
	opt->perjob = 1;
	string_ref(opt->mailto);
	string_ref(opt->syslog_tag);
	opt->prev = *popt;
	*popt = opt;
    }
    return 0;
}

void
cronjob_options_unref(struct cronjob_options **popt)
{
    struct cronjob_options *opt = *popt;
    string_free(opt->mailto);
    string_free(opt->syslog_tag);
    if (opt->perjob) {
	*popt = opt->prev;
	free(opt);
    }
}

static int
set_syslog_facility(char const *val, struct cronjob_options *opt,
			  char **errmsg)
{
    int n;

    if (val) {
	/* Set */
	if (*val == 0 ||
	    strcasecmp(val, "off") == 0 ||
	    strcasecmp(val, "none") == 0)
	    n = 0;
	else if (strcasecmp(val, "default") == 0)
	    n = micron_options.syslog_facility;
	else
	    n = micron_log_str_to_fac(val);
	
	if (n == -1) {
	    *errmsg = "invalid value for builtin variable";
	    return 1;
	}
    } else {
	/* Unset */
	n = 0;
    }
    opt->syslog_facility = n;
    return 0;
}

static int
set_syslog_tag(char const *val, struct cronjob_options *opt, char **errmsg)
{
    string_free(opt->syslog_tag);
    if (val) {
	/* Set */
	string_free(opt->mailto);
	opt->mailto = NULL;
	opt->syslog_tag = string_copy(val);
	if (!opt->syslog_tag) {
	    *errmsg = "out of memory";
	    return 1;
	}
    } else {
	/* Unset */
	opt->syslog_tag = NULL;
    }
    return 0;
}

static int
set_builtin_mailto(char const *val, struct cronjob_options *opt, char **errmsg)
{
    string_free(opt->mailto);
    if (val) {
	/* Set */
	opt->syslog_facility = 0;
	string_free(opt->syslog_tag);
	opt->syslog_tag = NULL;
	opt->mailto = string_copy(val);
	if (!opt->mailto) {
	    *errmsg = "out of memory";
	    return 1;
	}
    } else {
	/* Unset */
	opt->mailto = NULL;
    }
    return 0;
}

/*
 * For backward compatibility, MAILTO takes precedence over the builtin
 * variables.  The built-in value of mailto is unset.  If the value is
 * not NULL, the syslog reporting is disabled as well.  Return value is
 * always 0, so the actual value of MAILTO will be stored in the
 * environment.
 */
static int
set_env_mailto(char const *val, struct cronjob_options *opt, char **errmsg)
{
    string_free(opt->mailto);
    opt->mailto = NULL;
    if (val) {
	opt->syslog_facility = 0;
	string_free(opt->syslog_tag);
	opt->syslog_tag = NULL;
    }
    return 0;
}

static int
set_maxinstances(char const *val, struct cronjob_options *opt, char **errmsg)
{
    char *endp;
    unsigned long n;

    if (val) {
	/* Set */
	errno = 0;
	n = strtoul(val, &endp, 10);
	if (errno || *endp) {
	    *errmsg = "not a valid number";
	    return 1;
	}
    } else {
	/* Unset */
	n = 0;
    }
    opt->maxinstances = (unsigned) n;
    return 0;
}

static int
set_day_semantics(char const *val, struct cronjob_options *opt, char **errmsg)
{
    if (val) {
	/* Set */
	int i;

	for (i = 0; i < MAX_MICRON_DAY; i++) {
	    if (strcasecmp(val, micron_dsem_str[i]) == 0) {
		opt->dsem = i;
		return 0;
	    }
	}
	*errmsg = "unknown day semantics value";
	return 1;
    } else {
	/* Unset */
	opt->dsem = MICRON_DAY_STRICT;
    }
    return 0;
}

static int
set_rovar(char const *val, struct cronjob_options *opt, char **errmsg)
{
    *errmsg = "assignment to a read-only variable";
    return 1;
}

static int
no_unset(char const *val, struct cronjob_options *opt, char **errmsg)
{
    if (!val) {
	*errmsg = "can't unset this variable";
	return 1;
    }
    return 0;
}

static struct vardef {
    char *name;
    int len;
    int builtin;
    int (*setval)(char const *, struct cronjob_options *, char **);
} vardef[] = {
#define S(s) s, sizeof(s)-1
    { S(BUILTIN_SYSLOG_FACILITY), 1, set_syslog_facility },
    { S(BUILTIN_SYSLOG_TAG),      1, set_syslog_tag },
    { S(BUILTIN_MAXINSTANCES),    1, set_maxinstances },
    { S(BUILTIN_DAY_SEMANTICS),   1, set_day_semantics },
    { S(BUILTIN_MAILTO),          1, set_builtin_mailto },
    { S(ENV_LOGNAME),             0, set_rovar },
    { S(ENV_USER),                0, set_rovar },
    { S(ENV_MAILTO),              0, set_env_mailto },
    { S(ENV_PATH),                0, no_unset },
    { S(ENV_SHELL),               0, no_unset },
    { S(ENV_HOME),                0, no_unset },
    { NULL }
};

enum {
    PARSE_ENV_OK,
    PARSE_ENV_BUILTIN,
    PARSE_ENV_FAILURE
};

static int
parse_env(char *def, size_t len, char *value,
	  struct cronjob_options **opt, char **errmsg)
{
    struct vardef *vd;
    int builtin = 0;
    int perjob = 0;
    
    static char micron_prefix[] = "_MICRON_";
    static int micron_prefix_len = sizeof(micron_prefix) - 1;
    static char job_prefix[] = "_JOB_";
    static int job_prefix_len = sizeof(job_prefix) - 1;
    
    if (strncmp(def, micron_prefix, micron_prefix_len) == 0) {
	builtin = 1;
	perjob = 0;
	def += micron_prefix_len;
	len -= micron_prefix_len;
    } else if (strncmp(def, job_prefix, job_prefix_len) == 0) {
	builtin = 1;
	perjob = 1;
	def += job_prefix_len;
	len -= job_prefix_len;
    }
		
    for (vd = vardef; vd->name; vd++) {
	if (vd->builtin == builtin &&
	    vd->len == len &&
	    strncmp(def, vd->name, vd->len) == 0) {
	    if (builtin) {
		if (perjob && cronjob_options_ref(opt)) {
		    *errmsg = "out of memory";
		    return PARSE_ENV_FAILURE;
		}
	    }
	    if (vd->setval(value, *opt, errmsg))
		return PARSE_ENV_FAILURE;
	    if (builtin)
		return PARSE_ENV_BUILTIN;
	}
    }

    if (builtin) {
	*errmsg = "unrecognized built-in variable";
	return PARSE_ENV_FAILURE;
    }
    
    return PARSE_ENV_OK;
}

static struct vardef const *
vardef_locate(char const *str, char **start)
{
    struct vardef *vd;
    for (vd = vardef; vd->name; vd++) {
	if (vd->builtin == 1 &&
	    strncasecmp(str, vd->name, vd->len) == 0 && str[vd->len] == '=') {
	    *start = (char*)str + vd->len + 1;
	    return vd;
	}
    }
    return NULL;
}

static void
set_crontab_options(char *str)
{
    char *p;
    
    for (p = strtok(str, ","); p; p = strtok(NULL, ",")) {
	struct vardef const *vd;
	char *start, *errmsg;

	if ((vd = vardef_locate(p, &start)) == NULL) {
	    micron_log(LOG_ERR, "unknown option: %s", p);
	    exit(EXIT_USAGE);
	}

	if (vd->setval(start, &micron_options, &errmsg)) {
	    micron_log(LOG_ERR, "%s: %s", p, errmsg);
	    exit(EXIT_USAGE);
	}
    }
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
crontab_parse(struct crongroup *cgrp, char const *filename, int ifmod)
{
    int fd;
    struct crontab *cp;
    FILE *fp;
    char buf[MAXCRONTABLINE+1];
    size_t off;
    unsigned line = 0;
    struct cronjob *job;
    struct cronjob_options options, *opt;
    struct passwd *pwd;
    int env_cont = 1;
    struct micron_environ *env;
    size_t filename_len = strlen(filename);
    
    /* Do nothing if this crongroup is disabled */
    if (cgrp->flags & (CGF_DISABLED | CGF_UNSAFE))
	return CRONTAB_SUCCESS;
    /* Do nothing if we're not interested in this file */
    if ((cgrp->type == CGTYPE_SINGLE) &&
	strcmp(cgrp->pattern, filename))
	return CRONTAB_SUCCESS;
    
    switch (crontab_check_file(cgrp, filename, &cp, &pwd)) {
    case CRONTAB_SUCCESS:
	if (ifmod & PARSE_IF_MODIFIED)
	    return CRONTAB_SUCCESS;
	micron_log(LOG_INFO, "reading " PRsCRONTAB,
		   ARGCRONTAB(cgrp, filename));
	crontab_clear(cp, 1);
	break;

    case CRONTAB_NEW:
	micron_log(LOG_INFO, "reading " PRsCRONTAB,
		   ARGCRONTAB(cgrp, filename));
	break;
	
    case CRONTAB_MODIFIED:
	micron_log(LOG_INFO, "re-reading " PRsCRONTAB,
		   ARGCRONTAB(cgrp, filename));
	crontab_clear(cp, 1);
	break;

    case CRONTAB_UNSAFE:
    case CRONTAB_FAILURE:
	if ((cp = crontab_find(cgrp, filename, 0)) != NULL) {
	    crontab_forget(cp);
	    return CRONTAB_MODIFIED;
	}
	return CRONTAB_FAILURE;
    }
	
    fd = openat(cgrp->dirfd, filename, O_RDONLY);
    if (fd == -1) {
	micron_log(LOG_ERR, "can't open file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cgrp, filename),
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    fp = fdopen(fd, "r");
    if (!fp) {
	micron_log(LOG_ERR, "can't fdopen file " PRsCRONTAB ": %s",
		   ARGCRONTAB(cgrp, filename),
		   strerror(errno));
	close(fd);
	return CRONTAB_FAILURE;
    }

    /* Create initial environment */
    micron_environ_alloc(&cp->env_head);

    /* Initialize options */
    options = micron_options;
    opt = &options;
    
    off = 0;
    while (1) {
	size_t len;
	int type;
	struct micronexp schedule;
	char *p;
	char *user = NULL;
	int rc;
	int name_len, val_start;
	char *errmsg;
	
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
		       ARGCRONTAB(cgrp, filename), line);
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
	    char *value;
	    char *var = malloc(len+1);
	    if (!var) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
			   ARGCRONTAB(cgrp, filename), line);
		break;
	    }
	    memcpy(var, p, name_len);
	    var[name_len] = '=';

	    p += val_start;
	    if (*p) {
		value = var + name_len + 1;
		if (*p == '"' || *p == '\'')
		    rc = copy_quoted(value, p + 1, *p);
		else 
		    rc = copy_unquoted(value, p);
	    } else {
		value = NULL;
		rc = 0;
	    }
		
	    if (rc) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: syntax error",
			   ARGCRONTAB(cgrp, filename), line);
		free(var);
		goto next;
	    }

	    rc = parse_env(var, name_len, value, &opt, &errmsg);
	    if (rc == PARSE_ENV_OK) {
		if (value) {
		    env = LIST_FIRST_ENTRY(&cp->env_head, env, link);
		    if (!env_cont) {
			env = micron_environ_alloc(&cp->env_head);
		    }
		    if (micron_environ_set_var(&env, var)) {
			micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
				   ARGCRONTAB(cgrp, filename), line);
			free(var);
			break;
		    }
		} else {
		    rc = micron_environ_unset(&cp->env_head, var);
		    free(var);
		    if (rc) {
			micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
				   ARGCRONTAB(cgrp, filename), line);
			break;
		    }
		}
	    } else if (rc == PARSE_ENV_FAILURE) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: %s",
			   ARGCRONTAB(cgrp, filename), line, errmsg);
		free(var);
	    } else /* PARSE_ENV_BUILTIN */
		free(var);
	    
	    env_cont = 1;
	    continue;
	} else
	    env_cont = 0;

	if (is_reboot(p, &p)) {
	    type = JOB_REBOOT;
	} else {
	    schedule.dsem = opt->dsem;
	    rc = micron_parse(p, &p, &schedule);
	    if (rc) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: %s near %s",
			   ARGCRONTAB(cgrp, filename), line,
			   micron_strerror(rc), p);
		goto next;
	    }
	    type = JOB_NORMAL;
	}

	while (*p && isws(*p))
	    p++;

	if (!*p) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: premature end of line",
		       ARGCRONTAB(cgrp, filename), line);
	    goto next;
	}

	if (cgrp->type != CGTYPE_USER && cgrp->type != CGTYPE_GROUP) {
	    user = p;
	    
	    while (*p && !isws(*p))
		p++;

	    if (!*p) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: premature end of line",
			   ARGCRONTAB(cgrp, filename), line);
		goto next;
	    }

	    *p++ = 0;

	    pwd = priv_getpwnam(user);
	    if (!pwd) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: no such user %s",
			   ARGCRONTAB(cgrp, filename), line, user);
		goto next;
	    }

	    while (*p && isws(*p))
	        p++;
        }

	if (running && type == JOB_REBOOT) {
	    /* Ignore @reboot entries when running */
	    micron_log(LOG_DEBUG, PRsCRONTAB ":%u: ignoring @reboot",
			   ARGCRONTAB(cgrp, filename), line);
	    goto next;
	}
	
	/* Finalize environment */
	env = LIST_FIRST_ENTRY(&cp->env_head, env, link);
	
	if (!micron_environ_get(env, &cp->env_head, ENV_HOME)) 
	    micron_environ_set(&env, ENV_HOME, pwd->pw_dir);
	if (!micron_environ_get(env, &cp->env_head, ENV_SHELL)) 
	    micron_environ_set(&env, ENV_SHELL, "/bin/sh");
    
	if (micron_environ_set(&env, ENV_LOGNAME, pwd->pw_name)
	    || micron_environ_set(&env, ENV_USER, pwd->pw_name)) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cgrp, filename), line);
	    break;
	}

	if (opt->syslog_facility && !opt->syslog_tag) {
	    int cmdlen = strcspn(p, " \t");
	    size_t len = strlen(cp->crongroup->dirname) +
		         cmdlen +
		         filename_len + 80;
	    
	    cronjob_options_ref(&opt);
	    opt->syslog_tag = string_alloc(len);
	    if (!opt->syslog_tag) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: can't allocate syslog tag",
			   ARGCRONTAB(cgrp, filename), line);
		goto next;
	    } else {
		//FIXME
		snprintf(opt->syslog_tag->str, len,
			 "%s/%s:%u(%*.*s)", cp->crongroup->dirname,
			 filename, line, cmdlen, cmdlen, p);
	    }
	}
	
	job = cronjob_alloc(opt, cp->fileid, type, &schedule,
			    pwd, p, env);
	if (!job) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cgrp, filename), line);
	    break;
	}
	
	cronjob_arm(job, ifmod & PARSE_APPLY_NOW);
    next:
	cronjob_options_unref(&opt);
    }
    cronjob_options_unref(&opt);
    fclose(fp);
    return CRONTAB_MODIFIED;
}

void
crongroups_parse_all(int ifmod)
{
    struct crongroup *cgrp, *last;

    micron_log(LOG_DEBUG, "rescanning crontabs");
    /*
     * crongroup_parse below can add user crongroups to the end of the
     * list.  During addition, the group is scanned.  To avoid rescanning
     * it when the cgrp pointer arrives at it, we cut off after this list
     * entry:
     */
    last = LIST_LAST_ENTRY(&crongroup_head, cgrp, list);
    LIST_FOREACH(cgrp, &crongroup_head, list) {
	crongroup_parse(cgrp, ifmod);
	if (cgrp == last)
	    break;
    }
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
    pthread_mutex_lock(&cronjob_mutex);    
    cp = cronjob_alloc(NULL, -1, JOB_INTERNAL, &schedule,
		       NULL, "<internal scanner>", NULL);
    if (!cp) {
	micron_log(LOG_ERR, "out of memory while installing internal scanner");
	/* Try to continue anyway */
    } else
	cronjob_arm(cp, 0);
    pthread_mutex_unlock(&cronjob_mutex);    
}

static int
mkdir_rec(char const *dirname)
{
    struct stat st;
    char *p;
    size_t len, stoplen;
    char *dir;
    int rc = -1;
    
    dir = strdup(dirname);
    if (!dir)
	return -1;
    stoplen = strlen(dirname);
    
    while (fstatat(AT_FDCWD, dir, &st, AT_SYMLINK_NOFOLLOW)) {
	if (errno == ENOENT) {
	    p = strrchr(dir, '/');
	    if (!p)
		abort();
	    *p = 0;
	    continue;
	} else {
	    micron_log(LOG_ERR, "can't stat directory %s: %s",
		       dir,
		       strerror(errno));
	    goto err;
	}
    }

    if (!S_ISDIR(st.st_mode)) {
	micron_log(LOG_ERR, "%s: not a directory", dir);
	goto err;
    }
    
    while ((len = strlen(dir)) != stoplen) {
	dir[len] = '/';
	if (mkdirat(AT_FDCWD, dir, 0755)) {
	    micron_log(LOG_ERR, "can't create directory %s: %s",
		       dir, strerror(errno));
	    goto err;
	}
    }
    
    rc = 0;
err:
    free(dir);
    return rc;
}

static int
crongroup_init(struct crongroup *cgrp)
{
    struct stat st;
    int created = 0;
    struct passwd *pwd;
    struct group *grp;
    
again:
    if (fstatat(AT_FDCWD, cgrp->dirname, &st, AT_SYMLINK_NOFOLLOW)) {
	if (!created && errno == ENOENT) {
	    if (mkdir_rec(cgrp->dirname)) {
		return CRONTAB_FAILURE;
	    }
	    created = 1;
	    goto again;
	} else {
	    micron_log(LOG_ERR, "can't stat file %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}
    }
    
    if (!S_ISDIR(st.st_mode)) {
	micron_log(LOG_ERR, "%s: not a directory", cgrp->dirname);
	return CRONTAB_FAILURE;
    }
    
    pwd = getpwnam(cgrp->owner_name);
    if (!pwd) {
	micron_log(LOG_ERR,
		   "can't change owner of directory %s: %s",
		   cgrp->dirname,
		   "no such user");
    }
    grp = getgrnam(cgrp->owner_group);
    if (!grp) {
	micron_log(LOG_ERR,
		   "can't change owner of directory %s: %s",
		   cgrp->dirname,
		   "no such group");
	    return CRONTAB_FAILURE;
    }

    if (st.st_uid != pwd->pw_uid || st.st_gid != grp->gr_gid) {
	if (fchownat(AT_FDCWD, cgrp->dirname, pwd->pw_uid, grp->gr_gid, 0)) {
	    micron_log(LOG_ERR,
		       "can't change owner of directory %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}
    }

    if ((st.st_mode & cgrp->mode) != cgrp->mode) {
	if (fchmodat(AT_FDCWD, cgrp->dirname, cgrp->mode, 0)) {
	    micron_log(LOG_ERR,
		       "can't change mode of directory %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}
    }
    return CRONTAB_SUCCESS;
}

static int
crongroup_check_default(struct crongroup *cgrp, struct stat *st)
{
    if (st->st_uid != 0) {
	micron_log(LOG_ERR, "%s not owned by root", cgrp->dirname);
	return CRONTAB_UNSAFE;
    }
    if (st->st_mode & S_IWOTH) {
	micron_log(LOG_ERR, "%s: unsafe permissions", cgrp->dirname);
	return CRONTAB_UNSAFE;
    }
    return CRONTAB_SUCCESS;
}

static int
crongroup_check_group(struct crongroup *cgrp, struct stat *st)
{
    char *name;
    struct passwd *pwd;

    name = strrchr(cgrp->dirname, '/');
    if (!name)
	return CRONTAB_FAILURE;
    name++;
    cgrp->owner_name = name;
    
    pwd = priv_getpwnam(name);
    if (!pwd) {
	micron_log(LOG_ERR, "%s: user group directory not named "
		   "after existing user", cgrp->dirname);
	return CRONTAB_FAILURE;
    }
    if (st->st_uid != pwd->pw_uid) {
	micron_log(LOG_ERR, "%s not owned by %s", cgrp->dirname, name);
	return CRONTAB_UNSAFE;
    }
    if (st->st_gid != pwd->pw_gid) {
	micron_log(LOG_ERR, "%s: owner directory not same as the "
		   "primary group of %s", cgrp->dirname, name);
	return CRONTAB_UNSAFE;
    }
    
    if (st->st_mode & S_IWOTH) {
	micron_log(LOG_ERR, "%s: unsafe permissions", cgrp->dirname);
	return CRONTAB_UNSAFE;
    }

    cgrp->owner_gid = st->st_gid;
    
    return CRONTAB_SUCCESS;
}

static int
usercrongroup_add_unlocked(struct crongroup *host, char const *name)
{
    struct crongroup *cgrp;
    int rc;
    char *dirname;

    dirname = catfilename(host->dirname, name);
    if (!dirname) {
	micron_log(LOG_ERR, "out of memory");
	return CRONTAB_FAILURE;
    }
    cgrp = calloc(1, sizeof(*cgrp));
    if (!cgrp) {
	micron_log(LOG_ERR, "out of memory");
	free(dirname);
	return CRONTAB_FAILURE;
    }
    cgrp->dirname = dirname;
    cgrp->id = strrchr(cgrp->dirname, '/') + 1;
    cgrp->type = CGTYPE_GROUP;
    cgrp->dirfd = -1;
    cgrp->pattern = NULL;
    cgrp->exclude = ignored_file_patterns;
    list_head_init(&cgrp->list);
    
    rc = crongroup_parse(cgrp, PARSE_ALWAYS);
    switch (rc) {
    case CRONTAB_SUCCESS:
    case CRONTAB_MODIFIED:
	LIST_HEAD_INSERT_LAST(&crongroup_head, cgrp, list);
	break;

    default:
	free(cgrp);
    }
    return rc;
}

int
usercrongroup_add(struct crongroup *host, char const *name)
{
    int rc;
    pthread_mutex_lock(&cronjob_mutex);
    rc = usercrongroup_add_unlocked(host, name);
    pthread_mutex_unlock(&cronjob_mutex);
    return rc;
}

static struct crongroup *
usercrongroup_find(struct crongroup *host, char const *dirname)
{
    struct crongroup *cgrp;

    LIST_FOREACH(cgrp, &crongroup_head, list)
	if (cgrp->type == CGTYPE_GROUP &&
	    /* FIXME: ?? cgrp->crongroup == host && */
	    strcmp(cgrp->dirname, dirname) == 0)
	    return cgrp;

    return NULL;
}

static void
usercrongroup_delete_unlocked(struct crongroup *cgrp)
{
    LIST_REMOVE(cgrp, list);
    crongroup_forget_crontabs(cgrp);
    close(cgrp->dirfd);
    free(cgrp->dirname);
    free(cgrp);
}

void
usercrongroup_delete(struct crongroup *host, char const *name)
{
    struct crongroup *cgrp;

    pthread_mutex_lock(&cronjob_mutex);
    cgrp = usercrongroup_find(host, name);
    if (cgrp) {
	usercrongroup_delete_unlocked(cgrp);
    }
    pthread_mutex_unlock(&cronjob_mutex);
}

static int (*crongroup_check[])(struct crongroup *, struct stat *) = {
    [CGTYPE_DEFAULT] = crongroup_check_default,
    [CGTYPE_SINGLE] = crongroup_check_default,
    [CGTYPE_USER] = crongroup_check_default,
    [CGTYPE_GROUPHOST] = crongroup_check_default,
    [CGTYPE_GROUP] = crongroup_check_group,
};

int
crongroup_skip_name(struct crongroup *cgrp, char const *name)
{
    return (strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0 ||
	    (cgrp->pattern && 
	     fnmatch(cgrp->pattern, name, FNM_PATHNAME|FNM_PERIOD)) ||
	    patmatch(cgrp->exclude, name));
}

static int
crongroup_parse(struct crongroup *cgrp, int ifmod)
{
    int dirfd;
    int rc;
    struct stat st;
    
    if (cgrp->flags & CGF_DISABLED)
	return CRONTAB_SUCCESS;

    micron_log(LOG_DEBUG, "scanning crongroup %s: %s", cgrp->id, cgrp->dirname);
    
    if (fstatat(AT_FDCWD, cgrp->dirname, &st, AT_SYMLINK_NOFOLLOW)) {
	micron_log(LOG_ERR, "can't stat file %s: %s",
		   cgrp->dirname,
		   strerror(errno));
	return CRONTAB_FAILURE;
    }
    if (!S_ISDIR(st.st_mode)) {
	micron_log(LOG_ERR, "%s: not a directory", cgrp->dirname);
	return CRONTAB_FAILURE;
    }

    rc = crongroup_check[cgrp->type](cgrp, &st);
    switch (rc) {
    case CRONTAB_SUCCESS:
	if (cgrp->flags & CGF_UNSAFE)
	    cgrp->flags &= ~CGF_UNSAFE;
	else if (ifmod & PARSE_CHATTR)
	    return CRONTAB_SUCCESS;
	break;

    case CRONTAB_UNSAFE:
	if (!no_safety_checking) {
	    cgrp->flags |= CGF_UNSAFE;
	    crongroup_forget_crontabs(cgrp);
	    return CRONTAB_FAILURE;
	}
	break;

    default:
	return rc;
    }
	
    if (cgrp->dirfd == -1) {
	dirfd = openat(AT_FDCWD, cgrp->dirname,
		       O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (dirfd == -1) {
	    micron_log(LOG_ERR, "can't open directory %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}

	cgrp->dirfd = dirfd;
    }
    
    if (cgrp->type == CGTYPE_SINGLE) {
	rc = crontab_parse(cgrp, cgrp->pattern, ifmod);
    } else {
	DIR *dir;
	struct dirent *ent;
	
	dirfd = dup(cgrp->dirfd);
	if (dirfd == -1) {
	    micron_log(LOG_ERR, "dup: %s", strerror(errno));
	    return CRONTAB_FAILURE;
	}
	
	dir = fdopendir(dirfd);
	if (!dir) {
	    micron_log(LOG_ERR, "can't open directory %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    close(dirfd);
	    return CRONTAB_FAILURE;
	}
	rewinddir(dir);

	rc = CRONTAB_SUCCESS;
	while ((ent = readdir(dir))) {
	    if (crongroup_skip_name(cgrp, ent->d_name))
		continue;

	    if (cgrp->type == CGTYPE_GROUPHOST) {
		rc = usercrongroup_add_unlocked(cgrp, ent->d_name);
	    } else {
		rc = crontab_parse(cgrp, ent->d_name, ifmod);
	    }
	    if (rc != CRONTAB_SUCCESS)
		rc = CRONTAB_MODIFIED;
	}
	closedir(dir);
    }
    return rc;
}

static void
crongroup_forget_crontabs(struct crongroup *cgrp)
{
    if (cgrp->type == CGTYPE_GROUPHOST) {
	struct crongroup *prev;
	LIST_FOREACH_SAFE(cgrp, prev, &crongroup_head, list) {
	    if (cgrp->type == CGTYPE_GROUP)
		usercrongroup_delete_unlocked(cgrp);
	}
    } else {
	struct crontab *cp, *prev;
    
	LIST_FOREACH_SAFE(cp, prev, &crontabs, list) {
	    if (cp->crongroup == cgrp)
		crontab_forget(cp);
	}
    }
}

void
crontab_deleted(struct crongroup *cgrp, char const *name)
{
    struct crontab *cp;
    pthread_mutex_lock(&cronjob_mutex);
    if ((cp = crontab_find(cgrp, name, 0)) != NULL) {
	crontab_forget(cp);
	pthread_cond_broadcast(&cronjob_cond);
    }
    pthread_mutex_unlock(&cronjob_mutex);
}

void
crontab_updated(struct crongroup *cgrp, char const *name)
{
    struct timespec ts;
    pthread_mutex_lock(&cronjob_mutex);
    clock_gettime(CLOCK_REALTIME, &ts);
    crontab_parse(cgrp, name, PARSE_ALWAYS |
		             (ts.tv_sec == 0 ? PARSE_APPLY_NOW : 0));
    pthread_cond_broadcast(&cronjob_cond);
    pthread_mutex_unlock(&cronjob_mutex);
}

void
crontab_chattr(struct crongroup *cgrp, char const *name)
{
    int rc;
    struct crontab *cp = crontab_find(cgrp, name, 0);

    if (cgrp->flags & (CGF_DISABLED | CGF_UNSAFE))
    micron_log(LOG_DEBUG, "crontab %s/%s changed attributes",
	       cgrp->dirname, name);
    if (no_safety_checking)
	return;

    pthread_mutex_lock(&cronjob_mutex);
    rc = crontab_stat(cgrp, name, NULL, NULL);
    if (rc == CRONTAB_SUCCESS) {
	if (cp == NULL) {
	    crontab_parse(cgrp, name, PARSE_ALWAYS);
	    pthread_cond_broadcast(&cronjob_cond);
	}
    } else if (cp) {
	micron_log(LOG_INFO, "unloading " PRsCRONTAB, ARGCRONTAB(cgrp, name));
	crontab_forget(cp);
	pthread_cond_broadcast(&cronjob_cond);
    }
    pthread_mutex_unlock(&cronjob_mutex);
}

void
crongroup_chattr(struct crongroup *cgrp)
{
    micron_log(LOG_DEBUG, "crongroup %s changed attributes", cgrp->dirname);
    pthread_mutex_lock(&cronjob_mutex);
    if (crongroup_parse(cgrp, PARSE_CHATTR) == CRONTAB_MODIFIED)
	pthread_cond_broadcast(&cronjob_cond);
    pthread_mutex_unlock(&cronjob_mutex);
}

static void
cron_cleanup_main(void *unused)
{
    pthread_mutex_unlock(&cronjob_mutex);    
}

static void *
cron_thr_main(void *ptr)
{
    struct cronjob *job;

    pthread_mutex_lock(&cronjob_mutex);
    pthread_cleanup_push(cron_cleanup_main, NULL);
    
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
	    crongroups_parse_all(PARSE_IF_MODIFIED | PARSE_APPLY_NOW);
	} else {
	    runner_enqueue(job);
	}
	cronjob_arm(job, 0);
    }
    pthread_cleanup_pop(1);
}

static void
stop_thr_main(pthread_t tid)
{
    pthread_mutex_lock(&cronjob_mutex);
    while (!list_head_is_empty(&crontabs)) {
	struct crontab *cp;
	crontab_forget(LIST_FIRST_ENTRY(&crontabs,cp,list));
    }
    pthread_mutex_unlock(&cronjob_mutex);
    default_stop_thread(tid);
}
