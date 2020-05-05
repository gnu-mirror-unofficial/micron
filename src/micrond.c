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
    { NULL, -1, "/etc/crontab", NULL, CDF_SINGLE },
    { "/etc/cron.d", -1, NULL, backup_file_table, CDF_DEFAULT },
    { "/var/spool/cron/crontabs", -1, NULL, backup_file_table, CDF_DEFAULT }
};

/* Mode argument for crontab parsing founctions */
enum {
    PARSE_ALWAYS,      /* Always parse the file(s) */
    PARSE_IF_MODIFIED  /* Parse the file only if mtime changed or if it
			  is a new file */
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

int crongroup_parse(int cid, int ifmod);
void *cron_thr_main(void *);

void
stderr_log(int prio, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    fflush(stderr);
}

void (*micron_log)(int prio, char const *, ...) = syslog;

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
    exit(1);
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
    
    while ((c = getopt(argc, argv, "C:c:fNs:")) != EOF) {
	switch (c) {
	case 'C':
	    if (strcmp(optarg, "none") == 0)
		crongroups[CRONID_MASTER].flags |= CDF_DISABLED;
	    else
		crongroups[CRONID_MASTER].pattern = optarg;
	    break;

	case 'N':
	    no_safety_checking = 1;
	    break;
	    
	case 'c':
	    if (strcmp(optarg, "none") == 0)
		crongroups[CRONID_USER].flags |= CDF_DISABLED;
	    else
		crongroups[CRONID_USER].dirname = optarg;
	    break;

	case 'f':
	    foreground = 1;
	    break;

	case 's':
	    if (strcmp(optarg, "none") == 0)
		crongroups[CRONID_SYSTEM].flags |= CDF_DISABLED;
	    else
		crongroups[CRONID_SYSTEM].dirname = optarg;
	    break;

	default:
	    exit(1);
	}
    }

    for (i = 0; i < NCRONID; i++) {
	if (crongroups[i].flags & CDF_DISABLED)
	    continue;
	if (!crongroups[i].dirname) {
	    if (crongroups[i].pattern) {
		if (parsefilename(crongroups[i].pattern,
				  &crongroups[i].dirname,
				  &crongroups[i].pattern))
		    nomem_exit();
	    } else
		crongroups[i].flags |= CDF_DISABLED;
	}
    }
    
    if (foreground)
	micron_log = stderr_log;
    else {
	openlog(progname, LOG_PID, LOG_CRON);
	if (daemon(0, 0)) {
	    micron_log(LOG_CRIT, "daemon failed: %s", strerror(errno));
	    exit(1);
	}
    }

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

    //...

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

    return 0;
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

char const *
env_get(char *name, char **env)
{
    size_t i;
    size_t len = strlen(name);
    
    for (i = 0; env[i]; i++) {
	if (strlen(env[i]) > len
	    && memcmp(env[i], name, len) == 0
	    &&  env[i][len] == '=')
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
    env_free(ebuf->varv);
    free(ebuf);
}    

/*
 * Find a variable NAME in environment EBUF (non-recursive).
 * On success, store the pointer to its definition in *ret and return 0.
 * Otherwise, return -1.
 */
static int
micron_environ_find(struct micron_environ *ebuf, char const *name, char ***ret)
{
    size_t len = strcspn(name, "=");
    size_t i;

    for (i = 0; i < ebuf->varc; i++) {
	if (strlen(ebuf->varv[i]) > len
	    && memcmp(ebuf->varv[i], name, len) == 0
	    && ebuf->varv[i][len] == '=') {
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

/* Finish the environment by appending a NULL entry to it */
static int
micron_environ_finish(struct micron_environ *ebuf)
{
    return micron_environ_append_var(ebuf, NULL);
}

/*
 * Copy plain environment ENV to incremental environment EBUF.
 * Return 0 on success, -1 on failure (not enough memory).
 */
static int
micron_environ_copy(struct micron_environ *ebuf, char **env)
{
    size_t i;

    for (i = 0; env[i]; i++) {
	char **vptr;
	char *s;

	if ((s = strdup(env[i])) == NULL)
	    return -1;
	if (micron_environ_find(ebuf, env[i], &vptr)) {
	    if (micron_environ_append_var(ebuf, s)) {
		free(s);
		return -1;
	    }
	} else {
	    free(*vptr);
	    *vptr = s;
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
micron_environ_get(struct micron_environ *ebuf, struct list_head *head,
		   char const *name)
{
    struct micron_environ *envp;
    
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
micron_environ_set(struct micron_environ *ebuf, char const *name,
		   const char *value)
{
    size_t len = strlen(name) + strlen(value) + 1;
    char *var = malloc(len + 1);
    if (!var)
	return -1;
    strcpy(var, name);
    strcat(var, "=");
    strcat(var, value);
    if (micron_environ_append_var(ebuf, var)) {
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

    if (micron_environ_copy(&ebuf, environ))
	goto err;

    LIST_FOREACH_FROM(p, micron_env, head, link) {
	if (micron_environ_copy(&ebuf, p->varv))
	    goto err;
    }

    if (micron_environ_append_var(&ebuf, NULL))
	goto err;
    
    return ebuf.varv;

err:
    env_free(ebuf.varv);
    return NULL;
}

static struct list_head cron_entries = LIST_HEAD_INITIALIZER(cron_entries);
static pthread_mutex_t cron_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cron_cond = PTHREAD_COND_INITIALIZER;

static void
cron_entries_remove(int fileid)
{
    struct micron_entry *cp, *prev;
    LIST_FOREACH_SAFE(cp, prev, &cron_entries, list) {
	if (cp->fileid == fileid) {
	    LIST_REMOVE(cp, list);
	    micron_entry_unref(cp);
	}
    }
}

static struct micron_entry *
cron_entry_alloc(int fileid, struct micronent const *schedule,
		 struct passwd const *pwd,
		 char const *command, struct micron_environ *env)
{
    struct micron_entry *cp;
    size_t size = sizeof(*cp) + strlen(command) + 1;
    
    cp = malloc(size);
    if (cp) {
	memset(cp, 0, size);
	cp->fileid = fileid;
	cp->schedule = *schedule;
	cp->command = (char*)(cp + 1);
	strcpy(cp->command, command);
	if (pwd) {
	    cp->uid = pwd->pw_uid;
	    cp->gid = pwd->pw_gid;
	} else {
	    cp->uid = 0;
	    cp->gid = 0;
	}
	list_head_init(&cp->list);
	list_head_init(&cp->runq);
	cp->env = env;
	micron_entry_ref(cp);
    }
    return cp;
}

void
cron_entry_insert(struct micron_entry *ent)
{
    struct micron_entry *p;
    
    LIST_REMOVE(ent, list);
    micron_next_time(&ent->schedule, &ent->next_time);

    LIST_FOREACH(p, &cron_entries, list) {
	if (timespec_cmp(&ent->next_time, &p->next_time) <= 0)
	    break;
    }
    LIST_INSERT_BEFORE(p, ent, list);
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
    micron_environ_alloc(&cp->env_head);
    LIST_HEAD_PUSH(&crontabs, cp, list);
    
    return cp;
}

void
crontab_forget(struct crontab *cp)
{
    struct micron_environ *env;
    cron_entries_remove(cp->fileid);
    LIST_REMOVE(cp, list);
    while ((env = LIST_HEAD_POP(&cp->env_head,env,link)) != NULL) {
	micron_environ_free(env);
    }
    free(cp);
}

char **
micron_entry_env(struct micron_entry *ent)
{
    struct crontab *cp;
    LIST_FOREACH(cp, &crontabs, list) {
	if (cp->fileid == ent->fileid)
	    return micron_environ_build(ent->env, &cp->env_head);
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
	sb = malloc(sizeof(*sb));
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
    if (!(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
	return CRONTAB_FAILURE;
    if (cid == CRONID_USER) {
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
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
	micron_log(LOG_ERR, PRsCRONTAB ": unsafe permissions",
		   ARGCRONTAB(cid, filename));
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }
    if (S_ISLNK(st.st_mode)) {
	if (fstatat(crongroups[cid].dirfd, filename, &st, 0)) {
	    micron_log(LOG_ERR, "can't stat file " PRsCRONTAB ": %s",
		       ARGCRONTAB(cid, filename),
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}
	if (!(st.st_mode & S_IFREG))
	    return CRONTAB_FAILURE;
	if (st.st_uid != pwd->pw_uid) {
	    micron_log(LOG_ERR, PRsCRONTAB
		       " points to file not owned by %s; ignored",
		       ARGCRONTAB(cid, filename), username);
	    if (!no_safety_checking)
		return CRONTAB_FAILURE;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
	    micron_log(LOG_ERR, PRsCRONTAB
		       "points to file with unsafe permissions",
		       ARGCRONTAB(cid, filename));
	    if (!no_safety_checking)
		return CRONTAB_FAILURE;
	}
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
    vs = ne + 1;
    while (s[vs] && isws(s[vs]))
	vs++;
    if (s[vs] != '=')
	return 0;
    vs++;
    while (s[vs] && isws(s[vs]))
	vs++;
    if (!s[vs])
	return 0;
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
crontab_parse(int cid, char const *filename, int ifmod)
{
    int fd;
    struct crontab *cp;
    FILE *fp;
    char buf[MAXCRONTABLINE+1];
    size_t off;
    unsigned line = 0;
    struct micron_entry *cron_entry;
    struct passwd *pwd;
    int env_cont = 1;
    struct micron_environ *env;
    
    /* Do nothing if this crongroup is disabled */
    if (crongroups[cid].flags & CDF_DISABLED)
	return CRONTAB_SUCCESS;
    /* Do nothing if we're not interested in this file */
    if ((crongroups[cid].flags & CDF_SINGLE) &&
	strcmp(crongroups[cid].pattern, filename))
	return CRONTAB_SUCCESS;
    
    switch (crontab_check_file(cid, filename, &cp, &pwd)) {
    case CRONTAB_SUCCESS:
	if (ifmod == PARSE_IF_MODIFIED)
	    return CRONTAB_SUCCESS;
	break;

    case CRONTAB_NEW:
	break;
	
    case CRONTAB_MODIFIED:
	micron_log(LOG_INFO, "re-reading " PRsCRONTAB,
		   ARGCRONTAB(cid, filename));
	break;
	
    case CRONTAB_FAILURE:
	if ((cp = crontab_find(cid, filename, 0)) != NULL) {
	    crontab_forget(cp);
	    return CRONTAB_MODIFIED;
	}
	return CRONTAB_FAILURE;
    }
	
    cron_entries_remove(cp->fileid);

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

    off = 0;
    while (1) {
	size_t len;
	struct micronent schedule;
	char *p;
	char *user = NULL;
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

	    env = LIST_FIRST_ENTRY(&cp->env_head, env, link);
	    if (!env_cont) {
		micron_environ_finish(env);
		env = micron_environ_alloc(&cp->env_head);
	    }
	    if (micron_environ_append_var(env, var)) {
		micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
			   ARGCRONTAB(cid, filename), line);
		free(var);
		break;
	    }
	    env_cont = 1;
	    continue;
	} else
	    env_cont = 0;
	
	rc = micron_parse(p, &p, &schedule);
	if (rc) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: %s near %s",
		       ARGCRONTAB(cid, filename), line,
		       micron_strerror(rc), p);
	    continue;
	}

	while (*p && isws(*p))
	    p++;

	if (!*p) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: premature end of line",
		       ARGCRONTAB(cid, filename), line);
	    continue;
	}

	if (cid != CRONID_USER) {
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
	}

	/* Finalize environment */
	env = LIST_FIRST_ENTRY(&cp->env_head, env, link);

	if (!micron_environ_get(env, &cp->env_head, "HOME")) 
	    micron_environ_set(env, "HOME", pwd->pw_dir);
    
	if (micron_environ_set(env, "LOGNAME", pwd->pw_name)) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}
	if (micron_environ_set(env, "USER", pwd->pw_name)) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}
	    
	micron_environ_finish(env);
	
	cron_entry = cron_entry_alloc(cp->fileid, &schedule, pwd, p, env);
	if (!cron_entry) {
	    micron_log(LOG_ERR, PRsCRONTAB ":%u: out of memory",
		       ARGCRONTAB(cid, filename), line);
	    break;
	}
	cron_entry_insert(cron_entry);
    }
    fclose(fp);
    return CRONTAB_MODIFIED;
}

void
crontab_scanner_schedule(void)
{
    struct micronent schedule;
    struct micron_entry *cp;
    LIST_FOREACH(cp, &cron_entries, list) {
	if (cp->internal)
	    return;
    }
    micron_parse("* * * * *", NULL, &schedule);
    cp = cron_entry_alloc(-1, &schedule, NULL, "<internal scanner>", NULL);
    if (!cp) {
	micron_log(LOG_ERR, "out of memory while installing internal scanner");
	/* Try to continue anyway */
	return;
    }
    cp->internal = 1;
    cron_entry_insert(cp);
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
    
    if (cdef->flags & CDF_DISABLED)
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
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
	micron_log(LOG_ERR, "%s: unsafe permissions",
		   cdef->dirname);
	if (!no_safety_checking)
	    return CRONTAB_FAILURE;
    }
    if (S_ISLNK(st.st_mode)) {
	if (fstatat(AT_FDCWD, cdef->dirname, &st, 0)) {
	    micron_log(LOG_ERR, "can't stat file %s: %s",
		       cdef->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}
	if (st.st_uid != 0) {
	    micron_log(LOG_ERR,
		       "%s points to file not owned by root; ignored",
		       cdef->dirname);
	    if (!no_safety_checking)
		return CRONTAB_FAILURE;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
	    micron_log(LOG_ERR, 
		       "%s: points to file with unsafe permissions",
		       cdef->dirname);
	    if (!no_safety_checking)
		return CRONTAB_FAILURE;
	}
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
    
    if (cdef->flags & CDF_SINGLE) {
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
    pthread_mutex_lock(&cron_mutex);
    cron_entries_remove(cp->fileid);
    pthread_cond_broadcast(&cron_cond);
    pthread_mutex_unlock(&cron_mutex);
}

void
crontab_updated(int cid, char const *name)
{
    pthread_mutex_lock(&cron_mutex);
    crontab_parse(cid, name, PARSE_ALWAYS);
    pthread_cond_broadcast(&cron_cond);
    pthread_mutex_unlock(&cron_mutex);
}

void *
cron_thr_main(void *ptr)
{
    micron_log(LOG_DEBUG, "main thread started");
    pthread_mutex_lock(&cron_mutex);
    while (1) {
	struct micron_entry *entry;
	int rc;
	
	if (list_head_is_empty(&cron_entries)) {
	    pthread_cond_wait(&cron_cond, &cron_mutex);
	    continue;
	}
	
	entry = LIST_FIRST_ENTRY(&cron_entries, entry, list);
	rc = pthread_cond_timedwait(&cron_cond, &cron_mutex, &entry->next_time);
	if (rc == 0)
	    continue;
	if (rc != ETIMEDOUT) {
	    micron_log(LOG_CRIT,
		       "unexpected error from pthread_cond_timedwait: %s",
		       strerror(errno));
	    exit(1);
	}

	if (entry != LIST_FIRST_ENTRY(&cron_entries, entry, list)) {
	    /* Just in case... */
	    continue;
	}
	
	LIST_REMOVE(entry, list);

	if (entry->internal) {
	    int cid;

	    micron_log(LOG_DEBUG, "rescanning crontabs");
	    for (cid = 0; cid < NCRONID; cid++)
		crongroup_parse(cid, PARSE_IF_MODIFIED);
	} else {
	    micron_log(LOG_DEBUG, "Running \"%s\" on behalf of %lu.%lu",
		       entry->command, (unsigned long)entry->uid,
		       (unsigned long)entry->gid);
	    // enqueue entry
	    runner_enqueue(entry);
	}
	cron_entry_insert(entry);
    }
}

