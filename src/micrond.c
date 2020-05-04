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
#include "micrond.h"

static char const *backup_file_table[] = {
    ".#*",
    "*~",
    "#*#",
    NULL
};

struct crondef crondefs[] = {
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

int crontab_parse_id(int cid, int ifmod);
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
		crondefs[CRONID_MASTER].flags |= CDF_DISABLED;
	    else
		crondefs[CRONID_MASTER].pattern = optarg;
	    break;

	case 'N':
	    no_safety_checking = 1;
	    break;
	    
	case 'c':
	    if (strcmp(optarg, "none") == 0)
		crondefs[CRONID_USER].flags |= CDF_DISABLED;
	    else
		crondefs[CRONID_USER].dirname = optarg;
	    break;

	case 'f':
	    foreground = 1;
	    break;

	case 's':
	    if (strcmp(optarg, "none") == 0)
		crondefs[CRONID_SYSTEM].flags |= CDF_DISABLED;
	    else
		crondefs[CRONID_SYSTEM].dirname = optarg;
	    break;

	default:
	    exit(1);
	}
    }

    for (i = 0; i < NCRONID; i++) {
	if (crondefs[i].flags & CDF_DISABLED)
	    continue;
	if (!crondefs[i].dirname) {
	    if (crondefs[i].pattern) {
		if (parsefilename(crondefs[i].pattern,
				  &crondefs[i].dirname,
				  &crondefs[i].pattern))
		    nomem_exit();
	    } else
		crondefs[i].flags |= CDF_DISABLED;
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

    for (i = 0; i < NCRONID; i++)
	crontab_parse_id(i, PARSE_ALWAYS);

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

    // Start worker threads
    pthread_create(&tid, NULL, cron_thr_main, NULL);

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
	    free(cp);
	}
    }
}

static struct micron_entry *
cron_entry_alloc(int fileid, struct micronent const *schedule,
		 struct passwd const *pwd,
		 char const *command)
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
    cp->mtime = (time_t) -1;
    strcpy(cp->filename,filename);
    LIST_HEAD_PUSH(&crontabs, cp, list);
    
    return cp;
}

void
crontab_forget(struct crontab *cp)
{
    cron_entries_remove(cp->fileid);
    LIST_REMOVE(cp, list);
    free(cp);
}

#define PRsCRONTAB "%s%s%s"
#define ARGCRONTAB(cid, filename)\
    crondefs[cid].dirname ? crondefs[cid].dirname : "", \
    crondefs[cid].dirname ? "/" : "",		        \
    filename

static inline int
isws(int c)
{
    return c == ' ' || c == '\t';
}

static pthread_key_t strbuf_key;
static pthread_once_t strbuf_key_once = PTHREAD_ONCE_INIT;

struct strbuf {
    struct passwd pwd;
    char *buf;
    size_t size;
};

static void
strbuf_free(void *f)
{
    struct strbuf *sb = f;
    free(sb->buf);
    free(sb);
}

static void
make_strbuf_key(void)
{
    pthread_key_create(&strbuf_key, strbuf_free);
}

static struct strbuf *
priv_expand_strbuf(struct strbuf *sb)
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

static struct strbuf *
priv_get_strbuf(void)
{
    struct strbuf *sb;
    pthread_once(&strbuf_key_once, make_strbuf_key);
    if ((sb = pthread_getspecific(strbuf_key)) == NULL) {
	sb = malloc(sizeof(*sb));
	if (sb == NULL)
	    micron_log(LOG_ERR, "out of memory");
	else if (priv_expand_strbuf(sb) == NULL) {
	    free(sb);
	    sb = NULL;
	}
	pthread_setspecific(strbuf_key, sb);
    }
    return sb;
}

static struct passwd *
priv_get_passwd(char const *username)
{
    struct passwd *pwd;
    struct strbuf *sb = priv_get_strbuf();
    while (getpwnam_r(username, &sb->pwd, sb->buf, sb->size, &pwd) == ERANGE) {
	if (!priv_expand_strbuf(sb))
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
    
    if (fstatat(crondefs[cid].dirfd, filename, &st, AT_SYMLINK_NOFOLLOW)) {
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
	if (fstatat(crondefs[cid].dirfd, filename, &st, 0)) {
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

    /* Do nothing if this crongroup is disabled */
    if (crondefs[cid].flags & CDF_DISABLED)
	return CRONTAB_SUCCESS;
    /* Do nothing if we're not interested in this file */
    if ((crondefs[cid].flags & CDF_SINGLE) &&
	strcmp(crondefs[cid].pattern, filename))
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

    fd = openat(crondefs[cid].dirfd, filename, O_RDONLY);
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

	rc = micron_parse(buf, &p, &schedule);
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
	
	cron_entry = cron_entry_alloc(cp->fileid, &schedule, pwd, p);
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
    cp = cron_entry_alloc(-1, &schedule, NULL, "<internal scanner>");
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
crontab_parse_id(int cid, int ifmod)
{
    struct crondef const *cdef = &crondefs[cid];
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

    if (crondefs[cid].dirfd == -1) {
	dirfd = openat(AT_FDCWD, cdef->dirname,
		       O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (dirfd == -1) {
	    micron_log(LOG_ERR, "can't open directory %s: %s",
		       cdef->dirname,
		       strerror(errno));
	    return CRONTAB_FAILURE;
	}

	crondefs[cid].dirfd = dirfd;
    }
    
    if (cdef->flags & CDF_SINGLE) {
	rc = crontab_parse(cid, crondefs[cid].pattern, ifmod);
    } else {
	DIR *dir;
	struct dirent *ent;
	
	dirfd = dup(crondefs[cid].dirfd);
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
		crontab_parse_id(cid, PARSE_IF_MODIFIED);
	} else {
	    micron_log(LOG_DEBUG, "Running \"%s\" on behalf of %lu.%lu",
		       entry->command, (unsigned long)entry->uid,
		       (unsigned long)entry->gid);
	    micron_log(LOG_DEBUG, "Next entry: %s",
		       ((struct micron_entry *)LIST_FIRST_ENTRY(&cron_entries,entry,list))->command);
	    // enqueue entry
	}
	cron_entry_insert(entry);
    }
}

