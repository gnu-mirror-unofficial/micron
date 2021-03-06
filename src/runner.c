/* GNU micron - a minimal cron implementation
   Copyright (C) 2020-2021 Sergey Poznyakoff

   GNU micron is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   GNU micron is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GNU micron. If not, see <http://www.gnu.org/licenses/>. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include "micrond.h"

static pthread_mutex_t runner_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t runner_cond = PTHREAD_COND_INITIALIZER;
static struct list_head runner_queue = LIST_HEAD_INITIALIZER(runner_queue);

void
runner_enqueue(struct cronjob *job)
{
    pthread_mutex_lock(&runner_mutex);
    cronjob_ref(job);
    LIST_HEAD_ENQUEUE(&runner_queue, job, runq);
    pthread_cond_broadcast(&runner_cond);
    pthread_mutex_unlock(&runner_mutex);
}

static inline struct cronjob *
runner_dequeue(void)
{
    //FIXME: dummy variable to satisfy the macro below
    struct cronjob *job;
    return LIST_HEAD_DEQUEUE(&runner_queue, job, runq);
}

enum {
    PROCTAB_COMM,
    PROCTAB_MAIL
};

struct proctab {
    int type;
    pid_t pid;
    struct timespec start;
    struct cronjob *job;
    char **env;
    int fd;
    struct list_head link;
};

static struct list_head proctab_head = LIST_HEAD_INITIALIZER(proctab_head);
static pthread_mutex_t proctab_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t proctab_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t proctab_rm_cond = PTHREAD_COND_INITIALIZER;

static struct proctab *
proctab_alloc(void)
{
    struct proctab *pt = calloc(1, sizeof(*pt));
    if (!pt)
	return NULL;
    list_head_init(&pt->link);
    LIST_HEAD_ENQUEUE(&proctab_head, pt, link);
    return pt;
}

static struct proctab *
proctab_lookup(pid_t pid)
{
    struct proctab *pt;
    LIST_FOREACH(pt, &proctab_head, link) {
	if (pt->pid == pid)
	    return pt;
    }
    return NULL;
}

static struct proctab *
proctab_lookup_job(struct cronjob *job)
{
    struct proctab *pt;
    LIST_FOREACH(pt, &proctab_head, link) {
	if (pt->job == job)
	    return pt;
    }
    return NULL;
}

static inline void
proctab_remove(struct proctab *pt)
{
    LIST_REMOVE(pt, link);
    cronjob_unref(pt->job);
    env_free(pt->env);
    if (pt->fd != -1)
	close(pt->fd);
    free(pt);
}

static inline void
proctab_remove_safe(struct proctab *pt)
{
    pthread_mutex_lock(&proctab_mutex);
    proctab_remove(pt);
    pthread_cond_broadcast(&proctab_rm_cond);
    pthread_mutex_unlock(&proctab_mutex);
}

static inline struct proctab *
proctab_lookup_safe(pid_t pid)
{
    struct proctab *pt;
    pthread_mutex_lock(&proctab_mutex);
    pt = proctab_lookup(pid);
    pthread_mutex_unlock(&proctab_mutex);
    return pt;
}

static inline struct proctab *
proctab_lookup_job_safe(struct cronjob *job)
{
    struct proctab *pt;
    pthread_mutex_lock(&proctab_mutex);
    pt = proctab_lookup_job(job);
    pthread_mutex_unlock(&proctab_mutex);
    return pt;
}

extern char **environ;

static void
job_setprivs(struct cronjob *job, char **env)
{
    if (setgid(job->gid)) {
	fprintf(stderr, "setgid(%lu): %s\n",
		(unsigned long)job->gid, strerror(errno));
	_exit(127);
    }

    if (initgroups(env_get(ENV_LOGNAME, env), job->gid)) {
	fprintf(stderr, "initgroups(%s,%lu): %s\n",
		env_get(ENV_LOGNAME, env), (unsigned long)job->gid,
		strerror(errno));
	_exit(127);
    }

    if (setuid(job->uid)) {
	fprintf(stderr, "setuid(%lu): %s\n",
		(unsigned long)job->uid, strerror(errno));
	_exit(127);
    }
}

static void logger_enqueue(struct proctab *pt);

struct cronjob_input {
    struct cronjob *job;
    int fd;
};

static void
cronjob_input_free(struct cronjob_input *cin)
{
    cronjob_unref(cin->job);
    close(cin->fd);
    free(cin);
}

/*
 * Special thread for piping the string to the job's standard input.
 * This handles Vixie-style input specification, e.g.:
 *
 *    mail gray%Hello,%%This is a test message.%
 *
 */

void
pipe_input_cleanup(void *ptr)
{
    cronjob_input_free(ptr);
//    micron_log(LOG_DEBUG, "pipe_input_cleanup: finished");
}

void *
pipe_input_thread(void *ptr)
{
    struct cronjob_input *cin = ptr;
    char *p = cin->job->input;
    size_t len = strlen(p);

    pthread_cleanup_push(pipe_input_cleanup, cin);
    while (len > 0) {
	ssize_t n = write(cin->fd, p, len);
	if (n == -1) {
	    micron_log(LOG_ERR, "%s: write error: %s",
		       cin->job->command, strerror(errno));
	    break;
	}
	if (n == 0) {
	    micron_log(LOG_ERR, "%s: pipe full", cin->job->command);
	    break;
	}
	p += n;
	len -= n;
    }
    pthread_cleanup_pop(1);
    return NULL;
}

static void
runner_start(struct cronjob *job)
{
    pid_t pid;
    char **env;
    int fd;
    struct proctab *pt;
    int p[2];
    int in = -1;
    pthread_t input_tid;
    
    micron_log(LOG_DEBUG, "running \"%s\" on behalf of %lu.%lu",
	       job->command, (unsigned long)job->uid,
	       (unsigned long)job->gid);

    env = cronjob_mkenv(job);
    if (!env) {
	micron_log(LOG_ERR, "can't create environment");
	return;
    }

    /* Check the eventual multiple use */
    pt = proctab_lookup_job_safe(job);
    if (pt) {
	if (job->maxinstances <= 1) {
	    micron_log(LOG_ERR,
		       "won't start \"%s\": previous instance "
		       "is still running (PID %lu)",
		       job->command,
		       (unsigned long)pt->pid);
	    env_free(env);
	    cronjob_unref(job);
	    return;
	} else if (job->maxinstances == job->runcnt) {
	    micron_log(LOG_ERR,
		       "won't start \"%s\": %u instances already running",
		       job->command,
		       job->runcnt);
	    env_free(env);
	    cronjob_unref(job);
	    return;
	} else 	    
	    micron_log(LOG_WARNING,
		       "starting \"%s\": %u instances already running",
		       job->command,
		       job->runcnt);
    }
    job->runcnt++;
    
    if (job->output_type == cronjob_output_syslog) {
	if (pipe(p)) {
	    micron_log(LOG_ERR, "pipe: %s", strerror(errno));
	    env_free(env);
	    return;
	}
	fd = p[1];
    } else {
	char *tmpdir, *template;
	tmpdir = getenv("TMP");
	if (!tmpdir)
	    tmpdir = "/tmp";
	template = catfilename(tmpdir, "micronXXXXXX");
	if (!template) {
	    micron_log(LOG_ERR, "catfilename: %s", strerror(errno));
	    env_free(env);
	    return;
	}

	fd = mkstemp(template);
	if (fd == -1) {
	    micron_log(LOG_ERR, "mkstemp: %s", strerror(errno));
	    env_free(env);
	    free(template);
	    return;
	}

	unlink(template);
	free(template);
    }

    if (job->input) {
	int inpipe[2];
	pthread_attr_t attr;
	struct cronjob_input *cin;

	if (pipe(inpipe)) {
	    micron_log(LOG_ERR, "pipe: %s", strerror(errno));
	    goto err;
	}

	if ((cin = malloc(sizeof(*cin))) == NULL) {
	    micron_log(LOG_ERR, "out of memory");
	err:
	    env_free(env);
	    close(inpipe[0]);
	    close(inpipe[1]);
	    close(p[0]);
	    close(p[1]);
	    return;	   
	}
	
	cin->job = job;
	cronjob_ref(job);
	cin->fd = inpipe[1];
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&input_tid, &attr, pipe_input_thread, cin);
	pthread_attr_destroy(&attr);
	in = inpipe[0];
    }
    
    pthread_mutex_lock(&proctab_mutex);

    pid = fork();
    if (pid == -1) {
	micron_log(LOG_ERR, "fork: %s", strerror(errno));
	env_free(env);
	close(fd);
	if (in != -1)
	    pthread_cancel(input_tid);
	pthread_mutex_unlock(&proctab_mutex);
	return;
    }

    if (pid == 0) {
	char const *shell;

	/* Restore default signal handlers */
	restore_default_signals();
	
	/* Set the proper umask */
	umask(saved_umask);

	/* Provide standard input */
	if (in != -1)
	    dup2(in, 0);
	
	/* Redirect stdout and stderr to file */
	dup2(fd, 1);
	dup2(1, 2);

	/* Switch to user privileges */
	job_setprivs(job, env);

	if (chdir(env_get(ENV_HOME, env))) {
	    fprintf(stderr, "can't change to %s: %s",
		    env_get(ENV_HOME, env), strerror(errno));
	    _exit(127);
	}

	/* Close the rest of descriptors */
	close_fds(3);
	
	shell = env_get(ENV_SHELL, env);
	execle(shell, shell, "-c", job->command, NULL, env);
	fprintf(stderr, "execle failed: shell=%s, command=%s\n",
		shell, job->command);
	_exit(127);
    }

    /* Master */
    pt = proctab_alloc();
    pt->type = PROCTAB_COMM;
    pt->pid = pid;
    clock_gettime(CLOCK_REALTIME, &pt->start);
    pt->job = job;
    pt->env = env;
    if (job->output_type == cronjob_output_syslog) {
	close(p[1]);
	fd = p[0];
    }
    pt->fd = fd;
    if (job->output_type == cronjob_output_syslog)
	logger_enqueue(pt);
    pthread_cond_broadcast(&proctab_cond);
    pthread_mutex_unlock(&proctab_mutex);
}

static int
mailer_start(struct proctab *pt, const char *mailto)
{
    pid_t pid;

    micron_log(LOG_DEBUG, "command=\"%s\", mailing output to %s",
	       pt->job->command, mailto);
    pid = fork();
    if (pid == -1) {
	micron_log(LOG_ERR, "fork: %s", strerror(errno));
	return -1;
    }
    if (pid == 0) {
	/* Child */
	int p[2];
	FILE *in, *out;
	int i;
	char hostname[HOST_NAME_MAX+1];
	char const *mailfrom;
	
	gethostname(hostname, sizeof(hostname));
	hostname[HOST_NAME_MAX] = 0;

	if (pipe(p)) {
	    _exit(127);
	}

	pid = fork();

	if (pid == -1) {
	    _exit(127);
	}

	if (pid == 0) {
	    /* Grand-child */
	    job_setprivs(pt->job, pt->env);

	    dup2(p[0], 0);
	    close_fds(1);
	    open("/dev/null", O_WRONLY);
	    dup(1);
	    execlp("/bin/sh", "sh", "-c", mailer_command, NULL);
	    _exit(127);
	}

	/* Child again */
	close(p[0]);
	out = fdopen(p[1], "w");

	signal(SIGALRM, SIG_DFL);
	alarm(10);

	mailfrom = env_get(ENV_LOGNAME, pt->env);
	fprintf(out, "From: \"(Cron daemon)\" <%s@%s>\n",
		mailfrom, hostname);
	fprintf(out, "To: %s\n", mailto);
	fprintf(out, "Subject: Cron <%s@%s> %s\n",
		mailfrom, hostname, pt->job->command);
	for (i = 0; pt->env[i]; i++) {
	    fprintf(out, "X-Cron-Env: %s\n", pt->env[i]);
	}
	fprintf(out, "\n");

	lseek(pt->fd, 0, SEEK_SET);
	in = fdopen(pt->fd, "r");
	while ((i = fgetc(in)) != EOF)
	    fputc(i, out);
	fclose(out);
	
	_exit(0);
    }
    /* Master */
    pt->type = PROCTAB_MAIL;
    pt->pid = pid;
    close(pt->fd);
    pt->fd = -1;
    return 0;
}

static void
cron_cleanup_runner(void *unused)
{
    pthread_mutex_unlock(&runner_mutex);
}

void *
cron_thr_runner(void *ptr)
{
    pthread_mutex_lock(&runner_mutex);
    pthread_cleanup_push(cron_cleanup_runner, NULL);
    while (1) {
	struct cronjob *job;

	pthread_cond_wait(&runner_cond, &runner_mutex);
	while ((job = runner_dequeue()) != NULL)
	    runner_start(job);
    }
    pthread_cleanup_pop(0);
    pthread_mutex_unlock(&runner_mutex);
    return NULL;
}

static inline const char *
get_mailto(struct proctab *pt)
{
    char const *addr;

    if ((addr = pt->job->output.mailto) == NULL &&
	(addr = env_get(ENV_MAILTO, pt->env)) == NULL)
	addr = env_get(ENV_LOGNAME, pt->env);
    return addr;
}

static void cronjob_output_enqueue(struct proctab *pt);

void *
cron_thr_cleaner(void *ptr)
{
    while (1) {
	pid_t pid;
	struct proctab *pt;
	int status;

	pthread_mutex_lock(&proctab_mutex);
	while (list_head_is_empty(&proctab_head))
	    pthread_cond_wait(&proctab_cond, &proctab_mutex);
	pthread_mutex_unlock(&proctab_mutex);

	pid = wait(&status);
	if (pid == (pid_t)-1)
	    continue;

	pt = proctab_lookup_safe(pid);

	if (!pt) {
	    micron_log(LOG_DEBUG, "unregistered child %lu terminated",
		       (unsigned long)pid);
	    continue;
	}

	if (pt->type == PROCTAB_COMM) {
	    pt->job->runcnt--;
	    if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		micron_log(LOG_DEBUG, "exit=%d, command=\"%s\"",
			   code, pt->job->command);
	    } else if (WIFSIGNALED(status)) {
		micron_log(LOG_DEBUG, "signal=%d, command=\"%s\"",
			   WTERMSIG(status), pt->job->command);
	    } else
		micron_log(LOG_DEBUG, "status=%d, command=\"%s\"",
			   status, pt->job->command);

	    /* See whether results should be mailed to anybody */
	    if (pt->job->output_type != cronjob_output_syslog) {
		char const *p;
		off_t off = lseek(pt->fd, 0, SEEK_END);
		if (off == -1) {
		    micron_log(LOG_ERR, "can't seek in temp file: %s",
			       strerror(errno));
		} else if (off > 0) {
		    if (pt->job->output_type == cronjob_output_file) {
			cronjob_output_enqueue(pt);
			continue;
		    } else if (*(p = get_mailto(pt)) != 0 && mailer_start(pt, p) == 0)
			continue;
		}
	    }
	}

	proctab_remove_safe(pt);
    }
    return NULL;
}

void
stop_thr_cleaner(pthread_t tid)
{
    struct proctab *pt;
    struct timespec ts;

    /* Send all jobs the TERM signal */
    pthread_mutex_lock(&proctab_mutex);
    if (!list_head_is_empty(&proctab_head)) {
	micron_log(LOG_DEBUG, "sending all cronjobs the SIGTERM signal");
	LIST_FOREACH(pt, &proctab_head, link) {
	    if (pt->pid > 0)
		kill(pt->pid, SIGTERM);
	}

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += micron_termination_timeout;
    
	while (!list_head_is_empty(&proctab_head))
	    if (pthread_cond_timedwait(&proctab_rm_cond, &proctab_mutex, &ts) != 0)
		break;

	/* Forcibly terminate remaining jobs */
	if (!list_head_is_empty(&proctab_head)) {
	    micron_log(LOG_DEBUG, "sending all cronjobs the SIGKILL signal");

	    LIST_FOREACH(pt, &proctab_head, link) {
		if (pt->pid > 0)
		    kill(pt->pid, SIGKILL);
	    }
	}

	while (!list_head_is_empty(&proctab_head))
	    proctab_remove(LIST_FIRST_ENTRY(&proctab_head, pt, link));
    }
    pthread_mutex_unlock(&proctab_mutex);
    
    default_stop_thread(tid);
}


static pthread_mutex_t logger_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct list_head logger_queue = LIST_HEAD_INITIALIZER(logger_queue);
static int logger_pipe[2] = { -1, -1 };
static pthread_t logger_tid = 0;

struct logbuf {
    int fd;
    struct cronjob *job;
    pid_t pid;
    char *buffer;
    size_t level;
    size_t size;
    int overflow;
    struct list_head link;
};

static void
logbuf_flush(struct logbuf *bp, int flushall)
{
    while (bp->level > 0) {
	char *p;
	size_t len;

	p = memchr(bp->buffer, '\n', bp->level);
	if (p) {
	    *p++ = 0;
	    len = bp->level - (p - bp->buffer);
	} else if (flushall) {
	    bp->buffer[bp->level] = 0;
	    len = 0;
	} else
	    break;

	micron_log_enqueue(bp->job->output.syslog_facility|LOG_INFO,
			   bp->buffer,
			   bp->job->syslog_tag,
			   bp->pid);
	if (len > 0)
	    memmove(bp->buffer, p, len);
	bp->level = len;
    }
}

static void *
cron_thr_logger(void *arg)
{
    int reinit = 1;
    fd_set logger_set;
    int logger_max_fd;

    while (1) {
	struct logbuf *bp, *prev;
	fd_set rds;
	int n;

	if (reinit) {
	    logger_max_fd = logger_pipe[0];
	    FD_ZERO(&logger_set);
	    FD_SET(logger_pipe[0], &logger_set);
	    pthread_mutex_lock(&logger_mutex);
	    LIST_FOREACH(bp, &logger_queue, link) {
		if (bp->fd > logger_max_fd)
		    logger_max_fd = bp->fd;
		FD_SET(bp->fd, &logger_set);
	    }
	    pthread_mutex_unlock(&logger_mutex);
	    reinit = 0;
	}

	rds = logger_set;

	n = select(logger_max_fd + 1, &rds, NULL, NULL, NULL);
	if (n == -1) {
	    micron_log(LOG_ERR, "select: %s", strerror(errno));
	    reinit = 1;
	    continue;
	}

	if (FD_ISSET(logger_pipe[0], &rds)) {
	    n = read(logger_pipe[0], &reinit, 1);
	    if (n < 0) {
		micron_log(LOG_ERR, "read from control pipe: %s",
			   strerror(errno));
		break;
	    }
	}

	pthread_mutex_lock(&logger_mutex);
	LIST_FOREACH_SAFE(bp, prev, &logger_queue, link) {
	    if (FD_ISSET(bp->fd, &rds)) {
		if (bp->level == bp->size) {
		    if (bp->size >= MICRON_LOG_BUF_SIZE) {
			bp->overflow = 1;
			bp->level--;
			logbuf_flush(bp, 1);
		    } else {
			char *p;
			p = memrealloc(bp->buffer, &bp->size, 1);
			if (p == NULL) {
			    bp->overflow = 1;
			    logbuf_flush(bp, 1);
			} else
			    bp->buffer = p;
		    }
		}

		n = read(bp->fd, bp->buffer + bp->level, bp->size - bp->level);

		if (n <= 0) {
		    logbuf_flush(bp, 1);
		    close(bp->fd);
		    LIST_REMOVE(bp, link);
		    cronjob_unref(bp->job);	
		    free(bp->buffer);
		    free(bp);
		    reinit = 1;
		} else {		    
		    bp->level += n;
		    if (bp->overflow) {
			char *p = memchr(bp->buffer, '\n', bp->level);
			if (p) {
			    size_t len;
			    p++;
			    len = bp->level - (p - bp->buffer);
			    if (len)
				memmove(bp->buffer, p, len);
			    bp->level = len;
			    bp->overflow = 0;
			} else {
			    bp->level = 0;
			    continue;
			}
		    }
		    logbuf_flush(bp, 0);
		}
	    }
	}
	pthread_mutex_unlock(&logger_mutex);
    }
    micron_log(LOG_NOTICE, "logger thread terminating");
    logger_tid = 0;
    return NULL;
}

static void
logger_enqueue(struct proctab *pt)
{
    struct logbuf *bp;

    if (logger_pipe[0] == -1 && pipe(logger_pipe)) {
	micron_log(LOG_ERR, "can't create control pipe: %s",
		   strerror(errno));
	/* FIXME: Not the best solution, perhaps */
	exit(EXIT_FATAL);
    }
    if (!logger_tid) {
	pthread_attr_t attr;
	pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&logger_tid, &attr, cron_thr_logger, NULL);
	pthread_attr_destroy(&attr);
    }
    cronjob_ref(pt->job);
    bp = calloc(1, sizeof(*bp));
    if (bp) {
	int c;

	bp->fd = pt->fd;
	bp->job = pt->job;
	bp->pid = pt->pid;
	
	pt->fd = -1;

	pthread_mutex_lock(&logger_mutex);
	LIST_HEAD_ENQUEUE(&logger_queue, bp, link);
	pthread_mutex_unlock(&logger_mutex);

	c = 1;
	if (write(logger_pipe[1], &c, sizeof(c)) < 0) {
	    micron_log(LOG_ERR, "error writing to control pipe: %s",
		       strerror(errno));
	}
    } else
	cronjob_unref(pt->job);	
}

struct outfile
{
    struct list_head link; /* Links to the previous and next file. */
    unsigned refcnt;
    FILE *fp;              /* Pointer to the file. */
    char name[1];          /* File name. */
};

static pthread_mutex_t outfile_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct list_head outfile_head = LIST_HEAD_INITIALIZER(outfile_head);
static pthread_t cronjob_output_tid;
static void *cron_thr_output(void *arg);

FILE *
outfile_open(struct outfile *file)
{
    if (!file->fp) {
	if ((file->fp = fopen(file->name, "a")) == NULL) {
	    micron_log(LOG_ERR, "can't open output file %s: %s",
		       file->name, strerror(errno));
	}
    }
    return file->fp;
}

struct outfile *
outfile_find(char const *name)
{
    struct outfile *ofp, *found = NULL;
    pthread_mutex_lock(&outfile_mutex);
    LIST_FOREACH(ofp, &outfile_head, link) {
	if (strcmp(ofp->name, name) == 0) {
	    found = ofp;
	    break;
	}
    }
    if (!found) {
	if ((found = malloc(sizeof(*found) + strlen(name))) == NULL) {
	    micron_log(LOG_ERR, "out of memory allocating output file %s",
		       name);
	} else {
	    strcpy(found->name, name);
	    found->fp = NULL;
	    found->refcnt = 0;
	    LIST_HEAD_INSERT_LAST(&outfile_head, found, link);
	}
	if (!cronjob_output_tid) {
	    pthread_attr_t attr;
	    pthread_attr_init(&attr);
	    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	    pthread_create(&cronjob_output_tid, &attr, cron_thr_output, NULL);
	    pthread_attr_destroy(&attr);
	}
    }
    if (found)
	found->refcnt++;
    pthread_mutex_unlock(&outfile_mutex);
    return found;
}

void
outfile_release(struct outfile *ofile)
{
    if (ofile) {
	pthread_mutex_lock(&outfile_mutex);
	if (--ofile->refcnt == 0) {
	    LIST_REMOVE(ofile, link);
	    if (ofile->fp)
		fclose(ofile->fp);
	    free(ofile);

	    if (list_head_is_empty(&outfile_head)) {
		pthread_cancel(cronjob_output_tid);
		cronjob_output_tid = 0;
	    }
	}
	pthread_mutex_unlock(&outfile_mutex);
    }
}

static pthread_mutex_t cronjob_output_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct list_head cronjob_output_queue =
    LIST_HEAD_INITIALIZER(cronjob_output_queue);
static pthread_cond_t cronjob_output_cond = PTHREAD_COND_INITIALIZER;

void
outfiles_close(void)
{
    struct outfile *ofp;
    
    pthread_mutex_lock(&cronjob_output_mutex);
    pthread_mutex_lock(&outfile_mutex);
    LIST_FOREACH(ofp, &outfile_head, link) {
	if (ofp->fp) {
	    micron_log(LOG_DEBUG, "closing %s", ofp->name);
	    fclose(ofp->fp);
	    ofp->fp = NULL;
	}
    }	
    pthread_mutex_unlock(&outfile_mutex);
    pthread_mutex_unlock(&cronjob_output_mutex);
}

static void
cronjob_output_enqueue(struct proctab *pt)
{
    micron_log(LOG_DEBUG, "command=\"%s\", appending output to %s",
	       pt->job->command, pt->job->output.file->name);
    
    pthread_mutex_lock(&proctab_mutex);
    LIST_REMOVE(pt, link);
    pthread_mutex_unlock(&proctab_mutex);

    pthread_mutex_lock(&cronjob_output_mutex);
    LIST_HEAD_ENQUEUE(&cronjob_output_queue, pt, link);
    pthread_cond_broadcast(&cronjob_output_cond);
    pthread_mutex_unlock(&cronjob_output_mutex);
}

static inline struct proctab *
cronjob_output_dequeue(void)
{
    //FIXME: dummy variable to satisfy the macro below
    struct proctab *pt;
    return LIST_HEAD_DEQUEUE(&cronjob_output_queue, pt, link);
}

static void
cronjob_output_transfer(struct proctab *pt)
{
    FILE *in, *out;
    int c;
    struct timespec ts;
    struct tm tm;
    char tbuf[sizeof("1970-01-01T00:00:00")];
    
    out = outfile_open(pt->job->output.file);
    if (!out)
	return;

    if ((in = fdopen(pt->fd, "r")) == NULL) {
	micron_log(LOG_ERR, "fdopen failed: %s", strerror(errno));
	return;
    }
    rewind(in);
    pt->fd = -1;
    
    localtime_r(&pt->start.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(out, "%s: %s output begins\n", tbuf, pt->job->syslog_tag);
    while ((c = fgetc(in)) != EOF)
	fputc(c, out);

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(out, "%s: %s output ends\n", tbuf, pt->job->syslog_tag);
    fflush(out);

    if (ferror(in))
	micron_log(LOG_ERR, "%s: error reading captured output",
		   pt->job->syslog_tag);
    if (ferror(out))
	micron_log(LOG_ERR, "%s: error writing captured output to %s",
		   pt->job->syslog_tag, pt->job->output.file->name);
    
    fclose(in);    
}

void
thr_output_cleanup(void *ptr)
{
    pthread_mutex_unlock(&cronjob_output_mutex);
}

static void *
cron_thr_output(void *arg)
{
    pthread_mutex_lock(&cronjob_output_mutex);
    pthread_cleanup_push(thr_output_cleanup, NULL);
    while (1) {
	struct proctab *pt;
	pthread_cond_wait(&cronjob_output_cond, &cronjob_output_mutex);
	while ((pt = cronjob_output_dequeue()) != NULL) {
	    cronjob_output_transfer(pt);
	    proctab_remove_safe(pt);
	}
    }
    pthread_cleanup_pop(1);
    return NULL;
}
    
