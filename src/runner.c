#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#include <pthread.h>
#include <fcntl.h>
#include "micrond.h"

static pthread_mutex_t runner_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t runner_cond = PTHREAD_COND_INITIALIZER;
static struct list_head runner_queue = LIST_HEAD_INITIALIZER(runner_queue);

void
runner_enqueue(struct micron_entry *entry)
{
    pthread_mutex_lock(&runner_mutex);
    LIST_HEAD_ENQUEUE(&runner_queue, entry, runq);
    pthread_cond_broadcast(&runner_cond);
    pthread_mutex_unlock(&runner_mutex);
}

static inline struct micron_entry *
runner_dequeue(void)
{
    //FIXME: dummy variable to satisfy the macro below
    struct micron_entry *entry;
    return LIST_HEAD_DEQUEUE(&runner_queue, entry, runq);
}

enum {
    PROCTAB_COMM,
    PROCTAB_MAIL
};

struct proctab {
    int type;
    pid_t pid;
    struct micron_entry *ent;
    char **env;
    FILE *file;
    struct list_head link;
};

static struct list_head proctab_head = LIST_HEAD_INITIALIZER(proctab_head);
static pthread_mutex_t proctab_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct proctab *
proctab_alloc(void)
{
    struct proctab *pt = malloc(sizeof(*pt));
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

extern char **environ;

static void
runner_start(struct micron_entry *ent)
{
    pid_t pid;
    char **env;
    FILE *fp;
    struct proctab *pt;
    
    env = micron_entry_env(ent);
    if (!env) {
	micron_log(LOG_ERR, "can't create environment");
	return;
    }

    fp = tmpfile();
    if (!fp) {
	micron_log(LOG_ERR, "tmpfile: %s", strerror(errno));
	env_free(env);
	return;
    }
    
    pthread_mutex_lock(&proctab_mutex);
    
    pid = fork();
    if (pid == -1) {
	micron_log(LOG_ERR, "fork: %s", strerror(errno));
	env_free(env);
	fclose(fp);
	pthread_mutex_unlock(&proctab_mutex);
	return;
    }
    
    if (pid == 0) {
	int i;
	int fd = fileno(fp);
	char const *shell;
	
	/* Redirect stdout and stderr to file */
	dup2(fd, 1);
	dup2(1, 2);

	/* Override the environment */
	environ = env;

	/* Switch to user privileges */
	if (setgid(ent->gid)) {
	    micron_log(LOG_ERR, "setgid(%lu): %s", ent->gid, strerror(errno));
	    _exit(127);
	}

	if (initgroups(env_get("LOGNAME", env), ent->gid)) {
	    micron_log(LOG_ERR, "initgroups(%s,%lu): %s",
		       env_get("LOGNAME", env), ent->gid,
		       strerror(errno));
	    _exit(127);
	}

	if (setuid(ent->uid)) {
	    micron_log(LOG_ERR, "setuid(%lu): %s", ent->uid, strerror(errno));
	    _exit(127);
	}

	if (chdir(env_get("HOME", env))) {
	    micron_log(LOG_ERR, "can't change to %s: %s",
		       env_get("HOME", env), strerror(errno));
	    _exit(127);
	}
	    
	/* Close the rest of descriptors */
	for (i = sysconf(_SC_OPEN_MAX); i > 2; i--) {
	    close(i);
	}

	shell = env_get("SHELL", env);
	execle(shell, shell, "-c", ent->command, NULL, env);
	fprintf(stderr, "execle failed: shell=%s, command=%s\n",
		shell, ent->command);
	_exit(127);
    }

    /* Master */
    pt = proctab_alloc();
    pt->type = PROCTAB_COMM;
    pt->pid = pid;
    pt->ent = ent;
    pt->env = env;
    pt->file = fp;
    micron_entry_ref(pt->ent);
    pthread_mutex_unlock(&proctab_mutex);
}

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN 64
#endif

static int
mailer_start(struct proctab *pt, const char *mailto)
{
    pid_t pid;
    
    micron_log(LOG_DEBUG, "command=\"%s\", mailing results to %s",
	       pt->ent->command, mailto);
    pid = fork();
    if (pid == -1) {
	micron_log(LOG_ERR, "fork: %s", strerror(errno));
	return -1;
    }
    if (pid == 0) {
	/* Child */
	int p[2];
	FILE *out;
	int i;
	char hostname[MAXHOSTNAMELEN];
	char const *mailfrom;
	
	gethostname(hostname, MAXHOSTNAMELEN);
	
	if (pipe(p)) {
	    micron_log(LOG_ERR, "pipe: %s", strerror(errno));
	    _exit(127);
	}

	pid = fork();

	if (pid == -1) {
	    micron_log(LOG_ERR, "child fork: %s", strerror(errno));
	    _exit(127);
	}

	if (pid == 0) {
	    /* Grand-child */
	    dup2(p[0], 0);
	    for (i = sysconf(_SC_OPEN_MAX); i > 0; i--) {
		close(i);
	    }
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
	
	mailfrom = env_get("LOGNAME", pt->env);
	fprintf(out, "From: \"(Cron daemon)\" <%s@%s>\n",
		mailfrom, hostname);
	fprintf(out, "To: %s\n", mailto);
	fprintf(out, "Subject: Cron <%s@%s> %s\n",
		mailfrom, hostname, pt->ent->command);
	for (i = 0; pt->env[i]; i++) {
	    fprintf(out, "X-Cron-Env: %s\n", pt->env[i]);
	}
	fprintf(out, "\n");

	fseek(pt->file, 0, SEEK_SET);
	while ((i = fgetc(pt->file)) != EOF)
	    fputc(i, out);
	fclose(out);
	_exit(0);
    }
    /* Master */
    pt->type = PROCTAB_MAIL;
    pt->pid = pid;
    return 0;
}

void *
cron_thr_runner(void *ptr)
{
    pthread_mutex_lock(&runner_mutex);
    while (1) {
	struct micron_entry *ent;
	
	pthread_cond_wait(&runner_cond, &runner_mutex);
	ent = runner_dequeue();
	if (ent)
	    runner_start(ent);
    }
    return NULL;
}

void *
cron_thr_cleaner(void *ptr)
{
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGCHLD);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    while (1) {
	pid_t pid;
	struct proctab *pt;
	int status;
	
	pid = waitpid((pid_t)-1, &status, 0);
	if (pid == (pid_t)-1)
	    continue;

	pthread_mutex_lock(&proctab_mutex);
	pt = proctab_lookup(pid);
	pthread_mutex_unlock(&proctab_mutex);

	if (!pt) {
	    micron_log(LOG_DEBUG, "unregistered child terminated");
	    continue;
	}

	if (pt->type == PROCTAB_COMM) {
	    char const *p;
	    
	    if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		micron_log(LOG_DEBUG, "exit=%d, command=\"%s\"",
			   code, pt->ent->command);
	    } else if (WIFSIGNALED(status)) {
		micron_log(LOG_DEBUG, "signal=%d, command=\"%s\"",
			   WTERMSIG(status), pt->ent->command);
	    } else
		micron_log(LOG_DEBUG, "status=%d, command=\"%s\"",
			   status, pt->ent->command);

	    /* See whether the results should be mailed to anybody */
	    p = env_get("MAILTO", pt->env);
	    if (!p)
		p = env_get("LOGNAME", pt->env);
	    if (*p != 0) {
		/* See if we have any output at all */
		off_t off = lseek(fileno(pt->file), 0, SEEK_END);
		if (off == -1) {
		    micron_log(LOG_ERR, "can't seek in temp file: %s",
			       strerror(errno));
		} else if (off > 0 && mailer_start(pt, p))
		    continue;
	    }
	}
	
	pthread_mutex_lock(&proctab_mutex);
	LIST_REMOVE(pt, link);
	pthread_mutex_unlock(&proctab_mutex);
	
	micron_entry_unref(pt->ent);
	env_free(pt->env);
	fclose(pt->file);
	free(pt);
    }
    return NULL;
}
