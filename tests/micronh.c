/*
  NAME
    micronh - test harness for micrond

  SYNOPSIS
    micronh [-e NAME=VALUE] [-o FILE] [-s SOCKET] [-t SECONDS] [-hv] [-- ARGS]

  DESCRIPTION
    Micronh starts the micrond daemon in foreground with appropriately
    constructed command line and waits the given number of SECONDS
    for it to terminate (SECONDS can be a floating-point number).  When
    micrond finishes, the harness analyzes its exit status and prints
    diagnostics.

    The default command line for micrond consists of "-f" option followed by
    ARGS.  If the -s option is given, the "-p SOCKET" option is inserted after
    "-f".  In this case the harness starts a syslog server thread listening
    on the given SOCKET.  The server thread decodes each arrived message and
    prints it on the standard output (or FILE, if the -o option is given).

  OPTIONS
    -e NAME=VALUE
        Set the environment variable NAME to VALUE.  The constructed
	environment replaces the environment inherited from the parent process.
	Two variables are always appended to this environment: MICROND_PID,
	which contains the PID of the started micrond process, and PATH as
	inherited from the parent.  The latter is appended only if the
	constructed environment does not contain the PATH variable.

	No more than 16 environment variables can be set.

    -h  Display short usage summary and exit.
    
    -o FILE
        When used together with -s, output each decoded syslog message to
	FILE.
	
    -s SOCKET
        Start the syslog server listening on SOCKET.  If SOCKET starts with
	a /, a UNIX socket is assumed.  Otherwise, an INET datagram socket
	is opened.

    -t SECONDS
        Wait the given number of seconds for micrond to terminate.  If it
	doesn't exit within that interval, send it the TERM signal.  If it
	fails to exit within 5 seconds after the TERM signal is delivered,
	send it the KILL signal.

	SECONDS can be a floating-point number.  It defaults to 10.
    
    -v  Increase output verbosity
    
  LICENSE
    Copyright (C) 2020-2021 Sergey Poznyakoff

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program. If not, see <http://www.gnu.org/licenses/>.    
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

char *progname;

static void
usage(void)
{
    printf("usage: %s [OPTIONS] -- [ARGS]\n", progname);
    printf("runs micrond command with a timeout.\n");
    printf("\nOPTIONS are:\n\n");
    printf("   -e NAME=VALUE  set environment variable\n");
    printf("   -o FILE        (used with -s) output each decoded syslog message to FILE\n");
    printf("   -s SOCKET      start the syslog server listening on SOCKET\n");
    printf("   -t N           set execution timeout to N seconds (default is 10)\n");
    printf("   -v             increase verbosity\n");
    printf("   -h             display this help message\n");
    printf("\n");
    printf("ARGS are passed to micrond verbatim (the -f option is passed by default).\n");
}

struct syslog_bridge {
    int in;
    FILE *out;
};

static void
cleanup_syslog(void *ptr)
{
    struct syslog_bridge *b = ptr;
    close(b->in);
    fclose(b->out);
    free(b);
}

struct syslog_keyword {
    char *kw;
    int tok;
};

static struct syslog_keyword syslog_fac_kw[] = {
    { "auth",   LOG_AUTH },
#ifdef LOG_AUTHPRIV
    { "authpriv", LOG_AUTHPRIV },
#endif
    { "cron",   LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "ftp",    LOG_FTP },
    { "kern",   LOG_KERN },
    { "lpr",    LOG_LPR },
    { "mail",   LOG_MAIL },
    { "news",   LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user",   LOG_USER },
    { "uucp",   LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

static struct syslog_keyword syslog_pri_kw[] = {
    { "alert",  LOG_ALERT },
    { "crit",   LOG_CRIT },
    { "debug",  LOG_DEBUG },
    { "emerg",  LOG_EMERG },
    { "err",    LOG_ERR },
    { "info",   LOG_INFO },
    { "notice", LOG_NOTICE },
    { "warning", LOG_WARNING },
    { NULL, -1 }
};    

static char *
syslog_keyword_decode(struct syslog_keyword *kwtab, unsigned long n)
{
    while (kwtab->kw && kwtab->tok != n)
	++kwtab;
    return kwtab->kw;
}

#ifndef LOG_PRIMASK
# define LOG_PRIMASK     0x07
#endif

static void *
thr_syslog(void *ptr)
{
    struct syslog_bridge *b = ptr;
    char buf[1024], *p;
    ssize_t n;
    
    pthread_cleanup_push(cleanup_syslog, ptr);
    while ((n = read(b->in, buf, sizeof(buf)-1)) > 0) {
	buf[n] = 0;
	p = buf;
	if (buf[0] == '<') {
	    char *end, *s;
	    unsigned long pri, fac;

	    errno = 0;
	    pri = strtoul(buf + 1, &end, 10);
	    if (errno || *end != '>') {
		fprintf(b->out, "malformed message: ");
	    } else {
		p = end;
		n -= end - buf;

		fac = pri & ~LOG_PRIMASK;
		pri &= LOG_PRIMASK;

		fputc('<', b->out);
		
		s = syslog_keyword_decode(syslog_fac_kw, fac);
		if (!s) {
		    fprintf(b->out, "%lx", fac);
		} else {
		    fprintf(b->out, "%s", s);
		}

		fputc('|', b->out);
		
		s = syslog_keyword_decode(syslog_pri_kw, pri);
		if (!s) {
		    fprintf(b->out, "%lx", pri);
		} else {
		    fprintf(b->out, "%s", s);
		}
	    }
	} else {
	    fprintf(b->out, "malformed message: ");
	}
	    
	fwrite(p, n, 1, b->out);
	fputc('\n', b->out);
    }
    pthread_cleanup_pop(1);
    return NULL;
}

static pthread_t
start_syslog(char const *dev, char const *outfile)
{
    pthread_t tid;
    pthread_attr_t attr;
    union {
	struct sockaddr_in s_in;
	struct sockaddr_un s_un;
    } log_sa;
    int log_family;
    socklen_t log_salen;
    int fd;
    struct syslog_bridge *b;

    if (dev[0] == '/') {
	size_t len = strlen(dev);
	if (len >= sizeof log_sa.s_un.sun_path) {
	    fprintf(stderr, "%s: %s: UNIX socket name too long\n", progname,
		    dev);
	    exit(1);
	}
	strcpy(log_sa.s_un.sun_path, dev);
	log_sa.s_un.sun_family = AF_UNIX;
	log_family = PF_UNIX;
	log_salen = sizeof(log_sa.s_un);
	if (access(dev, F_OK) == 0)
	    unlink(dev);
    } else {
	struct addrinfo hints;
        struct addrinfo *res;
	int rc;
	char *node;
	char *service;
	
	node = strdup(dev);
	if (!node) {
	    perror("strdup");
	    exit(1);
	}
	
	service = strchr(node, ':');
	if (service)
	    *service++ = 0;
	else
	    service = "syslog";
	
	memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	rc = getaddrinfo(node, service, &hints, &res);
	free(node);
	if (rc) {
	    fprintf(stderr, "%s: %s: invalid socket address\n", progname, dev);
	    exit (1);
	}

	memcpy(&log_sa, res->ai_addr, res->ai_addrlen);
	log_family = PF_INET;
	log_salen = res->ai_addrlen;
	freeaddrinfo(res);
    }

    fd = socket(log_family, SOCK_DGRAM, 0);
    if (fd == -1) {
	fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
	exit(1);
    }

    if (log_family != PF_UNIX) {
	int t = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &t, sizeof(t));
    }
    
    if (bind(fd, (struct sockaddr*)&log_sa, log_salen)) {
	fprintf(stderr, "%s: bind: %s\n", progname, strerror(errno));
	exit(1);
    }

    b = malloc(sizeof(*b));
    if (!b) {
	fprintf(stderr, "%s: not enough memory\n", progname);
	exit(1);
    }
    b->in = fd;

    if (outfile) {
	b->out = fopen(outfile, "w");
	if (!b->out) {
	    fprintf(stderr, "%s: can't open output file %s\n", progname,
		    outfile);
	    exit(1);
	}
    } else
	b->out = stdout;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, thr_syslog, b);
    pthread_attr_destroy(&attr);
    
    return tid;
}

#define MAX_ENV 19
static char *env[MAX_ENV];
static int nenv = 0;

extern char **environ;

static void
signull(int sig)
{
}

int
main(int argc, char **argv)
{
    int c, i;
    struct timespec ts = { 10, 0 };
    char *p;
    pid_t pid;
    sigset_t sigs;
    struct sigaction act;
    static int fatal_signals[] = {
	SIGCHLD,
	SIGHUP,
	SIGINT,
	SIGQUIT,
	SIGTERM,
	0
    };
    char **xargv;
    int verbose = 0;
    int term = 0;
    char *syslog_socket = NULL;
    char *syslog_output = NULL;
    pthread_t log_tid = 0;
    int retcode = 0;
    
    progname = argv[0];
    
    while ((c = getopt(argc, argv, "e:ho:s:t:v")) != EOF) {
	switch (c) {
	case 'e':
	    if (nenv == MAX_ENV-3) {
		fprintf(stderr, "%s: env table overflow\n", progname);
		return 1;
	    }
	    env[nenv++] = optarg;
	    break;
	    
	case 'h':
	    usage();
	    return 0;

	case 'o':
	    syslog_output = optarg;
	    break;
	    
	case 's':
	    syslog_socket = optarg;
	    break;
	    
	case 't':
	    errno = 0;
	    ts.tv_sec = strtol(optarg, &p, 10);
	    if (errno || ts.tv_sec < 0) {
		fprintf(stderr, "%s: invalid duration: %s\n",
			progname, optarg);
		return 1;
	    }
	    if (*p == '.') {
		double x;
		char *q;
		
		errno = 0;
		x = strtod(p, &q);
		if (errno || *q) {
		    fprintf(stderr, "%s: invalid timeout: %s\n",
			    progname, optarg);
		    return 1;
		}
		ts.tv_nsec = (long) (x * 1e9);
	    } else if (*p) {
		fprintf(stderr, "%s: invalid timeout: %s\n",
			progname, optarg);
		return 1;
	    } else if (ts.tv_sec == 0) {
		fprintf(stderr, "%s: zero timeout is not allowed\n",
			progname);
		return 1;
	    }
	    break;

	case 'v':
	    verbose++;
	    break;
	    
	default:
	    return 2;
	}
    }

    argc -= optind;
    argv += optind;

    sigemptyset(&sigs);
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    act.sa_handler = signull;
    
    for (i = 0; fatal_signals[i]; i++) {
	sigaddset(&sigs, fatal_signals[i]);
	sigaction(fatal_signals[i], &act, NULL);
    }
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    if (syslog_socket) {
	log_tid = start_syslog(syslog_socket, syslog_output);
    }

    /*
     * Prepare micrond command line.
     */
    xargv = calloc(argc + 5, sizeof(xargv[0]));
    if (!xargv) {
	fprintf(stderr, "%s: out of memory\n", progname);
	exit(1);
    }

    i = 0;
    xargv[i++] = "micrond";
    xargv[i++] = "-f";
    if (syslog_socket) {
	xargv[i++] = "-p";
	xargv[i++] = syslog_socket;
    }
    for (c = 0; c <= argc; c++, i++)
	xargv[i] = argv[c];

    pid = fork();

    if (pid == -1) {
	perror("fork");
	return 1;
    }

    if (pid == 0) {
	/* Child */

	/*
	 * Restore default signal handlers.
	 */
	 act.sa_flags = 0;
	 sigemptyset(&act.sa_mask);
	 act.sa_handler = SIG_DFL;
	 for (i = 0; fatal_signals[i]; i++) {
	     sigaction(fatal_signals[i], &act, NULL);
	 }
	 
	 sigfillset(&sigs);
	 pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

	 if (nenv) {
	    int i;
	    char pbuf[80];
	    enum { HAVE_PATH = 0x1, HAVE_MICROND_PID = 0x2 } flags = 0;
	    snprintf(pbuf, sizeof(pbuf), "MICROND_PID=%d", getpid());

	    for (i = 0; i < nenv; i++) {
		if (strncmp(env[i], "MICROND_PID=", 12) == 0) {
	            env[i] = pbuf;
		    flags |= HAVE_MICROND_PID;
	        } else if (strncmp(env[i], "PATH=", 5) == 0) {
	            flags |= HAVE_PATH;
	        }
	    }

	    if (!(flags & HAVE_MICROND_PID)) {
		env[nenv++] = pbuf;
	    }
	    if (!(flags & HAVE_PATH)) {
		char *path = getenv("PATH");
		if (path) {
		    if ((env[nenv] = malloc(strlen(path) + 6)) == NULL) {
			perror("malloc");
			exit(127);
		    }
		    strcat(strcpy(env[nenv], "PATH="), path);
		}
	    }

	    environ = env;
	}
	execvp(xargv[0], xargv);
	fprintf(stderr, "%s: can't run %s: %s\n", progname, xargv[0],
		strerror(errno));
	_exit(127);
    }

again:
    c = sigtimedwait(&sigs, NULL, &ts);
    if (c == SIGCHLD) {
	int status;
	
	wait(&status);
	if (WIFEXITED(status)) {
	    status = WEXITSTATUS(status);
	    if (status == 127) {
		fprintf(stderr, "%s: can't run %s\n", progname, xargv[0]);
		retcode = 1;
	    } else if (status != 0) {
		fprintf(stderr, "%s: %s exited with status %d\n",
			progname, xargv[0], status);
	    }
	} else if (WIFSIGNALED(status)) {
	    fprintf(stderr, "%s: %s terminated on signal %d\n",
		    progname, xargv[0], WTERMSIG(status));
	    retcode = 1;
	} else {
	    fprintf(stderr, "%s: %s terminated with unknown status %d\n",
		    progname, xargv[0], status);
	    retcode = 1;
	}
    } else {
	if (c == -1 && errno != EAGAIN) {
	    perror("sigtimedwait");
	}	    
	if (term == 0) {
	    if (verbose)
		fprintf(stderr, "%s: terminating child process\n", progname);
	    kill(pid, SIGTERM);
	    ts.tv_sec = 5;
	    ts.tv_nsec = 0;
	    term = 1;
	    goto again;
	} else {
	    kill(pid, SIGKILL);
	    retcode = 1;
	}
    }

    if (log_tid) {
	pthread_cancel(log_tid);
    }
    
    return retcode;
}
