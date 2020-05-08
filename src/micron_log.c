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
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include "list.h"
#include "micron_log.h"

/* Global variables */
/* Fallback log file is used to log critical messages when syslog
   daemon is unavailable.  If NULL, stderr will be used. */
char *micron_fallback_file = "/tmp/micron_logger.log";
/* Name of the syslog device.  If starts with a slash, it is assumed
   to be a UNIX socket name.  Otherwise, it is assumed to be a host name
   or IPv4 address of the syslog daemon, optionally followed by a colon
   and port number or service name. */
char *micron_log_dev = MICRON_LOG_DEV;
/* Log tag */
char *micron_log_tag = "micron_logger";
/* Log facility */
int micron_log_facility = LOG_CRON;
/* Maximum capacity of the log message queue */
size_t micron_log_max_queue = MICRON_LOG_MAX_QUEUE;
/* Maximum delay (FIXME) */
int micron_log_max_delay = 1000;

/* Static variables */

/* Thread identifier of the running syslog thread.  If 0, it will
   be started upon entering next message. */
static pthread_t log_tid = 0;
/* When set, the syslog thread will exit as soon as the queue is drained. */
static int log_stop;

/* Connection information. */

/* Log socket descriptor. */
static int log_fd = -1;
/* Socket address */
static union {
    struct sockaddr_in s_in;
    struct sockaddr_un s_un;
} log_sa;
/* Socket address length. */
static socklen_t log_salen;
/* Socked address family. */
static int log_family;

/* Message queue. */

/* Messages are represented by object of the following structure: */
struct log_message {
    char *buf;                /* Message text (no terminating nul). */
    size_t len;               /* Length of the message text. */
    unsigned long count;      /* Number of dropped messages at the start
				 of the queue. */
    struct list_head link;
};

static struct list_head log_queue = LIST_HEAD_INITIALIZER(log_queue);
static size_t log_queue_length;
static pthread_mutex_t log_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_queue_cond = PTHREAD_COND_INITIALIZER;


/* Fallback logger */

static void
fallback_log(char const *fmt, ...)
{
    FILE *fp = NULL;
    va_list ap;

    if (micron_fallback_file)
	fp = fopen(micron_fallback_file, "a");
    if (!fp)
	fp = stderr;
    fprintf(fp, "micron[%lu]: ", (unsigned long) getpid());
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    if (fp != stderr)
	fclose(fp);
}

/* Interface functions */
static void *thr_syslog(void *ptr);

/* Internal log open function */
static inline void
log_open(const char *ident, int facility)
{
    if (log_tid)
	return;
    if (ident)
	micron_log_tag = strdup(ident);
    if (facility >= 0)
	micron_log_facility = facility;
    pthread_create(&log_tid, NULL, thr_syslog, micron_log_dev);
}

/* The micron_log_open call does not try to mimic the openlog function.
   It is basically equivalent to
      openlog(ident, LOG_PID|LOG_ODELAY, facility)
   If micron_fallback_file is NULL, the equivalent openlog invocation
   is
      openlog(ident, LOG_PID|LOG_ODELAY|LOG_CONS, facility)
*/
void
micron_log_open(const char *ident, int facility)
{
    log_open(ident, facility);
}

void
micron_log_close(void)
{
   pthread_mutex_lock(&log_queue_mutex);
   log_stop = 1;
   pthread_cond_broadcast(&log_queue_cond);
   pthread_mutex_unlock(&log_queue_mutex);
   pthread_join(log_tid, NULL);
   log_tid = 0;
}

/* Upper level logger API */
void
micron_vsyslog(int pri, char const *fmt, va_list ap)
{
    char buf[MICRON_LOG_BUF_SIZE];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    micron_log_enqueue(micron_log_facility|pri, buf, micron_log_tag, getpid());
}

void
micron_syslog(int pri, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    micron_vsyslog(pri, fmt, ap);
    va_end(ap);
}


static int
reopen_logger(void)
{
    int fd = socket(log_family, SOCK_DGRAM, 0);
    int flags;
    
    if (fd == -1) {
	fallback_log("socket: %s", strerror(errno));
	return -1;
    }

    if ((flags = fcntl(fd, F_GETFL)) == -1 ||
	fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
	(flags = fcntl(fd, F_GETFD)) == -1 ||
	fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
	close(fd);
	return -1;
    }
    
    if (connect(fd, (struct sockaddr*)&log_sa, log_salen)) {
	fallback_log("socket: %s", strerror(errno));
	close(fd);
	return -1;
    }
    log_fd = fd;
    return 0;
}

static int
open_logger(char const *dev)
{
    if (dev[0] == '/') {
	size_t len = strlen(dev);
	if (len >= sizeof log_sa.s_un.sun_path) {
	    fallback_log("%s: UNIX socket name too long", dev);
	    return -1;
	}
	strcpy(log_sa.s_un.sun_path, dev);
	log_sa.s_un.sun_family = AF_UNIX;
	log_family = PF_UNIX;
	log_salen = sizeof(log_sa.s_un);
    } else {
	struct addrinfo hints;
        struct addrinfo *res;
	int rc;
	char *node;
	char *service;
	
	node = strdup(dev);
	if (!node)
	    return -1;

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
	    fallback_log("%s: invalid socket address", dev);
	    return -1;
	}

	memcpy(&log_sa, res->ai_addr, res->ai_addrlen);
	log_family = PF_INET;
	log_salen = res->ai_addrlen;
	freeaddrinfo(res);
    }
    return reopen_logger();
}

static struct log_message *
log_message_create(int prio, char const *msgtext, char const *tag, pid_t pid)
{
    struct log_message *msg;
    char sbuf[MICRON_LOG_BUF_SIZE];
    char tbuf[sizeof("May  8 11:42:27")];
    char hostbuf[HOST_NAME_MAX];
    size_t len;
    struct timeval tv;
    struct tm tm;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", &tm);
    if (log_family == PF_UNIX) {
	snprintf(sbuf, sizeof(sbuf), "<%d>%s %s[%lu]: %s", 
		 prio, 
		 tbuf,
		 tag,
		 (unsigned long)pid, msgtext);
    } else {
	gethostname(hostbuf, HOST_NAME_MAX+1);
	snprintf(sbuf, sizeof(sbuf), "<%d>%s %s %s[%lu]: %s", 
		 prio, 
		 tbuf,
		 hostbuf,
		 tag,
		 (unsigned long)pid, msgtext);
    }
    len = strlen(sbuf);
    msg = malloc(sizeof(*msg) + len);
    if (msg) {
	msg->buf = (char*)(msg + 1);
	memcpy(msg->buf, sbuf, len);
	msg->len = len;
	msg->count = 0;
	list_head_init(&msg->link);
    }
    return msg;
}

static void
log_message_enqueue(struct log_message *msg)
{    
    LIST_HEAD_ENQUEUE(&log_queue, msg, link);
    log_queue_length++;
    pthread_cond_broadcast(&log_queue_cond);
}

static inline struct log_message *
log_message_dequeue(void)
{
    struct log_message *msg = LIST_HEAD_DEQUEUE(&log_queue, msg, link);
    if (msg)
	log_queue_length--;
    return msg;
}

static inline void
log_message_putback(struct log_message *msg)
{
    LIST_HEAD_PUSH(&log_queue, msg, link);
    log_queue_length++;
}

/* Low-level API */
int
micron_log_queue_is_empty(void)
{
    int res;
    pthread_mutex_lock(&log_queue_mutex);
    res = list_head_is_empty(&log_queue);
    pthread_mutex_unlock(&log_queue_mutex);
    return res;
}    

static inline int
pri_facility(int pri)
{
    return pri & ~0x7;
}

static inline int
pri_severity(int pri)
{
    return pri & 0x7;
}

void
micron_log_enqueue(int prio, char const *msgtext, char const *tag, pid_t pid)
{
    struct log_message *msg;

    log_open(NULL, -1);
    
    pthread_mutex_lock(&log_queue_mutex);

    /* Supply default facility, unless prio already contains one.
       Note: this means that we cannot use LOG_KERN, but that doesn't
       really matter as we're not a kernel, anyway. */
    if (pri_facility(prio) == 0)
	prio |= micron_log_facility;
	    
    if (micron_log_max_queue > 0 && micron_log_max_queue < 3)
	micron_log_max_queue = MICRON_LOG_MAX_QUEUE;
	/* Skip queue control */
    if (micron_log_max_queue > 0
	&& log_queue_length == micron_log_max_queue) {
	unsigned long dropped;
	char buf[MICRON_LOG_BUF_SIZE];
       
	msg = log_message_dequeue();
	dropped = msg->count;
	if (dropped == 0)
	    dropped++;
	free(msg);
       
	msg = log_message_dequeue();
	free(msg);
	dropped++;
       
	snprintf(buf, sizeof(buf), "%zu messages dropped", dropped);
	msg = log_message_create(pri_facility(prio)|LOG_CRIT,
				    buf, "micron_syslog",
				    getpid());
	if (msg) {
	    msg->count = dropped;
	    log_message_putback(msg);
	}
    }
    msg = log_message_create(prio, msgtext, tag, pid);
    if (msg)
	log_message_enqueue(msg);
    pthread_mutex_unlock(&log_queue_mutex);
}

/* Async syslog worker thread.
   Some fragments borrowed from the excellent syslog_async written by
   Simon Kelley (http://www.thekelleys.org.uk/syslog-async).
 */
static void *
thr_syslog(void *ptr)
{
    int rc;
    
    pthread_mutex_lock(&log_queue_mutex);
    open_logger((char const *)ptr);
    while (1) {
	struct log_message *msg;

	if (list_head_is_empty(&log_queue)) {
	    if (log_stop)
		break;
	    pthread_cond_wait(&log_queue_cond, &log_queue_mutex);
	} else {
	    struct timespec ts;
	    int d;
	    
	    d = 1;
	    LIST_FOREACH(msg, &log_queue, link) {
		d <<= 1;
		if (d >= micron_log_max_delay) {
		    d = micron_log_max_delay - 1;
		    break;
		}
	    }
	    ts.tv_sec = 0;
	    ts.tv_nsec = d * 1000000; /* 1 ms */
	    pthread_cond_timedwait(&log_queue_cond, &log_queue_mutex, &ts);
	}

	while ((msg = log_message_dequeue()) != NULL) {
	    if (log_fd == -1) {
		reopen_logger();
	    }
	    
	    rc = send(log_fd, msg->buf, msg->len, MSG_NOSIGNAL);
	    if (rc != -1) {
		free(msg);
		continue;
	    }
	    log_message_putback(msg);
		
	    if (errno == EINTR)
		continue;//Should not happen??
	    if (errno == EAGAIN)
		break;
	    
	    /* *BSD, returns this instead of blocking? */
	    if (errno == ENOBUFS)
		break;

	    /* A stream socket closed at the other end goes into EPIPE
	       forever, close and re-open. */
	    if (errno == EPIPE) {
		close(log_fd);
		log_fd = -1;
		continue;
	    }

	    if (errno == ECONNREFUSED || /* connection went down */
		errno == ENOTCONN ||     /* nobody listening */
		errno == EDESTADDRREQ || /* BSD equivalents of the above */ 
		errno == ECONNRESET) {

		/* The reader is gone.  Try reconnecting.  If failed,
		   retry when the thread is woken up again. */

		if (connect(log_fd, (struct sockaddr *)&log_sa,
			    log_salen) != -1)
		    /* Connected successfully: retry now */
		    continue;
	  
		if (errno == ENOENT || 
		    errno == EALREADY || 
		    errno == ECONNREFUSED ||
		    errno == EISCONN || 
		    errno == EINTR ||
		    errno == EAGAIN)
		    /* try again when woken up again */
		    break;
	    }
		
	    /* Else ? */
	    break;
	}
    }
    pthread_mutex_unlock(&log_queue_mutex);
    close(log_fd);
    log_fd = -1;
    log_stop = 0;
    return NULL;    
}

/* Conversion functions */

#define PRI_NUM(p) ((p) >> 3)
#define NUM_PRI(n) ((n)<<3)
#define NSTR(t) (sizeof(t)/sizeof(t[0]))

static char const *strfac[] = {
    [PRI_NUM(LOG_USER)] =      "USER"     ,
    [PRI_NUM(LOG_DAEMON)] =    "DAEMON"   ,
    [PRI_NUM(LOG_AUTH)] =      "AUTH"     ,
    [PRI_NUM(LOG_AUTHPRIV)] =  "AUTHPRIV" ,
    [PRI_NUM(LOG_MAIL)] =      "MAIL"     ,
    [PRI_NUM(LOG_CRON)] =      "CRON"     ,
    [PRI_NUM(LOG_LOCAL0)] =    "LOCAL0"   ,
    [PRI_NUM(LOG_LOCAL1)] =    "LOCAL1"   ,
    [PRI_NUM(LOG_LOCAL2)] =    "LOCAL2"   ,
    [PRI_NUM(LOG_LOCAL3)] =    "LOCAL3"   ,
    [PRI_NUM(LOG_LOCAL4)] =    "LOCAL4"   ,
    [PRI_NUM(LOG_LOCAL5)] =    "LOCAL5"   ,
    [PRI_NUM(LOG_LOCAL6)] =    "LOCAL6"   ,
    [PRI_NUM(LOG_LOCAL7)] =    "LOCAL7"   ,
};

static char const *strpri[] = {
    [LOG_EMERG] =   "EMERG",
    [LOG_ALERT] =   "ALERT",  
    [LOG_CRIT] =    "CRIT",  
    [LOG_ERR] =     "ERR",
    [LOG_WARNING] = "WARNING", 
    [LOG_NOTICE] =  "NOTICE", 
    [LOG_INFO] =    "INFO", 
    [LOG_DEBUG] =   "DEBUG",
};

static inline int
kw_to_num(char const *kw, char const **tab, int len)
{
    int i;
    for (i = 0; i < len; i++)
	if (tab[i] && strcasecmp(kw, tab[i]) == 0)
	    return i;
    return -1;
}

static inline char const *
num_to_kw(int n, char const **tab, int len)
{
    if (n < 0 || n > len)
	return NULL;
    return tab[n];
}

int
micron_log_str_to_fac(char const *str)
{
    int n = kw_to_num(str, strfac, NSTR(strfac));
    return (n < 0) ? n : NUM_PRI(n);
}

int
micron_log_str_to_pri(char const *str)
{
    return kw_to_num(str, strpri, NSTR(strpri));
}

char const *
micron_log_fac_to_str(int n)
{
    if (n < 0)
	return NULL;
    return num_to_kw(PRI_NUM(n), strfac, NSTR(strfac));
}

char const *
micron_log_pri_to_str(int n)
{
    return num_to_kw(n, strpri, NSTR(strpri));
}
