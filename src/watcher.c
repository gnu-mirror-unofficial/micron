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
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include "micrond.h"

static int
watcher_setup(int wd[])
{
    int ifd;
    int i;
    
    ifd = inotify_init();
    if (ifd == -1) {
	micron_log(LOG_ERR, "inotify_init: %s", strerror(errno));
	return -1;
    }
    
    for (i = 0; i < NCRONID; i++) {
	if (crongroups[i].flags & CDF_DISABLED) {
	    wd[i] = -1;
	    continue;
	}

	wd[i] = inotify_add_watch(ifd, crongroups[i].dirname,
				  IN_DELETE | IN_CREATE | IN_CLOSE_WRITE |
				  IN_MOVED_FROM | IN_MOVED_TO);
	if (wd[i] == -1) {
	    micron_log(LOG_ERR, "cannot set watch on %s: %s",
		       crongroups[i].dirname,
		       strerror(errno));
	    close(ifd);
	    ifd = -1;
	}
    }
    return ifd;
}

static void
event_handler(struct inotify_event *ep, int wd[])
{
    int cid;

    for (cid = 0; cid < NCRONID; cid++)
	if (wd[cid] == ep->wd)
	    break;

    if (ep->mask & IN_IGNORED)
	/* nothing */ ;
    else if (ep->mask & IN_Q_OVERFLOW)
	micron_log(LOG_NOTICE, "event queue overflow");
    else if (ep->mask & IN_UNMOUNT)
	/* FIXME? */ ;
    else if (cid == NCRONID) {
	if (ep->name)
	    micron_log(LOG_NOTICE, "unrecognized event %x for %s",
		       ep->mask, ep->name);
	else
	    micron_log(LOG_NOTICE, "unrecognized event %x", ep->mask);
    } else if (ep->mask & IN_CREATE) {
	micron_log(LOG_DEBUG, "%s/%s created",
		   crongroups[cid].dirname, ep->name);
    } else if (ep->mask & (IN_DELETE | IN_MOVED_FROM)) {
	micron_log(LOG_DEBUG, "%s/%s %s", 
		   crongroups[cid].dirname, ep->name,
		   ep->mask & IN_DELETE ? "deleted" : "moved out");
	crontab_deleted(cid, ep->name);
    } else if (ep->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
	micron_log(LOG_DEBUG, "%s/%s %s", 
		   crongroups[cid].dirname, ep->name,
		   ep->mask & IN_MOVED_TO ? "moved to" : "written");
	crontab_updated(cid, ep->name);
    } else {
	if (ep->name)
	    micron_log(LOG_NOTICE, "unrecognized event %x for %s",
		       ep->mask, ep->name);
	else
	    micron_log(LOG_NOTICE, "unrecognized event %x", ep->mask);
    }	
}

static char buffer[4096];
static int offset;

int
watcher_run(int ifd, int wd[])
{
    int n;
    int rdbytes;

    if (ioctl(ifd, FIONREAD, &n)) {
	micron_log(LOG_ERR, "ioctl: %s", strerror(errno));
	return -1;
    }
    if (offset + n > sizeof buffer)
	n = sizeof buffer - offset;
    if (n) {
	rdbytes = read(ifd, buffer + offset, n);
	if (rdbytes == -1) {
	    if (errno == EINTR) {
		return 0;
	    }

	    micron_log(LOG_NOTICE, "inotify read failed: %s", strerror(errno));
	    return -1;
	}
    }
    offset += n;

    for (n = 0; offset - n >= sizeof(struct inotify_event);) {
	struct inotify_event *ep;
	size_t size;

	ep = (struct inotify_event *) (buffer + n);
	size = sizeof(*ep) + ep->len;
	if (offset - n < size)
	    break;

	event_handler(ep, wd);

	n += size;
    }
    if (n > 0 && offset - n > 0)
	memmove(buffer, buffer + n, offset - n);
    offset -= n;

    return 0;
}

void *
cron_thr_watcher(void *ptr)
{
    int ifd;
    int wd[NCRONID];
    struct pollfd pfd;
    
    ifd = watcher_setup(wd);
    if (ifd == -1)
	return NULL;

    pfd.fd = ifd;
    pfd.events = POLLIN;

    while (1) {
	int n = poll(&pfd, 1, -1);
	if (n == -1) {
	    micron_log(LOG_ERR, "poll: %s", strerror(errno));
	    break;
	}
	if (n == 1) {
	    if (pfd.revents & POLLIN)
		watcher_run(ifd, wd);
	}
    }
    close(ifd);
    /* Fall back to the traditional scanner */
    crontab_scanner_schedule();
    return NULL;
}
	    
