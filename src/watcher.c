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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include "micrond.h"

static int ifd = -1;

static int
watcher_setup(void)
{
    int ifd;
    struct crongroup *cgrp;
    
    ifd = inotify_init();
    if (ifd == -1) {
	micron_log(LOG_ERR, "inotify_init: %s", strerror(errno));
	return -1;
    }

    LIST_FOREACH(cgrp, &crongroup_head, list) {
	if (cgrp->flags & CGF_DISABLED) {
	    cgrp->wd = -1;
	    continue;
	}

	cgrp->wd = inotify_add_watch(ifd, cgrp->dirname,
				     IN_DELETE | IN_CREATE | IN_CLOSE_WRITE |
				     IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB);
	if (cgrp->wd == -1) {
	    micron_log(LOG_ERR, "cannot set watch on %s: %s",
		       cgrp->dirname,
		       strerror(errno));
	    close(ifd);
	    ifd = -1;
	}
    }
    return ifd;
}

static int
watcher_add(struct crongroup *cgrp)
{
    cgrp->wd = inotify_add_watch(ifd, cgrp->dirname,
				 IN_DELETE | IN_CREATE | IN_CLOSE_WRITE |
				 IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB);
    if (cgrp->wd == -1) {
	micron_log(LOG_ERR, "cannot set watch on %s: %s",
		   cgrp->dirname,
		   strerror(errno));
	return -1;
    }
    return 0;
}

static inline int
watcher_remove(int wd)
{
    return inotify_rm_watch(ifd, wd);
}

static inline struct crongroup *
crongroup_by_wd(int wd)
{
    struct crongroup *cgrp;

    LIST_FOREACH(cgrp, &crongroup_head, list)
	if (cgrp->wd == wd)
	    return cgrp;
    return NULL;
}

static void
event_handler(struct inotify_event *ep)
{
    struct crongroup *cgrp = crongroup_by_wd(ep->wd);
    int rescan = 0;
    
    if (ep->mask & IN_IGNORED)
	/* nothing */ ;
    else if (ep->mask & IN_Q_OVERFLOW)
	micron_log(LOG_NOTICE, "watcher event queue overflow");
    else if (ep->mask & IN_UNMOUNT)
	/* FIXME? */ ;
    else if (!cgrp) {
	if (ep->name)
	    micron_log(LOG_NOTICE, "watcher: unrecognized event %x for %s",
		       ep->mask, ep->name);
	else
	    micron_log(LOG_NOTICE, "watcher: unrecognized event %x", ep->mask);
    } else if (crongroup_skip_name(cgrp, ep->name)) {
	return;
    } else if (ep->mask & IN_CREATE) {
	micron_log(LOG_DEBUG, "watcher: %s/%s created", cgrp->dirname,
		   ep->name);
	if (cgrp->type == CGTYPE_GROUPHOST) {
	    rescan = 1;
	    usercrongroup_add(cgrp, ep->name);
	}
    } else if (ep->mask & IN_ATTRIB) {
	rescan = 1;
	if ((ep->mask & IN_ISDIR) && ep->name[0] == 0)
	    crongroup_chattr(cgrp);
	else
	    crontab_chattr(cgrp, ep->name);
    } else if (ep->mask & (IN_DELETE | IN_MOVED_FROM)) {
	micron_log(LOG_DEBUG, "watcher: %s/%s %s", cgrp->dirname, ep->name,
		   ep->mask & IN_DELETE ? "deleted" : "moved out");
	if (cgrp->type == CGTYPE_GROUPHOST) {
	    watcher_remove(cgrp->wd);
	    usercrongroup_delete(cgrp, ep->name);
	} else
	    crontab_deleted(cgrp, ep->name);
    } else if (ep->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
	micron_log(LOG_DEBUG, "watcher: %s/%s %s", 
		   cgrp->dirname, ep->name,
		   ep->mask & IN_MOVED_TO ? "moved to" : "written");
	rescan = 1;
	if (cgrp->type == CGTYPE_GROUPHOST)
	    usercrongroup_add(cgrp, ep->name);
	else
	    crontab_updated(cgrp, ep->name);
    } else {
	if (ep->name)
	    micron_log(LOG_NOTICE, "watcher: unrecognized event %x for %s",
		       ep->mask, ep->name);
	else
	    micron_log(LOG_NOTICE, "watcher: unrecognized event %x", ep->mask);
    }
    if (rescan) {
	LIST_FOREACH(cgrp, &crongroup_head, list)
	    if (cgrp->wd <= 0)
		watcher_add(cgrp);
    }
}

static char buffer[4096];
static int offset;

int
watcher_run(void)
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

	event_handler(ep);

	n += size;
    }
    if (n > 0 && offset - n > 0)
	memmove(buffer, buffer + n, offset - n);
    offset -= n;

    return 0;
}

static void
cron_cleanup_watcher(void *unused)
{
    close(ifd);
}

void *
cron_thr_watcher(void *ptr)
{
    struct pollfd pfd;
    
    ifd = watcher_setup();
    if (ifd != -1) {
	pthread_cleanup_push(cron_cleanup_watcher, NULL);

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
		    watcher_run();
	    }
	}
	pthread_cleanup_pop(1);
    }
    /* Fall back to the traditional scanner */
    crontab_scanner_schedule();
    return NULL;
}
	    
