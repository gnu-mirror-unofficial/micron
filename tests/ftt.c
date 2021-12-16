/*
  NAME
    ftt - libfaketime tester
     
  SYNOPSIS
    ftt LIBNAME

  DESCRIPTION
    Argument must be a full pathname of the libfaketime.so library, or
    a colon-delimited list of library pathnames (one of them being
    libfaketime), suitable for use in LD_PRELOAD variable.  The program
    spawns a copy of itself with LD_PRELOAD set to LIBNAME, and FAKETIME
    set to one minute from now with a speedup of 60 times (one program's
    minute = one realtime second).  The spawned copy starts a thread that
    calls pthread_cond_timedwait with the time limit set to one minute from
    now, and joins that thread.  The master waits for three seconds for
    the child to terminate (in fact, it should take little longer than
    one second) and returns 0 if the child exits in time, meaning that
    libfaketime.so is usable, and 1 otherwise.

  NOTE
    Support for pthread_cond_timedwait appeared in version 0.9.8 of
    libfaketime (commit fb91c4fcde).  It is crucial for GNU micron testsuite.

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
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>

static pthread_mutex_t thr_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t thr_cond = PTHREAD_COND_INITIALIZER;

void *
thr_wait(void *ptr)
{
    pthread_mutex_lock(&thr_mutex);
    pthread_cond_timedwait(&thr_cond, &thr_mutex, ptr);
    pthread_mutex_unlock(&thr_mutex);
    return NULL;
}

int
main(int argc, char **argv)
{
    struct timespec now, ts;

    clock_gettime(CLOCK_REALTIME, &now);
    now.tv_sec += 60;
	
    if (argc == 2) {
	pid_t pid;
	int status;
	sigset_t sigs;
	
	pid = fork();
	if (pid == -1) {
	    perror("fork");
	    return 1;
	}

	if (pid == 0) {
	    struct tm *tm;
	    char tbuf[sizeof("@1970-01-01 00:00:00 x60")];
	    
	    tm = localtime(&now.tv_sec);
	    strftime(tbuf, sizeof(tbuf), "@%Y-%m-%d %H:%M:%S x60", tm);
	    setenv("LD_PRELOAD", argv[1], 1);
	    setenv("FAKETIME", tbuf, 1);
	    execlp(argv[0], argv[0], NULL);
	    perror("execlp");
	    _exit(127);
	}

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigs, NULL);

	ts.tv_sec = 3;
	ts.tv_nsec = 0;
	status = sigtimedwait(&sigs, NULL, &ts);
	if (status == -1) {
	    kill(pid, SIGKILL);
	    return 1;
	} else {
	    wait(&status);
	    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
		return 1;
	}
    } else {
	pthread_t tid;
	void *res;	
	pthread_create(&tid, NULL, thr_wait, &now);
	pthread_join(tid, &res);
    }
    return 0;
}
