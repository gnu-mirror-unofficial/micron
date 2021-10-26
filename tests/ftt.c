/*
  NAME
    ftt - libfaketime tester
     
  SYNOPSIS
    ftt LIBNAME

  DESCRIPTION
    Argument must be a full pathname of the libfaketime.so library, or
    a colon-delimited list of library pathnames (one of them being
    libfaketime), suitable for use in LD_PRELOAD variable.  The program
    spawns a copy of itself with LD_PRELOAD set to LIBNAME, FAKETIME
    set to a predefined value, and analyzes the output and time it took
    to produce it.

    If libfaketime.so is usable, exits with code 0.  Otherwise, exits
    with code 1.

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
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

static char expout[] = "1609452000\n\
1609452060\n\
1609452120\n\
1609452180\n\
1609452240\n";

int
main(int argc, char **argv)
{
    if (argc == 2) {
	pid_t pid;
	int status;
	struct timespec ts = { 3, 0 };
	sigset_t sigs;
	int p[2];
	
	if (pipe(p)) {
	    perror("pipe");
	    return 1;
	}
	
	pid = fork();
	if (pid == -1) {
	    perror("fork");
	    return 1;
	}

	if (pid == 0) {
	    if (dup2(p[1], 1) == -1) {
		perror("dup2");
	    } else {
		setenv("LD_PRELOAD", argv[1], 1);
		setenv("FAKETIME", "@2021-01-01 00:00:00 x120", 1);
		execlp(argv[0], argv[0], NULL);
		perror("execlp");
	    }
	    _exit(127);
	}

	close(p[1]);
	
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigs, NULL);

	status = sigtimedwait(&sigs, NULL, &ts);
	if (status == -1) {
	    kill(pid, SIGKILL);
	    return 1;
	} else {
	    char buf[sizeof(expout)-1];
	    ssize_t n;
	    
	    wait(&status);
	    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
		return 1;

	    n = read(p[0], buf, sizeof(buf));
	    if (n != sizeof(buf))
		return 1;
	    if (memcmp(buf, expout, n))
		return 1;
	    
	    n = read(p[0], buf, sizeof(buf));
	    if (n != 0)
		return 1;
	}
    } else {
	struct timespec to = { 60, 0 };
	int i, count = 5;
    
	for (i = 0;;) {
	    struct timespec ts;
	    clock_gettime(CLOCK_REALTIME, &ts);
	    printf("%ld\n", ts.tv_sec);
	    if (++i == count)
		break;
	    ts = to;
	    if (nanosleep(&ts, NULL)) {
		perror("nanosleep");
		return 1;
	    }
	}
    }
    return 0;
}
