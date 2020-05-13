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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include "defs.h"

static char *progname;
static char *crondirname;
static int crondirfd;
static char *crontabfile = NULL;
static int group_opt = 0;
static int interactive_opt = 0;
static char *username = NULL;
static gid_t crongroup_id;

static char *catfilename(char const *dir, char const *file);

static void
terror(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

enum {
    GETYN_NEUTRAL,
    GETYN_NO,
    GETYN_YES
};

static int
getyn(int dfl, const char *prompt, ...)
{
    static char *hint[] = { "y/n", "y/N", "Y/n" };
    static int retval[] = {    -1,    0 ,  1 };    
    enum { S_PROMPT, S_READ, S_ANSWER } state = S_PROMPT;
    int c, resp;
    va_list ap;

    do {
	switch (state) {
	case S_READ:
	    if (c == ' ' || c == '\t')
		continue;
	    resp = c;
	    state = S_ANSWER;
	    /* fall through */
	    
	case S_ANSWER:
	    if (c == '\n') {
		switch (resp) {
		case 'y':
		case 'Y':
		    return 1;
		case 'n':
		case 'N':
		    return 0;
		case '\n':
		    if (retval[dfl] >= 0)
			return retval[dfl];
		    /* fall through */
		default:
		    terror("Please, reply 'y' or 'n'");
		}
		state = S_PROMPT;
		/* fall through */
	    } else
		break;
	    
	case S_PROMPT:
	    va_start(ap, prompt);
	    vfprintf(stdout, prompt, ap);
	    va_end(ap);
	    fprintf(stdout, " [%s] ", hint[dfl]);
	    fflush(stdout);
	    state = S_READ;
	    break;
	}
    } while ((c = getchar()) != EOF);
    exit(EXIT_USAGE);
}

enum crontab_command { C_INSTALL, C_EDIT, C_LIST, C_REMOVE };

static int command_install(int, char **);
static int command_edit(int, char **);
static int command_list(int, char **);
static int command_remove(int, char **);

static int (*command_action[])(int, char **) = {
    command_install,
    command_edit,
    command_list,
    command_remove
};

static void
usage(int ex)
{
    FILE *fp = ex ? stderr : stdout;
    fprintf(fp, "usage: %s [-u NAME] FILE\n", progname);
    fprintf(fp, "       %s [-eilr] [-u NAME]\n", progname);
    fprintf(fp, "       %s -g -u NAME [-eilr] FILE\n", progname);
    fprintf(fp, "Crontab manipulations.\n");
    fprintf(fp, "\nOptions are:\n\n");
    fprintf(fp, "    -e              edit crontab\n");
    fprintf(fp, "    -i              interactively ask before removing or replacing\n");
    fprintf(fp, "    -l              list crontab\n");
    fprintf(fp, "    -r              remove crontab\n");
    fprintf(fp, "    -g              operate on user cron group files\n");
    fprintf(fp, "    -u NAME         operate on crontab of user NAME\n");
    fprintf(fp, "\n");
    fprintf(fp, "If none of [-elr] options given, replaces the crontab with the"
	    " content of FILE.\n");
    fprintf(fp, "\n");
    exit(ex);
}

int
main(int argc, char **argv)
{
    int c;
    enum crontab_command command = C_INSTALL;
    struct passwd *pwd;
    
    progname = strrchr(argv[0], '/');
    if (progname)
	progname++;
    else
	progname = argv[0];
    
    while ((c = getopt(argc, argv, "eghilru:")) != EOF) {
	switch (c) {
	case 'e':
	    command = C_EDIT;
	    break;
	    
	case 'g':
	    group_opt = 1;
	    break;

	case 'h':
	    usage(EXIT_OK);
	    break;
	    
	case 'i':
	    interactive_opt = 1;
	    break;
	    
	case 'l':
	    command = C_LIST;
	    break;
	    
	case 'r':
	    command = C_REMOVE;
	    break;

	case 'u':
	    username = optarg;
	    break;
	    
	default:
	    usage(EXIT_USAGE);
	}
    }

    argc -= optind;
    argv += optind;
    
    if (username) {
	if (getuid() && !group_opt) {
	    terror("only root can do that");
	    exit(EXIT_USAGE);
	}

	pwd = getpwnam(username);
	if (!pwd) {
	    terror("no such user: %s", username);
	    exit(EXIT_FATAL);
	}
    } else {
	pwd = getpwuid(getuid());
	if (!pwd) {
	    terror("who am I?");
	    exit(EXIT_FATAL);
	}
	username = strdup(pwd->pw_name);
    }

    if (group_opt) {
	struct group *grp;
	struct stat st;
	int fd;

	crondirname = MICRON_CRONDIR_GROUP;
	crondirfd = openat(AT_FDCWD, crondirname,
			   O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (crondirfd == -1) {
	    terror("can't open directory %s: %s",
		   crondirname,
		   strerror(errno));
	    exit(EXIT_FATAL);
	}
	if (fstatat(crondirfd, username, &st, AT_SYMLINK_NOFOLLOW)) {
	    if (errno == ENOENT) {
		terror("no such crongroup: %s", username);
	    } else {
		terror("can't stat %s/%s: %s",
		       crondirname, username, strerror(errno));
	    }
	    exit(EXIT_FATAL);
	}

	crongroup_id = st.st_gid;
	
	grp = getgrgid(crongroup_id);
	if (!grp) {
	    terror("no group for gid %lu", (unsigned long)crongroup_id);
	    exit(EXIT_FATAL);
	}

	if (getgid() != crongroup_id && getuid() != 0) {
	    int i;
	    char *logname = getenv("LOGNAME");
	    for (i = 0; grp->gr_mem[i]; i++)
		if (strcmp(grp->gr_mem[i], logname) == 0)
		    break;
	    if (!grp->gr_mem[i]) {
		terror("you are not allowed to use crongroup %s",
		       username);
		exit(EXIT_FATAL);
	    }
	}

	fd = openat(crondirfd, username,
		    O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (fd == -1) {
	    terror("can't open directory %s/%s: %s",
		   crondirname, username,
		   strerror(errno));
	    exit(EXIT_FATAL);
	}
	close(crondirfd);
	crondirfd = fd;
	crondirname = catfilename(crondirname, username);
	
	if (argc < 1) {
	    terror("missing group file name");
	    exit(EXIT_USAGE);
	}
	crontabfile = argv[0];
	argc--;
	argv++;
	
	umask(007);
    } else {
	crondirname = MICRON_CRONDIR_USER;
	crondirfd = openat(AT_FDCWD, crondirname,
			   O_RDONLY | O_NONBLOCK | O_DIRECTORY);
	if (crondirfd == -1) {
	    terror("can't open directory %s: %s",
		   crondirname,
		   strerror(errno));
	    exit(EXIT_FATAL);
	}
	crontabfile = getenv("LOGNAME");
	umask(077);
    }
    return command_action[command](argc, argv);
}

static int
fcopy(FILE *src, FILE *dst)
{
    int c;
    while ((c = fgetc(src)) != EOF)
	fputc(c, dst);
    if (ferror(src)) {
	terror("read error");
	return EXIT_FATAL;
    }
    if (ferror(dst)) {
	terror("write error");
	return EXIT_FATAL;
    }
    return EXIT_OK;
}

static FILE *
crontab_open(char const *filename, char const *smode)
{
    int mode;
    int fd;
    FILE *fp;
    
    switch (*smode) {
    case 'w':
	mode = O_CREAT | O_TRUNC;
	if (smode[1] == '+')
	    mode |= O_RDWR;
	else
	    mode |= O_WRONLY;
	break;

    case 'r':
	if (smode[1] == '+')
	    mode = O_RDWR;
	else
	    mode = O_RDONLY;
	break;

    default:
	abort();
    }

    fd = openat(crondirfd, filename, mode, 0660);
    if (fd == -1) {
	terror("can't open file %s/%s: %s", crondirname, filename,
	       strerror(errno));
	exit(EXIT_FATAL);
    }
    fp = fdopen(fd, smode);
    if (!fp) {
	terror("can't fdopen file %s/%s: %s", crondirname, filename,
	       strerror(errno));
	exit(EXIT_FATAL);
    }
    return fp;
}

static int
command_install(int argc, char **argv)
{
    FILE *src, *dst;
    int rc;
    
    if (argc == 0) {
	terror("required argument missing");
	return EXIT_USAGE;
    } else if (argc > 1) {
	terror("too many arguments");
	return EXIT_USAGE;
    }
    src = fopen(argv[0], "r");
    if (!src) {
	terror("can't open %s for reading: %s", argv[0], strerror(errno));
	return EXIT_FATAL;
    }

    if (interactive_opt) {
	struct stat st;
	if (fstatat(crondirfd, crontabfile, &st, AT_SYMLINK_NOFOLLOW) == 0) {
	    if (!getyn(GETYN_NEUTRAL, "file %s/%s already exists; replace",
		       crondirname, crontabfile))
		return EXIT_OK;
	}
    }

    dst = crontab_open(crontabfile, "w");
    if (group_opt) {
	if (fchown(fileno(dst), -1, crongroup_id)) {
	    terror("can't change owner group: %s", strerror(errno));
	    fclose(dst);
	    //FIXME: bail out; better even use tempfile
	}
    }
    rc = fcopy(src, dst);
    fclose(src);
    fclose(dst);
    return rc;
}

char *
catfilename(char const *dir, char const *file)
{
    char *buf;
    size_t dlen = strlen(dir);
    size_t len;

    while (dlen > 0 && dir[dlen-1] == '/')
	--dlen;

    while (*file && *file == '/')
	++file;

    if (dlen == 0) {
	errno = EINVAL;
	return NULL;
    }
    
    len = dlen + 1 + strlen(file);

    buf = malloc(len + 1);
    if (buf) {
	strcpy(buf, dir);
	strcat(buf, "/");
	strcat(buf, file);
    }
    return buf;
}

static void
cleanupdir(int fd, char *name)
{
    DIR *dir;
    struct dirent *ent;

    dir = fdopendir(fd);
    if (!dir) {
	terror("fdopendir(%s) failed: %s", name, strerror(errno));
	return;
    }
    rewinddir(dir);

    while ((ent = readdir(dir))) {
	if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
	    continue;
	if (unlinkat(fd, ent->d_name, 0)) {
	    terror("failed to unlink %s/%s: %s", name, ent->d_name,
		   strerror(errno));
	}
    }
    closedir(dir);
}

static int
command_edit(int argc, char **argv)
{
    char *editor;
    char *editor_command;
    size_t len;
    char template[] = ".#micronXXXXXX";
    int fd;
    FILE *fp;
    struct stat st;
    int tempdirfd;
    int rc = EXIT_FATAL;
    
    if (argc) {
	terror("too many arguments");
	return EXIT_USAGE;
    }

    if (((editor = getenv("VISUAL")) == NULL || !*editor) &&
	((editor = getenv("EDITOR")) == NULL || !*editor))
	editor = MICRON_EDITOR;

    tempdirfd = create_temp_file(crondirfd, template, 0, 1);
    if (tempdirfd == -1) {
	terror("can't create temporary directory in %s: %s",
	       crondirname, strerror(errno));
	return EXIT_FATAL;
    }
    
    fd = openat(tempdirfd, crontabfile, O_CREAT|O_TRUNC|O_RDWR, 0660);
    if (fd == -1) {
	terror("can't open temporary file %s/%s: %s",
	       template, crontabfile, strerror(errno));
	goto finish;
    }
    if (group_opt) {
	if (fchown(fd, -1, crongroup_id)) {
	    terror("can't change owner group: %s", strerror(errno));
	    close(fd);
	    goto finish;
	}
    }
    fp = fdopen(fd, "w");
    if (!fp) {
	terror("can't fdopen file %s/%s: %s", template, crontabfile,
	       strerror(errno));
	close(fd);
	goto finish;
    }
    
    if (fstatat(crondirfd, crontabfile, &st, AT_SYMLINK_NOFOLLOW) == 0) {
	FILE *src;

	src = crontab_open(crontabfile, "r");
	rc = fcopy(src, fp);
	fclose(src);
    } else if (errno == ENOENT) {
	rc = EXIT_OK;
    } else {
	terror("can't stat %s/%s: %s", crondirname, crontabfile,
	       strerror(errno));
	rc = EXIT_FATAL;
    }

    fclose(fp);

    if (rc)
	goto finish;

    rc = EXIT_FATAL; /* Assume worst */
    len = strlen(editor) + strlen(crontabfile) + 2;
    editor_command = malloc(len);
    if (!editor_command) {
	terror("out of memory");
	goto finish;
    }
    snprintf(editor_command, len, "%s %s", editor, crontabfile);

    while (1) {
	pid_t pid;
	int status;
	
	pid = fork();
	if (pid == -1) {
	    terror("fork: %s", strerror(errno));
	    goto finish;
	}
	if (pid == 0) {
	    int i;
	    
	    if (fchdir(tempdirfd)) {
		terror("failed to change to %s: %s", template,
		       strerror(errno));
		_exit(127);
	    }

	    for (i = sysconf(_SC_OPEN_MAX); i > 2; i--) {
		close(i);
	    }
	    
	    execlp("/bin/sh", "sh", "-c", editor_command, NULL);
	    _exit(127);
	}
	if (waitpid(pid, &status, 0) == -1) {
	    terror("%s", strerror(errno));
	    goto finish;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
	    //FIXME: parse the file and retry if necessary
	    break;
	}
	goto finish;
    }
    
    if (renameat(tempdirfd, crontabfile, crondirfd, crontabfile) == 0)
	rc = EXIT_OK;
    else {
	terror("failed to rename %s/%s to %s/%s: %s",
	       template, crontabfile, crondirname, crontabfile,
	       strerror(errno));
    }
    
finish:
    cleanupdir(tempdirfd, template);
    close(tempdirfd);
    if (unlinkat(crondirfd, template, AT_REMOVEDIR))
	terror("failed to remove %s: %s", template, strerror(errno));
    return rc;
}

static int
command_list(int argc, char **argv)
{
    FILE *src;
    int fd;
    int rc;
    
    if (argc) {
	terror("too many arguments");
	return EXIT_USAGE;
    }
    fd = openat(crondirfd, crontabfile, O_RDONLY, 0660);
    if (fd == -1) {
	if (errno == ENOENT) {
	    if (group_opt)
		printf("no crontab %s in group for %s\n", crontabfile, username);
	    else
		printf("no crontab for %s\n", username);
	    return EXIT_OK;
	} else {
	    terror("can't open file %s/%s for reading: %s",
		   crondirname, crontabfile,
		   strerror(errno));
	}
	return EXIT_FATAL;
    }
    src = fdopen(fd, "r");
    if (!src) {
	terror("can't fdopen file %s/%s: %s", crondirname, crontabfile,
	       strerror(errno));
	return EXIT_FATAL;
    }
    rc = fcopy(src, stdout);
    fclose(src);
    return rc;
}

static int
command_remove(int argc, char **argv)
{
    if (argc) {
	terror("too many arguments");
	return EXIT_USAGE;
    }
    if (interactive_opt) {
	struct stat st;
	if (fstatat(crondirfd, crontabfile, &st, AT_SYMLINK_NOFOLLOW) == 0) {
	    if (!getyn(GETYN_NEUTRAL, "really remove %s/%s",
		       crondirname, crontabfile))
		return EXIT_OK;
	}
    }
    if (unlinkat(crondirfd, crontabfile, 0)) {
	terror("failed to unlink %s/%s: %s",
	       crondirname, crontabfile, strerror(errno));
	return EXIT_FATAL;
    }
    return EXIT_OK;
}
