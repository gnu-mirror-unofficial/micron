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
#include "list.h"

static char *crondirname;
static int crondirfd;
static char const *crontabfile = NULL;
static int group_opt = 0;
static int interactive_opt = 0;
static char const *username = NULL;

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

static uid_t crontab_uid = -1;
static gid_t crontab_gid = -1;


enum crontab_command { C_INSTALL, C_EDIT, C_LIST, C_REMOVE };

static int command_install(int, char **);
static int command_edit(int, char **);
static int command_list(int, char **);
static int command_remove(int, char **);
static int usergrouplist(void);

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
    fprintf(fp, "       %s -g [-u NAME] [-eilr] FILE\n", progname);
    fprintf(fp, "Crontab manipulations.\n");
    fprintf(fp, "\nOptions are:\n\n");
    fprintf(fp, "    -e              edit crontab\n");
    fprintf(fp, "    -i              interactively ask before removing or replacing\n");
    fprintf(fp, "    -l              list crontab\n");
    fprintf(fp, "    -r              remove crontab\n");
    fprintf(fp, "    -g              operate on user cron group files\n");
    fprintf(fp, "    -u NAME         operate on crontab of user NAME\n");
    fprintf(fp, "    -h              print this help text\n");
    fprintf(fp, "    -V              print program version and exit\n");
    fprintf(fp, "\n");
    fprintf(fp, "If none of [-ehlrV] options given, replaces the crontab with the"
	    " content of\n");
    fprintf(fp, "FILE.\n");
    fprintf(fp, "\n");
    fprintf(fp, "Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
    fprintf(fp, "Micron home page: <%s>.\n", PACKAGE_URL);
    exit(ex);
}

static char const *
logname(void)
{
    static char *s;
    if (!s) {
	struct passwd *pwd = getpwuid(getuid());
	if (!pwd) {
	    terror("who am I?");
	    exit(EXIT_FATAL);
	}
	s = strdup(pwd->pw_name);
	if (!s) {
	    terror("out of memory");
	    exit(EXIT_FATAL);
	}
    }
    return s;
}

int
main(int argc, char **argv)
{
    int c;
    enum crontab_command command = C_INSTALL;
    
    set_progname(argv[0]);
    
    while ((c = getopt(argc, argv, "eghilru:V")) != EOF) {
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

	case 'V':
	    version();
	    exit(EXIT_USAGE);
	    
	default:
	    usage(EXIT_USAGE);
	}
    }

    argc -= optind;
    argv += optind;
    
    if (username) {
	if (group_opt) {
	    crontab_uid = -1;
	} else if (getuid()) {
	    terror("only root can do that");
	    exit(EXIT_USAGE);
	} else {
	    struct passwd *pwd = getpwnam(username);
	    if (!pwd) {
		terror("no such user: %s", username);
		exit(EXIT_FATAL);
	    }
	    if (getuid() == 0) {
		crontab_uid = pwd->pw_uid;
		crontab_gid = -1;
	    }
	}
    } else {
	username = logname();
	if (getuid() == 0) {
	    crontab_uid = getuid();
	    crontab_gid = getgid();
	}
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

	crontab_gid = st.st_gid;
	
	grp = getgrgid(crontab_gid);
	if (!grp) {
	    terror("no group for gid %lu", (unsigned long)crontab_gid);
	    exit(EXIT_FATAL);
	}

	if (getgid() != crontab_gid && getuid() != 0) {
	    int i;
	    char const *name = logname();
	    for (i = 0; grp->gr_mem[i]; i++)
		if (strcmp(grp->gr_mem[i], name) == 0)
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
	    if (command == C_LIST)
		return usergrouplist();
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
	crontabfile = username;
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
    if ((mode & O_CREAT) && (crontab_uid != -1 || crontab_gid != -1)) {
	/* Fix file ownership */
	if (fchown(fd, crontab_uid, crontab_gid)) {
	    terror("can't change ownership of %s/%s: %s",
		   crondirname, filename, strerror(errno));
	    exit(EXIT_FATAL);
	}
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
    if (crontab_uid != -1 || crontab_gid != -1) {
	if (fchown(fileno(dst), crontab_uid, crontab_gid)) {
	    terror("can't change ownership: %s", strerror(errno));
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
    char *tempdir;
    char template[] = "micronXXXXXX";
    int tempfd, fd;
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

    tempdir = getenv("TMP");
    if (!tempdir)
	tempdir = "/tmp";

    tempfd = open(tempdir, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
    if (tempfd == -1) {
	terror("can't open directory %s: %s", tempdir, strerror(errno));
	return EXIT_FATAL;
    }
	
    tempdirfd = create_temp_file(tempfd, template, 0, 1);
    if (tempdirfd == -1) {
	terror("can't create temporary directory in %s: %s",
	       crondirname, strerror(errno));
	close(tempfd);
	return EXIT_FATAL;
    }

    if (crontab_uid != -1 || crontab_gid != -1) {
	if (fchown(tempdirfd, crontab_uid, crontab_gid)) {
	    terror("can't change ownership: %s", strerror(errno));
	    close(tempdirfd);
	    goto finish;
	}
    }
    
    fd = openat(tempdirfd, crontabfile, O_CREAT|O_TRUNC|O_RDWR, 0660);
    if (fd == -1) {
	terror("can't open temporary file %s/%s: %s",
	       template, crontabfile, strerror(errno));
	goto finish;
    }

    if (crontab_uid != -1 || crontab_gid != -1) {
	if (fchown(fd, crontab_uid, crontab_gid)) {
	    terror("can't change ownership: %s", strerror(errno));
	    close(fd);
	    goto finish;
	}
    }

    fp = fdopen(fd, "w");
    if (!fp) {
	terror("can't fdopen file %s/%s/%s: %s", template, crontabfile,
	       tempdir, strerror(errno));
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
	    if (fchdir(tempdirfd)) {
		terror("failed to change to %s/%s: %s", tempdir, template,
		       strerror(errno));
		_exit(127);
	    }

	    close_fds(3);
	    
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
    else if (errno == EXDEV) {
	FILE *src;
	fd = openat(tempdirfd, crontabfile, O_RDONLY);
	if (fd == -1 || (src = fdopen(fd, "r")) == NULL) {
	    terror("can't open file %s/%s/%s: %s", tempdir, template,
		   crontabfile, strerror(errno));
	    close(fd);
	} else {
	    fp = crontab_open(crontabfile, "w");
	    rc = fcopy(src, fp);
	    fclose(src);
	    fclose(fp);
	}
    } else {
	terror("failed to rename %s/%s to %s/%s: %s",
	       template, crontabfile, crondirname, crontabfile,
	       strerror(errno));
    }
    
finish:
    cleanupdir(tempdirfd, template);
    close(tempdirfd);
    if (unlinkat(tempfd, template, AT_REMOVEDIR))
	terror("failed to remove %s: %s", template, strerror(errno));
    close(tempfd);
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

struct filedesc {
    char *file;
    char *owner;
    struct list_head list;
};

static void
filedesc_sorted_insert(struct filedesc *fdesc, struct list_head *head,
		       size_t *pcount)
{
    struct filedesc *l, *m, *p;
    size_t i, n, count = *pcount;
    char const *filename = fdesc->file;
    
    if (count == 0)
	l = NULL;
    else {
	l = LIST_FIRST_ENTRY(head, l, list);

	if (strcmp(l->file, filename) > 0) {
	    l = NULL;
	} else if (strcmp((p = LIST_LAST_ENTRY(head, l, list))->file,
			  filename) < 0) {
	    l = p;
	} else {
	    while (count > 1) {
		int c;

		n = count / 2;
		
		i = 0;
		LIST_FOREACH_FROM(m, l, head, list) {
		    i++;
		    if (i == n)
			break;
		}
				
		c = strcmp(m->file, filename);
		if (c < 0) {
		    l = m;
		    count -= n;
		} else {
		    count = n;
		}
	    }
	}
    }

    if (!l)
	LIST_HEAD_INSERT_FIRST(head, fdesc, list);
    else {
	if ((p = LIST_NEXT_ENTRY(head, l, list)) &&
	       strcmp(p->file, filename) < 0)
	    l = p;
	LIST_INSERT_AFTER(l, fdesc, list);
    }

    ++ *pcount;
}

static int
usergrouplist(void)
{
    DIR *dir;
    struct dirent *ent;
    int fd;
    int max_name_len = 0;
    struct filedesc *fdesc;
    
    struct list_head ls_head = LIST_HEAD_INITIALIZER(ls_head);
    size_t ls_count = 0;
    
    fd = open(crondirname, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
    if (fd == -1 || (dir = fdopendir(fd)) == NULL) {
	terror("can't open directory %s: %s", crondirname, strerror(errno));
	return EXIT_FATAL;
    }
	
    while ((ent = readdir(dir)) != NULL) {
	struct stat st;
	struct passwd *pwd;
	char *owner;
	char ownerbuf[80];
	int namelen;
	
	if (fstatat(fd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
	    terror("can't stat %s/%s: %s", crondirname, ent->d_name,
		   strerror(errno));
	    return EXIT_FATAL;
	}
	if (!S_ISREG(st.st_mode) ||
	    is_ignored_file_name(ent->d_name) ||
	    st.st_gid != crontab_gid)
	    continue;

	pwd = getpwuid(st.st_uid);
	if (pwd)
	    owner = pwd->pw_name;
	else {
	    snprintf(ownerbuf, sizeof(ownerbuf), "+%lu",
		     (unsigned long) st.st_uid);
	    owner = ownerbuf;
	}
	
	namelen = strlen(ent->d_name);
	if (namelen > max_name_len)
	    max_name_len = namelen;
	    
	fdesc = malloc(sizeof(*fdesc) + namelen + strlen(owner) + 2);
	if (!fdesc) {
	    terror("out of memory");
	    return EXIT_FATAL;
	}

	fdesc->file = (char*)(fdesc + 1);
	strcpy(fdesc->file, ent->d_name);
	fdesc->owner = fdesc->file + namelen + 1;
	strcpy(fdesc->owner, owner);

	filedesc_sorted_insert(fdesc, &ls_head, &ls_count);
    }
    closedir(dir);
    
    while ((fdesc = LIST_HEAD_POP(&ls_head, fdesc, list)) != NULL) {
	printf("%-*.*s %s\n", max_name_len, max_name_len,
	       fdesc->file, fdesc->owner);
	free(fdesc);
    }
    return EXIT_OK;
}
