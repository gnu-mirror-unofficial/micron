/* Exit codes. */
enum {
    EXIT_OK,
    EXIT_FATAL,
    EXIT_USAGE
};

#ifndef MICRON_CRONTAB_MASTER
# define MICRON_CRONTAB_MASTER "/etc/crontab"
#endif
#ifndef MICRON_CRONDIR_SYSTEM
# define MICRON_CRONDIR_SYSTEM "/etc/cron.d"
#endif
#ifndef MICRON_CRONDIR_USER
# define MICRON_CRONDIR_USER   "/var/spool/cron/crontabs"
#endif
#ifndef MICRON_CRONDIR_GROUP
# define MICRON_CRONDIR_GROUP  "/var/spool/cron/crongroups"
#endif
#ifndef MICRON_EDITOR
# define MICRON_EDITOR "vi"
#endif

int create_temp_file(int dirfd, char *filename, size_t suflen, int isdir);

