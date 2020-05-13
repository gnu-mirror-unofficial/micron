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

