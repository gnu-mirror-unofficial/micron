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

#include <stdarg.h>

#define MICRON_LOG_BUF_SIZE 1024
#define MICRON_LOG_DEV "/dev/log"
#define MICRON_LOG_MAX_QUEUE 500

extern char *micron_log_dev;
extern char *micron_fallback_file;
extern int micron_log_max_delay;
extern size_t micron_log_max_queue;
extern char *micron_log_tag;
extern int micron_log_facility;

#define ATTR_PRINTFLIKE(fmt,narg)                               \
    __attribute__ ((__format__ (__printf__, fmt, narg)))

void micron_log_open(const char *ident, int facility);
void micron_log_close(void);
void micron_vsyslog(int pri, char const *fmt, va_list ap);
void micron_syslog(int pri, char const *fmt, ...)
    ATTR_PRINTFLIKE(2,3);
int micron_log_queue_is_empty(void);
void micron_log_enqueue(int prio, char const *msgtext, char const *tag,
			pid_t pid);

int micron_log_str_to_fac(char const *str);
int micron_log_str_to_pri(char const *str);
char const *micron_log_fac_to_str(int n);
char const *micron_log_pri_to_str(int n);

