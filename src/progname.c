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
#include <stdio.h>
#include <string.h>

char *progname;

void
set_progname(char *arg0)
{
    progname = strrchr(arg0, '/');
    if (progname)
	progname++;
    else
	progname = arg0;
}    

void
version(void)
{
    printf("%s (%s) %s\n", progname, PACKAGE_NAME, PACKAGE_VERSION);
    printf("Copyright (C) 2021 Sergey Poznyakoff\n");
    printf("\
\n\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
\n\
");
}

