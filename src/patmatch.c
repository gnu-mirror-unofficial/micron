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
#include <fnmatch.h>
#include <defs.h>

int
patmatch(char const **patterns, const char *name)
{
    if (patterns) {
	int i;
	for (i = 0; patterns[i]; i++)
	    if (fnmatch(patterns[i], name, FNM_PATHNAME|FNM_PERIOD) == 0)
		return 1;
    }
    return 0;
}

char const *ignored_file_patterns[] = {
    ".*",
    "*~",
    "#*#",
    NULL
};

int
is_ignored_file_name(char const *name)
{
   return patmatch(ignored_file_patterns, name);
}
