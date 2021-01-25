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
