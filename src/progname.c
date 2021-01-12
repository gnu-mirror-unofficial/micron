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

