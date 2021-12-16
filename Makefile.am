## Top-level Makefile.am for GNU micron.
## Copyright (C) 2020-2021 Sergey Poznyakoff
##
## GNU micron is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 3 of the License, or (at your
## option) any later version.
##
## GNU micron is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with GNU micron. If not, see <http://www.gnu.org/licenses/>. */

ACLOCAL_AMFLAGS = -I m4 -I am
SUBDIRS=src doc tests
.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                    \
	   (git log --pretty='format:%ad  %cn  <%ae>%n%n%w(72,8,8)%s%n%n%b' \
                    --date=short;                                           \
            echo "";                                                        \
            echo "Local Variables:";                                        \
            echo "mode: change-log";                                        \
            echo "version-control: never";                                  \
            echo "buffer-read-only: t";                                     \
            echo "End:";                                                    \
            echo "";                                                        \
            sed -n -e '2,/^$$/s/^##//p' Makefile.am) > ChangeLog;           \
	fi
