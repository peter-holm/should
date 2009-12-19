# Local configuration for "should"

# this file is part of SHOULD

# Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING in the distribution).
# If not, see <http://www.gnu.org/licenses/>.

# generic installation prefix
PREFIX = /usr/local

# directory where we install binaries
INSTALLBIN = $(PREFIX)/bin

# directory where we install documentation (except manpages)
INSTALLDOC = $(PREFIX)/share/doc/should-$(VERSION)

# directory where we install manpages
INSTALLMAN = $(PREFIX)/share/man
INSTALLMAN1 = $(INSTALLMAN)/man1

# any arguments passed to Makefile.PL
MAKEFILE_PL = PREFIX=$(PREFIX)

