# Top-level makefile for "should"

# this file is part of SHOULD

# Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>

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

include Site.make
include Configure.make

SRCDIRS = src
PERLDIRS = perl
DOCDIRS = doc
INSTDIRS = $(SRCDIRS) $(PERLDIRS) $(DOCDIRS)
VERSION = 1.0.-5

.PHONY : all

all : Configure.make perl/Makefile
	@for sd in $(SRCDIRS) $(PERLDIRS); \
	    do (cd "$$sd" && $(MAKE) all) || exit 1; done

Configure.make : configure
	./configure

perl/Makefile : perl/Makefile.PL Site.make
	cd perl && perl Makefile.PL $(MAKEFILE_PL)

.PHONY : dist
dist : should-$(VERSION).tar.bz2

.PHONY : should-$(VERSION).tar.bz2
should-$(VERSION).tar.bz2 :
	mkdir should-$(VERSION)
	rsync -aq --files-from=MANIFEST ./ should-$(VERSION)/
	tar cvjf should-$(VERSION).tar.bz2 should-$(VERSION)
	rm -r should-$(VERSION)

.PHONY : depend

depend :
	@for sd in $(SRCDIRS); do (cd "$$sd" && $(MAKE) depend); done

.PHONY : install

install :
	@for sd in $(INSTDIRS); \
	    do (cd "$$sd" && $(MAKE) install VERSION=$(VERSION)) || exit 1; \
	    done

.PHONY : clean

clean :
	-@for sd in $(SRCDIRS); do (cd "$$sd" && $(MAKE) clean); done
	-@for sd in $(PERLDIRS); do (cd "$$sd" && $(MAKE) clean); done

.PHONY : realclean
.PHONY : distclean

realclean distclean :
	-@for sd in $(SRCDIRS); do (cd "$$sd" && $(MAKE) realclean); done
	-@for sd in $(PERLDIRS); do (cd "$$sd" && $(MAKE) realclean); done
	rm Configure.make

.PHONY : TODO

TODO :
	@for sd in $(SRCDIRS); do (cd "$$sd" && $(MAKE) TODO); done
	@[ -f TODO ] && cat TODO

.PHONY : XXX

XXX :
	@for sd in $(SRCDIRS); do (cd "$$sd" && $(MAKE) XXX); done

