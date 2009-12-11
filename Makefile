# Top-level makefile for "should"

# this file is part of SHOULD

# Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>

# Licenced under the terms of the GPL v3. See file COPYING in the
# distribution for further details.

SRCDIRS = src
SUBDIRS = $(SRCDIRS) perl docs
SUBMAKE = $(MAKE) --no-print-directory

.PHONY : all

all : 
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" all; done

.PHONY : depend

depend :
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" depend; done

.PHONY : install

install :
	@for sd in $(SUBDIRS); do $(SUBMAKE) -C "$$sd" install; done

.PHONY : clean

clean :
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" clean; done

.PHONY : realclean
.PHONY : distclean

realclean distclean :
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" realclean; done

.PHONY : TODO

TODO :
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" TODO; done

.PHONY : XXX

XXX :
	@for sd in $(SRCDIRS); do $(SUBMAKE) -C "$$sd" XXX; done

