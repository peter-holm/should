# C Makefile for should

# this file is part of SHOULD

# Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>

# Licenced under the terms of the GPL v3. See file COPYING in the
# distribution for further details.

include ../Site.make

OBJECTS = client.o compress.o config.o error.o mymalloc.o protocol.o socket.o usermap.o
THREADS = main_thread.o notify_thread.o control_thread.o store_thread.o
PROGRAMS = should

.PHONY : all

all : $(OBJECTS) $(THREADS) $(PROGRAMS)

depend : *.c *.h
	$(CC) $(CFLAGS) -MM *.c > depend

should : $(OBJECTS) $(THREADS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o should $(OBJECTS) $(THREADS)

include depend

.PHONY : clean

clean :
	rm -f $(OBJECTS) $(THREADS) depend

.PHONY : realclean

realclean :
	rm -f $(OBJECTS) $(THREADS) $(PROGRAMS) depend Site.make

.PHONY : TODO

TODO :
	@grep '\<TODO\>\|\<XXX\>' *.[ch] && echo || true
	@[ -f TODO ] && cat TODO

.PHONY : XXX

XXX :
	@grep '\<TODO\>\|\<XXX\>' *.[ch] || true

