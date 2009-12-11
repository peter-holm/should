# C Makefile for should

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

include ../Configure.make
include ../Site.make

OBJECTS = client.o checksum.o compress.o config.o error.o \
	  mymalloc.o protocol.o socket.o usermap.o
THREADS = main_thread.o notify_thread.o control_thread.o \
	  store_thread.o copy_thread.o
PROGRAMS = should

.PHONY : all

all : depend $(OBJECTS) $(THREADS) $(PROGRAMS)

depend : *.c *.h ../Configure.make
	$(CC) $(CFLAGS) -MM *.c > depend

should : $(OBJECTS) $(THREADS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o should $(OBJECTS) $(THREADS) $(LDFLAGS) 

install : all
	install -d $(INSTALLBIN)
	install should $(INSTALLBIN)

include depend

.PHONY : clean

clean :
	rm -f $(OBJECTS) $(THREADS) depend

.PHONY : realclean

realclean :
	rm -f $(OBJECTS) $(THREADS) $(PROGRAMS) depend

.PHONY : TODO

TODO :
	@grep '\<TODO\>\|\<XXX\>' *.[ch] && echo || true

.PHONY : XXX

XXX :
	@grep '\<TODO\>\|\<XXX\>' *.[ch] || true

