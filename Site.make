# compiler definitions (this file may be automatically generated in future)

# this file is part of SHOULD

# Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>

# Licenced under the terms of the GPL v3. See file COPYING in the
# distribution for further details.

CC = gcc
CFLAGS += -pthread -Wall -O2 -g -DUSE_SYSINOTIFY=0
LDFLAGS += -lrt -lssl -lz -lbz2

