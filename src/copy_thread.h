/* interface to should's copy thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SHOULD_COPY_THREAD_H__
#define __SHOULD_COPY_THREAD_H__ 1

#include <time.h>
#include "socket.h"

/* type used to return information about event processed */

typedef struct {
    int file_current;  /* current event file */
    int file_pos;      /* bytes in the current event file */
    int events;        /* events processed since startup */
    int dirsyncs;      /* dirsyncs currently pending */
    long long rbytes;  /* bytes read from server */
    long long wbytes;  /* bytes written to server */
    long long tbytes;  /* file data bytes (total) */
    long long xbytes;  /* file data bytes (actually transferred) */
} copy_status_t;

/* initialisation required before the copy thread starts; returns
 * NULL if OK, or an error message */

const char * copy_init(void);

/* run copy thread */

void copy_thread(void);

/* cleanup required after the copy thread terminates */

void copy_exit(void);

/* copy a single file from the server; from is the path on the server, to
 * is the path on the client; if tr_ids is nonzero the server will look up
 * user and group IDs and send them as strings, and the client will translate
 * them back to IDs, if tr_ids is 0 the IDs are copied untranslated;
 * if compression is nonnegative it identifies a compression method to
 * use to copy the file data; if checksum is nonnegative it identifies a
 * checksum method to use to avoid copying data already present in the client;
 * both compression and checksum must have already been set up on the server;
 * extcopy is an open file descriptor to the external copy program, or -1
 * to use the internal copy */

void copy_file(socket_t * p, const char * from, const char * to, int tr_ids,
	       int compression, int checksum, int extcopy);

/* returns current event files information etc */

void copy_status(copy_status_t *);

/* schedules an immediate dirsync of server:from/path to client:to/path */

int copy_dirsync(const char * reason, const char * path);

/* time of the last full dirsync */

time_t copy_last_dirsync(void);

#endif /* __SHOULD_COPY_THREAD_H__ */
