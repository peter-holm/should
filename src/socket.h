/* communicate with a running instance of should: either via a local
 * UNIX domain socket, or via a network connection
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>
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

#ifndef __SHOULD_SOCKET_H__
#define __SHOULD_SOCKET_H__ 1

#include <sys/socket.h>
#include "config.h"

/* used to represent a running connection */

typedef struct socket_s socket_t;

/* data structure used to receive one message */

typedef struct {
    int datalen;
    void * data;
} socket_receive_t;

/* data structure used to send one message */

typedef struct {
    int datalen;
    const void * data;
} socket_send_t;

/* prepare a socket suitable for listening on a UNIX path or TCP port */

socket_t * socket_listen(void);

/* accept next connection */

socket_t * socket_accept(socket_t * p, int timeout);

/* connect to a running server, TCP or UNIX domain */

socket_t * socket_connect(void);

/* send data on the socket: socket_put sends binary data, socket_puts
 * sends a line of text, terminated by CRLF */

int socket_put(socket_t *, const void *, int);
int socket_puts(socket_t *, const char *);

/* enable/disable autoflush by socket_put/socket_puts */

void socket_autoflush(socket_t *, int);

/* receive data from the socket: socket_get receives binary data,
 * socket_gets receives a line of text, up to a terminating CRLF
 * (which is not stored); socket_getc gets a single byte of binary data;
 * socket_getdata returns up to the required amount of data, but may
 * return less depending on what is available */

int socket_get(socket_t *, void *, int);
int socket_gets(socket_t *, char *, int);
int socket_getc(socket_t *);
int socket_getdata(socket_t *, void *, int);

/* returns file descriptor for use in poll / select */

int socket_poll(socket_t *);

/* connection information */

struct sockaddr_storage * socket_addr(socket_t *);
const char * socket_user(const socket_t *);
const char * socket_password(const socket_t *);
config_userop_t socket_actions(const socket_t *);
void socket_stats(socket_t *, long long * recv, long long * sent);

void socket_setdebug(socket_t *, int);

/* closes connection */

void socket_disconnect(socket_t *);

#endif /* __SHOULD_SOCKET_H__ */
