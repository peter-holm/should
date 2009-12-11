#ifndef __SHOULD_SOCKET_H__
#define __SHOULD_SOCKET_H__ 1

/* communicate with a running instance of should: either via a local
 * UNIX domain socket, or via a network connection
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

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

socket_t * socket_listen(const config_t * cfg);

/* accept next connection */

socket_t * socket_accept(socket_t * p, int timeout);

/* connect to a running server, TCP or UNIX domain */

socket_t * socket_connect(const config_t * cfg);

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

/* closes connection */

void socket_disconnect(socket_t *);

#endif /* __SHOULD_SOCKET_H__ */
