#ifndef __SHOULD_PROTOCOL_H__
#define __SHOULD_PROTOCOL_H__ 1

/* functions to encode and decode data in a network-independent way
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include <time.h>
#include "notify_thread.h"
#include "store_thread.h"
#include "socket.h"

/* server status information */

typedef struct {
    int shouldbox;
    struct timespec running;
    struct timespec usertime;
    struct timespec systime;
    long long memory;
    int clients;
    notify_status_t ns;
    store_status_t cs;
    int server_pid;
    int version[3];
} protocol_status_t;

/* sends status information to a file */

const char * protocol_status_send(socket_t *, const protocol_status_t *);

/* receives status information from a file */

const char * protocol_status_receive(socket_t *, protocol_status_t *);

#endif /* __SHOULD_PROTOCOL_H__ */
