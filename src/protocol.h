/* functions to encode and decode data in a network-independent way
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
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

#ifndef __SHOULD_PROTOCOL_H__
#define __SHOULD_PROTOCOL_H__ 1

#include <time.h>
#include "notify_thread.h"
#include "store_thread.h"
#include "copy_thread.h"
#include "socket.h"

/* server status information */

typedef struct {
    int shouldbox;
    struct timespec running;
    struct timespec usertime;
    struct timespec systime;
    long long memory;
    int clients;
    notify_status_t notify;
    store_status_t store;
    copy_status_t copy;
    int has_status;
    int server_pid;
    int server_mode;
    int version[3];
} protocol_status_t;

/* sends status information to a file */

const char * protocol_status_send(socket_t *, const protocol_status_t *);

/* receives status information from a file */

const char * protocol_status_receive(socket_t *, protocol_status_t *);

#endif /* __SHOULD_PROTOCOL_H__ */
