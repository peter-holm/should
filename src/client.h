/* interface to should's main thread when running in client mode
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

#ifndef __SHOULD_CLIENT_H__
#define __SHOULD_CLIENT_H__ 1

#include "socket.h"

/* type used to determine which extensions are supported by the server */

typedef enum {
    client_ext_checksum    = 0x01,
    client_ext_encrypt     = 0x02,
    client_ext_ignore      = 0x04,
    client_ext_none        = 0x00
} client_extensions_t;

int client_run(void);

/* ask the server for a list of extension and return the ones this client
 * knows about */

client_extensions_t client_get_extensions(socket_t *);

/* determine which checksum methods are supported by both server and client,
 * and returns the ID for the preferred one (or -1 if none found) */

int client_find_checksum(socket_t *, client_extensions_t);

/* determine which compression methods are supported by both server and client,
 * and returns the ID for the preferred one (or -1 if none found) */

int client_find_compress(socket_t *);

/* set up an external copy program, if configured; returns 1 if OK, 0
 * if an error occurred (errno will be set accordingly) */

int client_setup_extcopy(int * extcopy, pid_t * pid);

/* set connection parameters for file copy etc. */

int client_set_parameters(socket_t *);

/* sends a command to the server and verifies error code; if OK, returns
 * 1; otherwise it reports the error and returns 0; the data argument, if
 * not NULL, is sent immediately after the command, without terminating
 * CRLF; if the last argument is not NULL, the OK reply from the server
 * is copied there */

int client_send_command(socket_t * p, const char * command,
		 	const char * data, char * replbuff);

#endif /* __SHOULD_CLIENT_H__ */
