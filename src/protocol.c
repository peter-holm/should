/* functions to encode and decode data in a network-independent way
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

#include "site.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "protocol.h"
#include "main_thread.h"
#include "notify_thread.h"
#include "store_thread.h"
#include "error.h"

#define TIMESIZE 128
#define LINESIZE 256

/* sends status information to a file */

const char * protocol_status_send(socket_t * p, const protocol_status_t * S) {
    char buffer[LINESIZE];
#define SEND_INT(n, v) \
    sprintf(buffer, "%s: %d", n, v); \
    if (! socket_puts(p, buffer)) \
	return error_sys("protocol_status_send", "socket_puts");
#define SEND_LONG(n, v) \
    sprintf(buffer, "%s: %lld", n, v); \
    if (! socket_puts(p, buffer)) \
	return error_sys("protocol_status_send", "socket_puts");
#define SEND_TIME(n, v) \
    sprintf(buffer, "%s: %lld.%09lld", n, (long long)v.tv_sec, (long long)v.tv_nsec); \
    if (! socket_puts(p, buffer)) \
	return error_sys("protocol_status_send", "socket_puts");
    SEND_INT("server_mode", S->server_mode);
#if USE_SHOULDBOX
    SEND_INT("shouldbox", S->shouldbox);
#endif
    SEND_TIME("running", S->running);
    SEND_TIME("usertime", S->usertime);
    SEND_TIME("systime", S->systime);
    SEND_LONG("memory", S->memory);
    SEND_INT("clients", S->clients);
    if (S->server_mode) {
#if NOTIFY != NOTIFY_NONE
	SEND_INT("queue_events", S->notify.queue_events);
	SEND_INT("queue_bytes", S->notify.queue_bytes);
	SEND_INT("queue_min", S->notify.queue_min);
	SEND_INT("queue_max", S->notify.queue_max);
	SEND_INT("queue_cur", S->notify.queue_cur);
	SEND_INT("max_events", S->notify.max_events);
	SEND_INT("max_bytes", S->notify.max_bytes);
	SEND_INT("overflow", S->notify.overflow);
	SEND_INT("too_big", S->notify.too_big);
	SEND_INT("watches", S->notify.watches);
	SEND_INT("watchmem", S->notify.watchmem);
	SEND_INT("events", S->notify.events);
	SEND_INT("kernel_max_watches", S->notify.kernel_max_watches);
	SEND_INT("kernel_max_events", S->notify.kernel_max_events);
	SEND_INT("file_earliest", S->store.file_earliest);
	SEND_INT("file_current", S->store.file_current);
	SEND_INT("file_pos", S->store.file_pos);
#endif /* NOTIFY != NOTIFY_NONE */
    } else {
	SEND_INT("read_file_num", S->copy.file_current);
	SEND_INT("read_file_pos", S->copy.file_pos);
	SEND_INT("events_copied", S->copy.events);
	SEND_INT("pending_dirsyncs", S->copy.dirsyncs);
	SEND_TIME("event_time", S->copy.etime);
	SEND_LONG("bytes_received", S->copy.rbytes);
	SEND_LONG("bytes_sent", S->copy.wbytes);
	SEND_LONG("file_data_total", S->copy.tbytes);
	SEND_LONG("file_data_xfer", S->copy.xbytes);
    }
    SEND_INT("pid", S->server_pid);
#undef SEND_INT
#undef SEND_LONG
#undef SEND_TIME
    sprintf(buffer, "version: %d.%d.%d",
	   VERSION_MAJOR, VERSION_MINOR, VERSION_OFFSET);
    if (! socket_puts(p, buffer))
	return error_sys("protocol_status_send", "socket_puts");
    if (! socket_puts(p, "."))
	return error_sys("protocol_status_send", "socket_puts");
    return NULL;
}

/* receives status information from a file */

static const char * store_kw(const char * line, const char * kw) {
    int len = strlen(kw);
    if (strncmp(line, kw, len) != 0) return NULL;
    if (strlen(line) < len) return NULL;
    if (line[len] != ':') return NULL;
    line += len + 1;
    while (*line && isspace((int)*line)) line++;
    return line;
}

static int store_int(const char * line, const char * kw, int * res) {
    line = store_kw(line, kw);
    if (! line) return 0;
    *res = atoi(line);
    return 1;
}

static int store_long(const char * line, const char * kw, long long * res) {
    line = store_kw(line, kw);
    if (! line) return 0;
    *res = atoll(line);
    return 1;
}

static int store_time(const char * line, const char * kw,
		      struct timespec * res)
{
    long long sec, nsec;
    line = store_kw(line, kw);
    if (! line) return 0;
    if (sscanf(line, "%lld.%lld", &sec, &nsec) < 2)
	return 0;
    res->tv_sec = sec;
    res->tv_nsec = nsec;
    if (res->tv_nsec < 1000L) {
	/* older servers sent seconds.milliseconds */
	const char * p = line;
	int i;
	while (*p && isspace((int)*p)) p++;
	while (*p && isdigit((int)*p)) p++;
	if (*p == '.') p++;
	i = 0;
	while (p[i] && isdigit((int)p[i])) i++;
	if (i < 4)
	    res->tv_nsec *= 1000000L;
    }
    return 1;
}

static int store_list(const char * line, const char * kw, int N, int * R) {
    int i;
    line = store_kw(line, kw);
    if (! line) return 0;
    for (i = 0; i < N; i++) {
	const char * ep;
	if (! line) return 0;
	R[i] = atoi(line);
	ep = strchr(line, '.');
	if (ep)
	    line = ep + 1;
	else
	    line = NULL;
    }
    return 1;
}

const char * protocol_status_receive(socket_t * p, protocol_status_t * S) {
    char line[LINESIZE];
#if USE_SHOULDBOX
    S->shouldbox = -1;
#endif
    S->server_mode = 1;
    S->has_status = 0;
    while (socket_gets(p, line, LINESIZE)) {
	if (line[0] == '.') return NULL;
#define RECV_INT(n, p) if (store_int(line, n, &p)) continue;
#define RECV_INT_S(n, p) if (store_int(line, n, &p)) { S->has_status = 1; continue; }
#define RECV_LONG(n, p) if (store_long(line, n, &p)) continue;
#define RECV_TIME(n, p) if (store_time(line, n, &p)) continue;
#if USE_SHOULDBOX
	RECV_INT("shouldbox", S->shouldbox);
#else
	int sb;
	RECV_INT("shouldbox", sb);
#endif
	RECV_INT("server_mode", S->server_mode);
	RECV_TIME("running", S->running);
	RECV_TIME("usertime", S->usertime);
	RECV_TIME("systime", S->systime);
	RECV_LONG("memory", S->memory);
	RECV_INT("clients", S->clients);
	RECV_INT_S("queue_events", S->notify.queue_events);
	RECV_INT_S("queue_bytes", S->notify.queue_bytes);
	RECV_INT_S("queue_min", S->notify.queue_min);
	RECV_INT_S("queue_max", S->notify.queue_max);
	RECV_INT_S("queue_cur", S->notify.queue_cur);
	RECV_INT_S("max_events", S->notify.max_events);
	RECV_INT_S("max_bytes", S->notify.max_bytes);
	RECV_INT_S("overflow", S->notify.overflow);
	RECV_INT_S("too_big", S->notify.too_big);
	RECV_INT_S("watches", S->notify.watches);
	RECV_INT_S("watchmem", S->notify.watchmem);
	RECV_INT_S("events", S->notify.events);
	RECV_INT_S("kernel_max_watches", S->notify.kernel_max_watches);
	RECV_INT_S("kernel_max_events", S->notify.kernel_max_events);
	RECV_INT_S("file_earliest", S->store.file_earliest);
	RECV_INT_S("file_current", S->store.file_current);
	RECV_INT_S("file_pos", S->store.file_pos);
	RECV_INT("pid", S->server_pid);
	RECV_INT("read_file_num", S->copy.file_current);
	RECV_INT("read_file_pos", S->copy.file_pos);
	RECV_INT("events_copied", S->copy.events);
	RECV_INT("pending_dirsyncs", S->copy.dirsyncs);
	RECV_TIME("event_time", S->copy.etime);
	RECV_LONG("bytes_received", S->copy.rbytes);
	RECV_LONG("bytes_sent", S->copy.wbytes);
	RECV_LONG("file_data_total", S->copy.tbytes);
	RECV_LONG("file_data_xfer", S->copy.xbytes);
	if (store_list(line, "version", 3, S->version)) continue;
#undef RECV_INT
#undef RECV_LONG
#undef RECV_TIME
    }
    return "Missing end of list";
}

