/* functions to encode and decode data in a network-independent way
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
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
    sprintf(buffer, "%s: %ld.%03ld", \
	    n, v.tv_sec, v.tv_nsec / 1000000L); \
    if (! socket_puts(p, buffer)) \
	return error_sys("protocol_status_send", "socket_puts");
#if USE_SHOULDBOX
    SEND_INT("shouldbox", S->shouldbox);
#endif
    SEND_TIME("running", S->running);
    SEND_TIME("usertime", S->usertime);
    SEND_TIME("systime", S->systime);
    SEND_LONG("memory", S->memory);
    SEND_INT("clients", S->clients);
    SEND_INT("queue_events", S->ns.queue_events);
    SEND_INT("queue_bytes", S->ns.queue_bytes);
    SEND_INT("queue_min", S->ns.queue_min);
    SEND_INT("queue_max", S->ns.queue_max);
    SEND_INT("queue_cur", S->ns.queue_cur);
    SEND_INT("max_events", S->ns.max_events);
    SEND_INT("max_bytes", S->ns.max_bytes);
    SEND_INT("overflow", S->ns.overflow);
    SEND_INT("too_big", S->ns.too_big);
    SEND_INT("watches", S->ns.watches);
    SEND_INT("watchmem", S->ns.watchmem);
    SEND_INT("events", S->ns.events);
    SEND_INT("kernel_max_watches", S->ns.kernel_max_watches);
    SEND_INT("kernel_max_events", S->ns.kernel_max_events);
    SEND_INT("file_earliest", S->cs.file_earliest);
    SEND_INT("file_current", S->cs.file_current);
    SEND_INT("file_pos", S->cs.file_pos);
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
    while (*line && isspace(*line)) line++;
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

static int store_time(const char * line, const char * kw, struct timespec * res) {
    line = store_kw(line, kw);
    if (! line) return 0;
    if (sscanf(line, "%ld.%ld", &res->tv_sec, &res->tv_nsec) < 2)
	return 0;
    res->tv_nsec *= 1000000L;
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
    while (socket_gets(p, line, LINESIZE)) {
	if (line[0] == '.') return NULL;
#define RECV_INT(n, p) if (store_int(line, n, &p)) continue;
#define RECV_LONG(n, p) if (store_long(line, n, &p)) continue;
#define RECV_TIME(n, p) if (store_time(line, n, &p)) continue;
#if USE_SHOULDBOX
	RECV_INT("shouldbox", S->shouldbox);
#else
	int sb;
	RECV_INT("shouldbox", sb);
#endif
	RECV_TIME("running", S->running);
	RECV_TIME("usertime", S->usertime);
	RECV_TIME("systime", S->systime);
	RECV_LONG("memory", S->memory);
	RECV_INT("clients", S->clients);
	RECV_INT("queue_events", S->ns.queue_events);
	RECV_INT("queue_bytes", S->ns.queue_bytes);
	RECV_INT("queue_min", S->ns.queue_min);
	RECV_INT("queue_max", S->ns.queue_max);
	RECV_INT("queue_cur", S->ns.queue_cur);
	RECV_INT("max_events", S->ns.max_events);
	RECV_INT("max_bytes", S->ns.max_bytes);
	RECV_INT("overflow", S->ns.overflow);
	RECV_INT("too_big", S->ns.too_big);
	RECV_INT("watches", S->ns.watches);
	RECV_INT("watchmem", S->ns.watchmem);
	RECV_INT("events", S->ns.events);
	RECV_INT("kernel_max_watches", S->ns.kernel_max_watches);
	RECV_INT("kernel_max_events", S->ns.kernel_max_events);
	RECV_INT("file_earliest", S->cs.file_earliest);
	RECV_INT("file_current", S->cs.file_current);
	RECV_INT("file_pos", S->cs.file_pos);
	RECV_INT("pid", S->server_pid);
	if (store_list(line, "version", 3, S->version)) continue;
#undef RECV_INT
#undef RECV_LONG
#undef RECV_TIME
    }
    return "Missing end of list";
}

