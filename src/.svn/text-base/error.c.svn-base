/* report errors
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#define _XOPEN_SOURCE 600 /* for strerror_r */

#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include "error.h"
#include "config.h"
#include "main_thread.h"
#include "mymalloc.h"

#define LINE_SIZE 2048
#define TIMESTAMP 32
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define ARGSIZE 128
#define ARGS 5

static FILE * logfile;

typedef enum {
    arg_void,
    arg_int,
    arg_string,
    arg_errno,
    arg_addr
} arg_t;

/* user-defined error message */

typedef struct {
    error_dest_t destination;
    int facility;               /* facility, if using syslog */
    int changed;
    const char * message;       /* message */
    arg_t argdata[ARGS];
    char * free_me;
    const char * name;
} err_t;

#define DEST_INFO (error_dest_file)
#define DEST_WARN (error_dest_file)
#define DEST_ERR  (error_dest_file | error_dest_syslog)
#define DEST_CRIT (error_dest_file | error_dest_syslog)

static err_t errdata[error_MAX] = {
    [error_shouldbox_int]   = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s = %s",
				.argdata     = { arg_string, arg_string, arg_int, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_int",
				.changed     = 0,
    },
    [error_shouldbox_less]  = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s = %s < %s",
				.argdata     = { arg_string, arg_string, arg_int, arg_int, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_less",
				.changed     = 0,
    },
    [error_shouldbox_more]  = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s = %s > %s",
				.argdata     = { arg_string, arg_string, arg_int, arg_int, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_more",
				.changed     = 0,
    },
    [error_shouldbox_noteq] = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s = %s != %s = %s",
				.argdata     = { arg_string, arg_string, arg_int, arg_string, arg_int },
				.free_me     = NULL,
				.name        = "shouldbox_noteq",
				.changed     = 0,
    },
    [error_shouldbox_null]  = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s is NULL",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_null",
				.changed     = 0,
    },
    [error_shouldbox_misptr]= {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s points to the wrong place!",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_misptr",
				.changed     = 0,
    },
    [error_shouldbox_mod]   = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s = %s %% %s = %s != 0",
				.argdata     = { arg_string, arg_string, arg_int, arg_int, arg_int },
				.free_me     = NULL,
				.name        = "shouldbox_mod",
				.changed     = 0,
    },
    [error_shouldbox_notfound]= {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s not found",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "shouldbox_notfound",
				.changed     = 0,
    },
    [error_internal]        = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Internal error in %s: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "internal",
				.changed     = 0,
    },
    [error_allocation]      = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s: free() of invalid memory area!",
				.argdata     = { arg_string, arg_int, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "allocation",
				.changed     = 0,
    },
    [error_fork]            = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "fork(): %s",
				.argdata     = { arg_errno, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "fork",
				.changed     = 0,
    },
    [error_badevent]        = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Bad event descriptor: %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "badevent",
				.changed     = 0,
    },
    [error_bad_id]          = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Bad %d ID in event: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "bad_id",
				.changed     = 0,
    },
    [error_event]           = {
				.destination = DEST_CRIT,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error receiving event: %s",
				.argdata     = { arg_errno, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "event",
				.changed     = 0,
    },
    [error_add_watch]       = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot add watch %2$s: %1$s",
				.argdata     = { arg_errno, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "add_watch",
				.changed     = 0,
    },
    [error_rename_watch]    = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot rename watch %s to %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "rename_watch",
				.changed     = 0,
    },
    [error_rename_unknown]  = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot rename unknown watch %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "rename_unknown",
				.changed     = 0,
    },
    [error_rename_exists]   = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Rename: %s already exists",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "rename_exists",
				.changed     = 0,
    },
    [error_rename_children] = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Rename: %s has a subtree",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "rename_children",
				.changed     = 0,
    },
    [error_buffer_tiny]     = {
				.destination = DEST_WARN,
				.facility    = LOG_LOCAL0 | LOG_WARNING,
				.message     = "Buffer should be increased to at least %s",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "buffer_tiny",
				.changed     = 0,
    },
    [error_extending_queue] = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error extending queue: %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "extending_queue",
				.changed     = 0,
    },
    [error_queue_too_small] = {
				.destination = DEST_WARN,
				.facility    = LOG_LOCAL0 | LOG_WARNING,
				.message     = "Queue too small, consider increasing size",
				.argdata     = { arg_void, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "queue_too_small",
				.changed     = 0,
    },
    [error_connect]         = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error accepting connection: %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "connect",
				.changed     = 0,
    },
    [error_server]          = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Server thread error: %s: %s: %s",
				.argdata     = { arg_addr, arg_string, arg_errno, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "server",
				.changed     = 0,
    },
    [error_server_msg]      = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Server thread error: %s: %s: %s",
				.argdata     = { arg_addr, arg_string, arg_string, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "server_msg",
				.changed     = 0,
    },
    [error_start]           = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error initialising %s thread: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "start",
				.changed     = 0,
    },
    [error_create]          = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error creating %s thread: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "create",
				.changed     = 0,
    },
    [error_control]         = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error adding watch %s: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "control",
				.changed     = 0,
    },
    [error_run]             = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error running %s thread: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "run",
				.changed     = 0,
    },
    [error_lock]            = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: locking: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "lock",
				.changed     = 0,
    },
    [error_invalid]         = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Internal error: invalid error code %s",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "invalid",
				.changed     = 0,
    },
    [error_scan_dir]        = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "scan_dir: %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "scan_dir",
				.changed     = 0,
    },
    [error_scan_find]       = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "scan_find: %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "scan_find",
				.changed     = 0,
    },
    [error_client]          = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "client",
				.changed     = 0,
    },
    [error_client_msg]      = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "%s: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "client_msg",
				.changed     = 0,
    },
    [error_setup]           = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Copy setup: %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "setup",
				.changed     = 0,
    },
    [error_readcopy]        = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Read copy state: %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "readcopy",
				.changed     = 0,
    },
    [error_readcopy_fmt]    = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Read copy state: %s: invalid file format",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "readcopy_fmt",
				.changed     = 0,
    },
    [error_readcopy_compress]={
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Read copy state: %s: invalid compress method %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "readcopy_compress",
				.changed     = 0,
    },
    [error_readcopy_locked] = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Read copy state: % is locked by another process",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "readcopy_locked",
				.changed     = 0,
    },
    [error_copy_sys]        = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error copying %s: %s",
				.argdata     = { arg_string, arg_errno, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_sys",
				.changed     = 0,
    },
    [error_copy_rename]     = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Error renaming %s to %s) %s",
				.argdata     = { arg_string, arg_string, arg_errno, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_rename",
				.changed     = 0,
    },
    [error_copy_invalid]    = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Invalid reply while copying %s: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_invalid",
				.changed     = 0,
    },
    [error_copy_short]      = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Unexpected EOF while copying %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_short",
				.changed     = 0,
    },
    [error_copy_socket]     = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot copy %s: is a socket",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_socket",
				.changed     = 0,
    },
    [error_copy_uncompress] = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot copy %s: error while uncompressing: %s",
				.argdata     = { arg_string, arg_string, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_uncompress",
				.changed     = 0,
    },
    [error_copy_unknown]    = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Cannot copy %s: unknown file type",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "copy_unknown",
				.changed     = 0,
    },
    [error_unimplemented]   = {
				.destination = DEST_ERR,
				.facility    = LOG_LOCAL0 | LOG_ERR,
				.message     = "Not implemented: %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "unimplemented",
				.changed     = 0,
    },
    [info_normal_operation] = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Entering normal operation",
				.argdata     = { arg_void, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "normal_operation",
				.changed     = 0,
    },
    [info_initial_watches]  = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Added %s initial watch(es)",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "initial_watches",
				.changed     = 0,
    },
    [info_user_stop]        = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "User requested program stop",
				.argdata     = { arg_void, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "user_stop",
				.changed     = 0,
    },
    [info_adding_watch]     = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Adding watch: %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "adding_watch",
				.changed     = 0,
    },
    [info_removing_watch]   = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Removing watch: %s",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "removing_watch",
				.changed     = 0,
    },
    [info_signal_received]  = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Received signal #%s",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "signal_received",
				.changed     = 0,
    },
    [info_extending_buffer] = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Extending buffer to %s blocks",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "extending_buffer",
				.changed     = 0,
    },
    [info_connection_open]  = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Accepting connection from %s@%s",
				.argdata     = { arg_string, arg_addr, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "connection_open",
				.changed     = 0,
    },
    [info_connection_close] = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Closing connection from %s@%s",
				.argdata     = { arg_string, arg_addr, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "connection_close",
				.changed     = 0,
    },
    [info_count_watches]    = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "%s directories watched",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "count_watches",
				.changed     = 0,
    },
    [info_stop_thread]      = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Stopping %s thread",
				.argdata     = { arg_string, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "stop_thread",
				.changed     = 0,
    },
    [info_detach]           = {
				.destination = error_dest_stderr,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "Detaching, PID is %s",
				.argdata     = { arg_int, arg_void, arg_void, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "detach",
				.changed     = 0,
    },
    [info_changelog]        = {
				.destination = DEST_INFO,
				.facility    = LOG_LOCAL0 | LOG_INFO,
				.message     = "%-6s %-4s %s",
				.argdata     = { arg_string, arg_string, arg_string, arg_void, arg_void },
				.free_me     = NULL,
				.name        = "info_changelog",
				.changed     = 0,
    },
};

/* prepares for error reports */

static config_t config_data;

void error_init(const config_t * cfg) {
    config_data = *cfg;
    logfile = NULL;
    openlog(config_data.error_ident, LOG_ODELAY | LOG_PID, 0);
}

/* fills a buffer with a timestamp value */
inline void set_timestamp(char buffer[TIMESTAMP], time_t when) {
    struct tm tm_when;
    /* there is no reason why either localtime_r or strftime could fail...
     * but that's no excuse to avoid checking for it
     */
    if (localtime_r(&when, &tm_when) == 0 ||
        strftime(buffer, TIMESTAMP, TIME_FORMAT, &tm_when) == 0)
    {
	snprintf(buffer, TIMESTAMP, "(time=%lld)", (long long)when);
    }
}

/* prepares an error message after a failed system call; the message is
 * stored in a static area; this is only used during initialisation when
 * reporting conditions which prevent the program from running */

static char err_name[LINE_SIZE];
const char * error_sys(const char * caller, const char * called) {
    return error_sys_errno_r(err_name, LINE_SIZE, caller, called, errno);
}

/* same, but takes an explicit "errno" value */

const char * error_sys_errno(const char * caller, const char * called,
			     int code)
{
    return error_sys_errno_r(err_name, LINE_SIZE, caller, called, code);
}

/* like error_sys and error_sys_errno, but thread safe; caller provides
 * a pre-allocated buffer */

char * error_sys_r(char * buffer, int len,
		   const char * caller, const char * called)
{
    return error_sys_errno_r(buffer, len, caller, called, errno);
}

char * error_sys_errno_r(char * ptr, int buflen,
			 const char * caller, const char * called,
			 int code)
{
    int len, remain;
    len = strlen(caller);
    if (len > buflen / 3) len = buflen / 3;
    strncpy(ptr, caller, len);
    ptr += len;
    remain = buflen - len;
    *ptr++ = ':';
    *ptr++ = ' ';
    len = strlen(called);
    if (len > buflen / 2) len = buflen / 2;
    strncpy(ptr, called, len);
    ptr += len;
    remain -= len;
    *ptr++ = ':';
    *ptr++ = ' ';
    /* note: we are using the XSI standard strerror_r, not the GNU one */
    if (strerror_r(code, ptr, remain) < 0)
	snprintf(ptr, remain, "errno=%d", code);
    return ptr;
}

/* reports an error during normal operation */

void error_report(error_message_t em, ...) {
    int i, dest, uselog, ec;
    err_t ed;
    char buffers[ARGS][ARGSIZE + 1], timestamp[TIMESTAMP];
    const char * bptr[ARGS], * msg;
    va_list ap;
    struct sockaddr_storage * addr;
    if (em >= error_MAX) {
	error_report(error_invalid, em);
	return;
    }
    ed = errdata[em];
    va_start(ap, em);
    for (i = 0; i < ARGS; i++) {
	switch(ed.argdata[i]) {
	    case arg_void :
		bptr[i] = "";
		break;
	    case arg_addr :
		addr = va_arg(ap, struct sockaddr_storage *);
		switch (addr->ss_family) {
		    case AF_UNIX : {
			struct sockaddr_un * un = (struct sockaddr_un *)addr;
			if (* un->sun_path)
			    bptr[i] = un->sun_path;
			else
			    bptr[i] = "(unnamed socket)";
			break;
		    }
		    case AF_INET : {
			struct sockaddr_in * in = (struct sockaddr_in*)addr;
			if (inet_ntop(addr->ss_family, &in->sin_addr,
				      buffers[i], ARGSIZE))
			    bptr[i] = buffers[i];
			else 
			    bptr[i] = "(inet socket)";
			break;
		    }
		    case AF_INET6 : {
			struct sockaddr_in6 * in = (struct sockaddr_in6*)addr;
			if (inet_ntop(addr->ss_family, &in->sin6_addr,
				      buffers[i], ARGSIZE))
			    bptr[i] = buffers[i];
			else 
			    bptr[i] = "(inet6 socket)";
			break;
		    }
		    default :
			bptr[i] = "(socket)";
			break;
		}
		break;
	    case arg_int :
		snprintf(buffers[i], ARGSIZE, "%d", va_arg(ap, int));
		buffers[i][ARGSIZE] = 0;
		bptr[i] = buffers[i];
		break;
	    case arg_string :
		bptr[i] = va_arg(ap, const char *);
		break;
	    case arg_errno :
		ec = va_arg(ap, int);
		/* note: we are using the XSI standard strerror_r, not the GNU one */
		if (strerror_r(ec, buffers[i], ARGSIZE) < 0)
		    snprintf(buffers[i], ARGSIZE, "(errno=%d)", ec);
		bptr[i] = buffers[i];
		break;
	}
    }
    va_end(ap);
    set_timestamp(timestamp, time(NULL));
    dest = ed.destination;
    msg = ed.message;
    if (config_data.error_email &&
	config_data.error_submit &&
	(dest & error_dest_email))
    {
	/* XXX send email to config_data.error_email */
    }
    /* if we use a log file or stderr we lock stderr now: as a result:
     * 1. we eliminate race conditions in the if(!logfile)
     * 2. if the logfile cannot be opened the error message on stderr is
     *    followed immediately by the one which caused the open
     * 3. there is no need to lock the logfile as well */
    uselog = dest & (error_dest_file | error_dest_stderr);
    if (uselog) flockfile(stderr);
    if (dest & error_dest_file) {
	if (! logfile) {
	    logfile = fopen(config_data.error_logfile, "a");
	    if (! logfile) {
		fprintf(stderr, "%s  %s:  ",
			timestamp, config_data.error_ident);
		perror(config_data.error_logfile);
		dest |= error_dest_stderr;
	    }
	}
	if (logfile) {
	    fprintf(logfile, "%s  %s:  ", timestamp, config_data.error_ident);
	    fprintf(logfile, msg, bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
	    fprintf(logfile, "\n");
	    fflush(logfile);
	}
    }
    if (dest & error_dest_stderr) {
	fprintf(stderr, "%s  %s:  ", timestamp, config_data.error_ident);
	fprintf(stderr, msg, bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
	fprintf(stderr, "\n");
    }
    if (uselog) funlockfile(stderr);
    if (dest & error_dest_syslog) {
	syslog(ed.facility, msg, bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
    }
}

/* closes logfile: it will be reopened next time a message is logged; can
 * be used after rotating logs */

void error_closelog(void) {
    if (logfile) fclose(logfile);
    logfile = NULL;
}

/* change an error message; caller allocates string with mymalloc, and they
 * also myfree() it if they get an error */

const char * error_change_message(error_message_t em, char * msg) {
    if (em < error_MAX) {
	int old, new, ptr;
	const char * omsg = errdata[em].message;
	/* do a simple validity check, and make sure it contains the
	 * same number of %...s formats */
	for (old = ptr = 0; omsg[ptr]; ptr++) {
	    if (omsg[ptr] == '%' && omsg[ptr + 1] != '%') {
		ptr++;
		if (omsg[ptr] != '%')
		    old++;
	    }
	}
	for (new = ptr = 0; msg[ptr]; ptr++) {
	    if (msg[ptr] == '%') {
		ptr++;
		if (msg[ptr] != '%') {
		    if (msg[ptr] == '-') ptr++;
		    while (msg[ptr] && isdigit(msg[ptr])) ptr++;
		    if (msg[ptr] != 's')
			return "Invalid conversion, use %s";
		    new++;
		}
	    }
	}
	if (old != new)
	    return "Invalid message: wrong number of conversions";
	if (errdata[em].free_me) myfree (errdata[em].free_me);
	errdata[em].message = msg;
	errdata[em].free_me = msg;
	return NULL;
    } else {
	return "Invalid error code";
    }
}

/* get current error message */

const char * error_get_message(error_message_t em) {
    if (em < error_MAX)
	return errdata[em].message;
    return "?";
}

/* change an error destination: facility is only used with syslog */

void error_change_dest(error_message_t em, error_dest_t dest, int facility) {
    if (em < error_MAX) {
	errdata[em].destination = dest;
	errdata[em].facility = facility;
	errdata[em].changed = 1;
    }
}

/* get current destination and facility */

error_dest_t error_get_dest(error_message_t em) {
    if (em < error_MAX)
	return errdata[em].destination;
    return error_dest_stderr;
}

int error_get_facility(error_message_t em) {
    if (em < error_MAX)
	return errdata[em].facility;
    return 0;
}

/* check if an error destination has been changed from its default; returns
 * 0 if no, 1 if yes, -1 if invalid */

int error_dest_changed(error_message_t em) {
    if (em < error_MAX)
	return errdata[em].changed;
    return -1;
}

/* get an error code from its name */

error_message_t error_code(const char * name, int len) {
    error_message_t em;
    for (em = 0; em < error_MAX; em++)
	if (strncmp(errdata[em].name, name, len) == 0)
	    if (strlen(errdata[em].name) == len)
		return em;
    return error_MAX;
}

/* get error name from its code */

const char * error_name(error_message_t em) {
    if (em < error_MAX)
	return errdata[em].name;
    return "?";
}

/* frees any allocated error messages */

void error_free(void) {
    error_message_t em;
    for (em = 0; em < error_MAX; em++)
	if (errdata[em].free_me)
	    myfree(errdata[em].free_me);
}

