/* report errors
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
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
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
#include "pipe.h"

#define LINE_SIZE 2048
#define TIMESTAMP 32
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define ARGSIZE 128
#define ARGS 5

static FILE * logfile;

typedef enum {
    arg_void,
    arg_int,
    arg_llong,
    arg_string,
    arg_errno,
    arg_addr
} arg_t;

/* default error messages etc */

typedef struct {
    error_level_t level;        /* the error level */
    const char * defmsg;        /* default message */
    arg_t argtype[ARGS];        /* arguments it takes */
    const char * name;          /* name used to change the defaults */
} deferr_t;

static deferr_t deferr[error_MAX] = {
    [error_shouldbox_int] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s = %s",
	.argtype  = { arg_string, arg_string, arg_int, arg_void, arg_void },
	.name     = "shouldbox_int",
    },
    [error_shouldbox_less] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s = %s < %s",
	.argtype  = { arg_string, arg_string, arg_int, arg_int, arg_void },
	.name     = "shouldbox_less",
    },
    [error_shouldbox_more] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s = %s > %s",
	.argtype  = { arg_string, arg_string, arg_int, arg_int, arg_void },
	.name     = "shouldbox_more",
    },
    [error_shouldbox_noteq] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s = %s != %s = %s",
	.argtype  = { arg_string, arg_string, arg_int, arg_string, arg_int },
	.name     = "shouldbox_noteq",
    },
    [error_shouldbox_null] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s is NULL",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "shouldbox_null",
    },
    [error_shouldbox_misptr] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s points to the wrong place!",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "shouldbox_misptr",
    },
    [error_shouldbox_mod] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s = %s %% %s = %s != 0",
	.argtype  = { arg_string, arg_string, arg_int, arg_int, arg_int },
	.name     = "shouldbox_mod",
    },
    [error_shouldbox_notfound] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s not found",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "shouldbox_notfound",
    },
    [error_internal] = {
	.level    = error_level_crit,
	.defmsg   = "Internal error in %s: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "internal",
    },
    [error_allocation] = {
	.level    = error_level_crit,
	.defmsg   = "%s: %s: free() of invalid memory area!",
	.argtype  = { arg_string, arg_int, arg_void, arg_void, arg_void },
	.name     = "allocation",
    },
    [error_fork] = {
	.level    = error_level_crit,
	.defmsg   = "fork(): %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "fork",
    },
    [error_wait] = {
	.level    = error_level_crit,
	.defmsg   = "wait(): %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "wait",
    },
    [error_pipe] = {
	.level    = error_level_crit,
	.defmsg   = "pipe(): %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "pipe",
    },
    [error_badevent] = {
	.level    = error_level_crit,
	.defmsg   = "Bad event descriptor: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "badevent",
    },
    [error_baddirent] = {
	.level    = error_level_crit,
	.defmsg   = "Bad directory entry: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "baddirent",
    },
    [error_bad_id] = {
	.level    = error_level_crit,
	.defmsg   = "Bad %d ID in event: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "bad_id",
    },
    [error_event] = {
	.level    = error_level_crit,
	.defmsg   = "Error receiving event: %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "event",
    },
    [error_getdir] = {
	.level    = error_level_crit,
	.defmsg   = "Error receiving directory data for %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "getdir",
    },
    [error_cleanup] = {
	.level    = error_level_err,
	.defmsg   = "cleanup: %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "cleanup",
    },
    [error_accept] = {
	.level    = error_level_err,
	.defmsg   = "accept(): %s",
	.argtype  = { arg_errno, arg_void, arg_void, arg_void, arg_void },
	.name     = "accept",
    },
    [error_add_watch] = {
	.level    = error_level_err,
	.defmsg   = "Cannot add watch %2$s: %1$s",
	.argtype  = { arg_errno, arg_string, arg_void, arg_void, arg_void },
	.name     = "add_watch",
    },
    [error_rename_watch] = {
	.level    = error_level_err,
	.defmsg   = "Cannot rename watch %s to %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "rename_watch",
    },
    [error_rename_unknown] = {
	.level    = error_level_err,
	.defmsg   = "Cannot rename unknown watch %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "rename_unknown",
    },
    [error_rename_exists] = {
	.level    = error_level_err,
	.defmsg   = "Rename: %s already exists",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "rename_exists",
    },
    [error_rename_children] = {
	.level    = error_level_err,
	.defmsg   = "Rename: %s has a subtree",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "rename_children",
    },
    [error_buffer_tiny] = {
	.level    = error_level_warn,
	.defmsg   = "Buffer should be increased to at least %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "buffer_tiny",
    },
    [error_extending_queue] = {
	.level    = error_level_err,
	.defmsg   = "Error extending queue: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "extending_queue",
    },
    [error_queue_too_small] = {
	.level    = error_level_warn,
	.defmsg   = "Queue too small, consider increasing size",
	.argtype  = { arg_void, arg_void, arg_void, arg_void, arg_void },
	.name     = "queue_too_small",
    },
    [error_connect] = {
	.level    = error_level_err,
	.defmsg   = "Error accepting connection: %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "connect",
    },
    [error_server] = {
	.level    = error_level_err,
	.defmsg   = "Server thread error: %s: %s: %s",
	.argtype  = { arg_addr, arg_string, arg_errno, arg_void, arg_void },
	.name     = "server",
    },
    [error_server_msg] = {
	.level    = error_level_err,
	.defmsg   = "Server thread error: %s: %s: %s",
	.argtype  = { arg_addr, arg_string, arg_string, arg_void, arg_void },
	.name     = "server_msg",
    },
    [error_start] = {
	.level    = error_level_err,
	.defmsg   = "Error initialising %s thread: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "start",
    },
    [error_create] = {
	.level    = error_level_err,
	.defmsg   = "Error creating %s thread: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "create",
    },
    [error_control] = {
	.level    = error_level_err,
	.defmsg   = "Error adding watch %s: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "control",
    },
    [error_run] = {
	.level    = error_level_err,
	.defmsg   = "Error running %s thread: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "run",
    },
    [error_lock] = {
	.level    = error_level_err,
	.defmsg   = "%s: locking: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "lock",
    },
    [error_invalid] = {
	.level    = error_level_err,
	.defmsg   = "Internal error: invalid error code %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "invalid",
    },
    [error_scan_dir] = {
	.level    = error_level_err,
	.defmsg   = "scan_dir: %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "scan_dir",
    },
    [error_scan_find] = {
	.level    = error_level_err,
	.defmsg   = "scan_find: %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "scan_find",
    },
    [error_client] = {
	.level    = error_level_err,
	.defmsg   = "%s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "client",
    },
    [error_client_msg] = {
	.level    = error_level_err,
	.defmsg   = "%s: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "client_msg",
    },
    [error_setup] = {
	.level    = error_level_err,
	.defmsg   = "Copy setup: %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "setup",
    },
    [error_readcopy] = {
	.level    = error_level_err,
	.defmsg   = "Read copy state: %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "readcopy",
    },
    [error_readcopy_fmt] = {
	.level    = error_level_err,
	.defmsg   = "Read copy state: %s: invalid file format",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "readcopy_fmt",
    },
    [error_readcopy_compress] ={
	.level    = error_level_err,
	.defmsg   = "Read copy state: %s: invalid compress method %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "readcopy_compress",
    },
    [error_readcopy_locked] = {
	.level    = error_level_err,
	.defmsg   = "Read copy state: % is locked by another process",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "readcopy_locked",
    },
    [error_copy_sys] = {
	.level    = error_level_err,
	.defmsg   = "Error copying %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "copy_sys",
    },
    [error_copy_rename] = {
	.level    = error_level_err,
	.defmsg   = "Error renaming %s to %s) %s",
	.argtype  = { arg_string, arg_string, arg_errno, arg_void, arg_void },
	.name     = "copy_rename",
    },
    [error_copy_invalid] = {
	.level    = error_level_err,
	.defmsg   = "Invalid reply while copying %s: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "copy_invalid",
    },
    [error_copy_librsync] = {
	.level    = error_level_err,
	.defmsg   = "Unknown librsync error copying %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "copy_librsync",
    },
    [error_copy_librsync_sys] = {
	.level    = error_level_err,
	.defmsg   = "Librsync error while copying %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "copy_librsync_sys",
    },
    [error_copy_short] = {
	.level    = error_level_err,
	.defmsg   = "Unexpected EOF while copying %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "copy_short",
    },
    [error_copy_socket] = {
	.level    = error_level_err,
	.defmsg   = "Cannot copy %s: is a socket",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "copy_socket",
    },
    [error_copy_uncompress] = {
	.level    = error_level_err,
	.defmsg   = "Cannot copy %s: error while uncompressing: %s",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "copy_uncompress",
    },
    [error_copy_unknown] = {
	.level    = error_level_err,
	.defmsg   = "Cannot copy %s: unknown file type",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "copy_unknown",
    },
    [error_copy_sched_dirsync] = {
	.level    = error_level_err,
	.defmsg   = "Cannot schedule dirsync %s: %s",
	.argtype  = { arg_string, arg_errno, arg_void, arg_void, arg_void },
	.name     = "copy_sched_dirsync",
    },
    [error_unimplemented] = {
	.level    = error_level_err,
	.defmsg   = "Not implemented: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "unimplemented",
    },
    [error_notserver] = {
	.level    = error_level_err,
	.defmsg   = "Server is not in server mode",
	.argtype  = { arg_void, arg_void, arg_void, arg_void, arg_void },
	.name     = "notserver",
    },
    [error_nonotify] = {
	.level    = error_level_err,
	.defmsg   = "Server does not support notify",
	.argtype  = { arg_void, arg_void, arg_void, arg_void, arg_void },
	.name     = "nonotify",
    },
    [error_child_status] = {
	.level    = error_level_err,
	.defmsg   = "Child process exited with status %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "child_status",
    },
    [error_child_signal] = {
	.level    = error_level_err,
	.defmsg   = "Child process terminated by signal %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "child_signal",
    },
    [error_child_coredump] = {
	.level    = error_level_err,
	.defmsg   = "Child process terminated by signal %s (core dumped)",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "child_coredump",
    },
    [error_child_unknown] = {
	.level    = error_level_err,
	.defmsg   = "Child process terminated with unknown status %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "child_unknown",
    },
    [info_normal_operation] = {
	.level    = error_level_info,
	.defmsg   = "Entering normal operation",
	.argtype  = { arg_void, arg_void, arg_void, arg_void, arg_void },
	.name     = "normal_operation",
    },
    [info_initial_watches] = {
	.level    = error_level_info,
	.defmsg   = "Added %s initial watch(es)",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "initial_watches",
    },
    [info_user_stop] = {
	.level    = error_level_info,
	.defmsg   = "User requested program stop",
	.argtype  = { arg_void, arg_void, arg_void, arg_void, arg_void },
	.name     = "user_stop",
    },
    [info_adding_watch] = {
	.level    = error_level_info,
	.defmsg   = "Adding watch: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "adding_watch",
    },
    [info_removing_watch] = {
	.level    = error_level_info,
	.defmsg   = "Removing watch: %s",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "removing_watch",
    },
    [info_signal_received] = {
	.level    = error_level_info,
	.defmsg   = "Received signal #%s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "signal_received",
    },
    [info_extending_buffer] = {
	.level    = error_level_info,
	.defmsg   = "Extending buffer to %s blocks",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "extending_buffer",
    },
    [info_connection_open] = {
	.level    = error_level_info,
	.defmsg   = "Accepting connection from %s@%s",
	.argtype  = { arg_string, arg_addr, arg_void, arg_void, arg_void },
	.name     = "connection_open",
    },
    [info_connection_close] = {
	.level    = error_level_info,
	.defmsg   = "Closing connection from %s@%s",
	.argtype  = { arg_string, arg_addr, arg_void, arg_void, arg_void },
	.name     = "connection_close",
    },
    [info_count_watches] = {
	.level    = error_level_info,
	.defmsg   = "%s directories watched",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "count_watches",
    },
    [info_stop_thread] = {
	.level    = error_level_info,
	.defmsg   = "Stopping %s thread",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "stop_thread",
    },
    [info_detach] = {
	.level    = error_level_info,
	.defmsg   = "Detaching, PID is %s",
	.argtype  = { arg_int, arg_void, arg_void, arg_void, arg_void },
	.name     = "detach",
    },
    [info_changelog] = {
	.level    = error_level_info,
	.defmsg   = "%-6s %-4s %s",
	.argtype  = { arg_string, arg_string, arg_string, arg_void, arg_void },
	.name     = "info_changelog",
    },
    [info_replication_meta] = {
	.level    = error_level_info,
	.defmsg   = "replication: meta(%s, %s)",
	.argtype  = { arg_string, arg_int, arg_void, arg_void, arg_void },
	.name     = "info_replication_meta",
    },
    [info_replication_copy] = {
	.level    = error_level_info,
	.defmsg   = "replication: copy(%s, %s, %s)",
	.argtype  = { arg_string, arg_string, arg_llong, arg_void, arg_void },
	.name     = "info_replication_copy",
    },
    [info_replication_delete] = {
	.level    = error_level_info,
	.defmsg   = "replication: delete(%s)",
	.argtype  = { arg_string, arg_void, arg_void, arg_void, arg_void },
	.name     = "info_replication_delete",
    },
    [info_replication_rename] = {
	.level    = error_level_info,
	.defmsg   = "replication: rename(%s, %s)",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "info_replication_rename",
    },
    [info_sched_dirsync] = {
	.level    = error_level_info,
	.defmsg   = "scheduling %s dirsync \"%s\"",
	.argtype  = { arg_string, arg_string, arg_void, arg_void, arg_void },
	.name     = "info_sched_dirsync",
    },
};

/* prepares for error reports */

void error_init(void) {
    const config_data_t * cfg = config_get();
    logfile = NULL;
    openlog(config_strval(cfg, cfg_error_ident), LOG_ODELAY | LOG_PID, 0);
    config_put(cfg);
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

/* like error_sys and error_sys_errno, but thread safe; caller provides
 * a pre-allocated buffer */

char * error_sys_errno_r(char * ptr, int buflen, const char * caller,
			 const char * called, int code)
{
    int len, remain;
    len = strlen(caller);
    if (len > buflen / 3) len = buflen / 3;
    strncpy(ptr, caller, len);
    ptr += len;
    remain = buflen - len;
    *ptr++ = ':';
    *ptr++ = ' ';
    if (called) {
	len = strlen(called);
	if (len > buflen / 2) len = buflen / 2;
	strncpy(ptr, called, len);
	ptr += len;
	remain -= len;
	*ptr++ = ':';
	*ptr++ = ' ';
    }
    /* note: we are using the XSI standard strerror_r, not the GNU one */
    if (strerror_r(code, ptr, remain) < 0)
	snprintf(ptr, remain, "errno=%d", code);
    return ptr;
}

char * error_sys_r(char * buffer, int len,
		   const char * caller, const char * called)
{
    return error_sys_errno_r(buffer, len, caller, called, errno);
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

/* reports an error during normal operation */

void error_report(error_message_t em, ...) {
    int i, dest, uselog, ec;
    deferr_t ed;
    char buffers[ARGS][ARGSIZE + 1], timestamp[TIMESTAMP];
    const char * bptr[ARGS], * msg;
    va_list ap;
    struct sockaddr_storage * addr;
    const config_data_t * cfg = NULL;
    if (em >= error_MAX) {
	error_report(error_invalid, em);
	return;
    }
    cfg = config_get();
    dest = config_error_destination(cfg, em);
    if (! dest) {
	/* ignore this error message */
	config_put(cfg);
	return;
    }
    msg = config_error_message(cfg, em);
    if (! msg) {
	/* shouldn't happen, but what can you do? */
	config_put(cfg);
	return;
    }
    ed = deferr[em];
    va_start(ap, em);
    for (i = 0; i < ARGS; i++) {
	switch(ed.argtype[i]) {
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
				      buffers[i] + 1, ARGSIZE - 2))
			{
			    buffers[i][0] = '[';
			    strcat(buffers[i], "]");
			    bptr[i] = buffers[i];
			} else {
			    bptr[i] = "(inet6 socket)";
			}
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
	    case arg_llong :
		snprintf(buffers[i], ARGSIZE, "%lld", va_arg(ap, long long));
		buffers[i][ARGSIZE] = 0;
		bptr[i] = buffers[i];
		break;
	    case arg_string :
		bptr[i] = va_arg(ap, const char *);
		break;
	    case arg_errno :
		ec = va_arg(ap, int);
		/* note: we are using the XSI standard strerror_r,
		 * not the GNU one */
		if (strerror_r(ec, buffers[i], ARGSIZE) < 0)
		    snprintf(buffers[i], ARGSIZE, "(errno=%d)", ec);
		bptr[i] = buffers[i];
		break;
	}
    }
    va_end(ap);
    set_timestamp(timestamp, time(NULL));
    if (dest & error_dest_email) {
	char * const * eptr = config_strarr(cfg, cfg_strarr_email_submit);
	if (eptr && eptr[0] && config_strval(cfg, cfg_error_email)) {
	    int nes = config_strarr_len(cfg, cfg_strarr_email_submit), i, ok;
	    const char * command[2 + nes];
	    pipe_t pipe;
	    ok = 0;
	    for (i = 0; i < nes; i++)
		command[i] = eptr[i];
	    command[nes] = config_strval(cfg, cfg_error_email);
	    command[nes + 1] = NULL;
	    if (pipe_opento((char * const *)command, &pipe)) {
		FILE * F = fdopen(pipe.tochild, "w");
		if (F) {
		    pipe.tochild = -1;
		    fprintf(F, "Error from %s (pid %d) at %s:\n",
			    config_strval(cfg, cfg_error_ident),
			    (int)getpid(),
			    timestamp);
		    fprintf(F, msg,
			    bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
		    fprintf(F, "\n");
		    fclose(F);
		}
		pipe_close(&pipe);
	    }
	    if (! ok) {
		/* cannot email, log it */
		dest |= error_dest_file | error_dest_syslog;
	    }
	}
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
	    logfile = fopen(config_strval(cfg, cfg_error_logfile), "a");
	    if (! logfile) {
		fprintf(stderr, "%s  %s:  ",
			timestamp, config_strval(cfg, cfg_error_ident));
		perror(config_strval(cfg, cfg_error_logfile));
		dest |= error_dest_stderr;
	    }
	}
	if (logfile) {
	    fprintf(logfile, "%s  %s:  ",
		    timestamp, config_strval(cfg, cfg_error_ident));
	    fprintf(logfile, msg, bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
	    fprintf(logfile, "\n");
	    fflush(logfile);
	}
    }
    if (dest & error_dest_stderr) {
	fprintf(stderr, "%s  %s:  ", timestamp,
		config_strval(cfg, cfg_error_ident));
	fprintf(stderr, msg, bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
	fprintf(stderr, "\n");
    }
    if (uselog) funlockfile(stderr);
    if (dest & error_dest_syslog)
	syslog(config_error_facility(cfg, em), msg,
	       bptr[0], bptr[1], bptr[2], bptr[3], bptr[4]);
    config_put(cfg);
}

/* closes logfile: it will be reopened next time a message is logged; can
 * be used after rotating logs */

void error_closelog(void) {
    if (logfile) fclose(logfile);
    logfile = NULL;
}

/* get an error code from its name */

error_message_t error_code(const char * name, int len) {
    error_message_t em;
    for (em = 0; em < error_MAX; em++)
	if (strncmp(deferr[em].name, name, len) == 0)
	    if (strlen(deferr[em].name) == len)
		return em;
    return error_MAX;
}

/* get error name from its code */

const char * error_name(error_message_t em) {
    if (em < error_MAX)
	return deferr[em].name;
    return "?";
}

/* get default error messge, error level, number of arguments */

const char * error_defmsg(error_message_t em) {
    return em < error_MAX ? deferr[em].defmsg : "";
}

error_level_t error_level(error_message_t em) {
    return em < error_MAX ? deferr[em].level : error_level_info;
}

int error_argcount(error_message_t em) {
    if (em < error_MAX) {
	int na = 0, i;
	for (i = 0; i < ARGS; i++)
	    if (deferr[em].argtype[i] != arg_void)
		na++;
	return na;
    }
    return 0;
}

