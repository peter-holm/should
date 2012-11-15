/* used to report errors
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

#ifndef __SHOULD_ERROR_H__
#define __SHOULD_ERROR_H__ 1

/* prepares for error reports */

void error_init(void);

/* prepares an error message after a failed system call; the message is
 * stored in a static area; this is only used during initialisation when
 * reporting conditions which prevent the program from running */

const char * error_sys(const char * caller, const char * called);

/* same, but takes an explicit "errno" value */

const char * error_sys_errno(const char * caller, const char * called,
			     int code);

/* like error_sys and error_sys_errno, but thread safe; caller provides
 * a pre-allocated buffer */

char * error_sys_r(char * buffer, int len,
		   const char * caller, const char * called);
char * error_sys_errno_r(char * buffer, int len,
			 const char * caller, const char * called,
			 int code);

/* reports an error during normal operation */

typedef enum {
    /* critical */
    error_shouldbox_int,      /* const char * function,
                               * const char * variable, int value */
    error_shouldbox_less,     /* const char * function,
                               * const char * variable, int value, int minval */
    error_shouldbox_more,     /* const char * function,
                               * const char * variable, int value, int maxval */
    error_shouldbox_noteq,    /* const char * function,
                               * const char * variable, int value,
                               * const char * variable, int value */
    error_shouldbox_null,     /* const char * function, const char * variable */
    error_shouldbox_misptr,   /* const char * function, const char * variable */
    error_shouldbox_mod,      /* const char * function, const char * variable,
			       * int value, int modulus, int result */
    error_shouldbox_notfound, /* const char * function, const char * variable */
    error_internal,           /* const char * function, const char * problem */
    error_allocation,         /* const char * file, int line */
    error_fork,               /* int errno */
    error_wait,               /* int errno */
    error_pipe,               /* int errno */
    error_badevent,           /* const char * data */
    error_baddirent,          /* const char * data */
    error_bad_id,             /* const char * type, const char * data */
    error_event,              /* int errno */
    error_getdir,             /* const char * path, int errno */
    /* error */
    error_cleanup,            /* int errno */
    error_accept,             /* int errno */
    error_add_watch,          /* int errno, const char * name */
    error_rename_watch,       /* const char * from, const char * to */
    error_rename_unknown,     /* const char * from */
    error_rename_exists,      /* const char * to */
    error_rename_children,    /* const char * to */
    error_buffer_tiny,        /* int size */
    error_extending_queue,    /* const char * message */
    error_queue_too_small,    /* void */
    error_connect,            /* const char * called, int errno */
    error_server,             /* peer, const char * called, int errno */
    error_server_msg,         /* peer, const char * called, const char * what */
    error_start,              /* const char * thread, const char * message */
    error_create,             /* const char * thread, int errno */
    error_run,                /* const char * thread, int errno */
    error_control,            /* const char * watch, const char * message */
    error_lock,               /* const char * function, int errno */
    error_invalid,            /* int errcode */
    error_scan_dir,           /* const char * function, int errcode */
    error_scan_find,          /* const char * function, int errcode */
    error_client,             /* const char * function, int errcode */
    error_client_msg,         /* const char * function, const char * message */
    error_setup,              /* const char * function, int errcode */
    error_readcopy,           /* const char * function, int errcode */
    error_readcopy_fmt,       /* const char * function */
    error_readcopy_compress,  /* const char * function, const char * method */
    error_readcopy_locked,    /* const char * file */
    error_copy_sys,           /* const char * filename, int errcode */
    error_copy_rename,        /* const char * from, const char * to, int errc */
    error_copy_invalid,       /* const char * file, const char * error */
    error_copy_librsync,      /* const char * file */
    error_copy_librsync_sys,  /* const char * file, int errno */
    error_copy_short,         /* const char * file */
    error_copy_socket,        /* const char * file */
    error_copy_uncompress,    /* const char * file, const char * error */
    error_copy_unknown,       /* const char * file */
    error_copy_sched_dirsync, /* const char * path, int errno */
    error_unimplemented,      /* const char * what */
    error_notserver,          /* void */
    error_nonotify,           /* void */
    error_child_status,       /* int */
    error_child_signal,       /* int */
    error_child_coredump,     /* int */
    error_child_unknown,      /* int */
    /* informational */
    info_adding_watch,        /* const char * */
    info_removing_watch,      /* const char * */
    info_normal_operation,    /* void */
    info_initial_watches,     /* int num */
    info_user_stop,           /* void */
    info_extending_buffer,    /* int */
    info_signal_received,     /* int */
    info_connection_open,     /* user, peer */
    info_connection_close,    /* user, peer */
    info_count_watches,       /* int */
    info_stop_thread,         /* const char * */
    info_detach,              /* int */
    info_changelog,           /* const char *, const char *, const char * */
    info_replication_meta,    /* const char *, int */
    info_replication_copy,    /* const char *, const char *, long long */
    info_replication_delete,  /* const char * */
    info_replication_rename,  /* const char *, const char * */
    info_sched_dirsync,       /* const char *, const char * */
    info_start_dirsync,       /* const char * */
    info_end_dirsync,         /* const char *, int, int, int */
    error_MAX
} error_message_t;

void error_report(error_message_t, ...);

/* closes logfile: it will be reopened next time a message is logged; can
 * be used after rotating logs */

void error_closelog(void);

/* destination for an error message: OR one or more of the values */

typedef enum {
    error_dest_stderr   = 0x0001,    /* send message to standard error */
    error_dest_email    = 0x0002,    /* email message */
    error_dest_file     = 0x0004,    /* write message to file */
    error_dest_syslog   = 0x0008,    /* send message to syslog */
    error_dest_none     = 0          /* do not emit this message */
} error_dest_t;

/* error level: to automatically filter out messages */

typedef enum {
    error_level_info,                /* informational */
    error_level_warn,                /* warning */
    error_level_err,                 /* error */
    error_level_crit                 /* critical */
} error_level_t;

/* get an error code from its name */

error_message_t error_code(const char * name, int len);

/* get error name from its code */

const char * error_name(error_message_t);

/* get default error messge, error level, number of arguments */

const char * error_defmsg(error_message_t);
error_level_t error_level(error_message_t);
int error_argcount(error_message_t);

#endif /* __SHOULD_ERROR_H__ */
