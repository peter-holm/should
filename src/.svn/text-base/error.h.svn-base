#ifndef __SHOULD_ERROR_H__
#define __SHOULD_ERROR_H__ 1

/* used to report errors
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "config.h"

/* prepares for error reports */

void error_init(const config_t * cfg);

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
    error_badevent,           /* const char * data */
    error_bad_id,             /* const char * type, const char * data */
    error_event,              /* int errno */
    /* error */
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
    error_server_msg,         /* peer, const char * called, const char * problem */
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
    error_copy_short,         /* const char * file */
    error_copy_socket,        /* const char * file */
    error_copy_uncompress,    /* const char * file, const char * error */
    error_copy_unknown,       /* const char * file */
    error_unimplemented,      /* const char * what */
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
    error_MAX
} error_message_t;

void error_report(error_message_t, ...);

/* closes logfile: it will be reopened next time a message is logged; can
 * be used after rotating logs */

void error_closelog(void);

/* destination for an error message: OR one or more of the values */

typedef enum {
    error_dest_stderr = 1,    /* send message to standard error */
    error_dest_email  = 2,    /* email message */
    error_dest_file   = 4,    /* write message to file */
    error_dest_syslog = 8     /* send message to syslog */
} error_dest_t;

/* change an error message; caller allocates string using mymalloc, and they
 * also myfree() it if they get an error */

const char * error_change_message(error_message_t, char *);

/* get current error message */

const char * error_get_message(error_message_t);

/* change an error destination: facility is only used with syslog */

void error_change_dest(error_message_t, error_dest_t, int facility);

/* get current destination and facility */

error_dest_t error_get_dest(error_message_t);
int error_get_facility(error_message_t);

/* check if an error destination has been changed from its default; returns
 * 0 if no, 1 if yes, -1 if invalid */

int error_dest_changed(error_message_t);

/* get an error code from its name */

error_message_t error_code(const char * name, int len);

/* get error name from its code */

const char * error_name(error_message_t);

/* frees any allocated error messages */

void error_free(void);

#endif /* __SHOULD_ERROR_H__ */
