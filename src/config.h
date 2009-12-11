/* data structure used to hold configuration information
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

#ifndef __SHOULD_CONFIG_H__
#define __SHOULD_CONFIG_H__ 1

/* operation mode */

typedef enum {
    config_client_add           = 0x0000001,
    config_client_remove        = 0x0000002,
    config_client_stop          = 0x0000004,
    config_client_status        = 0x0000008,
    config_client_box           = 0x0000010,
    config_client_client        = 0x0000020,
    config_client_closelog      = 0x0000040,
    config_client_watches       = 0x0000080,
    config_client_setup         = 0x0000100,
    config_client_copy          = 0x0000200,
    config_client_peek          = 0x0000400,
    config_client_config        = 0x0000800,
    config_client_purge         = 0x0001000,
    config_client_listcompress  = 0x0002000,
    config_client_listchecksum  = 0x0004000,
    config_client_telnet        = 0x0008000,
    config_client_version       = 0x0010000,
    config_client_ls            = 0x0020000,
    config_client_cp            = 0x0040000,
    config_client_df            = 0x0080000,
    config_client_getpid        = 0x0100000,
    config_client_setdebug      = 0x0200000,
    config_client_cleardebug    = 0x0400000,
    config_client_update        = 0x0800000,
    config_client_NONE          = 0
} config_client_t;

typedef enum {
    config_server_start         = 0x00001,
    config_server_detach        = 0x00002,
    config_server_NONE          = 0
} config_server_t;

typedef enum {
    config_flag_debug_server     = 0x00001,
    config_flag_translate_ids    = 0x00002,
    config_flag_skip_matching    = 0x00004,
    config_flag_skip_should      = 0x00008,
    config_flag_initial_dirsync  = 0x00010,
    config_flag_overflow_dirsync = 0x00020,
    config_flag_dirsync_delete   = 0x00040,
    config_flag_copy_oneshot     = 0x00080,
    config_flag_socket_changed   = 0x00100,
    config_flag_NONE             = 0
} config_flags_t;

/* specifies a list of subdirectories to exclude */

typedef struct config_match_s config_match_t;
struct config_match_s {
    config_match_t * next;
    enum {
	config_match_name,      /* last component of the name only */
	config_match_path       /* full path */
    } match;
    enum {
	config_match_exact,     /* like strcmp() */
	config_match_icase,     /* like strcasecmp() */
	config_match_glob,      /* like a shell glob */
	config_match_iglob      /* like a shell glob, ignoring case */
    } how;
    char * pattern;
};

/* specifies a directory tree to watch */

typedef struct config_dir_s config_dir_t;
struct config_dir_s {
    config_dir_t * next;
    int crossmount;
    config_match_t * exclude;
    config_match_t * find;
    char * path;
};

/* defines a username/password pair */

typedef struct config_user_s config_user_t;
struct config_user_s {
    config_user_t * next;
    char * user;
    const char * pass;
};

/* defines a list of "listen" */

typedef struct config_listen_s config_listen_t;
struct config_listen_s {
    config_listen_t * next;
    char * host;
    const char * port;
};

/* defines a list of paths for "cp" and "ls" */

typedef struct config_strlist_s config_strlist_t;
struct config_strlist_s {
    config_strlist_t * next;
    char * data;
};

/* definitions for timed dirsyncs */
typedef struct {
    int daymask;
    int start_time;
} config_dirsync_t;

/* definitions for the filter */
typedef enum {
    config_event_meta          = 0,
    config_event_data          = 1,
    config_event_create        = 2,
    config_event_delete        = 3,
    config_event_rename        = 4,
    config_event_COUNT         = 5,
    config_event_all           = (1 << config_event_COUNT) - 1
} config_event_t;

typedef enum {
    config_file_regular        = 0x01,
    config_file_dir            = 0x02,
    config_file_char           = 0x04,
    config_file_block          = 0x08,
    config_file_fifo           = 0x10,
    config_file_symlink        = 0x20,
    config_file_socket         = 0x40,
    config_file_unknown        = 0x80,
    config_file_all            = 0xff,
} config_filter_t;

/* integer-valued configuration elements */

typedef enum {
    cfg_client_mode,              /* do an operation to a running should */
    cfg_server_mode,              /* start server */
    cfg_flags,                    /* various flags */
    cfg_notify_queue_block,       /* size of the notify queue alloc. block */
    cfg_notify_initial,           /* initial number of blocks allocated */
    cfg_notify_max,               /* max number of blocks allocated */
    cfg_notify_watch_block,       /* size of the notify watch alloc. block */
    cfg_notify_buffer,            /* size of buffer used to read from kernel */
    cfg_notify_name_block,        /* size of notify name allocation block */
    cfg_eventsize,                /* size of file before rotation */
    cfg_checkpoint_events,        /* during copy, checkpoint to state file after
                                   * this number of events */
    cfg_checkpoint_time,          /* during copy, checkpoint to state file after
                                   * this number of seconds */
    cfg_from_length,              /* length of from_prefix (see strings) */
    cfg_to_length,                /* length of to_prefix (see strings) */
    cfg_bwlimit,                  /* bandwidth limit KB/s, 0 == network's max */
    cfg_purge_days,               /* if nonzero, client asks to purge event
				   * files older than that number of days */
    cfg_autopurge_days,           /* if nonzero, store thread automatically
				   * purges files on rotation */
    cfg_optimise_client,          /* number of events the client tries to
                                   * pre-read to optimise event processing */
    cfg_optimise_buffer,          /* buffer allocated by the client to optimise
				   * events received from server. */
    cfg_nchecksums,               /* size of "checksums" */
    cfg_ncompressions,            /* size of "compressions" */
    cfg_dirsync_interval,         /* frequency of periodic dirsyncs, 0=never */
    cfg_dirsync_count,            /* size of "dirsync_timed" */
    cfg_int_COUNT                 /* number of integer elements */
} config_int_t;

/* string-valued configuration elements */

typedef enum {
    cfg_base_name,                /* used to generate other defaults */
    cfg_error_ident,              /* program identity */
    cfg_error_logfile,            /* log file */
    cfg_error_email,              /* email notification recipients */
    cfg_error_submit,             /* email submit program.
				   * must behave like /usr/sbin/sendmail */
    cfg_user,                     /* identity to use on server */
    cfg_password,                 /* identity to use on server */
    cfg_eventdir,                 /* log file base name */
    cfg_store,                    /* method used by the store thread */
    cfg_from_prefix,              /* copy events with this prefix */
    cfg_to_prefix,                /* replace this to the from_prefix */
    cfg_copy_state,               /* state file to use for copy */
    cfg_homedir,                  /* user's home directory */
    cfg_str_COUNT                 /* number of string elements */
} config_str_t;

/* string-list-valued configuration elements */

typedef enum {
    cfg_cp_path,                  /* arguments to "cp" */
    cfg_ls_path,                  /* arguments to "ls" */
    cfg_df_path,                  /* arguments to "df" */
    cfg_update,                   /* configuration updates to request */
    cfg_strlist_COUNT             /* number of string-list elements */
} config_list_t;

/* the configuration data */

typedef struct {
    int intval[cfg_int_COUNT];    /* integer-valued data */
    char * strval[cfg_str_COUNT]; /* string data */
    config_strlist_t * strlist[cfg_strlist_COUNT]; /* string list data */
    config_dir_t * dirs;          /* initial list of directory trees to watch */
    config_dir_t * remove;        /* directories to remove from server */
    config_user_t * users;        /* users allowed to connect to server */
    config_listen_t * listen;     /* listen for TCP connections */
    config_listen_t server;       /* run as a TCP client to server */
    char ** tunnel;               /* run a program to set up tunnel */
    char ** remote_should;        /* path to should at other end of tunnel */
    int * checksums;              /* checksum method preference */
    int * compressions;           /* compression method preference */
    config_dirsync_t * dirsync_timed; /* timed dirsyncs */
    config_filter_t filter[config_event_COUNT]; /* bitmaps of allowed events */
} config_data_t;

/* obtain configuration data from command-line arguments; returns 0 on
 * error, 1 on success */

int config_init(int argc, char *argv[]);

/* obtain a read-only copy of the current configuration; this is guaranteed
 * not to change even if the configuration gets updated; however a second
 * call to config_get may return different data */

const config_data_t * config_get(void);

/* stop using a read-only copy of the configuration */

void config_put(const config_data_t *);

/* makes a copy of the configuration which will allow updates; returns an
 * error message, or NULL if OK */

const char * config_start_update(void);

/* updates the configuration; this only works if config_update has been
 * called and also the update is valid; returns an error message or NULL
 * if the update succeeded */

const char * config_do_update(const char *);

/* commits the configuration update; the next call to config_get() will
 * get the new configuration; returns and error message or NULL if OK */

const char * config_commit_update(void);

/* cancels the update */

void config_cancel_update(void);

/* free configuration data */

void config_free(void);

/* filehandle to the current copy file, if it has been opened by config_init */

extern FILE * config_copy_file;

/* start of variable part of copy file, if it has been opened by config_init */

extern long config_copy_start;

/* free a single directory tree */

void config_dir_free(config_dir_t *);

/* print current configuration to a file */

void config_print(int (*)(void *, const char *), void *);

/* parse a time interval and returns a number of seconds */

int config_parse_interval(const char *);

/* the opposite of the above */

const char * config_print_interval(int);

/* parse a size and returns a number of bytes */

int config_parse_size(const char *);

/* the opposite of the above */

const char * config_print_size(int);

/* parse a day range (mon-fri or tue,sat or sun,tue-thu,sat etc); returns
 * a pointer to the end of the parsed range and updates the second argument
 * with the corresponding mask; if the range is invalid, returns NULL */

const char * config_parse_dayrange(const char *, int *);

/* the opposite of the above */

const char * config_print_dayrange(int);

/* stores copy data to a small configuration file, suitable for loading
 * by the copy thread */

int config_store_copy(int fnum, int fpos, const char * user, const char * pass);

/* useful functions we export */

const char * config_getfacility(const char *, int *);

#endif /* __SHOULD_CONFIG_H__ */
