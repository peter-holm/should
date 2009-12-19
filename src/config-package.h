/* data structure used to hold configuration information
 * package-independent parts
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
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

#ifndef __SHOULD_CONFIG_PACKAGE_H__
#define __SHOULD_CONFIG_PACKAGE_H__ 1

/* operation mode - client / copy */

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
    config_client_dirsync       = 0x1000000,
    config_client_NONE          = 0
} config_client_t;

/* operation mode - server */

typedef enum {
    config_server_start         = 0x00001,
    config_server_detach        = 0x00002,
    config_server_NONE          = 0
} config_server_t;

/* various bits which don't deserve a whole "int" */

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
    config_flag_use_librsync     = 0x00200,
    config_flag_extra_fork       = 0x00400,
    config_flag_NONE             = 0
} config_flags_t;

/* type of operation a user will be allowed to do on the server */

typedef enum {
    config_op_status     = 0x0001,         /* obtain status information */
    config_op_watches    = 0x0002,         /* obtain list of watches */
    config_op_add        = 0x0004,         /* add watches */
    config_op_remove     = 0x0008,         /* remove watches */
    config_op_closelog   = 0x0010,         /* close logfiles for rotation */
    config_op_purge      = 0x0020,         /* purge old event logs */
    config_op_getconf    = 0x0040,         /* get configuration */
    config_op_setconf    = 0x0080,         /* update configuration */
    config_op_read       = 0x0100,         /* read files from server */
    config_op_ignore     = 0x0200,         /* ignore filesystem events */
    config_op_dirsync    = 0x0400,         /* schedule a dirsync */
    config_op_debug      = 0x4000,         /* debug communication protocol */
    config_op_stop       = 0x8000,         /* stop running server */
    config_op_all        = 0xc7ff          /* anything */
} config_userop_t;

/* file type bits for the event filter */

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
    /* keep the event filter first */
    cfg_event_meta,               /* event filter for metadata changes */
    cfg_event_data,               /* event filter for data changes */
    cfg_event_create,             /* event filter for create operations */
    cfg_event_delete,             /* event filter for delete operations */
    cfg_event_rename,             /* event filter for rename operations */
    cfg_event_hardlink,           /* event filter for hard link creation */
    cfg_flags,                    /* bit-valued elements */
    cfg_client_mode,              /* do an operation to a running should */
    cfg_server_mode,              /* start server */
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
    cfg_bwlimit,                  /* bandwidth limit KB/s, 0 == network's max */
    cfg_purge_days,               /* if nonzero, client asks to purge event
				   * files older than that number of days */
    cfg_autopurge_days,           /* if nonzero, store thread automatically
				   * purges files on rotation */
    cfg_optimise_client,          /* number of events the client tries to
                                   * pre-read to optimise event processing */
    cfg_optimise_buffer,          /* buffer allocated by the client to optimise
				   * events received from server. */
    cfg_dirsync_interval,         /* frequency of periodic dirsyncs, 0=never */
    cfg_int_COUNT,                /* number of integer elements */
    cfg_event_COUNT = cfg_flags,  /* end of filter */
    cfg_event_all = (1 << cfg_event_COUNT) - 1
} config_int_names_t;

/* integer-array-valued configuration elements */

typedef enum {
    cfg_checksums,                /* checksum method preference */
    cfg_compressions,             /* compression method preference */
    cfg_dirsync_timed,            /* timed dirsyncs */
    cfg_intarr_COUNT              /* number of integer arrays */
} config_intarr_names_t;

/* string-valued configuration elements */

typedef enum {
    cfg_base_name,                /* used to generate other defaults */
    cfg_error_ident,              /* program identity */
    cfg_error_logfile,            /* log file */
    cfg_error_email,              /* email notification recipients */
    cfg_user,                     /* identity to use on server */
    cfg_password,                 /* identity to use on server */
    cfg_eventdir,                 /* log file base name */
    cfg_store,                    /* method used by the store thread */
    cfg_from_prefix,              /* copy events with this prefix */
    cfg_to_prefix,                /* replace this to the from_prefix */
    cfg_copy_state,               /* state file to use for copy */
    cfg_copy_config,              /* separate copy configuration file,
                                   * if the configuration is not included
				   * in the copy state file */
    cfg_homedir,                  /* user's home directory */
    cfg_server,                   /* server to connect to */
    cfg_str_COUNT                 /* number of string elements */
} config_str_names_t;

/* string-list-valued configuration elements */

typedef enum {
    cfg_cp_path,                  /* arguments to "cp" */
    cfg_ls_path,                  /* arguments to "ls" */
    cfg_df_path,                  /* arguments to "df" */
    cfg_update,                   /* configuration updates to request */
    cfg_dirsync_path,             /* list of "dirsync"s to schedule */
    cfg_listen,                   /* sockets to listen on */
    cfg_strlist_COUNT             /* number of string-list elements */
} config_strlist_names_t;

/* array-valued configuration elements */

typedef enum {
    cfg_strarr_tunnel,            /* run a program to set up tunnel */
    cfg_strarr_remote_should,     /* path to should at other end of tunnel */
    cfg_strarr_email_submit,      /* email submit program.
				   * must behave like /usr/sbin/sendmail */
    cfg_strarr_extcopy,           /* external copy program */
    cfg_strarr_COUNT
} config_strarr_names_t;

/* directory tree configuration elements */

typedef enum {
    cfg_tree_add,                 /* directories to watch */
    cfg_tree_remove,              /* directories to stop watching */
    cfg_tree_COUNT
} config_tree_names_t;

/* access control lists */

typedef enum {
    cfg_acl_local,                /* local (Unix) users */
    cfg_acl_tcp,                  /* TCP users */
    cfg_acl_COUNT
} config_acl_names_t;

/* data we pass to User (connection) ACLs */

typedef enum {
    cfg_uacl_ipv4,                /* IPv4 address or NULL */
    cfg_uacl_ipv6,                /* IPv6 address or NULL */
    cfg_uacl_path,                /* path to local socket used or NULL */
    cfg_uacl_user,                /* username provided */
    cfg_uacl_pass,                /* password provided (hashed) */
    cfg_uacl_challenge,           /* challenge issued to the client */
    cfg_uacl_checksum,            /* checksum used by the client */
    cfg_uacl_COUNT
} config_user_acl_t;

/* data we pass to directory selections (exclude, find) */

typedef enum {
    cfg_dacl_path,                /* full path */
    cfg_dacl_name,                /* last component of file name */
    cfg_dacl_COUNT
} config_dir_acl_t;

/* function to handle with hashed passwords */

#define CHALLENGE_SIZE 8
void config_hash_user(const char * user, const char * pass, int ctype,
		      const unsigned char * challenge, unsigned char * hash);

#endif /* __SHOULD_CONFIG_PACKAGE_H__ */
