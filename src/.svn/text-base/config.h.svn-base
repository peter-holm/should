#ifndef __SHOULD_CONFIG_H__
#define __SHOULD_CONFIG_H__ 1

/* data structure used to hold configuration information
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

/* operation mode */

typedef enum {
    config_client_add          = 0x00001,
    config_client_remove       = 0x00002,
    config_client_stop         = 0x00004,
    config_client_status       = 0x00008,
    config_client_box          = 0x00010,
    config_client_client       = 0x00020,
    config_client_closelog     = 0x00040,
    config_client_watches      = 0x00080,
    config_client_setup        = 0x00100,
    config_client_copy         = 0x00200,
    config_client_peek         = 0x00400,
    config_client_config       = 0x00800,
    config_client_purge        = 0x01000,
    config_client_listcompress = 0x02000,
    config_client_telnet       = 0x04000,
    config_client_version      = 0x08000,
    config_client_ls           = 0x10000,
    config_client_cp           = 0x20000,
    config_client_df           = 0x40000,
    config_client_getpid       = 0x80000,
    config_client_NONE         = 0
} config_client_t;

typedef enum {
    config_server_start        = 0x00001,
    config_server_detach       = 0x00002,
    config_server_NONE         = 0
} config_server_t;

typedef enum {
    config_flag_debug_server   = 0x00001,
    config_flag_translate_ids  = 0x00002,
    config_flag_skip_matching  = 0x00004,
    config_flag_NONE           = 0
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

typedef struct config_path_s config_path_t;
struct config_path_s {
    config_path_t * next;
    char * path;
};

/* the configuration data */

typedef struct {
    config_client_t client_mode;/* do an operation to a running should */
    config_server_t server_mode;/* start server */
    config_flags_t flags;       /* various flags */
    int notify_queue_block;     /* size of the notify queue allocation block */
    int notify_initial;         /* initial number of blocks allocated */
    int notify_max;             /* max number of blocks allocated */
    int notify_watch_block;     /* size of the notify watch allocation block */
    int notify_buffer;          /* size of buffer used to read from kernel */
    int notify_name_block;      /* size of notify name allocation block */
    char * control_socket;      /* socket to talk to control thread */
    char * error_ident;         /* program identity */
    char * error_logfile;       /* log file */
    char * error_email;         /* email notification recipients */
    char * error_submit;        /* email submit program.
				 * must behave like /bin/mail */
    config_dir_t * dirs;        /* initial list of directory trees to watch */
    config_dir_t * remove;      /* list of directories to remove from server */
    config_user_t * users;      /* users allowed to connect to server */
    char * user;                /* identity to use on server */
    char * password;            /* identity to use on server */
    char * eventdir;            /* log file base name */
    int eventsize;              /* size of file before rotation */
    int checkpoint_events;      /* during copy, checkpoint to state file after
                                 * this number of events */
    int checkpoint_time;        /* during copy, checkpoint to state file after
                                 * this number of seconds */
    char * store;               /* method used by the store thread */
    config_listen_t * listen;   /* listen for TCP connections */
    config_listen_t server;     /* run as a TCP client to server */
    config_path_t * cp_path;    /* arguments to "cp" */
    config_path_t * ls_path;    /* arguments to "ls" */
    config_path_t * df_path;    /* arguments to "df" */
    char * from_prefix;         /* copy events with this prefix */
    int from_length;            /* length of from_prefix */
    char * to_prefix;           /* replace this to the from_prefix */
    int to_length;              /* length of to_prefix */
    char * copy_state;          /* state file to use for copy */
    int bwlimit;                /* bandwidth limit KB/s, 0 == network's max */
    int compression;            /* compression method for file data copy */
    int purge_days;             /* if nonzero, client asks to purge event files */
    int optimise_server;        /* number of events the server tries to pre-read
                                 * to optimise event transmission */
    int optimise_client;        /* number of events the client tries to pre-read
                                 * to optimise event processing */
    int optimise_buffer;        /* buffer allocated by the client to optimise
				 * events received from server. */
} config_t;

/* obtain configuration data */

int config_init(config_t * cfg, int argc, char *argv[]);

/* free configuration data */

void config_free(config_t * cfg);

/* free a single directory tree */

void config_dir_free(config_dir_t *);

/* print configuration to a file */

void config_print(int (*)(void *, const char *), void *, const config_t *);

/* useful functions we export */

const char * config_getfacility(const char *, int *);

#endif /* __SHOULD_CONFIG_H__ */
