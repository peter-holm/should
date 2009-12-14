/* interface to should's notify thread
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

#ifndef __SHOULD_NOTIFY_THREAD_H__
#define __SHOULD_NOTIFY_THREAD_H__ 1

#define NOTIFY_NONE              0
#define NOTIFY_INOTIFY           1

#define SYS_INOTIFY             10
#define OUR_INOTIFY             11

#include <sys/types.h>
#include "config.h"

/* type used to identify a single event */

typedef enum {
    notify_change_meta,       /* metadata changed */
    notify_change_data,       /* file data changed */
    notify_create,            /* new file or dir created */
    notify_delete,            /* file or dir deleted */
    notify_rename,            /* file or directory renamed */
    notify_overflow,          /* events were lost */
    notify_nospace,           /* block size too small: event could not be
			       * stored */
    notify_add_tree           /* tree was added to the watch list */
} notify_event_type_t;

/* file type, if known */
typedef enum {
    notify_filetype_regular,
    notify_filetype_dir,
    notify_filetype_device_char,
    notify_filetype_device_block,
    notify_filetype_fifo,
    notify_filetype_symlink,
    notify_filetype_socket,
    notify_filetype_unknown
} notify_filetype_t;

/* type used to store a single event; the name field will contain the
 * file name, consisting of namelen bytes followed by a NUL; if the
 * event is a rename, the new name will be in to_name, and contain to_length
 * bytes */

typedef struct {
    notify_event_type_t event_type;
    int from_length;
    const char * from_name;
    int to_length;
    const char * to_name;
    notify_filetype_t file_type;
    int stat_valid;
    /* the following data is only valid if stat_valid is nonzero */
    mode_t file_mode;
    uid_t file_user;
    gid_t file_group;
    dev_t file_device;
    long long file_size;
    /* the following is valid if stat_valid is nonzero, or event_type is
     * notify_add_tree */
    time_t file_mtime;
} notify_event_t;

/* type used to return information about queue usage */

typedef struct {
    int queue_events;       /* number of events awaiting processing */
    int queue_bytes;        /* space allocated to the queue */
    int queue_min;          /* minimum queue space */
    int queue_max;          /* maximum queue space */
    int queue_cur;          /* allocated queue space */
    int max_events;         /* maximum value of queue_events observed */
    int max_bytes;          /* maximum value of queue_bytes observed */
    int overflow;           /* queue overflow count, if nonzero it suggests
			     * that the kernel queue should be increased */
    int too_big;            /* number of events which did not fit in buffer.
			     * if nonzero increase blocksize */
    int watches;            /* number of watches currently active */
    int watchmem;           /* memory allocated to watches */
    int events;             /* total number of events since startup */
    int kernel_max_watches; /* value of sysconf(fs:inotify:max_user_watches) */
    int kernel_max_events;  /* value of sysconf(fs:inotify:max_queued_events) */
} notify_status_t;

#if NOTIFY != NOTIFY_NONE

/* opaque type used by the thread to identify a watch */

typedef struct notify_watch_s notify_watch_t;

/* initialisation required before the notify thread starts;
 * returns NULL if OK, otherwise an error message */

const char * notify_init(void);

/* run notify thread; returns NULL on normal termination,
 * or an error message */

const char * notify_thread(void);

/* cleanup required after the notify thread terminates */

void notify_exit(void);

/* look up a directory by name and return the corresponding watch, if
 * found; if not found, return NULL if addit is NULL, otherwise it will
 * try to add it: returns NULL if that is not possible; the value
 * of addit is the same as for notify_add */

notify_watch_t * notify_find_bypath(const char * path,
				    const config_dir_t * addit);

/* remove a watch and all its subdirectories */

void notify_remove_under(notify_watch_t *);

/* adds a directory watch; returns NULL, and sets errno, on error;
 * parent is an existing directory watch; name is relative to that
 * directory and must not contain directory separator characters;
 * the last parameter just tells us how this was added, as this will
 * be required when new directories are created inside this one */

notify_watch_t * notify_add(notify_watch_t * parent, const char * name,
			    const config_dir_t * how);

/* removes a directory watch; returns 1 if found, 0 if not found,
 * -1 if found but has children; parent and name are the same as
 * notify_add */

int notify_remove(notify_watch_t * parent, const char * name, int recurse);

/* returns root watch */

notify_watch_t * notify_root(void);

/* returns current queue status */

void notify_status(notify_status_t *);

/* returns next pending event; returns:
 * 0  if the notify thread terminated
 * 1  if data is available (size will be adjusted to show how much buffer
 *    was used)
 * -3 if the buffer is too small (size will be adjusted to show how much
 *    space is required)
 * -2 if no data available after blocking milliseconds
 * -1 if an error occurred (code will be in errno) */

int notify_get(notify_event_t *, int blocking, char * buffer, int * size);

/* executes a callback once for each active watch */

int notify_forall_watches(int (*)(const char *, void *), void *);
#endif /* NOTIFY != NOTIFY_NONE */

/* convert a mode_t to a notify_filetype_t */

notify_filetype_t notify_filetype(mode_t);

#endif /* __SHOULD_NOTIFY_THREAD_H__ */
