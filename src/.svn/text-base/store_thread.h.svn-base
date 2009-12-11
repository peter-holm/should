#ifndef __SHOULD_STORE_THREAD_H__
#define __SHOULD_STORE_THREAD_H__ 1

/* interface to should's store thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "config.h"
#include "notify_thread.h"

/* type used to return information about event files */

typedef struct {
    int file_earliest; /* earliest available event file */
    int file_current;  /* current event file */
    int file_pos;      /* bytes in the current event file */
} store_status_t;

/* opaque type to keep information about events being retrieved
 * from store */

typedef struct store_get_s store_get_t;

/* initialisation required before the store thread starts; returns
 * NULL if OK, or an error message */

const char * store_init(const config_t * cfg);

/* run store thread; returns NULL on normal termination,
 * or an error message */

const char * store_thread(void);

/* cleanup required after the store thread terminates */

void store_exit(void);

/* returns current event files information */

void store_status(store_status_t *);

/* purges event files */

int store_purge(const config_t * cfg, int days);

/* useful function to print an event */

void store_printevent(const notify_event_t * ev,
		      const char * user, const char * group);

/* prepare to read events back from store */

store_get_t * store_prepare(const config_t * cfg,
			    int filenum, int filepos, const char * root);

/* get next event from file; if there are no more events, waits for more
 * for up to "timeout" seconds or until there is activity on file descriptor
 * "fd". Returns 0 if OK, -1 if timeout, -2 if other error: in this case,
 * the error fields are filled with the message; if there is an event but its
 * variable part is larger than "size" bytes, returns the actual size of the
 * event */

int store_get(store_get_t *, notify_event_t *, int timeout, int size,
	      int fd, char * errmsg, int errsize);

/* get file number and position */

int store_get_file(const store_get_t *);
int store_get_pos(const store_get_t *);

/* finish reading events from store */

void store_finish(store_get_t *);

/* useful function to print a name, quoted if required */

void store_printname(const char * name, char next);

#endif /* __SHOULD_STORE_THREAD_H__ */
