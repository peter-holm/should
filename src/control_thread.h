#ifndef __SHOULD_CONTROL_THREAD_H__
#define __SHOULD_CONTROL_THREAD_H__ 1

/* interface to should's control thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "config.h"

/* initialisation required before the control thread starts;
 * returns NULL if OK, otherwise an error message */

const char * control_init(const config_t * cfg);

/* run control thread; returns NULL on normal termination,
 * or an error message */

const char * control_thread(void);

/* run initial thread, which does any delayed initialisation;
 * errors are logged but this never fails */

void control_initial_thread(void);

/* ask the control thread to add a directory tree; returns NULL if OK or
 * an error message; stores the number of watches added in the second
 * argument */

const char * control_add_tree(const config_dir_t *, int *);

/* ask the control thread to remove a directory tree; returns NULL if OK or
 * an error message */

const char * control_remove_tree(const char *);

/* cleanup required after the control thread terminates */

void control_exit(void);

#endif /* __SHOULD_CONTROL_THREAD_H__ */
