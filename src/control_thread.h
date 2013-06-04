/* interface to should's control thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
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

#ifndef __SHOULD_CONTROL_THREAD_H__
#define __SHOULD_CONTROL_THREAD_H__ 1

#include "config.h"

/* initialisation required before the control thread starts;
 * returns NULL if OK, otherwise an error message */

const char * control_init(void);

/* run control thread; returns NULL on normal termination,
 * or an error message */

const char * control_thread(void);

/* run initial thread, which does any delayed initialisation;
 * errors are logged but this never fails */

void control_initial_thread(void);

#if NOTIFY != NOTIFY_NONE
/* ask the control thread to add a directory tree; returns NULL if OK or
 * an error message; stores the number of watches added in the second
 * argument */

const char * control_add_tree(const config_strlist_t *, int *);

/* ask the control thread to remove a directory tree; returns NULL if OK or
 * an error message */

const char * control_remove_tree(const char *);
#endif /* NOTIFY != NOTIFY_NONE */

/* cleanup required after the control thread terminates */

void control_exit(void);

#endif /* __SHOULD_CONTROL_THREAD_H__ */
