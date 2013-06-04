/* interface to should's main thread
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

#ifndef __SHOULD_MAIN_THREAD_H__
#define __SHOULD_MAIN_THREAD_H__ 1

#include "site.h"
#include <time.h>

#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_OFFSET -3

/* when the program started */

extern struct timespec main_started;

/* global variable used for controlled shutdown of threads */

extern volatile int main_running;

/* global variable recording whether the main program has received a
 * signal (and which one) */

extern volatile int main_signal_seen;

/* set up signal handlers -- only called by main or client */

void main_setup_signals(void);

#if USE_SHOULDBOX
/* count the times you get to a "shouldn't happen(TM)" branch */

extern int main_shouldbox;
#endif

#endif /* __SHOULD_MAIN_THREAD_H__ */
