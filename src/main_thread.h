#ifndef __SHOULD_MAIN_THREAD_H__
#define __SHOULD_MAIN_THREAD_H__ 1

/* interface to should's main thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "site.h"
#include <time.h>

#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_OFFSET -7

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
