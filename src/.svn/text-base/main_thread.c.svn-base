/* should's main thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#define _GNU_SOURCE
#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include "main_thread.h"
#include "notify_thread.h"
#include "control_thread.h"
#include "store_thread.h"
#include "client.h"
#include "config.h"
#include "error.h"
#include "mymalloc.h"

/* when the program started */

struct timespec main_started;

/* global variable used for controlled shutdown of threads */

volatile int main_running;

#if USE_SHOULDBOX
/* count the times you get to a "shouldn't happen(TM)" branch */

int main_shouldbox;
#endif

/* record if we've received a signal */

volatile int main_signal_seen = 0;

static void signal_handler(int s) {
    main_running = 0;
    main_signal_seen = s;
}

static void signal_ignore(int s) {
}

/* run the various threads */

static void * run_control(void * _p) {
    const char * err = control_thread();
    if (err)
	error_report(error_run, "control", err);
    return NULL;
}

static void * run_notify(void * _p) {
    const char * err = notify_thread();
    if (err)
	error_report(error_run, "notify", err);
    return NULL;
}

static void * run_store(void * _p) {
    const char * err = store_thread();
    if (err)
	error_report(error_run, "store", err);
    return NULL;
}

static void * run_initial(void * _p) {
    control_initial_thread();
    return NULL;
}

static void wait_thread(pthread_t t, const char * name) {
    void * result;
    error_report(info_stop_thread, name);
    if (! pthread_kill(t, 0)) {
	int patience = POLL_TIME * 2 / WAIT_TIME;
	poll(NULL, 0, WAIT_TIME);
	while (patience-- > 0 && ! pthread_kill(t, 0))
	    poll(NULL, 0, WAIT_TIME);
	if (! pthread_kill(t, 0))
	    pthread_cancel(t);
    }
    pthread_join(t, &result);
}

void main_setup_signals(void) {
    struct sigaction sact;
    main_signal_seen = 0;
    sact.sa_handler = signal_handler;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = 0;
    sigaction(SIGINT, &sact, NULL);
    sigaction(SIGHUP, &sact, NULL);
    sigaction(SIGQUIT, &sact, NULL);
    sigaction(SIGTERM, &sact, NULL);
    sact.sa_handler = signal_ignore;
    sigaction(SIGPIPE, &sact, NULL);
}

/* do something */

int main(int argc, char *argv[]) {
    const char * err;
    config_t cfg;
    pthread_t notify, control, store, initial;
    int errcode, status = 1;
    void * result;
    err = mymalloc_init();
    if (err) {
	fprintf(stderr, err);
	return 2;
    }
#if USE_SHOULDBOX
    main_shouldbox = 0;
#endif
    main_running = 0;
    umask(0077);
    /* initialise system */
    clock_gettime(CLOCK_REALTIME, &main_started);
    if (! config_init(&cfg, argc, argv))
	return 2;
    error_init(&cfg);
    /* local client mode? */
    if (cfg.client_mode) {
	status = client_run(&cfg);
	goto out_nothreads;
    }
    /* do they want to detach? */
    if (cfg.server_mode & config_server_detach) {
	int fd;
	pid_t pid = fork();
	if (pid < 0) {
	    error_report(error_fork, errno);
	    goto out_nothreads;
	}
	if (pid > 0) {
	    error_report(info_detach, (int)pid);
	    goto out_nothreads;
	}
	fd = open("/dev/tty", O_RDONLY);
	if (fd >= 0) {
	    ioctl(fd, TIOCNOTTY);
	    close(fd);
	}
    }
    /* initialise threads */
    err = notify_init(&cfg);
    if (err) {
	error_report(error_start, "notify", err);
	goto out_nothreads;
    }
    err = control_init(&cfg);
    if (err) {
	error_report(error_start, "control", err);
	goto out_notify;
    }
    err = store_init(&cfg);
    if (err) {
	error_report(error_start, "store", err);
	goto out_control_notify;
    }
    /* start threads */
    main_running = 1;
    errcode = pthread_create(&control, NULL, run_control, NULL);
    if (errcode) {
	error_report(error_create, "control", errcode);
	main_running = 0;
	goto out_store_control_notify;
    }
    errcode = pthread_create(&store, NULL, run_store, NULL);
    if (errcode) {
	error_report(error_create, "store", errcode);
	main_running = 0;
	wait_thread(control, "control");
	goto out_store_control_notify;
    }
    errcode = pthread_create(&notify, NULL, run_notify, NULL);
    if (errcode) {
	error_report(error_create, "notify", errcode);
	main_running = 0;
	wait_thread(control, "control");
	wait_thread(store, "store");
	goto out_store_control_notify;
    }
    errcode = pthread_create(&initial, NULL, run_initial, NULL);
    if (errcode) {
	error_report(error_create, "initial", errcode);
	main_running = 0;
	wait_thread(notify, "notify");
	wait_thread(control, "control");
	wait_thread(store, "store");
	goto out_store_control_notify;
    }
    status = 0;
    error_report(info_normal_operation);
    /* just in case */
    main_setup_signals();
    /* wait for the initial thread to finish */
    pthread_join(initial, &result);
    /* wait for the threads */
    while (main_running)
	poll(NULL, 0, WAIT_TIME);
    if (main_signal_seen)
	error_report(info_signal_received, main_signal_seen);
    main_running = 0;
    wait_thread(notify, "notify");
    wait_thread(store, "store");
    wait_thread(control, "control");
out_store_control_notify:
    store_exit();
out_control_notify:
    control_exit();
out_notify:
    notify_exit();
out_nothreads:
#if USE_SHOULDBOX
    if (main_shouldbox)
	error_report(error_shouldbox_int, "main",
		     "shouldbox", main_shouldbox);
#endif
    config_free(&cfg);
    error_closelog();
    error_free();
    mymalloc_exit();
    return status;
}

