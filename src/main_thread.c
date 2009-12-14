/* should's main thread
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

#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <locale.h>
#include "main_thread.h"
#include "notify_thread.h"
#include "control_thread.h"
#include "store_thread.h"
#include "copy_thread.h"
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

static void * run_copy(void * _p) {
    copy_thread();
    return NULL;
}

#if NOTIFY != NOTIFY_NONE
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
#endif /* NOTIFY != NOTIFY_NONE */

static void * run_initial(void * _p) {
    control_initial_thread();
    return NULL;
}

static void wait_thread(pthread_t t, const char * name, int force) {
    void * result;
    error_report(info_stop_thread, name);
    if (force)
	pthread_kill(t, SIGINT);
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
    const config_data_t * cfg;
    const char * err;
#if NOTIFY != NOTIFY_NONE
    pthread_t notify, store;
#endif /* NOTIFY != NOTIFY_NONE */
    pthread_t control, initial, copy;
    int errcode, status = 1;
    pid_t pid;
    void * result;
    setlocale(LC_ALL, "");
    tzset(); /* localtime_r may want us to call it */
    err = mymalloc_init();
    if (err) {
	fprintf(stderr, "%s\n", err);
	return 2;
    }
#if USE_SHOULDBOX
    main_shouldbox = 0;
#endif
    main_running = 1;
    umask(0077);
    /* initialise system */
    clock_gettime(CLOCK_REALTIME, &main_started);
    if (! config_init(argc, argv))
	return 2;
    error_init();
    /* local client mode? */
    cfg = config_get();
    if (config_intval(cfg, cfg_client_mode) &&
        ! (config_intval(cfg, cfg_client_mode) &
	   (config_client_copy|config_client_peek)))
    {
	status = client_run();
	goto out_nothreads;
    }
    /* do they want to detach? */
    if (config_intval(cfg, cfg_server_mode) & config_server_detach) {
	int fd;
	pid = fork();
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
    /* wrapper process (not thread) to clean up in case of crash */
#if USE_EXTRA_FORK
    // XXX create a channel to receive socket create/delete notifications
    pid = fork();
    if (pid < 0) {
	error_report(error_fork, errno);
	goto out_nothreads;
    }
    if (pid > 0) {
	/* wrapper process: wait for the child to finish, then clean up */
	// XXX read socket notification pipe and store results
	if (waitpid(pid, &status, 0) < 0) {
	    error_report(error_wait, errno);
	    status = 10;
	    goto out_cleanup;
	}
	if (WIFEXITED(status)) {
	    if (WEXITSTATUS(status)) {
		error_report(error_child_status, WEXITSTATUS(status));
		status = 11;
	    } else {
		status = 0;
	    }
	    goto out_cleanup;
	}
	if (WIFSIGNALED(status)) {
#ifdef WCOREDUMP
	    error_report(WCOREDUMP(status) ? error_child_coredump
					   : error_child_signal,
			 WTERMSIG(status));
#else
	    error_report(error_child_signal, WTERMSIG(status));
#endif
	    status = 12;
	    goto out_cleanup;
	}
	error_report(error_child_unknown, status);
	status = 13;
	goto out_cleanup;
    }
#endif
    /* initialise threads */
#if NOTIFY != NOTIFY_NONE
    if (! config_intval(cfg, cfg_client_mode)) {
	err = notify_init();
	if (err) {
	    error_report(error_start, "notify", err);
	    goto out_nothreads;
	}
    }
#endif /* NOTIFY != NOTIFY_NONE */
    err = control_init();
    if (err) {
	error_report(error_start, "control", err);
	goto out_notify;
    }
#if NOTIFY != NOTIFY_NONE
    if (! config_intval(cfg, cfg_client_mode)) {
	err = store_init();
	if (err) {
	    error_report(error_start, "store", err);
	    goto out_control_notify;
	}
    }
#endif /* NOTIFY != NOTIFY_NONE */
    /* start threads */
    if (config_intval(cfg, cfg_client_mode)) {
	err = copy_init();
	if (err) {
	    error_report(error_start, "copy", err);
	    goto out_store_control_notify;
	}
    }
    errcode = pthread_create(&control, NULL, run_control, NULL);
    if (errcode) {
	error_report(error_create, "control", errcode);
	main_running = 0;
	goto out_copy_store_control_notify;
    }
#if NOTIFY != NOTIFY_NONE
    if (! config_intval(cfg, cfg_client_mode)) {
	errcode = pthread_create(&store, NULL, run_store, NULL);
	if (errcode) {
	    error_report(error_create, "store", errcode);
	    main_running = 0;
	    wait_thread(control, "control", 0);
	    goto out_copy_store_control_notify;
	}
	errcode = pthread_create(&notify, NULL, run_notify, NULL);
	if (errcode) {
	    error_report(error_create, "notify", errcode);
	    main_running = 0;
	    wait_thread(control, "control", 0);
	    wait_thread(store, "store", 0);
	    goto out_copy_store_control_notify;
	}
    }
#endif /* NOTIFY != NOTIFY_NONE */
    if (! config_intval(cfg, cfg_client_mode)) {
	errcode = pthread_create(&initial, NULL, run_initial, NULL);
	if (errcode) {
	    error_report(error_create, "initial", errcode);
	    main_running = 0;
#if NOTIFY != NOTIFY_NONE
	    wait_thread(notify, "notify", 0);
#endif /* NOTIFY != NOTIFY_NONE */
	    wait_thread(control, "control", 0);
#if NOTIFY != NOTIFY_NONE
	    wait_thread(store, "store", 0);
#endif /* NOTIFY != NOTIFY_NONE */
	    goto out_copy_store_control_notify;
	}
    }
    if (config_intval(cfg, cfg_client_mode)) {
	errcode = pthread_create(&copy, NULL, run_copy, NULL);
	if (errcode) {
	    error_report(error_create, "copy", errcode);
	    main_running = 0;
	    wait_thread(control, "control", 0);
	    goto out_copy_store_control_notify;
	}
    }
    status = 0;
    error_report(info_normal_operation);
    /* just in case */
    main_setup_signals();
    /* wait for the initial thread to finish */
    if (! config_intval(cfg, cfg_client_mode))
	pthread_join(initial, &result);
    /* wait for the threads */
    while (main_running)
	poll(NULL, 0, WAIT_TIME);
    if (main_signal_seen)
	error_report(info_signal_received, main_signal_seen);
    main_running = 0;
    if (config_intval(cfg, cfg_client_mode))
	wait_thread(copy, "copy", 0);
#if NOTIFY != NOTIFY_NONE
    if (! config_intval(cfg, cfg_client_mode)) {
	wait_thread(notify, "notify", 0);
	wait_thread(store, "store", 0);
    }
#endif /* NOTIFY != NOTIFY_NONE */
    wait_thread(control, "control", 0);
out_copy_store_control_notify:
    if (config_intval(cfg, cfg_client_mode))
	copy_exit();
out_store_control_notify:
#if NOTIFY != NOTIFY_NONE
    store_exit();
out_control_notify:
#endif /* NOTIFY != NOTIFY_NONE */
    control_exit();
out_notify:
#if NOTIFY != NOTIFY_NONE
    notify_exit();
#endif /* NOTIFY != NOTIFY_NONE */
out_nothreads:
#if USE_SHOULDBOX
    if (main_shouldbox)
	error_report(error_shouldbox_int, "main",
		     "shouldbox", main_shouldbox);
#endif
    config_put(cfg);
    config_free();
    error_closelog();
    mymalloc_exit();
    return status;
#if USE_EXTRA_FORK
out_cleanup:
    // XXX remove any socket created and not yet destroyed by the child
    goto out_nothreads;
#endif
}

