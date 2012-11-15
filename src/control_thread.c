/* should's control thread
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

#define _GNU_SOURCE /* undo some of glibc's brain damage; works fine
                     * on BSD and other real OSs without this */
#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#if DIRENT_TYPE == DIRENT
#include <dirent.h>
#else
#include <sys/dirent.h>
#endif
#include <time.h>
#include <limits.h>
#include <sys/times.h>
#include <string.h>
#include <ctype.h>
#if THEY_HAVE_LIBRSYNC
#include <librsync.h>
#endif
#include "notify_thread.h"
#include "control_thread.h"
#include "store_thread.h"
#include "main_thread.h"
#include "mymalloc.h"
#include "error.h"
#include "socket.h"
#include "protocol.h"
#include "compress.h"
#include "checksum.h"
#include "usermap.h"
#include "config.h"

#define LINESIZE 2048

#if DATA_BLOCKSIZE < 8192
#error DATA_BLOCKSIZE must be at least 8192
#endif

/* control thread's state */

typedef struct {
    char cblock[DATA_BLOCKSIZE];
    char ublock[DATA_BLOCKSIZE];
    struct sockaddr_storage * peer;
    socket_t * p;
    int poll_fd;
    int running;
    long bwlimit;
    int csum_n;
    int compression;
    int rfd;
    int updating;
    long long block_start;
    long long block_size;
    char * Dname;
#if NOTIFY != NOTIFY_NONE
    config_strlist_t * add;
    store_get_t * get;
    char * rootdir;
    int translate_ids;
    int changes;
#endif
#if THEY_HAVE_LIBRSYNC
    int has_signatures;
    off_t delta_pos;
    long long rdiff_start;
    long long rdiff_end;
    rs_signature_t * rs_signature;
    rs_job_t * rs_job;
#endif
} state_t;

/* commands from a client */

typedef enum {
    cm_server = 0x01,
    cm_copy   = 0x02,
    cm_any    = cm_server | cm_copy
} cmdmode_t;

typedef struct {
    const char * keyword;
    config_userop_t opclass;
    cmdmode_t mode;
    const char * (*op)(char *, state_t *);
} command_t;

/* to wait for threads... */

typedef struct thlist_s thlist_t;
struct thlist_s {
    thlist_t * prev, * next;
    socket_t * p;
    int completed;
    pthread_t name;
};

static socket_t * server;
static thlist_t * all_threads;
static int clients, client_mode;

/* initialisation required before the control thread starts;
 * returns NULL if OK, otherwise an error message */

const char * control_init(void) {
    const config_data_t * cfg = config_get();
    client_mode = config_intval(cfg, cfg_client_mode);
    config_put(cfg);
    all_threads = NULL;
    clients = 0;
    server = socket_listen();
    if (! server)
	return error_sys("control_init", "socket_listen");
    return NULL;
}

static const char * send_status(socket_t * p) {
    struct tms tms;
    long long used, hz;
    protocol_status_t status;
    status.server_mode = ! client_mode;
    if (status.server_mode) {
#if NOTIFY != NOTIFY_NONE
	notify_status(&status.notify);
	store_status(&status.store);
#endif /* NOTIFY != NOTIFY_NONE */
    } else {
	copy_status(&status.copy);
    }
#if USE_SHOULDBOX
    status.shouldbox = main_shouldbox;
#else
    status.shouldbox = -1;
#endif
    clock_gettime(CLOCK_REALTIME, &status.running);
    if (status.running.tv_nsec < main_started.tv_nsec) {
	status.running.tv_sec--;
	status.running.tv_nsec += 1000000000LL;
    }
    status.running.tv_nsec -= main_started.tv_nsec;
    status.running.tv_sec -= main_started.tv_sec;
    times(&tms);
    hz = sysconf(_SC_CLK_TCK);
    used = 1000000000LL * (long long)(tms.tms_utime + tms.tms_cutime) / hz;
    status.usertime.tv_sec = used / 1000000000LL;
    status.usertime.tv_nsec = used % 1000000000LL;
    used = 1000000000LL * (long long)(tms.tms_stime + tms.tms_cstime) / hz;
    status.systime.tv_sec = used / 1000000000LL;
    status.systime.tv_nsec = used % 1000000000LL;
    status.memory = mymalloc_used;
    status.clients = clients;
    status.server_pid = getpid();
    return protocol_status_send(p, &status);
}

#if NOTIFY != NOTIFY_NONE
/* send watch name */

static int send_watch(const char * name, void * _VP) {
    state_t * state = _VP;
    char buffer[32];
    sprintf(buffer, "%d", (int)strlen(name));
    if (! socket_puts(state->p, buffer)) {
	error_report(error_server, state->peer, "send_watch", errno);
	return 0;
    }
    if (! socket_put(state->p, name, strlen(name))) {
	error_report(error_server, state->peer, "send_watch", errno);
	return 0;
    }
    return 1;
}
#endif /* NOTIFY != NOTIFY_NONE */

/* sends a STAT or GETDIR result */

static int send_stat(socket_t * p, const char * path, int trans,
		     const char * prefix, const char * name)
{
    int ft, tl = 0;
    struct stat sbuff;
    char mtime[64], ctime[64], nlen[32], linkbuff[DATA_BLOCKSIZE];
    char uname[64], gname[64], buffer[128 + strlen(prefix)];
    struct tm tm;
    const char * nspace;
    if (lstat(path, &sbuff) < 0)
	return -1;
    if (S_ISREG(sbuff.st_mode)) ft = 0;
    else if (S_ISDIR(sbuff.st_mode)) ft = 1;
    else if (S_ISCHR(sbuff.st_mode)) ft = 2;
    else if (S_ISBLK(sbuff.st_mode)) ft = 3;
    else if (S_ISFIFO(sbuff.st_mode)) ft = 4;
    else if (S_ISLNK(sbuff.st_mode)) ft = 5;
    else if (S_ISSOCK(sbuff.st_mode)) ft = 6;
    else ft = 7;
    if (ft == 5) {
	tl = readlink(path, linkbuff, sizeof(linkbuff) - 1);
	if (tl < 0) tl = 0;
    }
    linkbuff[tl] = 0;
    gmtime_r(&sbuff.st_mtime, &tm);
    strftime(mtime, sizeof(mtime), "%Y-%m-%d:%H:%M:%S", &tm);
    gmtime_r(&sbuff.st_ctime, &tm);
    strftime(ctime, sizeof(ctime), "%Y-%m-%d:%H:%M:%S", &tm);
    if (trans) {
	if (usermap_fromid(sbuff.st_uid, uname, sizeof(uname)) <= 0)
	    strcpy(uname, "?");
	if (groupmap_fromid(sbuff.st_gid, gname, sizeof(gname)) <= 0)
	    strcpy(gname, "?");
	nspace = " ";
    } else {
	nspace = "";
	uname[0] = gname[0] = 0;
    }
    if (name)
	sprintf(nlen, "%d ", (int)strlen(name));
    else
	nlen[0] = 0;
    sprintf(buffer, "%s%d %lld %lld 0%o %s%s%d %s%s%d "
		    "%lld %s %s %d %d %s%d",
	    prefix, ft, (long long)sbuff.st_dev, (long long)sbuff.st_ino,
	    sbuff.st_mode & 0777, uname, nspace, sbuff.st_uid,
	    gname, nspace, sbuff.st_gid, (long long)sbuff.st_size,
	    mtime, ctime, major(sbuff.st_rdev), minor(sbuff.st_rdev),
	    nlen, tl);
    if (! socket_puts(p, buffer))
	return 0;
    if (name && ! socket_put(p, name, strlen(name)))
	return 0;
    if (tl > 0 && ! socket_put(p, linkbuff, tl))
	return 0;
    return 1;
}

static void skip_data(socket_t * p, int len) {
    char block[256];
    while (len > 0) {
	int nl = len > sizeof(block) ? sizeof(block) : len;
	if (! socket_get(p, block, nl))
	    return;
	len -= nl;
    }
}

#if NOTIFY != NOTIFY_NONE
static const char * handle_excl_find(state_t * state, char * lptr, int excl) {
    int match, how, namelen = atoi(lptr);
    config_acl_cond_t * item;
    config_add_t * av;
    const char * rep, * kw;
    if (namelen < 1)
	return "EINVAL Invalid name";
    if (! state->add) {
	rep = "ENOADD Pattern match outside add request";
	goto skip_report;
    }
    while (*lptr && isdigit((int)*lptr)) lptr++;
    while (*lptr && isspace((int)*lptr)) lptr++;
    kw = lptr;
    while (*lptr && ! isspace((int)*lptr)) lptr++;
    if (kw == lptr) {
	rep = "EMISS Missing match type";
	goto skip_report;
    }
    if (*lptr) {
	*lptr++ = 0;
	while (*lptr && isspace((int)*lptr)) lptr++;
    }
    if (strcasecmp(kw, "NAME") == 0) {
	match = cfg_dacl_name;
    } else if (strcasecmp(kw, "PATH") == 0) {
	match = cfg_dacl_path;
    } else {
	rep = "EINVAL Invalid match type";
	goto skip_report;
    }
    kw = lptr;
    while (*lptr && ! isspace((int)*lptr)) lptr++;
    if (kw == lptr) {
	rep = "EMISS Missing match mode";
	goto skip_report;
    }
    if (*lptr) {
	*lptr++ = 0;
	while (*lptr && isspace((int)*lptr)) lptr++;
    }
    if (strcasecmp(kw, "EXACT") == 0) {
	how = cfg_acl_exact;
    } else if (strcasecmp(kw, "ICASE") == 0) {
	how = cfg_acl_icase;
    } else if (strcasecmp(kw, "GLOB") == 0) {
	how = cfg_acl_glob;
    } else if (strcasecmp(kw, "IGLOB") == 0) {
	how = cfg_acl_iglob;
    } else {
	rep = "EINVAL Invalid match mode";
	goto skip_report;
    }
    item = mymalloc(sizeof(config_acl_cond_t) + 1 + namelen);
    if (! item) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "ADD", "malloc");
	goto skip_report;
    }
    if (! socket_get(state->p, item->pattern, namelen)) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "ADD", "malloc");
	myfree(item);
	return rep;
    }
    item->pattern[namelen] = 0;
    av = state->add->privdata;
    if (excl) {
	item->next = av->exclude;
	av->exclude = item;
    } else {
	item->next = av->find;
	av->find = item;
    }
    return "OK added";
skip_report:
    skip_data(state->p, namelen);
    return rep;
}

static const char * finish_add(config_strlist_t * add, int * changes,
			       char cblock[])
{
    const char * rep;
    int count = 0;
    if (! add)
	return "EINVAL Add request was never prepared";
    rep = control_add_tree(add, &count);
    config_free_add(add->privdata);
    myfree(add);
    if (rep)
	return rep;
    *changes = 1;
    sprintf(cblock, "OK %d watches added", count);
    return cblock;
}
#endif /* NOTIFY != NOTIFY_NONE */

static int sendlines(void * _p, const char * l) {
    socket_t * p = _p;
    return socket_puts(p, l);
}

static inline char * get_block(state_t * state,
			       long long start, long long *size)
{
    ssize_t nr;
    if (*size < 1) return state->ublock;
    if (state->block_start >= 0 && state->block_size >= 0) {
	if (state->block_start <= start &&
	    state->block_start + state->block_size >= start + *size)
		return state->ublock + (start - state->block_start);
    }
    if (lseek(state->rfd, (off_t)start, SEEK_SET) < 0)
	return NULL;
    if (*size > DATA_BLOCKSIZE)
	*size = DATA_BLOCKSIZE;
    nr = read(state->rfd, state->ublock, *size);
    if (nr < 0)
	return NULL;
    *size = state->block_size = nr;
    state->block_start = start;
    return state->ublock;
}

#if NOTIFY != NOTIFY_NONE
static int send_event(const notify_event_t * ev, state_t * state) {
    sprintf(state->cblock, "OK EV %d %d %d %d %d %d %d %d",
	    store_get_file(state->get), store_get_pos(state->get),
	    ev->event_type, ev->file_type, ev->stat_valid,
	    ev->stat_valid || ev->event_type == notify_add_tree,
	    ev->from_length, ev->to_length);
    if (! socket_puts(state->p, state->cblock)) {
	error_report(error_server, state->peer, "send_event", errno);
	return 0;
    }
    if (ev->from_length &&
	! socket_put(state->p, ev->from_name, ev->from_length))
    {
	error_report(error_server, state->peer, "send_event", errno);
	return 0;
    }
    if (ev->to_length &&
	! socket_put(state->p, ev->to_name, ev->to_length))
    {
	error_report(error_server, state->peer, "send_event", errno);
	return 0;
    }
    if (ev->stat_valid) {
	if (state->translate_ids) {
	    char uname[64], gname[64];
	    if (usermap_fromid(ev->file_user, uname, sizeof(uname)) <= 0)
		strcpy(uname, "?");
	    if (groupmap_fromid(ev->file_group, gname, sizeof(gname)) <= 0)
		strcpy(gname, "?");
	    sprintf(state->cblock, "NSTAT 0%o %s %d %s %d %lld %d %d",
		    ev->file_mode, uname, ev->file_user,
		    gname, ev->file_group, ev->file_size,
		    major(ev->file_device),
		    minor(ev->file_device));
	} else {
	    sprintf(state->cblock, "STAT 0%o %d %d %lld %d %d",
		    ev->file_mode, ev->file_user,
		    ev->file_group, ev->file_size,
		    major(ev->file_device),
		    minor(ev->file_device));
	}
	if (! socket_puts(state->p, state->cblock)) {
	    error_report(error_server, state->peer, "send_event", errno);
	    return 0;
	}
    }
    if (ev->stat_valid || ev->event_type == notify_add_tree) {
	char mtime[64];
	struct tm tm;
	gmtime_r(&ev->file_mtime, &tm);
	strftime(mtime, sizeof(mtime), "%Y-%m-%d:%H:%M:%S", &tm);
	sprintf(state->cblock, "MTIME %s", mtime);
	if (! socket_puts(state->p, state->cblock)) {
	    error_report(error_server, state->peer, "send_event", errno);
	    return 0;
	}
    }
    return 1;
}
#endif

static const char * send_data(state_t * state,
			      const char * udata, long long usize)
{
    long long csize, dsize;
    const char * dptr;
    if (state->compression >= 0 && usize > 0)
	csize = compress_data(state->compression, udata,
			      usize, state->cblock);
    else
	csize = -1;
    if (csize <= 0) {
	char tmpbuff[64];
	sprintf(tmpbuff, "OK %lld", usize);
	if (! socket_puts(state->p, tmpbuff)) {
	    error_report(error_server, state->peer, "send_data", errno);
	    state->running = 0;
	    return NULL;
	}
	dptr = udata;
	dsize = usize;
    } else {
	char tmpbuff[64];
	sprintf(tmpbuff, "OK %lld %lld", csize, usize);
	if (! socket_puts(state->p, tmpbuff)) {
	    error_report(error_server, state->peer, "send_data", errno);
	    state->running = 0;
	    return NULL;
	}
	dptr = state->cblock;
	dsize = csize;
    }
    if (state->bwlimit > 0) {
	while (dsize > 0) {
	    long diff = dsize;
	    if (diff > state->bwlimit) diff = state->bwlimit;
	    if (! socket_put(state->p, dptr, diff)) {
		error_report(error_server, state->peer, "send_data", errno);
		state->running = 0;
		return NULL;
	    }
	    dptr += diff;
	    dsize -= diff;
	    socket_flush(state->p);
	    sleep(1);
	}
    } else {
	if (! socket_put(state->p, dptr, dsize)) {
	    error_report(error_server, state->peer, "send_data", errno);
	    state->running = 0;
	    return NULL;
	}
    }
    return NULL;
}

static const char * list_items(state_t * state, int max,
			       const char * (*name)(int), const char * func)
{
    int n;
    if (! socket_puts(state->p, "OK")) {
	error_report(error_server, state->peer, "list_items", errno);
	state->running = 0;
	return NULL;
    }
    for (n = 0; n < max; n++) {
	const char * c = name(n);
#if USE_SHOULDBOX
	if (! c) {
	    error_report(error_shouldbox_null, "list_items", func);
	    break;
	}
#endif
	if (! socket_puts(state->p, c)) {
	    error_report(error_server, state->peer, "list_items", errno);
	    state->running = 0;
	    break;
	}
    }
    if (! socket_puts(state->p, "__END__")) {
	error_report(error_server, state->peer, "list_items", errno);
	state->running = 0;
    }
    return NULL;
}

/* client commands */

#if NOTIFY != NOTIFY_NONE
static const char * op_add(char * lptr, state_t * state) {
    int namelen = atoi(lptr);
    const char * rep = NULL;
    config_add_t * av;
    if (namelen < 1)
	return "EINVAL Invalid name";
    if (state->add)
	return "EINVAL Add already in progress";
    state->add = mymalloc(sizeof(config_strlist_t) + 1 + namelen);
    if (! state->add) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "ADD", "malloc");
	goto skip_report;
    }
    av = mymalloc(sizeof(config_add_t));
    if (! av) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "ADD", "malloc");
	myfree(state->add);
	state->add = NULL;
	goto skip_report;
    }
    state->add->privdata = av;
    state->add->next = NULL;
    state->add->datalen = namelen;
    state->add->data[namelen] = 0;
    av->crossmount = 1;
    av->exclude = NULL;
    av->find = NULL;
    if (! socket_get(state->p, state->add->data, namelen))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "ADD", "malloc");
    return "OK added";
skip_report:
    skip_data(state->p, namelen);
    return rep;
}
#endif

static const char * op_bwlimit(char * lptr, state_t * state) {
    long limit = atol(lptr);
    if (limit < 0 || limit >= LONG_MAX / 1024L)
	return "EINVAL bandwidth limit";
    state->bwlimit = limit * 1024L;
    return "OK limit changed";
}

static const char * op_checksum(char * lptr, state_t * state) {
    long long start, size;
    int i, wp, clen = checksum_size(state->csum_n);
    unsigned char hash[clen < 0 ? 0 : clen];
    char * block;
    if (state->csum_n < 0)
	return "ENOSYS No checksums available";
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (sscanf(lptr, "%lld %lld", &start, &size) < 2)
	return "EINVAL Invalid request";
    if (start < 0 || size < 0) 
	return "EINVAL Invalid request";
    block = get_block(state, start, &size);
    if (! block)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "CHECKSUM", "get_block");
    if (! checksum_data(state->csum_n, block, size, hash))
	return "Error calculating checksum";
    wp = sprintf(state->cblock, "OK %lld ", size);
    for (i = 0; i < clen; i++)
	wp += sprintf(state->cblock + wp, "%02X",
		      (unsigned int)hash[i]);
    return state->cblock;
}

static const char * op_closelog(char * lptr, state_t * state) {
    error_closelog();
    return "OK closed";
}

static const char * op_compress(char * lptr, state_t * state) {
    int num;
    char * kw = lptr;
    while (*lptr && ! isspace((int)*lptr)) lptr++;
    if (lptr == kw)
	return "EINVAL Invalid empty compression method";
    if (*lptr)
	*lptr++ = 0;
    num = compress_byname(kw);
    if (num < 0)
	return "EINVAL Unknown compression method";
    state->compression = num;
    return "OK compression selected";
}

static const char * op_closefile(char * lptr, state_t * state) {
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (state->Dname) myfree(state->Dname);
    state->Dname = NULL;
    close(state->rfd);
    state->rfd = -1;
    return "OK file closed";
}

static const char * op_config(char * lptr, state_t * state) {
    if (! socket_puts(state->p, "OK")) {
	error_report(error_server, state->peer, "CONFIG", errno);
	state->running = 0;
	return NULL;
    }
    config_print(sendlines, state->p);
    if (! socket_puts(state->p, "__END__")) {
	error_report(error_server, state->peer, "CONFIG", errno);
	state->running = 0;
	return NULL;
    }
    return NULL;
}

#if NOTIFY != NOTIFY_NONE
static const char * op_cross(char * lptr, state_t * state) {
    const char * rep;
    config_add_t * av;
    if (! state->add)
	return "EINVAL Need ADD command first";
    av = state->add->privdata;
    av->crossmount = 1;
    rep = finish_add(state->add, &state->changes, state->cblock);
    state->add = NULL;
    return rep;
}
#endif /* NOTIFY != NOTIFY_NONE */

static const char * op_data(char * lptr, state_t * state) {
    long long start, usize;
    const char * udata;
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (sscanf(lptr, "%lld %lld", &start, &usize) < 2)
	return "EINVAL Invalid request";
    udata = get_block(state, start, &usize);
    if (! udata)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "DATA", "get_block");
    return send_data(state, udata, usize);
}

static const char * op_debug(char * lptr, state_t * state) {
    socket_setdebug(state->p, 1);
    return "OK";
}

#if THEY_HAVE_LIBRSYNC
static const char * op_delta(char * lptr, state_t * state) {
    long long msize;
    ssize_t nr;
    rs_buffers_t rs_buf;
    rs_result rs_res;
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (! state->has_signatures)
	return "EINVAL Did not see a SIGNATURE command";
    if (sscanf(lptr, "%lld", &msize) < 1)
	return "EINVAL Invalid request";
    if (msize > DATA_BLOCKSIZE)
	msize = DATA_BLOCKSIZE;
    if (state->delta_pos < 0) {
	/* first time after reading signatures */
	rs_buf.next_in = rs_buf.next_out = NULL;
	rs_buf.avail_in = rs_buf.avail_out = 0;
	rs_buf.eof_in = 1;
	rs_res = rs_job_iter(state->rs_job, &rs_buf);
	if (rs_res != RS_DONE)
	    return "EBADF Error from librsync";
	rs_job_free(state->rs_job);
	state->rs_job = NULL;
	rs_res = rs_build_hash_table(state->rs_signature);
	if (rs_res != RS_DONE)
	    return "EBADF Error from librsync";
	state->rs_job = rs_delta_begin(state->rs_signature);
	state->delta_pos = state->rdiff_start;
    }
    /* read more file data and get some more deltas */
    while (1) {
	int todo = state->rdiff_end - state->delta_pos;
	long long usize;
	if (lseek(state->rfd, state->delta_pos, SEEK_SET) < 0)
	    return error_sys_r(state->cblock, DATA_BLOCKSIZE, "DELTA", "delta");
	if (todo > DATA_BLOCKSIZE)
	    todo = DATA_BLOCKSIZE;
	nr = read(state->rfd, state->cblock, todo);
	if (nr < 0)
	    return error_sys_r(state->cblock, DATA_BLOCKSIZE, "DELTA", "delta");
	rs_buf.next_in = state->cblock;
	rs_buf.avail_in = nr;
	rs_buf.eof_in = nr == 0;
	rs_buf.next_out = state->ublock;
	rs_buf.avail_out = msize;
	rs_res = rs_job_iter(state->rs_job, &rs_buf);
	if (rs_res != RS_BLOCKED && rs_res != RS_DONE)
	    return "EBADF Error from librsync";
	/* send this delta back */
	state->delta_pos += nr - rs_buf.avail_in;
	usize = msize - rs_buf.avail_out;
	if (usize > 0)
	    return send_data(state, state->ublock, usize);
    }
}
#endif

static const char * op_dirsync(char * lptr, state_t * state) {
    char * path;
    const config_data_t * cfg = config_get();
    int ok, namelen = atoi(lptr);
    time_t deadline = config_intval(cfg, cfg_dirsync_deadline);
    config_put(cfg);
    if (namelen < 1)
	return "EINVAL Invalid name";
    path = mymalloc(1 + namelen);
    if (! path)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "DIRSYNC", "malloc");
    if (! socket_get(state->p, path, namelen)) {
	const char * rep = error_sys_r(state->cblock, DATA_BLOCKSIZE,
				       "DIRSYNC", "malloc");
	myfree(path);
	return rep;
    }
    path[namelen] = 0;
    if (deadline > 0) deadline += time(NULL);
    ok = copy_dirsync("user", path, deadline);
    myfree(path);
    if (ok)
	return "OK scheduled";
    return error_sys_r(state->cblock, DATA_BLOCKSIZE,
		      "DIRSYNC", "schedule_dirsync");
}

static const char * op_extensions(char * lptr, state_t * state) {
    if (! socket_puts(state->p, "OK sending extensions list")) {
	error_report(error_server, state->peer, "EXTENSIONS", errno);
	state->running = 0;
	return NULL;
    }
    // XXX ENCRYPT
    if (! socket_puts(state->p, "UPDATE")) {
	error_report(error_server, state->peer, "EXTENSIONS", errno);
	state->running = 0;
	return NULL;
    }
    if (! client_mode) {
	if (state->csum_n >= 0 && ! socket_puts(state->p, "CHECKSUM")) {
	    error_report(error_server, state->peer, "EXTENSIONS", errno);
	    state->running = 0;
	    return NULL;
	}
	// XXX IGNORE (! client_mode)
	if (! socket_puts(state->p, "EVBATCH")) {
	    error_report(error_server, state->peer, "EXTENSIONS", errno);
	    state->running = 0;
	    return NULL;
	}
#if THEY_HAVE_LIBRSYNC
	if (! socket_puts(state->p, "RSYNC")) {
	    error_report(error_server, state->peer, "EXTENSIONS", errno);
	    state->running = 0;
	    return NULL;
	}
#endif
    } else {
	if (! socket_puts(state->p, "DIRSYNC")) {
	    error_report(error_server, state->peer, "EXTENSIONS", errno);
	    state->running = 0;
	    return NULL;
	}
    }
    if (! socket_puts(state->p, ".")) {
	error_report(error_server, state->peer, "EXTENSIONS", errno);
	state->running = 0;
	return NULL;
    }
    return NULL;
}

#if NOTIFY != NOTIFY_NONE
static const char * op_evbatch(char * lptr, state_t * state) {
    notify_event_t ev;
    int count, size, avail, used = 0;
    if (! state->get)
	return "EINVAL no root dir";
    if (sscanf(lptr, "%d %d", &count, &size) < 2)
	return "EINVAL Invalid request";
    avail = store_get(state->get, &ev, -1, -1, state->poll_fd,
		      state->cblock, DATA_BLOCKSIZE, &used);
    if (avail == -2)
	return state->cblock;
    if (! send_event(&ev, state)) {
	state->running = 0;
	return NULL;
    }
    count--;
    while (count > 0 && used <= size) {
	int nu = 0;
	avail = store_get(state->get, &ev, 0, size - used,
			  state->poll_fd, state->cblock,
			  DATA_BLOCKSIZE, &nu);
	if (avail != 0) break;
	used += nu;
	count --;
	if (! send_event(&ev, state))
	    break;
    }
    return "OK NO";
}
#endif

#if NOTIFY != NOTIFY_NONE
static const char * op_event(char * lptr, state_t * state) {
    notify_event_t ev;
    int timeout, size, avail;
    if (! state->get)
	return "EINVAL no root dir";
    if (sscanf(lptr, "%d %d", &timeout, &size) < 2)
	return "EINVAL Invalid request";
    avail = store_get(state->get, &ev, timeout, size, state->poll_fd,
		      state->cblock, DATA_BLOCKSIZE, NULL);
    if (avail == -2)
	return state->cblock;
    if (avail < 0)
	/* no event available */
	return "OK NO";
    if (avail > 0) {
	/* event too big */
	sprintf(state->cblock, "OK BIG %d", avail);
	if (! socket_puts(state->p, state->cblock)) {
	    error_report(error_server, state->peer, "EVENT", errno);
	    state->running = 0;
	}
	return NULL;
    }
    /* an event is available */
    if (! send_event(&ev, state))
	state->running = 0;
    return NULL;
}
#endif

#if NOTIFY != NOTIFY_NONE
static const char * op_excl(char * lptr, state_t * state) {
    return handle_excl_find(state, lptr, 1);
}
#endif

#if NOTIFY != NOTIFY_NONE
static const char * op_find(char * lptr, state_t * state) {
    return handle_excl_find(state, lptr, 0);
}
#endif

static const char * op_getdir(char * lptr, state_t * state) {
    int len, trans;
    DIR * dp;
    struct dirent * ent;
    const config_data_t * cfg = config_get();
    int skip_should = config_intval(cfg, cfg_flags) & config_flag_skip_should;
    config_put(cfg);
    if (sscanf(lptr, "%d %d", &len, &trans) < 2)
	return "EINVAL Invalid request";
    if (len >= DATA_BLOCKSIZE - NAME_MAX - 2) {
	skip_data(state->p, len);
	return "EINVAL name too long";
    }
    if (! socket_get(state->p, state->cblock, len))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "GETDIR", "socket_get");
    state->cblock[len] = 0;
    dp = opendir(state->cblock);
    if (! dp) {
	strcpy(state->ublock, state->cblock);
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "GETDIR", state->ublock);
    }
    if (! socket_puts(state->p, "OK")) {
	error_report(error_server, state->peer, "GETDIR", errno);
	closedir(dp);
	state->running = 0;
	return NULL;
    }
    state->cblock[len++] = '/';
    while ((ent = readdir(dp)) != NULL) {
	int nl = strlen(ent->d_name), el;
	if (ent->d_name[0] == '.') {
	    if (ent->d_name[1] == 0) continue;
	    if (ent->d_name[1] == '.' && ent->d_name[2] == 0)
		continue;
	    /* skip should's temporary files, if required */
	    if (skip_should && nl == 14 &&
		strncmp(ent->d_name, ".should.", 8) == 0)
		    continue;
	}
	el = len + nl;
	if (nl >= DATA_BLOCKSIZE)
	    /* not supposed to happen but you never know */
	    continue;
	strcpy(state->cblock + len, ent->d_name);
	if (send_stat(state->p, state->cblock, trans, "", ent->d_name))
	    continue;
	error_report(error_server, state->peer, "GETDIR", errno);
	state->running = 0;
	closedir(dp);
	return NULL;
    }
    closedir(dp);
    if (! socket_puts(state->p, ".")) {
	error_report(error_server, state->peer, "GETDIR", errno);
	state->running = 0;
    }
    return NULL;
}

static const char * op_listchecksum(char * lptr, state_t * state) {
    return list_items(state, checksum_count(), checksum_name, "checksum_name");
}

static const char * op_listcompress(char * lptr, state_t * state) {
    return list_items(state, compress_count(), compress_name, "compress_name");
}

#if NOTIFY != NOTIFY_NONE
static const char * op_nocross(char * lptr, state_t * state) {
    const char * rep;
    config_add_t * av;
    if (! state->add)
	return "EINVAL Need ADD command first";
    av = state->add->privdata;
    av->crossmount = 0;
    rep = finish_add(state->add, &state->changes, state->cblock);
    state->add = NULL;
    return rep;
}
#endif /* NOTIFY != NOTIFY_NONE */

static const char * op_nodebug(char * lptr, state_t * state) {
    socket_setdebug(state->p, 0);
    return "OK";
}

static const char * op_open(char * lptr, state_t * state) {
    struct stat sbuff;
    int namelen = atoi(lptr);
    if (namelen < 1)
	return "EINVAL Invalid name";
    if (state->Dname) myfree(state->Dname);
    if (state->rfd >= 0) close(state->rfd);
    state->rfd = -1;
    state->Dname = mymalloc(1 + namelen);
    if (! state->Dname) {
	const char * rep = error_sys_r(state->cblock, DATA_BLOCKSIZE,
				       "OPEN", "malloc");
	skip_data(state->p, namelen);
	return rep;
    }
    if (! socket_get(state->p, state->Dname, namelen))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "OPEN", "socket_get");
    state->Dname[namelen] = 0;
    /* don't wait on a named pipe or similar thing */
    if (lstat(state->Dname, &sbuff) < 0)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "OPEN", state->Dname);
    if (! S_ISREG(sbuff.st_mode))
	return "EBADF not a regular file";
    if (sbuff.st_size == 0)
	return "File has zero size, no need to OPEN it...";
    /* there's a chance somebody will rename a pipe into Dname just right now.
     * Nothing we can do about it, but we open the file in nonblocking mode
     * and then re-check with fstat that it's still a regular file */
    state->rfd = open(state->Dname, O_RDONLY|O_NONBLOCK);
    if (state->rfd < 0)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "OPEN", state->Dname);
    if (fstat(state->rfd, &sbuff) < 0) {
	const char * rep = error_sys_r(state->cblock, DATA_BLOCKSIZE,
				       "OPEN", state->Dname);
	close(state->rfd);
	state->rfd = -1;
	return rep;
    }
    if (! S_ISREG(sbuff.st_mode)) {
	close(state->rfd);
	state->rfd = -1;
	return "EBADF not a regular file";
    }
    if (sbuff.st_size == 0) {
	close(state->rfd);
	state->rfd = -1;
	return "File has zero size, no need to OPEN it...";
    }
    /* reset O_NONBLOCK */
    fcntl(state->rfd, F_SETFL, 0L);
    return "OK file opened";
}

#if NOTIFY != NOTIFY_NONE
static const char * op_purge(char * lptr, state_t * state) {
    int days = atoi(lptr);
    if (days < 2)
	return "EINVAL Invalid number of days";
    if (! store_purge(days))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "PURGE", "store_purge");
    return "OK purged";
}
#endif /* NOTIFY != NOTIFY_NONE */

static const char * op_quit(char * lptr, state_t * state) {
    state->running = 0;
    return "OK bye then";
}

#if NOTIFY != NOTIFY_NONE
static const char * op_remove(char * lptr, state_t * state) {
    char * path;
    int namelen = atoi(lptr);
    const char * rep;
    if (namelen < 1)
	return "EINVAL Invalid name";
    path = mymalloc(1 + namelen);
    if (! path) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "REMOVE", "malloc");
	skip_data(state->p, namelen);
	return rep;
    }
    if (! socket_get(state->p, path, namelen)) {
	rep = error_sys_r(state->cblock, DATA_BLOCKSIZE, "REMOVE", "malloc");
	myfree(path);
	return rep;
    }
    path[namelen] = 0;
    rep = control_remove_tree(path);
    myfree(path);
    if (rep) return rep;
    state->changes = 1;
    return "OK removed";
}
#endif /* NOTIFY != NOTIFY_NONE */

#if THEY_HAVE_LIBRSYNC
static const char * op_rsync(char * lptr, state_t * state) {
    long long start, usize;
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (sscanf(lptr, "%lld %lld", &start, &usize) < 2)
	return "EINVAL Invalid request";
    if (start < 0 || usize < 0)
	return "EINVAL Invalid request";
    state->delta_pos = -1;
    state->has_signatures = 0;
    state->rdiff_start = state->rdiff_end = -1;
    if (state->rs_signature) rs_free_sumset(state->rs_signature);
    state->rs_signature = NULL;
    if (state->rs_job) rs_job_free(state->rs_job);
    state->rs_job = NULL;
    state->rs_job = rs_loadsig_begin(&state->rs_signature);
    state->rdiff_start = start;
    state->rdiff_end = start + usize;
    snprintf(state->cblock, DATA_BLOCKSIZE, "OK %lld %d",
	     usize, DATA_BLOCKSIZE);
    return state->cblock;
}
#endif /* THEY_HAVE_LIBRSYNC */

static const char * op_setchecksum(char * lptr, state_t * state) {
    int num;
    char * kw = lptr;
    while (*lptr && ! isspace((int)*lptr)) lptr++;
    if (lptr == kw)
	return "EINVAL Invalid empty checksum method";
    if (*lptr)
	*lptr++ = 0;
    num = checksum_byname(kw);
    if (num < 0)
	return "EINVAL Unknown checksum method";
    state->csum_n = num;
    return "OK checksum method selected";
}

#if NOTIFY != NOTIFY_NONE
static const char * op_setroot(char * lptr, state_t * state) {
    int pos, file, namelen;
    if (sscanf(lptr, "%d %d %d %d",
	       &file, &pos, &namelen, &state->translate_ids) < 4)
	return "EINVAL Invalid data";
    if (namelen < 1)
	return "EINVAL invalid name";
    if (state->rootdir) myfree(state->rootdir);
    if (state->get) store_finish(state->get);
    state->get = NULL;
    state->rootdir = mymalloc(1 + namelen);
    if (! state->rootdir) {
	const char * rep = error_sys_r(state->cblock, DATA_BLOCKSIZE,
				       "SETROOT", "malloc");
	skip_data(state->p, namelen);
	return rep;
    }
    if (! socket_get(state->p, state->rootdir, namelen))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "SETROOT", "malloc");
    state->rootdir[namelen] = 0;
    state->get = store_prepare(file, pos, state->rootdir);
    if (! state->get)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "SETROOT", "store_prepare");
    return "OK root changed";
}
#endif /* NOTIFY != NOTIFY_NONE */

#if THEY_HAVE_LIBRSYNC
static const char * op_signature(char * lptr, state_t * state) {
    long long csize, usize;
    int dcount;
    rs_result rs_res;
    rs_buffers_t rs_buf;
    if (state->rfd < 0)
	return "EBADF File not opened";
    if (state->rdiff_start < 0 || ! state->rs_signature || ! state->rs_job)
	return "EINVAL Did not see an RSYNC command";
    dcount = sscanf(lptr, "%lld %lld", &csize, &usize);
    if (dcount < 1)
	return "EINVAL Invalid request";
    if (dcount < 2)
	usize = csize;
    else if (state->compression < 0)
	return "EINVAL no compression selected";
    if (csize < 0 || usize < 0 || usize < csize)
	return "EINVAL Invalid request";
    if (usize > DATA_BLOCKSIZE) {
	skip_data(state->p, usize);
	return "EINVAL Buffer overflow";
    }
    if (! socket_puts(state->p, "OK send the data"))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "SIGNATURE", "socket_put");
    if (! socket_get(state->p, state->cblock, csize))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "SIGNATURE", "socket_get");
    rs_buf.next_in = state->cblock;
    if (dcount >= 2) {
	int bsize = DATA_BLOCKSIZE;
	const char * rep;
	state->block_start = state->block_size = -1;
	rep = uncompress_data(state->compression, state->cblock, csize,
			      state->ublock, &bsize);
	if (rep) return rep;
	if (bsize != usize)
	    return "EBADF Uncompressed data has wrong size";
	rs_buf.next_in = state->ublock;
    }
    rs_buf.avail_in = usize;
    rs_buf.eof_in = 0;
    rs_buf.avail_out = 0;
    rs_buf.next_out = NULL;
    rs_res = rs_job_iter(state->rs_job, &rs_buf);
    if (rs_res != RS_BLOCKED && rs_res != RS_DONE)
	return "EBADF Error from librsync";
    if (rs_buf.avail_in > 0) {
	// XXX uhm, need to store this somewhere?
	error_report(error_internal, "signature", "avail>0");
    }
    state->has_signatures = 1;
    return "OK";
}
#endif

static const char * op_stat(char * lptr, state_t * state) {
    int len, trans, s;
    if (sscanf(lptr, "%d %d", &len, &trans) < 2)
	return "EINVAL Invalid request";
    if (len >= DATA_BLOCKSIZE - NAME_MAX - 2) {
	skip_data(state->p, len);
	return "EINVAL name too long";
    }
    if (! socket_get(state->p, state->cblock, len))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "STAT", "socket_get");
    state->cblock[len] = 0;
    s = send_stat(state->p, state->cblock, trans, "OK ", NULL);
    if (s > 0)
	return NULL;
    if (s < 0)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE, "STAT", "stat");
    error_report(error_server, state->peer, "STAT", errno);
    state->running = 0;
    return NULL;
}

const char * op_statfs(char * lptr, state_t * state) {
    int len;
    struct statvfs sbuff;
    if (sscanf(lptr, "%d", &len) < 1)
	return "EINVAL Invalid request";
    if (len >= DATA_BLOCKSIZE - 2) {
	skip_data(state->p, len);
	return "EINVAL name too long";
    }
    if (! socket_get(state->p, state->cblock, len))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "STATFS", "socket_get");
    state->cblock[len] = 0;
    if (statvfs(state->cblock, &sbuff) < 0)
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "STATFS", "statfs");
    sprintf(state->cblock, "OK %llu %llu %llu %llu %llu %llu %llu %d",
	    (unsigned long long)sbuff.f_bsize,
	    (unsigned long long)sbuff.f_blocks,
	    (unsigned long long)sbuff.f_bfree,
	    (unsigned long long)sbuff.f_bavail,
	    (unsigned long long)sbuff.f_files,
	    (unsigned long long)sbuff.f_ffree,
	    (unsigned long long)sbuff.f_favail,
	    ! (sbuff.f_flag & ST_RDONLY));
    if (! socket_puts(state->p, state->cblock)) {
	error_report(error_server, state->peer, "STATFS", errno);
	state->running = 0;
    }
    return NULL;
}

static const char * op_status(char * lptr, state_t * state) {
    const char * rep;
    if (! socket_puts(state->p, "OK sending status")) {
	error_report(error_server, state->peer, "STATUS", errno);
	state->running = 0;
	return NULL;
    }
    rep = send_status(state->p);
    if (rep) {
	error_report(error_server_msg, state->peer, "STATUS", rep);
	state->running = 0;
    }
    return NULL;
}

static const char * op_stop(char * lptr, state_t * state) {
    main_running = 0;
    error_report(info_user_stop);
    return "OK stopping";
}

static const char * op_update(char * lptr, state_t * state) {
    const char * rep;
    int len = atoi(lptr);
    if (len < 1)
	return "EINVAL Invalid update";
    if (len >= DATA_BLOCKSIZE - 2) {
	skip_data(state->p, len);
	return "EINVAL update too long";
    }
    if (! socket_get(state->p, state->cblock, len))
	return error_sys_r(state->cblock, DATA_BLOCKSIZE,
			   "UPDATE", "socket_get");
    state->cblock[len] = 0;
    if (! state->updating) {
	rep = config_start_update();
	if (rep) return rep;
	state->updating = 1;
    }
    if (strcasecmp(state->cblock, "commit") == 0) {
	if (state->updating != 1)
	    return "Previous update failed, cannot commit";
	rep = config_commit_update();
	state->updating = 0;
	if (rep) return rep;
	return "OK committed";
    }
    if (strcasecmp(state->cblock, "rollback") == 0) {
	config_cancel_update();
	state->updating = 0;
	return "OK rolled back";
    }
    rep = config_do_update(state->cblock);
    if (rep) {
	state->updating = 2;
	return rep;
    }
    return "OK updated";
}

#if NOTIFY != NOTIFY_NONE
static const char * op_watches(char * lptr, state_t * state) {
    if (! socket_puts(state->p, "OK")) {
	error_report(error_server, state->peer, "WATCHES", errno);
	state->running = 0;
	return NULL;
    }
    if (! notify_forall_watches(send_watch, state)) {
	state->running = 0;
	return NULL;
    }
    if (! socket_puts(state->p, "0")) {
	error_report(error_server, state->peer, "WATCHES", errno);
	state->running = 0;
    }
    return NULL;
}
#endif /* NOTIFY != NOTIFY_NONE */

const static command_t commands[] = {
    /* keep commands grouped by letter and in upper case */
#if NOTIFY != NOTIFY_NONE
    { "ADD",          config_op_add,      cm_server,  op_add },
#endif
    { "BWLIMIT",      config_op_read,     cm_server,  op_bwlimit },
    { "CHECKSUM",     config_op_read,     cm_server,  op_checksum },
    { "CLOSELOG",     config_op_closelog, cm_any,     op_closelog },
    { "COMPRESS",     config_op_read,     cm_server,  op_compress },
    { "CLOSEFILE",    config_op_read,     cm_server,  op_closefile },
    { "CONFIG",       config_op_getconf,  cm_any,     op_config },
#if NOTIFY != NOTIFY_NONE
    { "CROSS",        config_op_add,      cm_server,  op_cross },
#endif
    { "DATA",         config_op_read,     cm_server,  op_data },
    { "DEBUG",        config_op_debug,    cm_any,     op_debug },
#if THEY_HAVE_LIBRSYNC
    { "DELTA",        config_op_read,     cm_server,  op_delta },
#endif
    { "DIRSYNC",      config_op_dirsync,  cm_copy,    op_dirsync },
#if 0 // XXX ENCRYPT
    { "ENCRYPT",      config_op_read,     cm_server,  op_encrypt },
#endif
#if NOTIFY != NOTIFY_NONE
    { "EVBATCH",      config_op_read,     cm_server,  op_evbatch },
    { "EVENT",        config_op_read,     cm_server,  op_event },
    { "EXCL",         config_op_add,      cm_server,  op_excl },
#endif
    { "EXTENSIONS",   ~0,                 cm_any,     op_extensions },
#if NOTIFY != NOTIFY_NONE
    { "FIND",         config_op_add,      cm_server,  op_find },
#endif
    { "GETDIR",       config_op_read,     cm_server,  op_getdir },
#if 0 // XXX IGNORE
    { "IGNORE",       config_op_ignore,   cm_server,  op_ignore },
#endif
    { "LISTCHECKSUM", config_op_read |
		      config_op_getconf,  cm_server,  op_listchecksum },
    { "LISTCOMPRESS", config_op_read |
		      config_op_getconf,  cm_server,  op_listcompress },
#if NOTIFY != NOTIFY_NONE
    { "NOCROSS",      config_op_add,      cm_server,  op_nocross },
#endif
    { "NODEBUG",      config_op_debug,    cm_any,     op_nodebug },
    { "OPEN",         config_op_read,     cm_server,  op_open },
#if NOTIFY != NOTIFY_NONE
    { "PURGE",        config_op_purge,    cm_server,  op_purge },
#endif
    { "QUIT",         ~0,                 cm_any,     op_quit },
#if NOTIFY != NOTIFY_NONE
    { "REMOVE",       config_op_remove,   cm_server,  op_remove },
#endif
#if THEY_HAVE_LIBRSYNC
    { "RSYNC",        config_op_read,     cm_server,  op_rsync },
#endif
    { "SETCHECKSUM",  config_op_read,     cm_server,  op_setchecksum },
#if NOTIFY != NOTIFY_NONE
    { "SETROOT",      config_op_read,     cm_server,  op_setroot },
#endif
#if THEY_HAVE_LIBRSYNC
    { "SIGNATURE",    config_op_read,     cm_server,  op_signature },
#endif
    { "STAT",         config_op_read,     cm_server,  op_stat },
    { "STATFS",       config_op_read,     cm_server,  op_statfs },
    { "STATUS",       config_op_status,   cm_any,     op_status },
    { "STOP",         config_op_stop,     cm_any,     op_stop },
    { "UPDATE",       config_op_setconf,  cm_any,     op_update },
#if NOTIFY != NOTIFY_NONE
    { "WATCHES",      config_op_watches,  cm_server,  op_watches },
#endif
};
#define NR_COMMANDS (sizeof(commands) / sizeof(command_t))

static int cmdindex[27];

/* talks to a client */

void * run_server(void * _tp) {
    thlist_t * tp = _tp;
    state_t state;
    int ov;
    const char * user;
    config_userop_t allowed;
    cmdmode_t mode = client_mode ? cm_copy : cm_server;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    state.p = tp->p;
    state.poll_fd = socket_poll(state.p);
    state.peer = socket_addr(state.p);
    state.running = 1;
    state.updating = 0;
    state.bwlimit = 0L;
    state.csum_n = checksum_byname("md5");
    state.compression = state.rfd = -1;
    state.block_start = state.block_size = -1;
    state.Dname = NULL;
#if NOTIFY != NOTIFY_NONE
    state.add = NULL;
    state.get = NULL;
    state.rootdir = NULL;
    state.translate_ids = 1;
    state.changes = 0;
#endif
#if THEY_HAVE_LIBRSYNC
    state.has_signatures = 0;
    state.delta_pos = -1;
    state.rdiff_start = state.rdiff_end = -1;
    state.rs_signature = NULL;
    state.rs_job = NULL;
#endif
    user = socket_user(state.p);
    allowed = socket_actions(state.p);
    error_report(info_connection_open, user, state.peer);
    while (main_running && state.running) {
	char line[LINESIZE], * lptr, * kw;
	const char * rep;
	int cmdi, cmde;
	if (! socket_gets(state.p, line, LINESIZE)) {
	    if (errno != EINTR && errno != EPIPE)
		error_report(error_server, state.peer, "run_server", errno);
	    break;
	}
	lptr = line;
	while (*lptr && isspace((int)*lptr)) lptr++;
	kw = lptr;
	while (*lptr && ! isspace((int)*lptr)) lptr++;
	if (lptr == kw) {
	    rep = "EINVAL Invalid empty command";
	    goto report;
	}
	if (*lptr) {
	    *lptr++ = 0;
	    while (*lptr && isspace((int)*lptr)) lptr++;
	}
	if (isupper((int)kw[0])) {
	    cmdi = kw[0] - 'A';
	} else if (islower((int)kw[0])) {
	    cmdi = kw[0] - 'a';
	} else {
	    goto not_found;
	}
	cmde = cmdindex[cmdi + 1];
	cmdi = cmdindex[cmdi];
	while (cmdi < cmde) {
	    if (strcasecmp(kw, commands[cmdi].keyword) == 0) {
		if (! (mode & commands[cmdi].mode)) {
		    rep = client_mode
			? "ENOSYS Operation not supported in copy mode"
			: "ENOSYS Operation not supported in server mode";
		    goto report;
		}
		if (! (allowed & commands[cmdi].opclass)) {
		    rep = "EPERM Operation not permitted";
		    goto report;
		}
		rep = commands[cmdi].op(lptr, &state);
		if (! rep) goto noreport;
		goto report;
	    }
	    cmdi++;
	}
    not_found:
	rep = "Invalid request";
    report:
	if (! socket_puts(state.p, rep)) {
	    error_report(error_server, state.peer, "run_server", errno);
	    state.running = 0;
	    break;
	}
    noreport:
	if (! socket_flush(state.p)) {
	    error_report(error_server, state.peer, "run_server", errno);
	    state.running = 0;
	}
    }
    if (state.updating) config_cancel_update();
    if (state.rfd >= 0) close(state.rfd);
    if (state.Dname) myfree(state.Dname);
#if NOTIFY != NOTIFY_NONE
    if (state.get) store_finish(state.get);
    if (state.rootdir) myfree(state.rootdir);
    if (state.add) {
	config_free_add(state.add->privdata);
	myfree(state.add);
    }
    if (state.changes) {
	notify_status_t info;
	notify_status(&info);
	error_report(info_count_watches, info.watches);
    }
#endif /* NOTIFY != NOTIFY_NONE */
#if THEY_HAVE_LIBRSYNC
    if (state.rs_signature) rs_free_sumset(state.rs_signature);
    if (state.rs_job) rs_job_free(state.rs_job);
#endif
    error_report(info_connection_close, user, state.peer);
    socket_disconnect(state.p);
    tp->completed = 1;
    return NULL;
}

/* run control thread; returns NULL on normal termination,
 * or an error message */

const char * control_thread(void) {
    int ov, inum, pos;
    for (pos = inum = 0; pos < 27; pos++) {
	char letter = pos + 'A';
	cmdindex[pos] = inum;
	while (inum < NR_COMMANDS && commands[inum].keyword[0] == letter)
	    inum++;
    }
    cmdindex[26] = NR_COMMANDS;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    while (main_running) {
	int errcode;
	socket_t * p;
	thlist_t * tp;
	tp = all_threads;
	while (tp) {
	    thlist_t * this = tp;
	    tp = tp->next;
	    if (this->completed) {
		void * result;
		pthread_t name = this->name;
		if (all_threads == this)
		    all_threads = tp;
		else
		    this->prev->next = tp;
		if (tp)
		    tp->prev = this->prev;
		myfree(this);
		pthread_join(name, &result);
	    }
	}
	if (client_mode) {
	    /* see if we need to schedule dirsyncs */
	    time_t ld = copy_last_dirsync(), now = time(NULL);
	    const config_data_t * cfg = config_get();
	    time_t deadline = config_intval(cfg, cfg_dirsync_deadline);
	    int interval = config_intval(cfg, cfg_dirsync_interval);
	    const char * do_one = NULL;
	    /* for periodic rsyncs, check that we haven't done one in
	     * the last "interval" seconds */
	    if (interval > 0 && ld + interval <= now)
		do_one = "periodic";
	    /* for timed ones, check if we've done one more than 10 minutes
	     * ago, and there is one with starttime up to 10 minutes in the
	     * past; supposedly, POLL_TIME is small enough that we check
	     * more often than once an hour... */
	    if (! do_one &&
		config_intarr_len(cfg, cfg_dirsync_timed) > 0 &&
		ld + 600 <= now)
	    {
		struct tm tm_now;
		if (localtime_r(&now, &tm_now)) {
		    int i, daynum = 1 << (24 + tm_now.tm_wday);
		    int thistime = tm_now.tm_hour * 3600
				 + tm_now.tm_min * 60
				 + tm_now.tm_sec;
		    int count = config_intarr_len(cfg, cfg_dirsync_timed);
		    const int * dp = config_intarr_data(cfg, cfg_dirsync_timed);
		    for (i = 0; i < count; i++) {
			int st = dp[i];
			if (! (st & daynum))
			    continue;
			st &= 0xffffff;
			if (st <= 85800) {
			    /* start time between 00:00:00 and 23:50:00 */
			    if (thistime >= st && thistime < st + 800) {
				do_one = "timed";
				break;
			    }
			} else {
			    /* start time between 23:50:01 and 23:59:59 */
			    if (thistime >= st || thistime < st - 85800) {
				do_one = "timed";
				break;
			    }
			}
		    }
		}
	    }
	    config_put(cfg);
	    if (do_one) {
		if (deadline > 0) deadline += now;
		copy_dirsync(do_one, "", deadline);
	    }
	}
	p = socket_accept(server, POLL_TIME);
	if (! p) {
	    if (errno != ETIMEDOUT && errno != EINTR)
		error_report(error_accept, errno);
	    continue;
	}
	tp = mymalloc(sizeof(thlist_t));
	if (! tp) {
	    error_report(error_connect, "malloc", errno);
	    socket_disconnect(p);
	    continue;
	}
	tp->prev = NULL;
	tp->p = p;
	tp->completed = 0;
	tp->next = all_threads;
	if (all_threads) all_threads->prev = tp;
	all_threads = tp;
	clients++;
	errcode = pthread_create(&tp->name, NULL, run_server, tp);
	if (errcode) {
	    error_report(error_connect, "pthread_create", errcode);
	    socket_disconnect(p);
	    tp->completed = 1;
	    continue;
	}
    }
    while (all_threads) {
	thlist_t * tp;
	tp = all_threads;
	while (tp) {
	    thlist_t * this = tp;
	    tp = tp->next;
	    if (this->completed) {
		void * result;
		pthread_t name = this->name;
		if (all_threads == this)
		    all_threads = tp;
		else
		    this->prev->next = tp;
		if (tp)
		    tp->prev = this->prev;
		myfree(this);
		pthread_join(name, &result);
	    } else {
		//pthread_cancel(this->name);
		pthread_kill(this->name, SIGINT);
		//this->completed = 1;
	    }
	}
    }
    return NULL;
}

/* run initial thread, which does any delayed initialisation;
 * errors are logged but this never fails */

void control_initial_thread(void) {
#if NOTIFY != NOTIFY_NONE
    if (! client_mode) {
	notify_status_t info;
	const config_data_t * cfg = config_get();
	const config_strlist_t * d = config_strlist(cfg, cfg_add_path);
	if (! d) {
	    config_put(cfg);
	    return;
	}
	while (d) {
	    int count;
	    const char * err = control_add_tree(d, &count);
	    if (err)
		error_report(error_control, d->data, err);
	    d = d->next;
	}
	notify_status(&info);
	error_report(info_initial_watches, info.watches);
	config_put(cfg);
    }
#endif /* NOTIFY != NOTIFY_NONE */
}

#if NOTIFY != NOTIFY_NONE

/* scan a directory and adds a watch for all its subdirectories */

static void scan_dir(notify_watch_t * parent,
		     const char * path, int pathlen,
		     const config_add_t * how,
		     const dev_t * dev,
		     const dev_t * ev, ino_t evino,
		     int * count)
{
    DIR * dp;
    struct dirent * ent;
    char buffer[NAME_MAX + 2 + pathlen];
    struct stat sbuff;
    strncpy(buffer, path, pathlen);
    buffer[pathlen] = 0;
    if (stat(buffer, &sbuff) < 0) {
	error_report(error_scan_dir, buffer, errno);
	return;
    }
    dp = opendir(buffer);
    if (! dp) {
	error_report(error_scan_dir, buffer, errno);
	return;
    }
    buffer[pathlen++] = '/';
    while ((ent = readdir(dp)) != NULL) {
	int entlen = strlen(ent->d_name);
	const char * data[cfg_dacl_COUNT];
#if USE_SHOULDBOX
	if (entlen < 1 || entlen > NAME_MAX) {
	    /* shouldn't happen(TM) */
	    main_shouldbox++;
	    continue;
	}
#endif
	if (ent->d_name[0] == '.') {
	    if (entlen == 1) continue;
	    if (entlen == 2 && ent->d_name[1] == '.') continue;
	}
	strcpy(buffer + pathlen, ent->d_name);
	entlen += pathlen;
	/* check if this is excluded */
	data[cfg_dacl_name] = ent->d_name;
	data[cfg_dacl_path] = buffer;
	if (config_check_acl_cond(how->exclude, 0, data, cfg_dacl_COUNT))
	    continue;
	/* see if it is a subdir */
	if (lstat(buffer, &sbuff) < 0) {
	    error_report(error_scan_dir, buffer, errno);
	    continue;
	}
	if (S_ISDIR(sbuff.st_mode)) {
	    notify_watch_t * watch;
	    if (dev && sbuff.st_dev != *dev)
		continue;
	    if (ev && sbuff.st_dev == *ev && sbuff.st_ino == evino)
		continue;
	    watch = notify_add(parent, ent->d_name, how);
	    if (! watch) {
		error_report(error_scan_dir, buffer, errno);
		continue;
	    }
	    (*count)++;
	    scan_dir(watch, buffer, entlen, how, dev, ev, evino, count);
	}
    }
    closedir(dp);
}

/* scan a single root tree */

static const char * scan_root(const config_add_t * d,
			      const char * rootpath,
			      const dev_t * dev,
			      const dev_t * ev, ino_t evino,
			      int * count)
{
    notify_watch_t * root;
    struct stat sbuff;
    if (stat(rootpath, &sbuff) < 0)
	return error_sys("scan_root", rootpath);
    if (ev && sbuff.st_dev == *ev && sbuff.st_ino == evino)
	return NULL;
    error_report(info_adding_watch, rootpath);
    root = notify_find_bypath(rootpath, d);
    if (! root)
	return error_sys("scan_root", "notify_find_bypath");
    (*count)++;
    scan_dir(root, rootpath, strlen(rootpath), d, dev, ev, evino, count);
    notify_unlock_watch(root);
    return NULL;
}

/* find all matching directories, and scan them as separate roots */

static const char * scan_find(const config_add_t * d, const char * path,
			      int pathlen, const dev_t * dev,
			      const dev_t * ev, ino_t evino, int * count)
{
    DIR * dp;
    struct dirent * ent;
    char buffer[NAME_MAX + 2 + pathlen];
    struct stat sbuff;
    strncpy(buffer, path, pathlen);
    buffer[pathlen] = 0;
    if (stat(buffer, &sbuff) < 0) {
	error_report(error_scan_dir, buffer, errno);
	return NULL;
    }
    if (ev && sbuff.st_dev == *ev && sbuff.st_ino == evino)
	return NULL;
    dp = opendir(buffer);
    if (! dp) {
	error_report(error_scan_find, path, errno);
	return NULL;
    }
    buffer[pathlen++] = '/';
    while ((ent = readdir(dp)) != NULL) {
	int entlen = strlen(ent->d_name);
#if USE_SHOULDBOX
	if (entlen < 1 || entlen > NAME_MAX) {
	    /* shouldn't happen(TM) */
	    error_report(error_shouldbox_int,
			 "readdir", "strlen(d_name)", entlen);
	    main_shouldbox++;
	    continue;
	}
#endif
	if (ent->d_name[0] == '.') {
	    if (entlen == 1) continue;
	    if (entlen == 2 && ent->d_name[1] == '.') continue;
	}
	strcpy(buffer + pathlen, ent->d_name);
	entlen += pathlen;
	/* see if it is a subdir */
	if (lstat(buffer, &sbuff) < 0) {
	    error_report(error_scan_find, buffer, errno);
	    continue;
	}
	if (S_ISDIR(sbuff.st_mode)) {
	    const char * err = NULL;
	    const char * data[cfg_dacl_COUNT];
	    if (dev && sbuff.st_dev != *dev)
		continue;
	    data[cfg_dacl_name] = ent->d_name;
	    data[cfg_dacl_path] = buffer;
	    if (config_check_acl_cond(d->find, 0, data, cfg_dacl_COUNT))
		err = scan_root(d, buffer, dev, ev, evino, count);
	    else
		err = scan_find(d, buffer, entlen, dev, ev, evino, count);
	    if (err) {
		closedir(dp);
		return err;
	    }
	}
    }
    closedir(dp);
    return NULL;
}

/* ask the control thread to add a directory tree; returns NULL if OK or
 * an error message */

const char * control_add_tree(const config_strlist_t * d, int * count) {
    struct stat sbuff;
    dev_t devbuff, * dev = NULL, evbuff, * ev = NULL;
    ino_t evino = (ino_t)0;
    const config_data_t * cfg;
    const config_add_t * av;
    if (d->data[0] != '/')
	return "Tree is not an absolute path";
    if (stat(d->data, &sbuff) < 0)
	return error_sys("control_add_tree", "stat");
    if (! S_ISDIR(sbuff.st_mode))
	return "Path is not a directory";
    av = d->privdata;
    if (! av)
	return "Invalid data";
    if (! av->crossmount) {
	devbuff = sbuff.st_dev;
	dev = &devbuff;
    }
    cfg = config_get();
    if (stat(config_strval(cfg, cfg_eventdir), &sbuff) >= 0) {
	evbuff = sbuff.st_dev;
	ev = &evbuff;
	evino = sbuff.st_ino;
    }
    config_put(cfg);
    *count = 0;
    /* make sure we identify this as a rootpoint */
    if (av->find)
	return scan_find(av, d->data, d->datalen, dev, ev, evino, count);
    else
	return scan_root(av, d->data, dev, ev, evino, count);
}

/* ask the control thread to remove a directory tree; returns NULL if OK or
 * an error message */

const char * control_remove_tree(const char * path) {
    const char * res;
    if (path[0] != '/')
	return "Tree is not an absolute path";
    res = notify_remove_under(path);
    if (res) return res;
    error_report(info_removing_watch, path);
    return NULL;
}
#endif /* NOTIFY != NOTIFY_NONE */

/* cleanup required after the control thread terminates */

void control_exit(void) {
    if (server) socket_disconnect(server);
    /* wait for all remaining threads */
    while (all_threads) {
	void * result;
	thlist_t * this = all_threads;
	all_threads = this->next;
	pthread_cancel(this->name);
	pthread_join(this->name, &result);
	myfree(this);
    }
}

