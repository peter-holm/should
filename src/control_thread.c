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
    socket_t * p = _VP;
    char buffer[32];
    sprintf(buffer, "%d", (int)strlen(name));
    if (! socket_puts(p, buffer)) {
	struct sockaddr_storage * addr = socket_addr(p);
	error_report(error_server, addr, "send_watch", errno);
	return 0;
    }
    if (! socket_put(p, name, strlen(name))) {
	struct sockaddr_storage * addr = socket_addr(p);
	error_report(error_server, addr, "send_watch", errno);
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

#if NOTIFY != NOTIFY_NONE
static const char * handle_excl_find(socket_t * p, char * lptr, int is_excl,
				     config_dir_t * add, char cblock[])
{
    int match, how, namelen = atoi(lptr);
    config_acl_cond_t * item;
    const char * rep, * kw;
    char line[LINESIZE];
    if (namelen < 1)
	return "EINVAL Invalid name";
    if (! add) {
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
	rep = error_sys_r(cblock, DATA_BLOCKSIZE,
			  "run_server", "malloc");
	goto skip_report;
    }
    if (! socket_get(p, item->pattern, namelen)) {
	rep = error_sys_r(cblock, DATA_BLOCKSIZE,
			  "run_server", "malloc");
	myfree(item);
	return rep;
    }
    item->pattern[namelen] = 0;
    if (is_excl) {
	item->next = add->exclude;
	add->exclude = item;
    } else {
	item->next = add->find;
	add->find = item;
    }
    return "OK added";
skip_report:
    while (namelen > 0) {
	int sz = namelen > LINESIZE ? LINESIZE : namelen;
	socket_get(p, line, LINESIZE);
	namelen -= sz;
    }
    return rep;
}

static const char * finish_add(config_dir_t * add, int * changes,
			       char cblock[])
{
    const char * rep;
    int count = 0;
    if (! add)
	return "EINVAL Add request was never prepared";
    rep = control_add_tree(add, &count);
    config_dir_free(add);
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

static void skip_data(socket_t * p, int len) {
    char block[256];
    while (len > 0) {
	int nl = len > sizeof(block) ? sizeof(block) : len;
	if (! socket_get(p, block, nl))
	    return;
	len -= nl;
    }
}

static inline char * get_block(int fd, long long start, long long *size,
			       char * block, long long * block_start, 
			       long long * block_size)
{
    ssize_t nr;
    if (*size < 1) return block;
    if (*block_start >= 0 && *block_size >= 0) {
	if (*block_start <= start &&
	    *block_start + *block_size >= start + *size)
		return block + (start - *block_start);
    }
    if (lseek(fd, (off_t)start, SEEK_SET) < 0)
	return NULL;
    if (*size > DATA_BLOCKSIZE)
	*size = DATA_BLOCKSIZE;
    nr = read(fd, block, *size);
    if (nr < 0)
	return NULL;
    *size = *block_size = nr;
    *block_start = start;
    return block;
}

/* talks to a client */

void * run_server(void * _tp) {
    thlist_t * tp = _tp;
    socket_t * p = tp->p;
    struct sockaddr_storage * addr = socket_addr(p);
    int ov, running = 1, csum_n, is_server = ! client_mode, updating = 0;
    int compression = -1, rfd = -1;
    char * Dname = NULL;
    char cblock[DATA_BLOCKSIZE], ublock[DATA_BLOCKSIZE];
    const char * user = socket_user(p), * udata;
    long long usize, block_start = -1, block_size = -1;
#if THEY_HAVE_LIBRSYNC
    long long rdiff_start = -1, rdiff_size = -1;
    pipe_t rdiff_pipe; // XXX replace with librsync
    int has_signatures = 0;
#endif
#if NOTIFY != NOTIFY_NONE
    store_get_t * get = NULL;
    config_dir_t * add = NULL;
    char * rootdir = NULL;
    int changes = 0, translate_ids = 1;
#endif /* NOTIFY != NOTIFY_NONE */
    long bwlimit = 0L;
    config_userop_t allowed = socket_actions(p);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    error_report(info_connection_open, user, addr);
    csum_n = checksum_byname("md5");
#if THEY_HAVE_LIBRSYNC
    rdiff_pipe.pid = -1;
    rdiff_pipe.fromchild = rdiff_pipe.tochild = -1;
#endif
    while (main_running && running) {
	char line[LINESIZE], * lptr, * kw;
	const char * rep;
	int namelen = 0;
	if (! socket_gets(p, line, LINESIZE)) {
	    if (errno != EINTR && errno != EPIPE)
		error_report(error_server, addr, "run_server", errno);
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
	switch (kw[0]) {
#if NOTIFY != NOTIFY_NONE
	    case 'A' : case 'a' :
		if (is_server && strcasecmp(kw, "ADD") == 0) {
		    if (! (allowed & config_op_add)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    namelen = atoi(lptr);
		    if (namelen < 1) {
			rep = "EINVAL Invalid name";
			goto report;
		    }
		    add = mymalloc(sizeof(config_dir_t));
		    if (! add) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    add->next = NULL;
		    add->crossmount = 1;
		    add->exclude = NULL;
		    add->find = NULL;
		    add->path = mymalloc(1 + namelen);
		    if (! add->path) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    if (! socket_get(p, add->path, namelen)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto report;
		    }
		    add->path[namelen] = 0;
		    rep = "OK added";
		    goto report;
		}
		break;
#endif /* NOTIFY != NOTIFY_NONE */
	    case 'B' : case 'b' :
		if (is_server && strcasecmp(kw, "BWLIMIT") == 0) {
		    long limit;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    limit = atol(lptr);
		    if (limit < 0 || limit >= LONG_MAX / 1024L) {
			rep = "EINVAL bandwidth limit";
		    } else {
			bwlimit = limit * 1024L;
			rep = "OK limit changed";
		    }
		    goto report;
		}
		break;
	    case 'C' : case 'c' :
		if (is_server && csum_n >= 0 && strcasecmp(kw, "CHECKSUM") == 0)
		{
		    long long start;
		    int i, wp, clen = checksum_size(csum_n);
		    unsigned char hash[clen];
		    char * block;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (sscanf(lptr, "%lld %lld", &start, &usize) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (start < 0 || usize < 0) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    block = get_block(rfd, start, &usize, ublock,
				      &block_start, &block_size);
		    if (! block) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "get_block");
			goto report;
		    }
		    if (! checksum_data(csum_n, block, usize, hash)) {
			rep = "Error calculating checksum";
			goto report;
		    }
		    wp = sprintf(cblock, "OK %lld ", usize);
		    for (i = 0; i < clen; i++)
			wp += sprintf(cblock + wp, "%02X",
				      (unsigned int)hash[i]);
		    rep = cblock;
		    goto report;
		}
		if (strcasecmp(kw, "CLOSELOG") == 0) {
		    if (! (allowed & config_op_closelog)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    error_closelog();
		    rep = "OK closed";
		    goto report;
		}
		if (is_server && strcasecmp(kw, "COMPRESS") == 0) {
		    int num;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    kw = lptr;
		    while (*lptr && ! isspace((int)*lptr)) lptr++;
		    if (lptr == kw) {
			rep = "EINVAL Invalid empty compression method";
			goto report;
		    }
		    if (*lptr)
			*lptr++ = 0;
		    num = compress_byname(kw);
		    if (num < 0) {
			rep = "EINVAL Unknown compression method";
			goto report;
		    }
		    compression = num;
		    rep = "OK compression selected";
		    goto report;
		}
		if (is_server && strcasecmp(kw, "CLOSEFILE") == 0) {
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (Dname) myfree(Dname);
		    Dname = NULL;
		    close(rfd);
		    rfd = -1;
		    rep = "OK file closed";
		    goto report;
		}
		if (strcasecmp(kw, "CONFIG") == 0) {
		    if (! (allowed & config_op_getconf)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    config_print(sendlines, p);
		    if (! socket_puts(p, "__END__")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "CROSS") == 0) {
		    if (! (allowed & config_op_add)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    add->crossmount = 1;
		    rep = finish_add(add, &changes, cblock);
		    add = NULL;
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		break;
	    case 'D' : case 'd' :
		if (is_server && strcasecmp(kw, "DATA") == 0) {
		    long long start, csize, dsize;
		    const char * dptr;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (sscanf(lptr, "%lld %lld", &start, &usize) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    udata = get_block(rfd, start, &usize, ublock,
				      &block_start, &block_size);
		    if (! udata) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "get_block");
			goto report;
		    }
#if THEY_HAVE_LIBRSYNC
		send_data:
#endif
		    if (compression >= 0 && usize > 0)
			csize = compress_data(compression, udata,
					      usize, cblock);
		    else
			csize = -1;
		    if (csize <= 0) {
			char tmpbuff[64];
			sprintf(tmpbuff, "OK %lld", usize);
			if (! socket_puts(p, tmpbuff)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
			dptr = udata;
			dsize = usize;
		    } else {
			char tmpbuff[64];
			sprintf(tmpbuff, "OK %lld %lld", csize, usize);
			if (! socket_puts(p, tmpbuff)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
			dptr = cblock;
			dsize = csize;
		    }
		    if (bwlimit > 0) {
			while (dsize > 0) {
			    long diff = dsize;
			    if (diff > bwlimit) diff = bwlimit;
			    if (! socket_put(p, dptr, diff)) {
				error_report(error_server, addr,
					     "run_server", errno);
				break;
			    }
			    dptr += diff;
			    dsize -= diff;
			    sleep(1);
			}
		    } else {
			if (! socket_put(p, dptr, dsize)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
		    }
		    goto noreport;
		}
#if THEY_HAVE_LIBRSYNC
		if (is_server && strcasecmp(kw, "DELTA") == 0) {
		    long long msize;
		    ssize_t nr;
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (! has_signatures) {
			rep = "EINVAL Did not see a SIGNATURE command";
			goto report;
		    }
		    if (rdiff_pipe.tochild >= 0) {
			close(rdiff_pipe.tochild);
			rdiff_pipe.tochild = -1;
		    }
		    if (sscanf(lptr, "%lld", &msize) < 1) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (msize > DATA_BLOCKSIZE)
			msize = DATA_BLOCKSIZE;
		    // XXX replace following with librsync
		    block_start = block_size = -1;
		    nr = read(rdiff_pipe.fromchild, ublock, msize);
		    if (nr < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "rdiff");
			goto report;
		    }
		    usize = nr;
		    udata = ublock;
		    goto send_data;
		}
#endif
		if (strcasecmp(kw, "DEBUG") == 0) {
		    if (! (allowed & config_op_debug)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    socket_setdebug(p, 1);
		    rep = "OK";
		    goto report;
		}
		if (! is_server && strcasecmp(kw, "DIRSYNC") == 0) {
		    char * path;
		    int ok;
		    if (! (allowed & config_op_dirsync)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    namelen = atoi(lptr);
		    if (namelen < 1) {
			rep = "EINVAL Invalid name";
			goto report;
		    }
		    path = mymalloc(1 + namelen);
		    if (! path) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    if (! socket_get(p, path, namelen)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			myfree(path);
			goto report;
		    }
		    path[namelen] = 0;
		    ok = copy_dirsync("user", path);
		    myfree(path);
		    if (ok) {
			rep = "OK scheduled";
		    } else {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "schedule_dirsync");
		    }
		    goto report;
		}
		break;
	    case 'E' : case 'e' :
		if (strcasecmp(kw, "EXTENSIONS") == 0) {
		    if (! socket_puts(p, "OK sending extensions list")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    // XXX ENCRYPT
		    if (! socket_puts(p, "UPDATE")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    if (is_server) {
			if (csum_n >= 0 &&
			    ! socket_puts(p, "CHECKSUM"))
			{
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
			// XXX IGNORE (is_server)
#if THEY_HAVE_LIBRSYNC
			if (! socket_puts(p, "RSYNC")) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
#endif
		    } else {
			if (! socket_puts(p, "DIRSYNC")) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
		    }
		    if (! socket_puts(p, ".")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    continue;
		}
		// XXX ENCRYPT [config_op_read]
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "EXCL") == 0) {
		    if (! (allowed & config_op_add)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    rep = handle_excl_find(p, lptr, 1, add, cblock);
		    goto report;
		}
		if (is_server && strcasecmp(kw, "EVENT") == 0) {
		    notify_event_t ev;
		    int timeout, size, avail;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! get) {
			rep = "EINVAL no root dir";
			goto report;
		    }
		    if (sscanf(lptr, "%d %d", &timeout, &size) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    avail = store_get(get, &ev, timeout, size, socket_poll(p),
				      cblock, DATA_BLOCKSIZE);
		    if (avail == -2) {
			rep = cblock;
			goto report;
		    }
		    if (avail < 0) {
			/* no event available */
			rep = "OK NO";
			goto report;
		    }
		    if (avail > 0) {
			/* event too big */
			sprintf(cblock, "OK BIG %d", avail);
			if (! socket_puts(p, cblock)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
			goto noreport;
		    }
		    /* an event is available */
		    sprintf(cblock, "OK EV %d %d %d %d %d %d %d %d",
			    store_get_file(get), store_get_pos(get),
			    ev.event_type, ev.file_type, ev.stat_valid,
			    ev.stat_valid || ev.event_type == notify_add_tree,
			    ev.from_length, ev.to_length);
		    if (! socket_puts(p, cblock)) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    if (ev.from_length &&
			! socket_put(p, ev.from_name, ev.from_length))
		    {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    if (ev.to_length &&
			! socket_put(p, ev.to_name, ev.to_length))
		    {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    if (ev.stat_valid) {
			if (translate_ids) {
			    char uname[64], gname[64];
			    if (usermap_fromid(ev.file_user, uname,
					       sizeof(uname)) <= 0)
				strcpy(uname, "?");
			    if (groupmap_fromid(ev.file_group, gname,
					        sizeof(gname)) <= 0)
				strcpy(gname, "?");
			    sprintf(cblock, "NSTAT 0%o %s %d %s %d %lld %d %d",
				    ev.file_mode, uname, ev.file_user,
				    gname, ev.file_group, ev.file_size,
				    major(ev.file_device),
				    minor(ev.file_device));
			} else {
			    sprintf(cblock, "STAT 0%o %d %d %lld %d %d",
				    ev.file_mode, ev.file_user,
				    ev.file_group, ev.file_size,
				    major(ev.file_device),
				    minor(ev.file_device));
			}
			if (! socket_puts(p, cblock)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
		    }
		    if (ev.stat_valid || ev.event_type == notify_add_tree) {
			char mtime[64];
			struct tm tm;
			gmtime_r(&ev.file_mtime, &tm);
			strftime(mtime, sizeof(mtime),
				 "%Y-%m-%d:%H:%M:%S", &tm);
			sprintf(cblock, "MTIME %s", mtime);
			if (! socket_puts(p, cblock)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
		    }
		    goto noreport;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		break;
#if NOTIFY != NOTIFY_NONE
	    case 'F' : case 'f' :
		if (is_server && strcasecmp(kw, "FIND") == 0) {
		    if (! (allowed & config_op_add)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    rep = handle_excl_find(p, lptr, 0, add, cblock);
		    goto report;
		}
		break;
#endif /* NOTIFY != NOTIFY_NONE */
	    case 'G' : case 'g' :
		if (is_server && strcasecmp(kw, "GETDIR") == 0) {
		    int len, trans, skip_should;
		    DIR * dp;
		    struct dirent * ent;
		    const config_data_t * cfg;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    cfg = config_get();
		    skip_should =
			config_intval(cfg, cfg_flags) & config_flag_skip_should;
		    config_put(cfg);
		    if (sscanf(lptr, "%d %d", &len, &trans) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (len >= DATA_BLOCKSIZE - NAME_MAX - 2) {
			skip_data(p, len);
			rep = "EINVAL name too long";
			goto report;
		    }
		    if (! socket_get(p, cblock, len)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    cblock[len] = 0;
		    dp = opendir(cblock);
		    if (! dp) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "opendir", cblock);
			goto report;
		    }
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			closedir(dp);
			break;
		    }
		    cblock[len++] = '/';
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
			strcpy(cblock + len, ent->d_name);
			if (send_stat(p, cblock, trans, "", ent->d_name))
			    continue;
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    closedir(dp);
		    if (! socket_puts(p, ".")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		break;
	    case 'I' : case 'i' :
		// XXX IGNORE (is_server) [config_op_ignore]
		break;
	    case 'L' : case 'l' :
		if (is_server && strcasecmp(kw, "LISTCOMPRESS") == 0) {
		    int n, max = compress_count(), err = 0;
		    if (! (allowed & (config_op_read | config_op_getconf))) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    for (n = 0; n < max; n++) {
			const char * c = compress_name(n);
#if USE_SHOULDBOX
			if (! c) {
			    error_report(error_shouldbox_null,
					 "run_server", "compression");
			    err = 1;
			    break;
			}
#endif
			if (! socket_puts(p, c)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    err = 1;
			    break;
			}
		    }
		    if (err) break;
		    if (! socket_puts(p, "__END__")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		if (is_server && strcasecmp(kw, "LISTCHECKSUM") == 0) {
		    int n, max = checksum_count(), err = 0;
		    if (! (allowed & (config_op_read | config_op_getconf))) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    for (n = 0; n < max; n++) {
			const char * c = checksum_name(n);
#if USE_SHOULDBOX
			if (! c) {
			    error_report(error_shouldbox_null,
					 "run_server", "compression");
			    err = 1;
			    break;
			}
#endif
			if (! socket_puts(p, c)) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    err = 1;
			    break;
			}
		    }
		    if (err) break;
		    if (! socket_puts(p, "__END__")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		break;
	    case 'N' : case 'n' :
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "NOCROSS") == 0) {
		    if (! (allowed & config_op_add)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    add->crossmount = 0;
		    rep = finish_add(add, &changes, cblock);
		    add = NULL;
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		if (strcasecmp(kw, "NODEBUG") == 0) {
		    if (! (allowed & config_op_debug)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    socket_setdebug(p, 0);
		    rep = "OK";
		    goto report;
		}
		break;
	    case 'O' : case 'o' :
		if (is_server && strcasecmp(kw, "OPEN") == 0) {
		    struct stat sbuff;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    namelen = atoi(lptr);
		    if (namelen < 1) {
			rep = "EINVAL Invalid name";
			goto report;
		    }
		    if (Dname) myfree(Dname);
		    if (rfd >= 0) close(rfd);
		    rfd = -1;
		    Dname = mymalloc(1 + namelen);
		    if (! Dname) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    if (! socket_get(p, Dname, namelen)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    Dname[namelen] = 0;
		    /* don't wait on a named pipe or similar thing */
		    if (lstat(Dname, &sbuff) < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			goto report;
		    }
		    if (! S_ISREG(sbuff.st_mode)) {
			rep = "EBADF not a regular file";
			goto report;
		    }
		    if (sbuff.st_size == 0) {
			rep = "File has zero size, no need to OPEN it...";
			goto report;
		    }
		    /* there's a chance somebody will rename a pipe into Dname
		     * just right now. Nothing we can do about it, but we open
		     * the file in nonblocking mode and then re-check with
		     * fstat that it's still a regular file */
		    rfd = open(Dname, O_RDONLY|O_NONBLOCK);
		    if (rfd < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			goto report;
		    }
		    if (fstat(rfd, &sbuff) < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			close(rfd);
			rfd = -1;
			goto report;
		    }
		    if (! S_ISREG(sbuff.st_mode)) {
			rep = "EBADF not a regular file";
			close(rfd);
			rfd = -1;
			goto report;
		    }
		    if (sbuff.st_size == 0) {
			rep = "File has zero size, no need to OPEN it...";
			close(rfd);
			rfd = -1;
			goto report;
		    }
		    /* reset O_NONBLOCK */
		    fcntl(rfd, F_SETFL, 0L);
		    rep = "OK file opened";
		    goto report;
		}
		break;
#if NOTIFY != NOTIFY_NONE
	    case 'P' : case 'p' :
		if (is_server && strcasecmp(kw, "PURGE") == 0) {
		    int days;
		    if (! (allowed & config_op_purge)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    days = atoi(lptr);
		    if (days < 2) {
			rep = "EINVAL number of days";
		    } else {
			if (! store_purge(days))
			    rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					      "run_server", "store_purge");
			else
			    rep = "OK purged";
		    }
		    goto report;
		}
		break;
#endif /* NOTIFY != NOTIFY_NONE */
	    case 'Q' : case 'q' :
		if (strcasecmp(kw, "QUIT") == 0) {
		    running = 0;
		    rep = "OK bye then";
		    goto report;
		}
		break;
	    case 'R' : case 'r' :
#if THEY_HAVE_LIBRSYNC
		if (is_server && strcasecmp(kw, "RSYNC") == 0) {
		    long long start;
		    const char * command[6];
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (sscanf(lptr, "%lld %lld", &start, &usize) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (start < 0 || usize < 0) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    // XXX replace following with librsync
		    pipe_close(&rdiff_pipe);
		    rdiff_start = rdiff_size = -1;
		    has_signatures = 0;
		    command[0] = "rdiff";
		    command[1] = "delta";
		    command[2] = "-";
		    command[3] = Dname;
		    command[4] = "-";
		    command[5] = NULL;
		    if (! pipe_openfromto((char * const *)command, &rdiff_pipe))
		    {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "rdiff");
			goto report;
		    }
		    rdiff_start = start;
		    rdiff_size = usize;
		    snprintf(cblock, DATA_BLOCKSIZE, "OK %lld %d",
			     usize, DATA_BLOCKSIZE);
		    rep = cblock;
		    goto report;
		}
#endif /* THEY_HAVE_LIBRSYNC */
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "REMOVE") == 0) {
		    char * path;
		    if (! (allowed & config_op_remove)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    namelen = atoi(lptr);
		    if (namelen < 1) {
			rep = "EINVAL Invalid name";
			goto report;
		    }
		    path = mymalloc(1 + namelen);
		    if (! path) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    if (! socket_get(p, path, namelen)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			myfree(path);
			goto report;
		    }
		    path[namelen] = 0;
		    rep = control_remove_tree(path);
		    myfree(path);
		    if (! rep) {
			changes = 1;
			rep = "OK removed";
		    }
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		break;
	    case 'S' : case 's' :
#if THEY_HAVE_LIBRSYNC
		if (is_server && strcasecmp(kw, "SIGNATURE") == 0) {
		    long long csize;
		    int dcount;
		    const char * dptr;
		    if (rfd < 0) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (rdiff_start < 0) {
			rep = "EINVAL Did not see an RSYNC command";
			goto report;
		    }
		    dcount = sscanf(lptr, "%lld %lld", &csize, &usize);
		    if (dcount < 1) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (dcount < 2) {
			usize = csize;
		    } else if ( compression < 0) {
			rep = "EINVAL no compression selected";
			goto report;
		    }
		    if (csize < 0 || usize < 0 || usize < csize) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (usize > DATA_BLOCKSIZE) {
			skip_data(p, usize);
			rep = "EINVAL Buffer overflow";
			goto report;
		    }
		    if (! socket_puts(p, "OK send the data")) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_put");
			goto report;
		    }
		    // XXX replace following with librsync
		    if (! socket_get(p, cblock, csize)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    dptr = cblock;
		    if (dcount >= 2) {
			int bsize = DATA_BLOCKSIZE;
			block_start = block_size = -1;
			rep = uncompress_data(compression, cblock, csize,
					      ublock, &bsize);
			if (rep) goto report;
			if (bsize != usize) {
			    rep = "EBADF Uncompressed data has wrong size";
			    goto report;
			}
			dptr = ublock;
		    }
		    while (usize > 0) {
			ssize_t nw = write(rdiff_pipe.tochild, dptr, usize);
			if (nw < 0) {
			    rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					      "run_server", "delta");
			    goto report;
			}
			if (nw == 0) {
			    rep = "EINVAL short write";
			    goto report;
			}
			usize -= nw;
			dptr += nw;
		    }
		    has_signatures = 1;
		    rep = "OK";
		    goto report;
		}
#endif
		if (is_server && strcasecmp(kw, "STAT") == 0) {
		    int len, trans, s;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (sscanf(lptr, "%d %d", &len, &trans) < 2) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (len >= DATA_BLOCKSIZE - NAME_MAX - 2) {
			skip_data(p, len);
			rep = "EINVAL name too long";
			goto report;
		    }
		    if (! socket_get(p, cblock, len)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    cblock[len] = 0;
		    s = send_stat(p, cblock, trans, "OK ", NULL);
		    if (s > 0)
			goto noreport;
		    if (s < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "stat");
			goto report;
		    }
		    error_report(error_server, addr, "run_server", errno);
		    break;
		}
		if (strcasecmp(kw, "STOP") == 0) {
		    if (! (allowed & config_op_stop)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    main_running = 0;
		    error_report(info_user_stop);
		    rep = "OK stopping";
		    goto report;
		}
		if (strcasecmp(kw, "STATUS") == 0) {
		    if (! (allowed & config_op_status)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! socket_puts(p, "OK sending status")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    rep = send_status(p);
		    if (rep) {
			error_report(error_server_msg, addr, "run_server", rep);
			break;
		    }
		    continue;
		}
		if (is_server && strcasecmp(kw, "STATFS") == 0) {
		    int len;
		    struct statvfs sbuff;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (sscanf(lptr, "%d", &len) < 1) {
			rep = "EINVAL Invalid request";
			goto report;
		    }
		    if (len >= DATA_BLOCKSIZE - 2) {
			skip_data(p, len);
			rep = "EINVAL name too long";
			goto report;
		    }
		    if (! socket_get(p, cblock, len)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    cblock[len] = 0;
		    if (statvfs(cblock, &sbuff) < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "statfs");
			goto report;
		    }
		    sprintf(cblock, "OK %llu %llu %llu %llu %llu %llu %llu %d",
			    (unsigned long long)sbuff.f_bsize,
			    (unsigned long long)sbuff.f_blocks,
			    (unsigned long long)sbuff.f_bfree,
			    (unsigned long long)sbuff.f_bavail,
			    (unsigned long long)sbuff.f_files,
			    (unsigned long long)sbuff.f_ffree,
			    (unsigned long long)sbuff.f_favail,
			    ! (sbuff.f_flag & ST_RDONLY));
		    if (! socket_puts(p, cblock)) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "SETROOT") == 0) {
		    int pos, file;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (sscanf(lptr, "%d %d %d %d",
			       &file, &pos, &namelen, &translate_ids) < 4)
		    {
			rep = "EINVAL Invalid data";
			goto report;
		    }
		    if (namelen < 1) {
			rep = "EINVAL invalid name";
			goto report;
		    }
		    if (rootdir) myfree(rootdir);
		    if (get) store_finish(get);
		    get = NULL;
		    rootdir = mymalloc(1 + namelen);
		    if (! rootdir) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto skip_report;
		    }
		    if (! socket_get(p, rootdir, namelen)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "malloc");
			goto report;
		    }
		    rootdir[namelen] = 0;
		    get = store_prepare(file, pos, rootdir);
		    if (! get) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "store_prepare");
			goto report;
		    }
		    rep = "OK root changed";
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		if (is_server && strcasecmp(kw, "SETCHECKSUM") == 0) {
		    int num;
		    if (! (allowed & config_op_read)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    kw = lptr;
		    while (*lptr && ! isspace((int)*lptr)) lptr++;
		    if (lptr == kw) {
			rep = "EINVAL Invalid empty checksum method";
			goto report;
		    }
		    if (*lptr)
			*lptr++ = 0;
		    num = checksum_byname(kw);
		    if (num < 0) {
			rep = "EINVAL Unknown checksum method";
			goto report;
		    }
		    csum_n = num;
		    rep = "OK checksum method selected";
		    goto report;
		}
		break;
	    case 'U' : case 'u' :
		if (strcasecmp(kw, "UPDATE") == 0) {
		    int len;
		    if (! (allowed & config_op_setconf)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    len = atoi(lptr);
		    if (len < 1) {
			rep = "EINVAL Invalid update";
			goto report;
		    }
		    if (len >= DATA_BLOCKSIZE - 2) {
			skip_data(p, len);
			rep = "EINVAL update too long";
			goto report;
		    }
		    if (! socket_get(p, cblock, len)) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", "socket_get");
			goto report;
		    }
		    cblock[len] = 0;
		    if (! updating) {
			rep = config_start_update();
			if (rep) goto report;
			updating = 1;
		    }
		    if (strcasecmp(cblock, "commit") == 0) {
			if (updating != 1) {
			    rep = "Previous update failed, cannot commit";
			    goto report;
			}
			rep = config_commit_update();
			updating = 0;
			if (! rep) rep = "OK committed";
			goto report;
		    }
		    if (strcasecmp(cblock, "rollback") == 0) {
			config_cancel_update();
			rep = "OK rolled back";
			updating = 0;
			goto report;
		    }
		    rep = config_do_update(cblock);
		    if (rep)
			updating = 2;
		    else
			rep = "OK updated";
		    goto report;
		}
#if NOTIFY != NOTIFY_NONE
	    case 'W' : case 'w' :
		if (is_server && strcasecmp(kw, "WATCHES") == 0) {
		    if (! (allowed & config_op_watches)) {
			rep = "EPERM Operation not permitted";
			goto report;
		    }
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    if (! notify_forall_watches(send_watch, p))
			break;
		    if (! socket_puts(p, "0")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		break;
#endif /* NOTIFY != NOTIFY_NONE */
	}
	goto not_found;
    skip_report:
	while (namelen > 0) {
	    int sz = namelen > LINESIZE ? LINESIZE : namelen;
	    socket_get(p, line, LINESIZE);
	    namelen -= sz;
	}
	goto report;
    not_found:
	rep = "Invalid request";
    report:
	if (! socket_puts(p, rep)) {
	    error_report(error_server, addr, "run_server", errno);
	    break;
	}
    noreport:
	if (! socket_flush(p)) {
	    error_report(error_server, addr, "run_server", errno);
	    break;
	}
	continue;
    }
    if (updating) config_cancel_update();
    if (rfd >= 0) close(rfd);
    if (Dname) myfree(Dname);
#if NOTIFY != NOTIFY_NONE
    if (get) store_finish(get);
    if (rootdir) myfree(rootdir);
    if (add) config_dir_free(add);
    if (changes) {
	notify_status_t info;
	notify_status(&info);
	error_report(info_count_watches, info.watches);
    }
#endif /* NOTIFY != NOTIFY_NONE */
#if THEY_HAVE_LIBRSYNC
    pipe_close(&rdiff_pipe);
#endif
    error_report(info_connection_close, user, addr);
    socket_disconnect(p);
    tp->completed = 1;
    return NULL;
}

/* run control thread; returns NULL on normal termination,
 * or an error message */

const char * control_thread(void) {
    int ov;
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
	    if (do_one)
		copy_dirsync(do_one, "");
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
	const config_dir_t * d = config_treeval(cfg, cfg_tree_add);
	if (! d) {
	    config_put(cfg);
	    return;
	}
	while (d) {
	    int count;
	    const char * err = control_add_tree(d, &count);
	    if (err)
		error_report(error_control, d->path, err);
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
		     const config_dir_t * how,
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
    if (ev && sbuff.st_dev == *ev && sbuff.st_ino == evino)
	return;
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

static const char * scan_root(const config_dir_t * d,
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
    return NULL;
}

/* find all matching directories, and scan them as separate roots */

static const char * scan_find(const config_dir_t * d, const char * path,
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
		err = scan_find(d, buffer, entlen,
				dev, ev, evino, count);
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

const char * control_add_tree(const config_dir_t * d, int * count) {
    struct stat sbuff;
    dev_t devbuff, * dev = NULL, evbuff, * ev = NULL;
    ino_t evino = (ino_t)0;
    const config_data_t * cfg;
    if (d->path[0] != '/')
	return "Tree is not an absolute path";
    if (stat(d->path, &sbuff) < 0)
	return error_sys("control_add_tree", "stat");
    if (! S_ISDIR(sbuff.st_mode))
	return "Path is not a directory";
    if (! d->crossmount) {
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
    if (d->find)
	return scan_find(d, d->path, strlen(d->path),
			 dev, ev, evino, count);
    else
	return scan_root(d, d->path, dev, ev, evino, count);
}

/* ask the control thread to remove a directory tree; returns NULL if OK or
 * an error message */

const char * control_remove_tree(const char * path) {
    notify_watch_t * root;
    if (path[0] != '/')
	return "Tree is not an absolute path";
    root = notify_find_bypath(path, 0);
    if (! root)
	return "No such tree";
    error_report(info_removing_watch, path);
    notify_remove_under(root);
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

