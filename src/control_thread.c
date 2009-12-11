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
#include <sys/mman.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <fnmatch.h>
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

/* apr likes to screw up fnmatch.h */

#ifdef FNM_CASE_BLIND
int fnmatch(const char *, const char *, int);
#define FNM_CASEFOLD    (1 << 4)
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
    client_mode = cfg->intval[cfg_client_mode];
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
    config_match_t * item;
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
	match = config_match_name;
    } else if (strcasecmp(kw, "PATH") == 0) {
	match = config_match_path;
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
	how = config_match_exact;
    } else if (strcasecmp(kw, "ICASE") == 0) {
	how = config_match_icase;
    } else if (strcasecmp(kw, "GLOB") == 0) {
	how = config_match_glob;
    } else if (strcasecmp(kw, "IGLOB") == 0) {
	how = config_match_iglob;
    } else {
	rep = "EINVAL Invalid match mode";
	goto skip_report;
    }
    item = mymalloc(sizeof(config_match_t));
    if (! item) {
	rep = error_sys_r(cblock, DATA_BLOCKSIZE,
			  "run_server", "malloc");
	goto skip_report;
    }
    item->pattern = mymalloc(1 + namelen);
    if (! item->pattern) {
	rep = error_sys_r(cblock, DATA_BLOCKSIZE,
			  "run_server", "malloc");
	myfree(item);
	goto skip_report;
    }
    if (! socket_get(p, item->pattern, namelen)) {
	rep = error_sys_r(cblock, DATA_BLOCKSIZE,
			  "run_server", "malloc");
	myfree(item->pattern);
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

/* talks to a client */

void * run_server(void * _tp) {
    thlist_t * tp = _tp;
    socket_t * p = tp->p;
    struct sockaddr_storage * addr = socket_addr(p);
    int ov, running = 1, csum_n, is_server = ! client_mode, updating = 0;
    int compression = -1, pagesize = sysconf(_SC_PAGESIZE);
    char * Dname = NULL, * pagemap = NULL;
    char cblock[DATA_BLOCKSIZE];
    const char * user = socket_user(p);
#if NOTIFY != NOTIFY_NONE
    store_get_t * get = NULL;
    config_dir_t * add = NULL;
    char * rootdir = NULL;
    int changes = 0, translate_ids = 1;
#endif /* NOTIFY != NOTIFY_NONE */
    long bwlimit = 0L;
    off_t mapsize = 0, maprealsize = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    error_report(info_connection_open, user, addr);
    csum_n = checksum_byname("md5");
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
		    long limit = atol(lptr);
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
		    long long start, usize;
		    int i, wp, clen = checksum_size(csum_n);
		    unsigned char hash[clen];
		    if (! pagemap) {
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
		    if (start >= maprealsize) {
			rep = "OK 0";
			goto report;
		    }
		    if (start + usize >= maprealsize)
			usize = maprealsize - start;
		    if (! checksum_data(csum_n, pagemap + start, usize, hash)) {
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
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "CROSS") == 0) {
		    add->crossmount = 1;
		    rep = finish_add(add, &changes, cblock);
		    add = NULL;
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		if (strcasecmp(kw, "CLOSELOG") == 0) {
		    error_closelog();
		    rep = "OK closed";
		    goto report;
		}
		if (is_server && strcasecmp(kw, "COMPRESS") == 0) {
		    int num;
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
		    if (! pagemap) {
			rep = "EBADF File not opened";
			goto report;
		    }
		    if (Dname) myfree(Dname);
		    Dname = NULL;
		    munmap(pagemap, mapsize); 
		    pagemap = NULL;
		    rep = "OK file closed";
		    goto report;
		}
		if (strcasecmp(kw, "CONFIG") == 0) {
		    socket_autoflush(p, 0);
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    config_print(sendlines, p);
		    socket_autoflush(p, 1);
		    if (! socket_puts(p, "__END__")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		break;
	    case 'D' : case 'd' :
		if (is_server && strcasecmp(kw, "DATA") == 0) {
		    long long start, usize, csize, dsize;
		    const char * dptr;
		    if (! pagemap) {
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
		    if (start >= maprealsize) {
			rep = "OK 0";
			goto report;
		    }
		    if (usize > DATA_BLOCKSIZE) usize = DATA_BLOCKSIZE;
		    if (start + usize >= maprealsize)
			usize = maprealsize - start;
		    if (compression >= 0)
			csize = compress_data(compression, pagemap + start,
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
			dptr = pagemap + start;
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
		if (strcasecmp(kw, "DEBUG") == 0) {
		    socket_setdebug(p, 1);
		    rep = "OK";
		    goto report;
		}
		break;
	    case 'E' : case 'e' :
		if (strcasecmp(kw, "EXTENSIONS") == 0) {
		    socket_autoflush(p, 0);
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
		    } else {
			if (! socket_puts(p, "DIRSYNC")) {
			    error_report(error_server, addr,
					 "run_server", errno);
			    break;
			}
		    }
		    socket_autoflush(p, 1);
		    if (! socket_puts(p, ".")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    continue;
		}
		// XXX ENCRYPT
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "EXCL") == 0) {
		    rep = handle_excl_find(p, lptr, 1, add, cblock);
		    goto report;
		}
		if (is_server && strcasecmp(kw, "EVENT") == 0) {
		    notify_event_t ev;
		    int timeout, size, avail;
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
			    error_report(error_server, addr, "run_server", errno);
			    break;
			}
		    }
		    if (ev.stat_valid || ev.event_type == notify_add_tree) {
			char mtime[64];
			struct tm tm;
			gmtime_r(&ev.file_mtime, &tm);
			strftime(mtime, sizeof(mtime), "%Y-%m-%d:%H:%M:%S", &tm);
			sprintf(cblock, "MTIME %s", mtime);
			if (! socket_puts(p, cblock)) {
			    error_report(error_server, addr, "run_server", errno);
			    break;
			}
		    }
		    goto noreport;
		}
		break;
	    case 'F' : case 'f' :
		if (is_server && strcasecmp(kw, "FIND") == 0) {
		    rep = handle_excl_find(p, lptr, 0, add, cblock);
		    goto report;
		}
		break;
#endif /* NOTIFY != NOTIFY_NONE */
	    case 'G' : case 'g' :
		if (is_server && strcasecmp(kw, "GETDIR") == 0) {
		    int len, trans;
		    DIR * dp;
		    struct dirent * ent;
		    const config_data_t * cfg = config_get();
		    int skip_should =
			cfg->intval[cfg_flags] & config_flag_skip_should;
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
		    socket_autoflush(p, 0);
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
		    socket_autoflush(p, 1);
		    if (! socket_puts(p, ".")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		break;
	    case 'I' : case 'i' :
		// XXX IGNORE (is_server)
		break;
	    case 'L' : case 'l' :
		if (is_server && strcasecmp(kw, "LISTCOMPRESS") == 0) {
		    int n, max = compress_count(), err = 0;
		    socket_autoflush(p, 0);
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
		    socket_autoflush(p, 1);
		    if (! socket_puts(p, "__END__")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    goto noreport;
		}
		if (is_server && strcasecmp(kw, "LISTCHECKSUM") == 0) {
		    int n, max = checksum_count(), err = 0;
		    socket_autoflush(p, 0);
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
		    socket_autoflush(p, 1);
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
		    add->crossmount = 0;
		    rep = finish_add(add, &changes, cblock);
		    add = NULL;
		    goto report;
		}
#endif /* NOTIFY != NOTIFY_NONE */
		if (strcasecmp(kw, "NODEBUG") == 0) {
		    socket_setdebug(p, 0);
		    rep = "OK";
		    goto report;
		}
		break;
	    case 'O' : case 'o' :
		if (is_server && strcasecmp(kw, "OPEN") == 0) {
		    struct stat sbuff;
		    int dfd;
		    namelen = atoi(lptr);
		    if (namelen < 1) {
			rep = "EINVAL Invalid name";
			goto report;
		    }
		    if (Dname) myfree(Dname);
		    if (pagemap) munmap(pagemap, mapsize); 
		    pagemap = NULL;
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
		    dfd = open(Dname, O_RDONLY|O_NONBLOCK);
		    if (dfd < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			goto report;
		    }
		    if (fstat(dfd, &sbuff) < 0) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			close(dfd);
			goto report;
		    }
		    if (! S_ISREG(sbuff.st_mode)) {
			rep = "EBADF not a regular file";
			close(dfd);
			goto report;
		    }
		    if (sbuff.st_size == 0) {
			rep = "File has zero size, no need to OPEN it...";
			close(dfd);
			goto report;
		    }
		    /* reset O_NONBLOCK */
		    fcntl(dfd, F_SETFL, 0L);
		    /* mmap the file */
		    maprealsize = sbuff.st_size;
		    mapsize = (maprealsize + pagesize - 1) / pagesize;
		    mapsize *= pagesize;
		    pagemap = mmap(NULL, mapsize, PROT_READ,
				   MAP_PRIVATE, dfd, (off_t)0);
		    if (! pagemap || pagemap == MAP_FAILED) {
			rep = error_sys_r(cblock, DATA_BLOCKSIZE,
					  "run_server", Dname);
			close(dfd);
			pagemap = NULL;
			goto report;
		    }
		    rep = "OK file opened";
		    goto report;
		}
		break;
#if NOTIFY != NOTIFY_NONE
	    case 'P' : case 'p' :
		if (is_server && strcasecmp(kw, "PURGE") == 0) {
		    int days = atoi(lptr);
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
#if NOTIFY != NOTIFY_NONE
	    case 'R' : case 'r' :
		if (is_server && strcasecmp(kw, "REMOVE") == 0) {
		    char * path;
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
		if (! is_server && strcasecmp(kw, "DIRSYNC") == 0) {
		    char * path;
		    int ok;
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
		    ok = copy_dirsync(path);
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
#endif /* NOTIFY != NOTIFY_NONE */
	    case 'S' : case 's' :
		if (strcasecmp(kw, "STOP") == 0) {
		    main_running = 0;
		    error_report(info_user_stop);
		    rep = "OK stopping";
		    goto report;
		}
		if (strcasecmp(kw, "STATUS") == 0) {
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
		if (is_server && strcasecmp(kw, "STAT") == 0) {
		    int len, trans, s;
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
#if NOTIFY != NOTIFY_NONE
		if (is_server && strcasecmp(kw, "SETROOT") == 0) {
		    int pos, file;
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
		    int len = atoi(lptr);
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
		    if (! socket_puts(p, "OK")) {
			error_report(error_server, addr, "run_server", errno);
			break;
		    }
		    socket_autoflush(p, 0);
		    if (! notify_forall_watches(send_watch, p))
			break;
		    socket_autoflush(p, 1);
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
    not_found:
	rep = "Invalid request";
    report:
	if (! socket_puts(p, rep)) {
	    error_report(error_server, addr, "run_server", errno);
	    break;
	}
    noreport:
	continue;
    }
    if (updating) config_cancel_update();
    if (pagemap) munmap(pagemap, mapsize);
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
		pthread_cancel(this->name);
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
	config_dir_t * d = cfg->dirs;
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
/* check an exclude or find list */

static int match_list(const char * name, const char * path,
		      const config_match_t * list)
{
    while (list) {
	const char * match =
	    list->match == config_match_name ? name : path;
	switch (list->how) {
	    case config_match_exact :
		if (strcmp(list->pattern, match) == 0)
		    return 1;
		break;
	    case config_match_icase :
		if (strcasecmp(list->pattern, match) == 0)
		    return 1;
		break;
	    case config_match_glob :
		if (fnmatch(list->pattern, match, 0) == 0)
		    return 1;
		break;
	    case config_match_iglob :
		if (fnmatch(list->pattern, match, FNM_CASEFOLD) == 0)
		    return 1;
		break;
	}
	list = list->next;
    }
    return 0;
}

/* scan a directory and adds a watch for all its subdirectories */

static void scan_dir(notify_watch_t * parent,
		     const char * path, int pathlen,
		     const config_match_t * exclude,
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
	if (match_list(ent->d_name, buffer, exclude))
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
	    watch = notify_add(parent, ent->d_name);
	    if (! watch) {
		error_report(error_scan_dir, buffer, errno);
		continue;
	    }
	    (*count)++;
	    scan_dir(watch, buffer, entlen, exclude, dev, ev, evino, count);
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
    root = notify_find_bypath(rootpath, 1);
    if (! root)
	return error_sys("scan_root", "notify_find_bypath");
    (*count)++;
    scan_dir(root, rootpath, strlen(rootpath), d->exclude,
	     dev, ev, evino, count);
    return NULL;
}

/* find all matching directories, and scan them as separate roots */

static const char * scan_find(const config_dir_t * d,
			      const char * path, int pathlen,
			      const config_match_t * find,
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
	    if (dev && sbuff.st_dev != *dev)
		continue;
	    if (match_list(ent->d_name, buffer, find))
		err = scan_root(d, buffer, dev, ev, evino, count);
	    else
		err = scan_find(d, buffer, entlen, find,
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
    if (stat(cfg->strval[cfg_eventdir], &sbuff) >= 0) {
	evbuff = sbuff.st_dev;
	ev = &evbuff;
	evino = sbuff.st_ino;
    }
    config_put(cfg);
    *count = 0;
    /* make sure we identify this as a rootpoint */
    if (d->find)
	return scan_find(d, d->path, strlen(d->path),
			 d->find, dev, ev, evino, count);
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

