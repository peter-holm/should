/* should's copy thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
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
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <utime.h>
#include <sys/mman.h>
#if DIRENT_TYPE == DIRENT
#include <dirent.h>
#else
#include <sys/dirent.h>
#endif
#include "config.h"
#include "socket.h"
#include "protocol.h"
#include "client.h"
#include "error.h"
#include "compress.h"
#include "checksum.h"
#include "mymalloc.h"
#include "usermap.h"
#include "main_thread.h"
#include "copy_thread.h"

#define REPLSIZE 256
#define MAX_POS 4096

#if ! defined NAME_MAX && defined MAXNAMLEN
#define NAME_MAX MAXNAMLEN
#endif

typedef struct dirsync_queue_s dirsync_queue_t;
struct dirsync_queue_s {
    dirsync_queue_t * next;
    int pathlen;
    char path[0];
};

typedef struct dirscan_s dirscan_t;
struct dirscan_s {
    dirscan_t * next;
    notify_event_t ev;
    char names[0];
};

static socket_t * p;
static client_extensions_t extensions;
static int fnum, fpos, event_count, num_dirsyncs;
static protocol_status_t status;
static dirsync_queue_t * dirsyncs;
static pthread_mutex_t dirsyncs_lock;

static const char * read_copy_state(const config_data_t * cfg) {
    char linebuff[REPLSIZE];
    int len;
    if (fseek(config_copy_file, config_copy_start, SEEK_SET) < 0)
	goto problem;
    len = 0;
    while (fgets(linebuff, sizeof(linebuff), config_copy_file)) {
	if (sscanf(linebuff, "%d %d\n", &fnum, &fpos) < 0)
	    continue;
	len++;
    }
    if (len < 1)
	return "State file format error";
    if (len > MAX_POS) {
	long pos;
	/* write back to position pos and truncate file */
	if (fseek(config_copy_file, config_copy_start, SEEK_SET) < 0)
	    goto problem;
	if (fprintf(config_copy_file, "%d %d\n", fnum, fpos) < 0)
	    goto problem;
	fflush(config_copy_file);
	pos = ftell(config_copy_file);
	if (pos < 0)
	    goto problem;
	if (ftruncate(fileno(config_copy_file), pos) < 0)
	    goto problem;
    }
    return NULL;
problem:
    return error_sys_errno("copy thread", "state file", errno);
}

static const char * send_command_noreport(const char * command) {
    char repl[REPLSIZE];
    if (! socket_puts(p, command))
	return error_sys("copy thread", command);
    errno = 0;
    repl[0] = 0;
    if (! socket_gets(p, repl, REPLSIZE)) {
	if (errno == 0)
	    return "No data";
	else
	    return error_sys("copy thread", command);
    }
    errno = 0;
    if (repl[0] == 'O' && repl[1] == 'K')
	return NULL;
    return error_sys("copy thread", command);
}

static inline const char * get_status(void) {
    const char * err;
    err = send_command_noreport("STATUS");
    if (err)
	return err;
    err = protocol_status_receive(p, &status);
    if (err)
	return err;
    return NULL;
}

/* initialisation required before the copy thread starts; returns
 * NULL if OK, or an error message */

const char * copy_init(void) {
    const char * err;
    int code;
    const config_data_t * cfg = config_get();
    code = pthread_mutex_init(&dirsyncs_lock, NULL);
    if (code) {
	config_put(cfg);
	return error_sys_errno("copy_init", "pthread_mutex_init", code);
    }
    if (cfg->intval[cfg_client_mode] & config_client_copy) {
	err = read_copy_state(cfg);
	if (err) {
	    pthread_mutex_destroy(&dirsyncs_lock);
	    config_put(cfg);
	    return err;
	}
    }
    p = socket_connect();
    if (! p) {
	int sv = errno;
	pthread_mutex_destroy(&dirsyncs_lock);
	config_put(cfg);
	return error_sys_errno("copy thread", "connect", sv);
    }
    err = get_status();
    if (err)
	goto out;
    if (! status.server_mode) {
	error_report(error_notserver);
	goto out;
    }
    if (cfg->intval[cfg_client_mode] & config_client_cleardebug) {
	err = send_command_noreport("NODEBUG");
	if (err)
	    goto out;
    }
    if (cfg->intval[cfg_client_mode] & config_client_setdebug) {
	err = send_command_noreport("DEBUG");
	if (err)
	    goto out;
    }
    extensions = client_get_extensions(p);
    event_count = 0;
    num_dirsyncs = 0;
    dirsyncs = NULL;
    config_put(cfg);
    return NULL;
out:
    send_command_noreport("QUIT");
    socket_disconnect(p);
    pthread_mutex_destroy(&dirsyncs_lock);
    config_put(cfg);
    return err;
}

static int mkparent(const char * name);

static int mkpath(const char * name) {
    struct stat sbuff;
    if (lstat(name, &sbuff) >= 0) {
	if (S_ISDIR(sbuff.st_mode)) return 1;
	error_report(error_copy_sys, name, ENOTDIR);
	return 0;
    }
    if (! mkparent(name)) return 0;
    if (mkdir(name, 0777) < 0) {
	error_report(error_copy_sys, name, errno);
	return 0;
    }
    return 1;
}

static int mkparent(const char * name) {
    char parent[strlen(name)], * ptr;
    int len;
    ptr = strrchr(name, '/');
    if (! ptr) return 1;
    len = ptr - name;
    strncpy(parent, name, len);
    parent[len] = 0;
    return mkpath(parent);
}

static int rmtree(const char * dname) {
    DIR * D = opendir(dname);
    if (D) {
	struct dirent * E;
	int dlen = strlen(dname);
	while ((E = readdir(D)) != NULL) {
	    char sname[dlen + 2 + strlen(E->d_name)];
	    struct stat sbuff;
	    if (E->d_name[0] == '.') {
		if (! E->d_name[1]) continue;
		if (E->d_name[1] == '.' && ! E->d_name[2]) continue;
	    }
	    sprintf(sname, "%s/%s", dname, E->d_name);
	    if (lstat(sname, &sbuff) >= 0 && S_ISDIR(sbuff.st_mode))
		rmtree(sname);
	    else
		unlink(sname);
	}
	closedir(D);
    }
    return rmdir(dname);
}

static int copy_file_data(socket_t * p, int flen, const char * fname,
			  const char * sname, const notify_event_t * ev,
			  struct stat * exists, notify_filetype_t filetype,
			  int compression, int checksum)
{
    switch (ev->file_type) {
	case notify_filetype_regular : {
	    int ffd, must_close = 0, digest_size = 0, rv;
	    const char * sl;
	    long long done, esize = 0;
	    int pagesize = sysconf(_SC_PAGESIZE), efd = -1;
	    off_t emapsize = 0;
	    char * epagemap = NULL;
	    char tempname[flen + 16], * dp = tempname, cmdbuff[64];
	    if (ev->file_size > 0) {
		sprintf(cmdbuff, "OPEN %d", (int)strlen(sname));
		if (! client_send_command(p, cmdbuff, sname, NULL))
		    return 1;
		must_close = 1;
		/* if and the server supports checksums, and the file already
		 * exists, is a regular file, and is readable, open it */
		if (checksum >= 0 &&
		    (digest_size = checksum_size(checksum)) > 0)
		{
		    struct stat sbuff;
		    if (lstat(fname, &sbuff) >= 0 && S_ISREG(sbuff.st_mode)) {
			/* in case somebody replaced it with a pipe or
			 * some such thing between the lstat() and the open() */
			efd = open(fname, O_RDONLY|O_NONBLOCK);
			epagemap = NULL;
			if (efd >= 0 &&
			    fstat(efd, &sbuff) >= 0 &&
			    S_ISREG(sbuff.st_mode))
			{
			    fcntl(efd, F_SETFL, 0L);
			    esize = sbuff.st_size;
			    emapsize = (esize + pagesize - 1) / pagesize;
			    emapsize *= pagesize;
			    epagemap = mmap(NULL, emapsize, PROT_READ,
					    MAP_PRIVATE, efd, (off_t)0);
			}
			if (! epagemap || epagemap == MAP_FAILED) {
			    close(efd);
			    epagemap = NULL;
			    efd = -1;
			}
		    }
		}
	    }
	    sl = strrchr(fname, '/');
	    if (sl) {
		int len = sl - fname;
		strncpy(dp, fname, len);
		dp += len;
		*dp = 0;
	    } else {
		strcpy(dp, fname);
	    }
	    if (! mkpath(tempname)) {
		error_report(error_copy_sys, tempname, errno);
		if (must_close)
		    client_send_command(p, "CLOSEFILE", NULL, NULL);
		return 1;
	    }
	    *dp++ = '/';
	    /* use .should.XXXXXX as temporary name, so that we can ask
	     * a server running on the same host to ignore these: this
	     * will be useful for multi-master replication setups */
	    strcpy(dp, ".should.XXXXXX");
	    ffd = mkstemp(tempname);
	    if (ffd < 0)
		goto error_tempname;
	    rv = fchmod(ffd, ev->file_mode); /* just in case */
	    rv = fchown(ffd, ev->file_user, ev->file_group);
	    done = 0L;
	    /* do the actual file data copy to ffd */
	    while (done < ev->file_size) {
		long long block = ev->file_size - done, realsize;
		char repl[REPLSIZE], data[DATA_BLOCKSIZE], ud[DATA_BLOCKSIZE];
		const char * dp;
		int nf;
		if (block > DATA_BLOCKSIZE) block = DATA_BLOCKSIZE;
		/* check if we already have this data */
		if (epagemap && done + block <= esize) {
		    long long eblock;
		    int rptr, i;
		    unsigned char lhash[digest_size];
		    unsigned char rhash[digest_size];
		    sprintf(cmdbuff, "CHECKSUM %lld %lld", done, block);
		    if (! client_send_command(p, cmdbuff, NULL, repl)) {
			if (errno == EINTR)
			    goto error_tempname_noreport;
			goto no_data;
		    }
		    if (sscanf(repl + 2, "%lld %n", &eblock, &rptr) < 1)
			goto no_data;
		    if (rptr < 1 || eblock < 1)
			goto no_data;
		    rptr += 2;
		    for (i = 0; i < digest_size; i++) {
			char val[3];
			val[0] = repl[rptr++];
			if (! isxdigit((int)val[0]))
			    goto no_data;
			val[1] = repl[rptr++];
			if (! isxdigit((int)val[1]))
			    goto no_data;
			val[2] = 0;
			rhash[i] = strtol(val, NULL, 16);
		    }
		    if (! checksum_data(checksum, epagemap + done,
					block, lhash))
			goto no_data;
		    for (i = 0; i < digest_size; i++)
			if (lhash[i] != rhash[i])
			    goto no_data;
		    /* OK, we have some data, copy it from the original
		     * file, then go and try another block */
		    dp = epagemap + done;
		    while (eblock > 0) {
			ssize_t nw = write(ffd, dp, eblock);
			if (nw < 0)
			    goto error_tempname;
			eblock -= nw;
			dp += nw;
			done += nw;
		    }
		    continue;
		}
	    no_data:
		sprintf(cmdbuff, "DATA %lld %lld", done, block);
		if (! client_send_command(p, cmdbuff, NULL, repl))
		    goto error_tempname_noreport;
		if (errno == EINTR)
		    goto error_tempname_noreport;
		nf = sscanf(repl + 2, "%lld %lld", &block, &realsize);
		if (nf < 1 || block < 0 || block > DATA_BLOCKSIZE) {
		    error_report(error_copy_invalid, fname, repl);
		    goto error_tempname_noreport;
		}
		if (nf >= 2) {
		    if (realsize < 0 || realsize <= block) {
			error_report(error_copy_invalid, fname, repl);
			goto error_tempname_noreport;
		    }
		} else {
		    realsize = block;
		}
		if (realsize == 0) {
		    error_report(error_copy_short, fname);
		    goto error_tempname_noreport;
		}
		if (! socket_get(p, data, block)) {
		    error_report(error_client, "socket_get", errno);
		    goto error_tempname_noreport;
		}
		if (nf >= 2) {
		    int bs = DATA_BLOCKSIZE;
		    const char * err =
			uncompress_data(compression, data, block, ud, &bs);
		    if (err) {
			error_report(error_copy_uncompress, err);
			goto error_tempname_noreport;
		    }
		    if (bs != realsize) {
			error_report(error_copy_uncompress, "Data size differ");
			goto error_tempname_noreport;
		    }
		    dp = ud;
		} else {
		    dp = data;
		}
		done += realsize;
		while (realsize > 0) {
		    ssize_t nw = write(ffd, dp, realsize);
		    if (nw < 0)
			goto error_tempname;
		    realsize -= nw;
		    dp += nw;
		}
	    }
	    if (epagemap)
		munmap(epagemap, emapsize);
	    epagemap = NULL;
	    if (efd >= 0)
		close(efd);
	    efd = -1;
	    if (close(ffd) < 0) {
		error_report(error_copy_sys, tempname, errno);
		unlink(tempname);
		if (must_close)
		    client_send_command(p, "CLOSEFILE", NULL, NULL);
		return 1;
	    }
	    ffd = -1;
	    if (exists && filetype != notify_filetype_regular)
		filetype == notify_filetype_dir ? rmtree(fname) : unlink(fname);
	    if (rename(tempname, fname) < 0)
		goto error_tempname;
	    if (ev->file_size > 0)
		if (! client_send_command(p, "CLOSEFILE", NULL, NULL))
		    return 1;
	    return 2;
	error_tempname:
	    error_report(error_copy_sys, tempname, errno);
	error_tempname_noreport:
	    if (epagemap)
		munmap(epagemap, emapsize);
	    epagemap = NULL;
	    if (efd >= 0)
		close(efd);
	    if (ffd >= 0) {
		close(ffd);
		unlink(tempname);
	    }
	    if (must_close)
		if (! client_send_command(p, "CLOSEFILE", NULL, NULL))
		    return 1;
	    return 1;
	}
	case notify_filetype_dir :
	    if (exists) {
		if (filetype == ev->file_type)
		    return 2;
		unlink(fname);
	    }
	    if (! mkparent(fname)) return 1;
	    if (mkdir(fname, ev->file_mode) < 0)
		goto error_fname;
	    return 1;
	case notify_filetype_device_block :
	case notify_filetype_device_char :
	    if (exists) {
		if (filetype == ev->file_type)
		    return 2;
		filetype == notify_filetype_dir ? rmtree(fname) : unlink(fname);
	    }
	    if (! mkparent(fname)) return 1;
	    if (mknod(fname, ev->file_mode,
		      ev->file_type == notify_filetype_device_block
				    ? S_IFBLK
				    : S_IFCHR) < 0)
		goto error_fname;
	    return 1;
	case notify_filetype_fifo :
	    if (exists) {
		if (filetype == ev->file_type)
		    return 2;
		filetype == notify_filetype_dir ? rmtree(fname) : unlink(fname);
	    }
	    if (! mkparent(fname)) return 1;
	    if (mkfifo(fname, ev->file_mode) < 0)
		goto error_fname;
	    return 1;
	case notify_filetype_symlink :
	    if (exists) {
		if (filetype == ev->file_type) {
		    char rl[1 + exists->st_size];
		    int used = readlink(fname, rl, exists->st_size);
		    if (used >= 0) {
			rl[used] = 0;
			if (strcmp(rl, ev->to_name) == 0)
			    return 2;
		    }
		}
		filetype == notify_filetype_dir ? rmtree(fname) : unlink(fname);
	    }
	    if (! mkparent(fname)) return 1;
	    if (symlink(ev->to_name, fname) < 0)
		goto error_fname;
	    return 1;
	case notify_filetype_socket :
	    error_report(error_copy_socket, fname);
	    return 1;
	case notify_filetype_unknown :
	    error_report(error_copy_unknown, fname);
	    return 1;
    }
    return 1;
error_fname:
    error_report(error_copy_sys, fname, errno);
    return 1;
}

/* copy a single file from the server; from is the path on the server, to
 * is the path on the client; if tr_ids is nonzero the server will look up
 * user and group IDs and send them as strings, and the client will translate
 * them back to IDs, if tr_ids is 0 the IDs are copied untranslated;
 * if compression is nonnegative it identifies a compression method to
 * use to copy the file data; if checksum is nonnegative it identifies a
 * checksum method to use to avoid copying data already present in the client;
 * both compression and checksum must have already been set up on the server */

void copy_file(socket_t * p, const char * from, const char * to, int tr_ids,
	       int compression, int checksum)
{
    char command[REPLSIZE], target[DATA_BLOCKSIZE + 1];
    long long size;
    int ft, dev, ino, mode, uid, gid, major, minor, tl, rv;
    char mtime[REPLSIZE], ctime[REPLSIZE];
    struct tm tm;
    struct utimbuf ut;
    struct stat _oldsbuff, * oldsbuff = NULL;
    notify_filetype_t ot = notify_filetype_unknown;
    notify_event_t ev;
    const config_data_t * cfg = config_get();
    sprintf(command, "STAT %d %d", (int)strlen(from), tr_ids);
    if (! client_send_command(p, command, from, command)) {
	config_put(cfg);
	return;
    }
    if (tr_ids) {
	char uname[REPLSIZE], gname[REPLSIZE];
	if (sscanf(command + 2,
		   "%d %d %d %o %s %d %s %d %lld %s %s %d %d %d",
		   &ft, &dev, &ino, &mode, uname, &uid, gname, &gid,
		   &size, mtime, ctime, &major, &minor, &tl) < 14)
	    goto invalid;
	uid = usermap_fromname(uname, uid);
	gid = groupmap_fromname(gname, gid);
    } else {
	if (sscanf(command + 2,
		   "%d %d %d %o %d %d %lld %s %s %d %d %d",
		   &ft, &dev, &ino, &mode, &uid, &gid,
		   &size, mtime, ctime, &major, &minor, &tl) < 12)
	    goto invalid;
    }
    if (tl > DATA_BLOCKSIZE) {
	fprintf(stderr, "Link target too big\n");
	while (tl > DATA_BLOCKSIZE) {
	    socket_gets(p, target, DATA_BLOCKSIZE);
	    tl -= DATA_BLOCKSIZE;
	}
	if (tl > 0)
	    socket_gets(p, target, tl);
	config_put(cfg);
	return;
    }
    if (tl > 0)
	if (! socket_gets(p, target, tl))
	    goto invalid;
    config_put(cfg);
    strptime(mtime, "%Y-%m-%d:%H:%M:%S", &tm);
    ut.actime = ut.modtime = timegm(&tm);
    if (! client_set_parameters(p))
	return;
    if (stat(to, &_oldsbuff) >= 0) {
	oldsbuff = &_oldsbuff;
	ot = notify_filetype(_oldsbuff.st_mode);
    }
    ev.event_type = notify_create;
    ev.from_length = strlen(from);
    ev.from_name = from;
    ev.to_length = tl;
    ev.to_name = target;
    ev.file_type = ft;
    ev.stat_valid = 1;
    ev.file_mode = mode;
    ev.file_user = uid;
    ev.file_group = gid;
    ev.file_device = makedev(major, minor);
    ev.file_size = size;
    ev.file_mtime = ut.modtime;
    if (! copy_file_data(p, strlen(to), to, ev.from_name, &ev,
			 oldsbuff, ot, compression, checksum))
	return;
    rv = chown(to, uid, gid);
    rv = chmod(to, mode);
    rv = utime(to, &ut);
    return;
invalid:
    fprintf(stderr, "Invalid data received from server\n");
    config_put(cfg);
    return;
}

static int cp(const config_data_t * cfg, const notify_event_t * ev,
	      int compression, int checksum)
{
    int do_lstat = 1, fstat_valid, ok, clen;
    int do_debug = cfg->intval[cfg_flags] & config_flag_debug_server;
    struct stat sbuff;
    config_filter_t filter = config_file_all;
    /* translate server's names to local names */
    int flen = ev->from_name && ev->from_length >= cfg->intval[cfg_from_length]
	     ? ev->from_length + 1 +
		cfg->intval[cfg_to_length] - cfg->intval[cfg_from_length]
	     : 1;
    int tlen = ev->to_name && ev->to_length >= cfg->intval[cfg_to_length]
	     ? ev->to_length + 1 +
		cfg->intval[cfg_to_length] - cfg->intval[cfg_from_length]
	     : 1;
    char fname[flen], tname[tlen];
    const char * cptr, * sptr;
    if (ev->from_name && ev->from_length >= cfg->intval[cfg_from_length]) {
	if (ev->from_length >= cfg->intval[cfg_from_length]) {
	    strncpy(fname, cfg->strval[cfg_to_prefix],
		    cfg->intval[cfg_to_length]);
	    strcpy(fname + cfg->intval[cfg_to_length],
		   ev->from_name + cfg->intval[cfg_from_length]);
	} else {
	    fname[0] = 0;
	}
    }
    if (ev->to_name && ev->to_length >= cfg->intval[cfg_to_length]) {
	if (ev->to_length >= cfg->intval[cfg_to_length]) {
	    strncpy(tname, cfg->strval[cfg_to_prefix],
		    cfg->intval[cfg_to_length]);
	    strcpy(tname + cfg->intval[cfg_to_length],
		   ev->to_name + cfg->intval[cfg_from_length]);
	} else {
	    tname[0] = 0;
	}
    }
    /* duplicate event */
    switch (ev->file_type) {
	case notify_filetype_regular :
	    filter = config_file_regular;
	    break;
	case notify_filetype_dir :
	    filter = config_file_dir;
	    break;
	case notify_filetype_device_char :
	    filter = config_file_char;
	    break;
	case notify_filetype_device_block :
	    filter = config_file_block;
	    break;
	case notify_filetype_fifo :
	    filter = config_file_fifo;
	    break;
	case notify_filetype_symlink :
	    filter = config_file_symlink;
	    break;
	case notify_filetype_socket :
	    filter = config_file_socket;
	    break;
	case notify_filetype_unknown :
	    filter = config_file_unknown;
	    break;
    }
    switch (ev->event_type) {
	case notify_change_meta :
	    /* change metadata: uid, gid, mode, mtime */
	    if (do_debug)
		error_report(info_replication_meta, fname, ev->stat_valid);
	    if (! ev->stat_valid)
		/* means file was deleted before we got to it */
		return 1;
	adjust_meta:
	    if (! (cfg->filter[config_event_meta] & filter))
		return 1;
	    if (do_lstat && lstat(fname, &sbuff) < 0)
		goto error_fname;
	    if (ev->file_user != sbuff.st_uid &&
		ev->file_group != sbuff.st_gid &&
		lchown(fname, ev->file_user, ev->file_group) < 0)
		    goto error_fname;
	    if ((sbuff.st_mode & 07777) != ev->file_mode &&
		! S_ISLNK(sbuff.st_mode) &&
		chmod(fname, ev->file_mode) < 0)
		    goto error_fname;
	    if (ev->file_mtime != sbuff.st_mtime) {
		struct utimbuf timbuf;
		timbuf.actime = sbuff.st_atime;
		timbuf.modtime = ev->file_mtime;
		if (utime(fname, &timbuf) < 0)
		    goto error_fname;
	    }
	    return 1;
	case notify_change_data :
	    if (! (cfg->filter[config_event_data] & filter))
		return 1;
	    goto data_or_create;
	case notify_create :
	    if (! (cfg->filter[config_event_create] & filter))
		return 1;
	data_or_create:
	    cptr = fname;
	    clen = flen;
	    sptr = ev->from_name;
	copy_data:
	    /* file was created or modified */
	    if (! ev->stat_valid)
		/* means file was deleted before we got to it */
		return 1;
	    fstat_valid = lstat(cptr, &sbuff) >= 0;
	    /* if file exists, mtime & size are identical, and the user want
	     * to skip matching files, skip them */
	    if (fstat_valid &&
		(cfg->intval[cfg_flags] & config_flag_skip_matching) &&
		sbuff.st_mtime == ev->file_mtime &&
		sbuff.st_size == ev->file_size &&
		notify_filetype(sbuff.st_mode) == ev->file_type)
	    {
		/* in case we missed a change_meta event */
		if (sbuff.st_uid != ev->file_user ||
		    sbuff.st_gid != ev->file_group ||
		    (sbuff.st_mode & 07777) != ev->file_mode)
		{
		    do_lstat = 0;
		    goto adjust_meta;
		}
		return 1;
	    }
	    /* must copy file data */
	    if (! (cfg->filter[config_event_data] & filter) &&
	        ! (cfg->filter[config_event_create] & filter))
		    return 1;
	    if (do_debug)
		error_report(info_replication_copy, sptr, cptr, ev->file_size);
	    ok = copy_file_data(p, clen, cptr, sptr, ev,
				fstat_valid ? &sbuff : NULL,
				fstat_valid ? notify_filetype(sbuff.st_mode)
					    : notify_filetype_unknown,
				compression, checksum);
	    if (! ok)
		return 0;
	    if (ok == 1)
		return 1;
	    goto adjust_meta;
	case notify_delete :
	    if (! (cfg->filter[config_event_delete] & filter))
		return 1;
	    if (do_debug)
		error_report(info_replication_delete, fname);
	    if (lstat(fname, &sbuff) >= 0 && S_ISDIR(sbuff.st_mode)) {
		if (rmtree(fname) < 0 && errno != ENOENT)
		    goto error_fname;
	    } else {
		if (unlink(fname) < 0 && errno != ENOENT)
		    goto error_fname;
	    }
	    return 1;
	case notify_rename :
	    if (! (cfg->filter[config_event_rename] & filter))
		return 1;
	    if (do_debug)
		error_report(info_replication_rename, fname, tname);
	    if (rename(fname, tname) < 0) {
		if (errno == ENOENT) {
		    int se = errno;
		    if (lstat(fname, &sbuff) < 0) {
			/* try executing it as a copy */
			if (cfg->filter[config_event_delete] & filter)
			    unlink(fname);
			cptr = tname;
			clen = tlen;
			sptr = ev->to_name;
			goto copy_data;
		    }
		    errno = se;
		}
		error_report(error_copy_rename, fname, tname, errno);
	    }
	    return 1;
	case notify_overflow :
	case notify_nospace :
	    /* if configured, schedule a full dirsync */
	    if (cfg->intval[cfg_flags] & config_flag_overflow_dirsync)
		copy_dirsync("");
	    return 1;
	case notify_add_tree :
	    /* if configured, do an initial dirsync */
	    if (cfg->intval[cfg_flags] & config_flag_initial_dirsync) {
		const char * path;
		if (strlen(fname) >= cfg->intval[cfg_to_length])
		    path = fname + cfg->intval[cfg_to_length];
		else
		    path = "";
		while (*path && *path == '/') path++;
		copy_dirsync(path);
	    }
	    return 1;
    }
    return 1;
error_fname :
    error_report(error_copy_sys, fname, errno);
    return 1;
}

/* Find a name in the previous event list, and replace the current
 * pointer if found. This not only reduces buffer usage, but more
 * importantly makes optimisation so much easier */

static int find_event(int len, const char ** name,
		      const notify_event_t * evlist, int evcount)
{
    int en;
    for (en = 0; en < evcount; en++) {
	if (evlist[en].from_length == len &&
	    strncmp(evlist[en].from_name, *name, len) == 0)
	{
	    *name = evlist[en].from_name;
	    return 1;
	}
	if (evlist[en].to_length == len &&
	    strncmp(evlist[en].to_name, *name, len) == 0)
	{
	    *name = evlist[en].to_name;
	    return 1;
	}
    }
    return 0;
}

/* Get an event from the server, if there is space in the buffer.
 * If there is no space and this is the first event, allocate some
 * space for it */

static int get_next_event(char ** evstart, int * evspace, char ** freeit,
			  int timeout, notify_event_t * ev, int tr_ids,
			  const notify_event_t * evlist, int evcount)
{
    int etype, ftype, tvalid, rsz, csz;
    char * buffer, command[REPLSIZE], uname[REPLSIZE], gname[REPLSIZE];
    sprintf(uname, "EVENT %d %d", timeout, freeit ? -1 : *evspace - 2);
    if (! client_send_command(p, uname, NULL, command))
	return 0;
    if (errno == EINTR)
	return 1;
    buffer = command + 2;
    while (*buffer && isspace((int)*buffer)) buffer++;
    if (buffer[0] == 'N' && buffer[1] == 'O')
	return 2;
    if (buffer[0] == 'B' && buffer[1] == 'I')
	return 3;
    if (buffer[0] != 'E' || buffer[1] != 'V') {
	error_report(error_client_msg, uname, command);
	return 0;
    }
    if (sscanf(buffer + 2, "%d %d %d %d %d %d %d %d",
	       &fnum, &fpos, &etype, &ftype, &ev->stat_valid,
	       &tvalid, &ev->from_length, &ev->to_length) < 8)
    {
	error_report(error_badevent, command);
	return 0;
    }
    ev->event_type = etype;
    ev->file_type = ftype;
    /* receive filenames */
    rsz = 0;
    if (ev->from_length > 0) rsz += 1 + ev->from_length;
    if (ev->to_length > 0) rsz += 1 + ev->to_length;
    csz = rsz;
    if (csz > *evspace) {
	if (! freeit) return 0;
	buffer = mymalloc(csz);
	if (! buffer) {
	    error_report(error_event, errno);
	    return 0;
	}
	*freeit = buffer;
    } else {
	buffer = *evstart;
	*evstart += rsz;
	*evspace -= rsz;
    }
    rsz = 0;
    if (ev->from_length > 0) {
	ev->from_name = buffer + rsz;
	if (! socket_get(p, buffer + rsz, ev->from_length)) {
	    error_report(error_event, errno);
	    return 0;
	}
	if (! find_event(ev->from_length, &ev->from_name, evlist, evcount)) {
	    rsz += ev->from_length;
	    buffer[rsz++] = 0;
	}
    } else {
	ev->from_name = NULL;
    }
    if (ev->to_length > 0) {
	ev->to_name = buffer + rsz;
	if (! socket_get(p, buffer + rsz, ev->to_length)) {
	    error_report(error_event, errno);
	    return 0;
	}
	if (! find_event(ev->to_length, &ev->to_name, evlist, evcount)) {
	    rsz += ev->to_length;
	    buffer[rsz++] = 0;
	}
    } else {
	ev->to_name = NULL;
    }
    /* receive stat structure */
    if (ev->stat_valid) {
	int minor, major;
	if (! socket_gets(p, command, sizeof(command))) {
	    error_report(error_event, errno);
	    return 0;
	}
	uname[0] = gname[0] = 0;
	if (strncmp(command, "NSTAT", 5) == 0) {
	    if (sscanf(command + 5, "%o %s %d %s %d %lld %d %d",
		       &ev->file_mode, uname, &ev->file_user,
		       gname, &ev->file_group, &ev->file_size,
		       &major, &minor) < 8)
	    {
		error_report(error_badevent, command);
		return 0;
	    }
	    if (tr_ids) {
		ev->file_user = usermap_fromname(uname, ev->file_user);
		ev->file_group = groupmap_fromname(gname, ev->file_group);
	    }
	} else if (strncmp(command, "STAT", 4) == 0) {
	    if (sscanf(command + 4, "%o %d %d %lld %d %d",
		       &ev->file_mode, &ev->file_user,
		       &ev->file_group, &ev->file_size,
		       &major, &minor) < 6)
	    {
		error_report(error_badevent, command);
		return 0;
	    }
	    if (tr_ids) {
		error_report(error_badevent, "Untranslated IDs");
		return 0;
	    }
	} else {
	    error_report(error_badevent, command);
	    return 0;
	}
	ev->file_device = makedev(major, minor);
    }
    /* receive modification time */
    if (tvalid) {
	if (! socket_gets(p, command, sizeof(command))) {
	    error_report(error_event, errno);
	    return 0;
	}
	if (strncmp(command, "MTIME", 5) == 0) {
	    struct tm tm;
	    char * c = command + 5, * e;
	    while (*c && isspace((int)*c)) c++;
	    e = strptime(c, "%Y-%m-%d:%H:%M:%S", &tm);
	    if (e) while (*e && isspace((int)*e)) e++;
	    if (! e || *e) {
		error_report(error_badevent, command);
		return 0;
	    }
	    ev->file_mtime = timegm(&tm);
	} else {
	    error_report(error_badevent, command);
	    return 0;
	}
    }
    event_count++;
    return 4;
}

/* look for unprocessed events which refer to a file which we know
 * is going to be deleted - might as well ignore them... */

static void delete_events(int evcount, notify_event_t evlist[],
			  int valid[], const char * name)
{
    while (evcount >= 0) {
	evcount--;
	if (! valid[evcount]) continue;
	if (evlist[evcount].event_type == notify_rename) {
	    /* if this is a rename to this, delete both the "from"
	     * and the "to". The "from" because it'll be renamed and
	     * then deleted; the "to" because the rename will effectively
	     * delete it anyway */
	    if (evlist[evcount].to_name == name) {
		delete_events(evcount, evlist, valid,
			      evlist[evcount].from_name);
		valid[evcount] = 0;
	    }
	    /* if this was a rename from, stop right here */
	    if (evlist[evcount].from_name == name)
		return;
	}
	/* if this event refers to something about to be deleted, might
	 * as well skip it */
	if (evlist[evcount].from_name == name)
	    valid[evcount] = 0;
    }
}

/* look for unprocessed events which refer to a file which we know is going
 * to be renamed: do the rename first, then apply the events to the destination,
 * which will be more likely to still exist on the server */

static void rename_events(int evcount, notify_event_t evlist[], int valid[]) {
    notify_event_t rev = evlist[evcount];
    /* move events one later, applying the rename as we go along */
    while (evcount > 0) {
	evcount--;
	valid[evcount + 1] = valid[evcount];
	evlist[evcount + 1] = evlist[evcount];
	if (! valid[evcount]) continue;
	/* apply the rename if appropriate */
	if (evlist[evcount].event_type == notify_rename) {
	    if (evlist[evcount].to_name == rev.from_name) {
		/* rename A -> B then B -> C: make it A -> C
		 * and also consider B deleted */
		delete_events(evcount, evlist, valid,
			      evlist[evcount].to_name);
		evlist[evcount + 1].to_name = rev.to_name;
		rev.from_name = evlist[evcount].from_name;
	    }
	} else {
	    if (evlist[evcount].from_name == rev.from_name) {
		/* this event now applies to the destination of
		 * the rename */
		evlist[evcount + 1].from_name = rev.to_name;
	    }
	}
    }
    /* move the rename right to the start */
    valid[0] = 1;
    evlist[0] = rev;
}

/* look for duplicate events and remove them from the queue */

static void remove_duplicate_events(int evcount, notify_event_t evlist[],
				    int valid[], notify_event_type_t evt,
				    const char * evn)
{
    while (evcount >= 0) {
	evcount--;
	if (! valid[evcount]) continue;
	if (evlist[evcount].event_type != evt) continue;
	if (evlist[evcount].from_name != evn) continue;
	valid[evcount] = 0;
    }
}

/* optimise the events; this is not complete yet */

static void optimise_events(int evcount,
			    notify_event_t evlist[], int valid[])
{
    int evnum;
    for (evnum = evcount - 1; evnum > 0; evnum--) {
	if (! valid[evnum]) continue;
	switch (evlist[evnum].event_type) {
	    case notify_delete :
		/* scan backwards and nuke any events with
		 * the same name: they don't matter */
		delete_events(evnum, evlist, valid, evlist[evnum].from_name);
		break;
	    case notify_rename :
		/* go and change all names in previous events, moving
		 * them one up as well -- then put the rename at the
		 * start */
		rename_events(evnum, evlist, valid);
		break;
	    case notify_create :
	    case notify_change_data :
	    case notify_change_meta :
		remove_duplicate_events(evnum, evlist, valid,
					evlist[evnum].event_type,
					evlist[evnum].from_name);
		break;
	    case notify_overflow :
	    case notify_nospace :
	    case notify_add_tree :
		/* do not optimise these */
		break;
	}
    }
}

static int compare_dir(const void * ap, const void * bp) {
    return strcmp((*(dirscan_t **)ap)->ev.from_name,
		  (*(dirscan_t **)bp)->ev.from_name);
}

static inline void skip_name(char buffer[], int bufsize, int len) {
    while (len > 0) {
	int block = len > bufsize ? bufsize : len;
	if (! socket_get(p, buffer, block))
	    return;
	len -= block;
    }
}

/* reads a directory from server; returns a block of dirscan_t pointers
 * terminated by a NULL pointer; or NULL if error */

static dirscan_t ** get_server_dir(const config_data_t * cfg,
				   int pathlen, const char * path)
{
    char buffer[REPLSIZE], fname[pathlen + cfg->intval[cfg_from_length] + 1];
    dirscan_t * entries = NULL;
    int tr_ids = cfg->intval[cfg_flags] & config_flag_translate_ids ? 1 : 0;
    int ok = 1, entcount = 0;
    strncpy(fname, cfg->strval[cfg_from_prefix], cfg->intval[cfg_from_length]);
    strncpy(fname + cfg->intval[cfg_from_length], path, pathlen);
    fname[cfg->intval[cfg_from_length] + pathlen] = 0;
    sprintf(buffer, "GETDIR %d %d",
	    pathlen + cfg->intval[cfg_from_length], tr_ids);
    if (! client_send_command(p, buffer, fname, NULL))
	return NULL;
    while (1) {
	char * eptr, svb;
	int type, major, minor, mtime, emtime;
	long long dnum, ino;
	struct tm tm;
	notify_event_t ev;
	dirscan_t * entry;
	if (! socket_gets(p, buffer, sizeof(buffer))) {
	    error_report(error_getdir, errno);
	    ok = 0;
	    break;
	}
	if (buffer[0] == '.' && ! buffer[1])
	    break;
	/* we use %*s but some systems count it and some don't, so we cannot
	 * really check the result of sscanf; however, if we initialise the
	 * last argument as negative and demand it is nonnegative that may
	 * give us a way to check for errors. Well, one hopes */
	ev.to_length = -1;
	if (tr_ids) {
	    int uname, euname, gname, egname;
	    sscanf(buffer, "%d %lld %lld %o %n%*s%n %d %n%*s%n "
			   "%d %lld %n%*s%n %*s %d %d %d %d",
		   &type, &dnum, &ino, &ev.file_mode, &uname, &euname,
		   &ev.file_user, &gname, &egname, &ev.file_group,
		   &ev.file_size, &mtime, &emtime, &major, &minor,
		   &ev.from_length, &ev.to_length);
	    if (ev.to_length >= 0) {
		svb = buffer[euname];
		buffer[euname] = 0;
		ev.file_user =
		    usermap_fromname(buffer + uname, ev.file_user);
		buffer[euname] = svb;
		svb = buffer[egname];
		buffer[egname] = 0;
		ev.file_group =
		    groupmap_fromname(buffer + gname, ev.file_group);
		buffer[egname] = svb;
	    }
	} else {
	    sscanf(buffer,
		   "%d %lld %lld %o %d %d %lld %n%*s%n %*s %d %d %d %d",
		   &type, &dnum, &ino, &ev.file_mode, &ev.file_user,
		   &ev.file_group, &ev.file_size, &mtime, &emtime,
		   &major, &minor, &ev.from_length, &ev.to_length);
	}
	if (ev.from_length < 1 || ev.to_length < 0 || type < 0 || type > 7) {
	    error_report(error_baddirent, buffer);
	    ok = 0;
	    continue;
	}
	/* parse modification time */
	svb = buffer[emtime];
	buffer[emtime] = 0;
	eptr = strptime(buffer + mtime, "%Y-%m-%d:%H:%M:%S", &tm);
	buffer[emtime] = svb;
	if (! eptr || *eptr) {
	    error_report(error_baddirent, buffer);
	    ok = 0;
	}
	if (! ok) {
	    skip_name(buffer, sizeof(buffer), ev.from_length + ev.to_length);
	    continue;
	}
	/* allocate space for entry */
	entry = mymalloc(sizeof(dirscan_t) + ev.from_length + ev.to_length + 2);
	if (! entry) {
	    error_report(error_copy_sys, "malloc", errno);
	    skip_name(buffer, sizeof(buffer), ev.from_length + ev.to_length);
	    ok = 0;
	    continue;
	}
	ev.file_mtime = timegm(&tm);
	/* read file name and target */
	entry->ev.from_name = eptr = entry->names;
	if (! socket_get(p, eptr, ev.from_length)) {
	    error_report(error_baddirent, buffer);
	    myfree(entry);
	    ok = 0;
	    break;
	}
	eptr[ev.from_length] = 0;
	if (ev.to_length > 0) {
	    eptr += entry->ev.from_length + 1;
	    entry->ev.to_name = eptr;
	    if (! socket_get(p, eptr, ev.to_length)) {
		error_report(error_baddirent, buffer);
		ok = 0;
		myfree(entry);
		break;
	    }
	    eptr[ev.to_length] = 0;
	}
	/* file type */
	switch (type) {
	    case 0 : ev.file_type = notify_filetype_regular; break;
	    case 1 : ev.file_type = notify_filetype_dir; break;
	    case 2 : ev.file_type = notify_filetype_device_char; break;
	    case 3 : ev.file_type = notify_filetype_device_block; break;
	    case 4 : ev.file_type = notify_filetype_fifo; break;
	    case 5 : ev.file_type = notify_filetype_symlink; break;
	    case 6 : ev.file_type = notify_filetype_socket; break;
	    case 7 : ev.file_type = notify_filetype_unknown; break;
	}
	ev.file_device = makedev(major, minor);
	ev.event_type = notify_create;
	ev.stat_valid = 1;
	/* store this entry */
	entry->ev = ev;
	entry->next = entries;
	entries = entry;
	entcount++;
    }
    if (ok) {
	dirscan_t ** result = mymalloc((1 + entcount) * sizeof(dirscan_t *));
	if (result) {
	    int i;
	    i = 0;
	    while (entries && i < entcount) {
		result[i] = entries;
		entries = entries->next;
		i++;
	    }
	    result[entcount] = NULL;
	    qsort(result, entcount, sizeof(dirscan_t *), compare_dir);
	    return result;
	}
    }
    /* failed - free any memory allocated and return NULL */
    while (entries) {
	dirscan_t * this = entries;
	entries = entries->next;
	myfree(this);
    }
    return NULL;
}

/* reads a directory from the local file system */

static dirscan_t ** get_local_dir(const config_data_t * cfg,
				  int pathlen, const char * path)
{
    char dname[pathlen + cfg->intval[cfg_to_length] + 1];
    char ename[pathlen + cfg->intval[cfg_to_length] + NAME_MAX + 2], * eptr;
    dirscan_t * entries = NULL, ** result;
    int entcount = 0;
    DIR * D;
    struct dirent * E;
    strncpy(dname, cfg->strval[cfg_to_prefix], cfg->intval[cfg_to_length]);
    strncpy(dname + cfg->intval[cfg_to_length], path, pathlen);
    dname[cfg->intval[cfg_to_length] + pathlen] = 0;
    D = opendir(dname);
    if (! D) return NULL;
    strcpy(ename, dname);
    eptr = ename + cfg->intval[cfg_to_length] + pathlen;
    *eptr++ = '/';
    while ((E = readdir(D)) != NULL) {
	dirscan_t * entry;
	struct stat sbuff;
	int namelen, targetlen = 0;
	char * nptr;
	if (E->d_name[0] == '.') {
	    if (! E->d_name[1]) continue;
	    if (E->d_name[1] == '.' && ! E->d_name[2]) continue;
	}
	namelen = strlen(E->d_name);
	if (namelen > NAME_MAX) continue;
	strcpy(eptr, E->d_name);
	if (lstat(ename, &sbuff) < 0) continue;
	if (S_ISLNK(sbuff.st_mode))
	    targetlen = sbuff.st_size;
	/* store this dir entry */
	entry = mymalloc(sizeof(dirscan_t) + namelen + targetlen + 2);
	if (! entry) continue;
	if (S_ISREG(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_regular;
	else if (S_ISDIR(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_dir;
	else if (S_ISCHR(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_device_char;
	else if (S_ISBLK(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_device_block;
	else if (S_ISFIFO(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_fifo;
	else if (S_ISLNK(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_symlink;
	else if (S_ISSOCK(sbuff.st_mode))
	    entry->ev.file_type = notify_filetype_socket;
	else
	    entry->ev.file_type = notify_filetype_unknown;
	entry->ev.event_type = notify_create;
	entry->ev.stat_valid = 1;
	entry->ev.file_mode = sbuff.st_mode & 07777;
	entry->ev.file_user = sbuff.st_uid;
	entry->ev.file_group = sbuff.st_gid;
	entry->ev.file_device = sbuff.st_rdev;
	entry->ev.file_size = sbuff.st_size;
	entry->ev.file_mtime = sbuff.st_mtime;
	entry->ev.from_length = namelen;
	entry->ev.to_length = targetlen;
	nptr = entry->names;
	entry->ev.from_name = nptr;
	strcpy(nptr, E->d_name);
	nptr += 1 + namelen;
	entry->ev.to_name = nptr;
	if (targetlen) {
	    ssize_t rl = readlink(ename, nptr, targetlen + 1);
	    if (rl < 0 || rl > targetlen) {
		myfree(entry);
		continue;
	    }
	    nptr[rl] = 0;
	} else {
	    *nptr = 0;
	}
	entry->next = entries;
	entries = entry;
	entcount++;
    }
    closedir(D);
    result = mymalloc((1 + entcount) * sizeof(dirscan_t *));
    if (result) {
	int i;
	i = 0;
	while (entries && i < entcount) {
	    result[i] = entries;
	    entries = entries->next;
	    i++;
	}
	result[entcount] = NULL;
	qsort(result, entcount, sizeof(dirscan_t *), compare_dir);
	return result;
    }
    /* failed - free any memory allocated and return NULL */
    while (entries) {
	dirscan_t * this = entries;
	entries = entries->next;
	myfree(this);
    }
    return NULL;
}

/* synchronise just one directory, but schedule synchronisation for any
 * subdirectories it finds, so recursion will happen at some point */

static void do_dirsync(int compression, int checksum) {
    dirsync_queue_t * dq;
    dirscan_t ** server_dir;
    int errcode = pthread_mutex_lock(&dirsyncs_lock), i;
    const config_data_t * cfg;
    if (errcode) {
	error_report(error_copy_sys, "locking", errno);
	return;
    }
    dq = dirsyncs;
    if (! dq) {
	num_dirsyncs = 0;
	pthread_mutex_unlock(&dirsyncs_lock);
	return;
    }
    dirsyncs = dq->next;
    num_dirsyncs--;
    pthread_mutex_unlock(&dirsyncs_lock);
    cfg = config_get();
    server_dir = get_server_dir(cfg, dq->pathlen, dq->path);
    if (server_dir) {
	dirscan_t ** local_dir = get_local_dir(cfg, dq->pathlen, dq->path);
	if (local_dir) {
	    /* determine differences and do copy/deletes as appropriate */
	    int sp, lp, maxname = 0;
	    int delete = cfg->intval[cfg_flags] & config_flag_dirsync_delete;
	    for (sp = 0; server_dir[sp]; sp++) {
		int l = strlen(server_dir[sp]->ev.from_name);
		if (l > maxname) maxname = l;
	    }
	    for (lp = 0; local_dir[lp]; lp++) {
		int l = strlen(local_dir[lp]->ev.from_name);
		if (l > maxname) maxname = l;
	    }
	    sp = lp = 0;
	    while (server_dir[sp] || local_dir[lp]) {
		char lname[dq->pathlen + cfg->intval[cfg_to_length] +
			   maxname + 2];
		int c;
		if (server_dir[sp] && local_dir[lp])
		    c = strcmp(server_dir[sp]->ev.from_name,
			       local_dir[lp]->ev.from_name);
		else if (server_dir[sp])
		    c = -1;
		else
		    c = 1;
		if (c > 0) {
		    /* file exists locally but not on server */
		    if (delete) {
			sprintf(lname, "%s%s/%s",
				cfg->strval[cfg_to_prefix],
				dq->path, local_dir[lp]->ev.from_name);
			if (local_dir[lp]->ev.file_type == notify_filetype_dir)
			    unlink(lname);
			else
			    rmtree(lname);
		    }
		    lp++;
		}
		if (c < 0) {
		    /* file exists on server but not locally */
		    sprintf(lname, "%s/%s",
			    dq->path, server_dir[lp]->ev.from_name);
		    server_dir[sp]->ev.from_name = lname;
		    server_dir[sp]->ev.from_length = strlen(lname);
		    cp(cfg, &server_dir[sp]->ev, compression, checksum);
		    sp++;
		}
		if (c == 0) {
		    /* file exists on server and locally */
		    // XXX check if we really need to copy this
		    sprintf(lname, "%s/%s",
			    dq->path, server_dir[lp]->ev.from_name);
		    server_dir[sp]->ev.from_name = lname;
		    server_dir[sp]->ev.from_length = strlen(lname);
		    cp(cfg, &server_dir[sp]->ev, compression, checksum);
		    sp++;
		    lp++;
		}
	    }
	    for (i = 0; local_dir[i]; i++)
		myfree(local_dir[i]);
	    myfree(local_dir);
	}
	for (i = 0; server_dir[i]; i++) {
	    if (server_dir[i]->ev.file_type == notify_filetype_dir) {
		int len =
		    server_dir[i]->ev.from_length + cfg->intval[cfg_to_length];
		char fname[len + 1];
		strcpy(fname, cfg->strval[cfg_to_prefix]);
		strcpy(fname + cfg->intval[cfg_to_length],
		       server_dir[i]->ev.from_name);
		copy_dirsync(fname);
	    }
	    myfree(server_dir[i]);
	}
	myfree(server_dir);
    }
    myfree(dq);
    config_put(cfg);
}

/* run copy thread */

void copy_thread(void) {
    const config_data_t * cfg = config_get();
    int checksum = -1, compression = -1;
    int check_events = cfg->intval[cfg_checkpoint_events];
    time_t check_time = cfg->intval[cfg_checkpoint_time] + time(NULL);
    char command[REPLSIZE];
    const char * fp =
	cfg->strval[cfg_from_prefix] ? cfg->strval[cfg_from_prefix] : "/";
    int fnum_cp = fnum, fpos_cp = fpos;
    int evmax = cfg->intval[cfg_optimise_client] < 1
	? 1 : cfg->intval[cfg_optimise_client];
    int evbuff = cfg->intval[cfg_optimise_buffer] < 256
	? 256 : cfg->intval[cfg_optimise_buffer];
    int tr_ids = (cfg->intval[cfg_flags] & config_flag_translate_ids) ||
		  config_copy_file == NULL;
    int oneshot = cfg->intval[cfg_flags] & config_flag_copy_oneshot;
    if (cfg->intval[cfg_client_mode] & config_client_copy) {
	checksum = client_find_checksum(p, extensions);
	compression = client_find_compress(p);
    } else {
	fnum = status.store.file_current;
	fpos = status.store.file_pos;
    }
    config_put(cfg);
    if (! client_set_parameters(p))
	goto out;
    sprintf(command, "SETROOT %d %d %d %d",
	    fnum, fpos, (int)strlen(fp), tr_ids);
    if (! client_send_command(p, command, fp, NULL))
	goto out;
    main_running = 1;
    main_setup_signals();
    while (main_running) {
	notify_event_t evlist[evmax];
	char evarea[evbuff], * evstart = evarea, * freeit = NULL;
	int evspace = evbuff, evcount = 1, evnum, valid[evmax], cmdok;
	int fnum_l[evmax], fpos_l[evmax];
	cfg = config_get();
	check_events = cfg->intval[cfg_checkpoint_events];
	/* read first event */
	cmdok = get_next_event(&evstart, &evspace, &freeit,
			       num_dirsyncs || oneshot ? 0 : -1,
			       &evlist[0], tr_ids, NULL, 0);
	if (cmdok == 2) {
	    config_put(cfg);
	    if (oneshot) break;
	    do_dirsync(compression, checksum);
	    continue;
	}
	if (cmdok == 1) {
	    config_put(cfg);
	    break;
	}
	if (cmdok != 4) {
	    config_put(cfg);
	    goto out;
	}
	valid[0] = 1;
	fnum_l[0] = fnum;
	fpos_l[0] = fpos;
	/* read as many events as will fit in the buffer */
	while (evcount < evmax) {
	    /* read next event */
	    cmdok = get_next_event(&evstart, &evspace, NULL, 0,
				   &evlist[evcount], tr_ids, evlist, evcount);
	    if (cmdok != 4) break;
	    valid[evcount] = 1;
	    fnum_l[evcount] = fnum;
	    fpos_l[evcount] = fpos;
	    evcount++;
	}
	optimise_events(evcount, evlist, valid);
	/* execute all the events */
	for (evnum = 0; evnum < evcount; evnum++) {
	    time_t now;
	    long pos;
	    int rv;
	    check_events--;
	    if (! valid[evnum]) continue;
	    if (config_copy_file) {
		if (! cp(cfg, &evlist[evnum], compression, checksum))
		    goto out;
	    } else {
		store_printevent(&evlist[evnum], NULL, NULL);
	    }
	    if (! config_copy_file) continue;
	    if (check_events > 0) continue;
	    now = time(NULL);
	    if (now < check_time) continue;
	    check_events = cfg->intval[cfg_checkpoint_events];
	    check_time = now + cfg->intval[cfg_checkpoint_time];
	    if (fnum_l[evnum] == fnum_cp && fpos_l[evnum] == fpos_cp) continue;
	    fprintf(config_copy_file, "%d %d\n", fnum_l[evnum], fpos_l[evnum]);
	    fflush(config_copy_file);
	    pos = ftell(config_copy_file);
	    if (pos <= MAX_POS) continue;
	    if (fseek(config_copy_file, config_copy_start, SEEK_SET) < 0)
		continue;
	    fprintf(config_copy_file, "%d %d\n", fnum, fpos);
	    fflush(config_copy_file);
	    pos = ftell(config_copy_file);
	    if (pos >= 0)
		rv = ftruncate(fileno(config_copy_file), pos);
	    fnum_cp = fnum_l[evnum];
	    fpos_cp = fpos_l[evnum];
	}
	if (freeit) myfree(freeit);
	config_put(cfg);
    }
    if (main_signal_seen)
	error_report(info_signal_received, main_signal_seen);
    main_running = 0;
out:
    if (config_copy_file && (fnum != fnum_cp || fpos != fpos_cp))
	fprintf(config_copy_file, "%d %d\n", fnum, fpos);
}

/* cleanup required after the copy thread terminates */

void copy_exit(void) {
    pthread_mutex_destroy(&dirsyncs_lock);
    if (p) {
	send_command_noreport("QUIT");
	socket_disconnect(p);
    }
    /* there may be pending dirsyncs - they won't happen now */
    while (dirsyncs) {
	dirsync_queue_t * this = dirsyncs;
	dirsyncs = this->next;
	myfree(this);
    }
}

/* returns current event files information */

void copy_status(copy_status_t * status) {
    int errcode = pthread_mutex_lock(&dirsyncs_lock);
    if (errcode) {
	status->file_current = -1;
	status->file_pos = -1;
	status->events = -1;
	status->dirsyncs = -1;
    } else {
	status->file_current = fnum;
	status->file_pos = fpos;
	status->events = event_count;
	status->dirsyncs = num_dirsyncs;
	pthread_mutex_unlock(&dirsyncs_lock);
    }
}

/* schedules an immediate dirsync of server:from/path to client:to/path */

int copy_dirsync(const char * path) {
    int len, errcode, do_it;
    dirsync_queue_t * dq, * check, * prev, * to_free;
    if (! path) path = "";
    while (*path && *path == '/') path++;
    len = strlen(path);
    while (len > 0 && path[len - 1] == '/') len--;
    dq = mymalloc(len + 1 + sizeof(dirsync_queue_t));
    if (! dq) goto fail;
    dq->pathlen = len;
    strncpy(dq->path, path, len);
    dq->path[len] = 0;
    errcode = pthread_mutex_lock(&dirsyncs_lock);
    if (errcode) {
	myfree(dq);
	errno = errcode;
	goto fail;
    }
    /* check the existing list -- if there is a subtree of this new one,
     * remove the subtree; if this one is inside an already scheduled
     * one, no need to do it */
    check = dirsyncs;
    prev = NULL;
    do_it = 1;
    to_free = NULL;
    while (check) {
	if ((check->pathlen == len ||
	     (check->pathlen < len && path[check->pathlen] == '/')) &&
	    strncmp(check->path, path, check->pathlen) == 0)
	{
	    /* path is inside check */
	    do_it = 0;
	}
	if (check->pathlen > len &&
	    check->path[len] == '/' &&
	    strncmp(check->path, path, len) == 0)
	{
	    /* check is inside path */
	    dirsync_queue_t * next = check->next;
	    if (prev)
		prev->next = next;
	    else
		dirsyncs = next;
	    num_dirsyncs--;
	    check->next = to_free;
	    to_free = check;
	    check = next;
	} else {
	    prev = check;
	    check = check->next;
	}
    }
    if (do_it) {
	if (prev) {
	    dq->next = prev->next;
	    prev->next = dq;
	} else {
	    dq->next = dirsyncs;
	    dirsyncs = dq;
	}
	num_dirsyncs++;
    } else {
	dq->next = to_free;
	to_free = dq;
    }
    pthread_mutex_unlock(&dirsyncs_lock);
    /* free the elements outside the lock, in case the locking done by the
     * free function results in a deadlock. You never know */
    while (to_free) {
	dirsync_queue_t * this = to_free;
	to_free = to_free->next;
	myfree(this);
    }
    return 1;
fail:
    error_report(error_copy_sched_dirsync, path, errno);
    return 0;
}

