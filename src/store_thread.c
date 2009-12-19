/* should's store thread
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
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/time.h>
#if DIRENT_TYPE == DIRENT
#include <dirent.h>
#else
#include <sys/dirent.h>
#endif
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>
#include "store_thread.h"
#include "main_thread.h"
#include "config.h"
#include "error.h"
#include "mymalloc.h"
#include "socket.h"
#include "usermap.h"
#include "notify_thread.h"
#if NOTIFY != NOTIFY_NONE

# if NOTIFY == NOTIFY_INOTIFY
#  if INOTIFY == SYS_INOTIFY
#   include <sys/inotify.h>
#  else
#   include <inotify-nosys.h>
#  endif
# endif

#define SUFFIX_SIZE 32
#define BLOCK_ADD 512
#define TIMESTAMP 32

struct store_get_s {
    int file_num;
    off_t file_pos;
    int fd;
    char * suffix;
    const char * root;
    int namemax;
    char * namebuff;
#if NOTIFY == NOTIFY_INOTIFY
    int iwatch;
#endif
    char name[0];
};

/* used to store events to file */

typedef struct {
    unsigned char event_type;          /*  1 */
    unsigned char file_type;           /*  2 */
    unsigned char has_stat;            /*  3 */
    unsigned char from_length[4];      /*  7 */
    unsigned char to_length[4];        /* 11 */
} event_t;

typedef struct {
    unsigned char file_mode[2];        /*  2 */
    unsigned char file_user[4];        /*  6 */
    unsigned char file_group[4];       /* 10 */
    unsigned char file_size[8];        /* 18 */
    unsigned char file_mtime[8];       /* 26 */
} stat_t;

/* predefined store methods */

typedef struct {
    const char * name;
    const char * (*init)(const config_data_t *, const char *);
    const char * (*process)(const notify_event_t *);
    void (*flush)(void);
    void (*exit)(void);
} store_t;

static FILE * save_file;
static char * save_name, * save_suffix;
static int save_count, save_earliest, save_current, save_len;
static long save_pos;
static pthread_mutex_t save_lock;

/* encode/decode integers in system-independent way */

static inline void encode_16(unsigned char * d, uint16_t n) {
    int i;
    for (i = 0; i < 2; i++) {
	*d++ = n & 0xff;
	n >>= 8;
    }
}

static inline uint16_t decode_16(const unsigned char * d) {
    int i;
    unsigned int n = 0;
    for (i = 0; i < 2; i++)
	n |= d[i] << (i * 8);
    return n;
}

static inline void encode_32(unsigned char * d, uint32_t n) {
    int i;
    for (i = 0; i < 4; i++) {
	*d++ = n & 0xff;
	n >>= 8;
    }
}

static inline uint32_t decode_32(const unsigned char * d) {
    int i;
    unsigned int n = 0;
    for (i = 0; i < 4; i++)
	n |= d[i] << (i * 8);
    return n;
}

static inline void encode_64(unsigned char * d, uint64_t n) {
    int i;
    for (i = 0; i < 8; i++) {
	*d++ = n & 0xff;
	n >>= 8;
    }
}

static inline uint64_t decode_64(const unsigned char * d) {
    int i;
    unsigned int n = 0;
    for (i = 0; i < 8; i++)
	n |= d[i] << (i * 8);
    return n;
}

static void set_timestamp(char * timebuff, time_t when) {
    struct tm tm_when;
    /* there is no reason why either localtime_r or strftime could fail...
     * but that's no excuse to avoid checking for it
     */
    if (localtime_r(&when, &tm_when) == 0 ||
        strftime(timebuff, TIMESTAMP, "%Y-%m-%d %H:%M:%S", &tm_when) == 0)
    {
	snprintf(timebuff, TIMESTAMP, "(time=%lld)", (long long)when);
    }
}

static const char * filetype(notify_filetype_t type) {
    switch(type) {
	case notify_filetype_regular :      return "FILE";
	case notify_filetype_dir :          return "DIR";
	case notify_filetype_device_char :  return "CHAR";
	case notify_filetype_device_block : return "BLK";
	case notify_filetype_fifo :         return "FIFO";
	case notify_filetype_symlink :      return "LINK";
	case notify_filetype_socket :       return "SOCK";
	case notify_filetype_unknown :      return "";
    }
    return "";
}

static const char * open_file(const config_data_t * cfg) {
    long pos;
    int errcode;
    if (save_file) fclose(save_file);
    snprintf(save_suffix, SUFFIX_SIZE, "ev%06d.log", save_count);
    save_file = fopen(save_name, "a");
    if (! save_file)
	return error_sys("open_file", save_name);
    if (fseek(save_file, 0L, SEEK_END) < 0)
	return error_sys("open_file", save_name);
    pos = ftell(save_file);
    if (pos < 0)
	return error_sys("open_file", save_name);
    errcode = pthread_mutex_lock(&save_lock);
    if (errcode)
	return error_sys_errno("open_file", "pthread_mutex_lock", errcode);
    save_current = save_count;
    save_pos = pos;
    pthread_mutex_unlock(&save_lock);
    save_count++;
    if (config_intval(cfg, cfg_autopurge_days) > 0)
	store_purge(config_intval(cfg, cfg_autopurge_days));
    return NULL;
}

static int count_files(const char * eventdir, int * earliest, int * newest) {
    DIR * edir;
    struct dirent * de;
    *earliest = -1;
    *newest = 0;
    edir = opendir(eventdir);
    if (! edir)
	return 0;
    while ((de = readdir(edir)) != NULL) {
	const char * en = de->d_name;
	int ptr, num;
	if (en[0] != 'e') continue;
	if (en[1] != 'v') continue;
	ptr = 2;
	while (en[ptr] && isdigit((int)en[ptr])) ptr++;
	if (ptr < 3) continue;
	if (en[ptr] != '.') continue;
	if (en[ptr + 1] != 'l') continue;
	if (en[ptr + 2] != 'o') continue;
	if (en[ptr + 3] != 'g') continue;
	if (en[ptr + 4]) continue;
	num = atoi(en + 2);
	if (num > *newest) *newest = num;
	if (*earliest < 0 || *earliest > num) *earliest = num;
    }
    closedir(edir);
    return 1;
}

static const char * save_init(const config_data_t * cfg, const char * cmd) {
    int len = config_strlen(cfg, cfg_eventdir);
    const char * err;
    struct stat sbuff;
    int code = pthread_mutex_init(&save_lock, NULL);
    if (code)
	return error_sys_errno("save_init", "pthread_mutex_init", code);
    if (stat(config_strval(cfg, cfg_eventdir), &sbuff) < 0) {
	if (mkdir(config_strval(cfg, cfg_eventdir), 0700) < 0) {
	    int e = errno;
	    pthread_mutex_destroy(&save_lock);
	    return error_sys_errno("save_init", "mkdir", e);
	}
    } else {
	if (! S_ISDIR(sbuff.st_mode))
	    return "eventdir exists but is not a directory";
    }
    save_len = len + SUFFIX_SIZE + 2;
    save_name = mymalloc(save_len);
    if (! save_name) {
	int e = errno;
	pthread_mutex_destroy(&save_lock);
	return error_sys_errno("save_init", "malloc", e);
    }
    strcpy(save_name, config_strval(cfg, cfg_eventdir));
    save_suffix = save_name + len;
    *save_suffix++ = '/';
    if (! count_files(config_strval(cfg, cfg_eventdir),
	&save_earliest, &save_count))
    {
	int e = errno;
	myfree(save_name);
	pthread_mutex_destroy(&save_lock);
	return
	    error_sys_errno("save_init", config_strval(cfg, cfg_eventdir), e);
    }
    if (save_count <= 0)
	save_count = 1;
    save_file = NULL;
    cfg = config_get();
    err = open_file(cfg);
    if (err) {
	myfree(save_name);
	pthread_mutex_destroy(&save_lock);
	config_put(cfg);
	return err;
    }
    /* see if we are going to rotate the file */
    if (save_pos > (long)INT_MAX ||
	save_pos >= config_intval(cfg, cfg_eventsize))
    {
	err = open_file(cfg);
	if (err) {
	    myfree(save_name);
	    pthread_mutex_destroy(&save_lock);
	    config_put(cfg);
	    return err;
	}
    }
    config_put(cfg);
    if (save_earliest < 0)
	save_earliest = save_current;
    return NULL;
}

static const char * save_process(const notify_event_t * ev) {
    event_t sev;
    long pos;
    const config_data_t * cfg;
    memset(&sev, 0, sizeof(sev));
    sev.event_type = ev->event_type;
    sev.file_type = ev->file_type;
    sev.has_stat = ev->stat_valid ? 1 : 0;
    encode_32(sev.from_length, ev->from_length);
    encode_32(sev.to_length, ev->to_length);
    if (fwrite(&sev, sizeof(sev), 1, save_file) < 1)
	return error_sys("save_process", save_name);
    if (ev->stat_valid) {
	stat_t stat;
	encode_16(stat.file_mode, ev->file_mode);
	encode_32(stat.file_user, ev->file_user);
	encode_32(stat.file_group, ev->file_group);
	if (ev->file_type == notify_filetype_device_block ||
	    ev->file_type == notify_filetype_device_char) {
	    encode_32(stat.file_size, major(ev->file_device));
	    encode_32(stat.file_size + 4, minor(ev->file_device));
	} else {
	    encode_64(stat.file_size, ev->file_size);
	}
	encode_64(stat.file_mtime, (long long)ev->file_mtime);
	if (fwrite(&stat, sizeof(stat), 1, save_file) < 1)
	    return error_sys("save_process", save_name);
    } else if (ev->event_type == notify_add_tree) {
	unsigned char mtime[8];
	encode_64(mtime, (long long)ev->file_mtime);
	if (fwrite(mtime, 8, 1, save_file) < 1)
	    return error_sys("save_process", save_name);
    }
    if (ev->from_length > 1 &&
	fwrite(ev->from_name, 1 + ev->from_length, 1, save_file) < 1)
	    return error_sys("save_process", save_name);
    if (ev->to_length > 1 &&
	fwrite(ev->to_name, 1 + ev->to_length, 1, save_file) < 1)
	    return error_sys("save_process", save_name);
    pos = ftell(save_file);
    if (pos < 0)
	return error_sys("save_process", save_name);
    cfg = config_get();
    if (pos > INT_MAX || pos >= config_intval(cfg, cfg_eventsize))
	open_file(cfg);
    else
	save_pos = pos;
    config_put(cfg);
    return NULL;
}

static void save_exit(void) {
    if (save_file) fclose(save_file);
    if (save_name) myfree(save_name);
    pthread_mutex_destroy(&save_lock);
}

static const char * print_process(const notify_event_t * ev) {
    char _user[64], _group[64];
    const char * user = NULL, * group = NULL;
    if (ev->stat_valid) {
	if (usermap_fromid(ev->file_user, _user, sizeof(_user)) > 0)
	    user = _user;
	if (groupmap_fromid(ev->file_group, _group, sizeof(_group)) > 0)
	    group = _group;
    }
    store_printevent(ev, user, group);
    return NULL;
}

static const char * logfile_init(const config_data_t * cfg, const char * cmd) {
    if (! cmd || ! cmd[0] || ! cmd[1])
	return "Missing filename: use \"store=log:FILENAME\"";
    cmd++;
    save_len = 1 + strlen(cmd);
    save_name = mymalloc(save_len);
    if (! save_name)
	return error_sys("logfile_init", "malloc");
    strcpy(save_name, cmd);
    save_file = fopen(save_name, "a");
    if (! save_file)
	return error_sys("logfile_init", save_name);
    return NULL;
}

static void logfile_sendname(const char * pre, notify_filetype_t type,
			     const char * name, int namelen, const char * post)
{
    char timebuff[TIMESTAMP];
    const char * ft = filetype(type);
    set_timestamp(timebuff, time(NULL));
    fprintf(save_file, "%-19s %-6s %-4s ", timebuff, pre, ft);
    while (namelen > 0) {
	if (isprint((int)*name) &&
	    *name != '\n' && *name != '\r' && *name != '%')
	    putc(*name, save_file);
	else
	    fprintf(save_file, "%%%02X", (unsigned char)*name);
	namelen--;
	name++;
    }
    fprintf(save_file, "%s", post);
}

static const char * logfile_process(const notify_event_t * ev) {
    const char * evtype = "?";
    switch (ev->event_type) {
	case notify_change_meta :
	    evtype = "CHMETA";
	    break;
	case notify_change_data :
	    evtype = "CREATE";
	    break;
	case notify_create :
	    evtype = "UPDATE";
	    break;
	case notify_delete :
	    evtype ="DELETE";
	    break;
	case notify_rename :
	    evtype ="RENAME";
	    break;
	case notify_hardlink :
	    evtype ="LINK";
	    break;
	case notify_overflow :
	case notify_nospace :
	case notify_add_tree :
	    return NULL;
    }
    logfile_sendname(evtype, ev->file_type,
		     ev->from_name, ev->from_length, "\n");
    if (ev->to_name)
	logfile_sendname("    TO", notify_filetype_unknown,
			 ev->to_name, ev->to_length, "\n");
    if (ev->stat_valid) {
	char timebuff[TIMESTAMP];
	set_timestamp(timebuff, ev->file_mtime);
	fprintf(save_file,
		"%32cmode=0%03o uid=%d gid=%d size=%lld mtime=%s\n",
		' ', ev->file_mode, ev->file_user, ev->file_group,
		ev->file_size, timebuff);
    }
    return NULL;
}

static void logfile_flush(void) {
    fflush(save_file);
}

static void logfile_exit(void) {
    if (save_file) fclose(save_file);
    if (save_name) myfree(save_name);
}

static const char * syslog_init(const config_data_t * cfg, const char * cmd) {
    return
	config_change_error_dest(info_changelog,
				 cmd && cmd[0] && cmd[1] ? cmd + 1
							 : "local7:info");
}

static void syslog_sendname(const char * pre, notify_filetype_t type,
			    const char * name, int namelen)
{
    char buffer[3 * namelen + 1];
    int buflen = 0;
    const char * ft = filetype(type);
    while (namelen > 0) {
	if (isprint((int)*name) &&
	    *name != '\n' && *name != '\r' && *name != '%')
	    buffer[buflen++] = *name;
	else
	    buflen += sprintf(buffer + buflen, "%%%02X", (unsigned char)*name);
	namelen--;
	name++;
    }
    buffer[buflen] = 0;
    error_report(info_changelog, ft, pre, buffer);
}

static const char * syslog_process(const notify_event_t * ev) {
    const char * evtype = "?";
    switch (ev->event_type) {
	case notify_change_meta :
	    evtype = "CHMETA";
	    break;
	case notify_change_data :
	    evtype = "CREATE";
	    break;
	case notify_create :
	    evtype = "UPDATE";
	    break;
	case notify_delete :
	    evtype = "DELETE";
	    break;
	case notify_rename :
	    evtype = "RENAME";
	    break;
	case notify_hardlink :
	    evtype ="LINK";
	    break;
	case notify_overflow :
	case notify_nospace :
	case notify_add_tree :
	    return NULL;
    }
    syslog_sendname(evtype, ev->file_type, ev->from_name, ev->from_length);
    if (ev->to_name)
	syslog_sendname("    TO", notify_filetype_unknown,
			ev->to_name, ev->to_length);
    if (ev->stat_valid) {
	char databuff[64];
	sprintf(databuff,
		"mode=0%03o uid=%d gid=%d\n",
		ev->file_mode, ev->file_user, ev->file_group);
	error_report(info_changelog, "", databuff);
    }
    return NULL;
}

static store_t store_methods[] = {
    { "save",    save_init,    save_process,    NULL,          save_exit },
    { "print",   NULL,         print_process,   NULL,          NULL },
    { "logfile", logfile_init, logfile_process, logfile_flush, logfile_exit },
    { "syslog",  syslog_init,  syslog_process,  NULL,          NULL },
    { NULL,      NULL,         NULL,            NULL,          NULL }
};

static store_t store_data;

/* initialisation required before the store thread starts; returns
 * NULL if OK, or an error message */

const char * store_init(void) {
    const config_data_t * cfg = config_get();
    int i, len;
    const char * colon = strchr(config_strval(cfg, cfg_store), ':');
    if (colon)
	len = colon - config_strval(cfg, cfg_store);
    else
	len = config_strlen(cfg, cfg_store);
    save_current = save_earliest = save_pos = -1;
    save_name = NULL;
    /* search for a predefined store method */
    for (i = 0; store_methods[i].name; i++) {
	if (strncmp(store_methods[i].name,
		    config_strval(cfg, cfg_store), len) == 0)
	{
	    if (! store_methods[i].name[len]) {
		store_data = store_methods[i];
		if (store_data.init) {
		    const char * err = store_data.init(cfg, colon);
		    config_put(cfg);
		    return err;
		}
		config_put(cfg);
		return NULL;
	    }
	}
    }
    config_put(cfg);
    return "No such store method";
}

static config_filter_t filter_type(notify_filetype_t ft) {
    switch (ft) {
	case notify_filetype_regular :
	    return config_file_regular;
	case notify_filetype_dir :
	    return config_file_dir;
	case notify_filetype_device_char :
	    return config_file_char;
	case notify_filetype_device_block :
	    return config_file_block;
	case notify_filetype_fifo :
	    return config_file_fifo;
	case notify_filetype_symlink :
	    return config_file_symlink;
	case notify_filetype_socket :
	    return config_file_socket;
	case notify_filetype_unknown :
	    return config_file_unknown;
    }
    return config_file_unknown;
}

/* run store thread; returns NULL on normal termination,
 * or an error message */

const char * store_thread(void) {
    int ov, bsize = 0, do_flush = 0;
    char * buffer = NULL;
    const config_data_t * cfg = NULL;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    while (main_running) {
	notify_event_t ev;
	config_filter_t filter = config_file_all, check;
	int reqsize = bsize;
	int g = notify_get(&ev, POLL_TIME, buffer, &reqsize);
	if (g == -3) {
	    if (buffer) myfree(buffer);
	    reqsize += BLOCK_ADD;
	    bsize = reqsize;
	    buffer = mymalloc(bsize);
	    if (! buffer) {
		int e = errno;
		if (cfg) config_put(cfg);
		return error_sys_errno("store_thread", "malloc", e);
	    }
	    g = notify_get(&ev, POLL_TIME, buffer, &reqsize);
	}
	if (g == -2) {
	    if (do_flush && store_data.flush) {
		store_data.flush();
		do_flush = 0;
	    }
	    if (cfg) config_put(cfg);
	    cfg = NULL;
	    continue;
	}
	if (g < 0) {
	    const char * err = error_sys("store_thread", "notify_get");
	    if (buffer) myfree(buffer);
	    if (cfg) config_put(cfg);
	    return err;
	}
	if (g == 0) {
	    if (buffer) myfree(buffer);
	    if (cfg) config_put(cfg);
	    return NULL;
	}
	/* check against the event filter if we do want to process this */
	if (! cfg) cfg = config_get();
	switch (ev.event_type) {
	    case notify_change_meta :
		filter = config_intval(cfg, cfg_event_meta);
		break;
	    case notify_change_data :
		filter = config_intval(cfg, cfg_event_data);
		break;
	    case notify_create :
		filter = config_intval(cfg, cfg_event_create);
		break;
	    case notify_delete :
		filter = config_intval(cfg, cfg_event_delete);
		break;
	    case notify_rename :
		filter = config_intval(cfg, cfg_event_rename);
		break;
	    case notify_hardlink :
		filter = config_intval(cfg, cfg_event_hardlink);
		break;
	    case notify_overflow :
	    case notify_nospace :
	    case notify_add_tree :
		filter = config_file_all;
		break;
	}
	check = filter_type(ev.file_type);
	if (filter & check) {
	    const char * err = store_data.process(&ev);
	    if (err) {
		if (buffer) myfree(buffer);
		if (cfg) config_put(cfg);
		return err;
	    }
	    do_flush = 1;
	}
    }
    if (buffer) myfree(buffer);
    if (cfg) config_put(cfg);
    return NULL;
}

/* cleanup required after the store thread terminates */

void store_exit(void) {
    if (store_data.exit)
	store_data.exit();
}

/* returns current event files information */

void store_status(store_status_t * status) {
    int errcode = pthread_mutex_lock(&save_lock);
    if (errcode) {
	status->file_earliest = -1;
	status->file_current = -1;
	status->file_pos = -1;
	return;
    }
    status->file_earliest = save_earliest;
    status->file_current = save_current;
    status->file_pos = save_pos;
    pthread_mutex_unlock(&save_lock);
}

/* purges event files */

int store_purge(int days) {
    const config_data_t * cfg = config_get();
    int len = config_strlen(cfg, cfg_eventdir), earliest, count;
    char name[len + SUFFIX_SIZE + 2], * suffix;
    time_t limit = time(NULL) - days * 86400;
    strcpy(name, config_strval(cfg, cfg_eventdir));
    suffix = name + len;
    *suffix++ = '/';
    if (! count_files(config_strval(cfg, cfg_eventdir), &earliest, &count)) {
	int e = errno;
	config_put(cfg);
	errno = e;
	return 0;
    }
    config_put(cfg);
    while (earliest < count - 2) {
	struct stat sbuff;
	snprintf(suffix, SUFFIX_SIZE, "ev%06d.log", earliest);
	if (stat(name, &sbuff) && sbuff.st_mtime < limit)
	    if (unlink(name) < 0)
		return 0;
	earliest++;
    }
    return 1;
}

/* prepare to read events back from store; note that the caller must make
 * sure "root" isn't modified after this call */

store_get_t * store_prepare(int filenum, int filepos, const char * root) {
    const config_data_t * cfg = config_get();
    int len = config_strlen(cfg, cfg_eventdir);
    int size = sizeof(store_get_t) + strlen(root) + len + SUFFIX_SIZE + 3;
    char * rptr;
    store_get_t * sg;
    if (! count_files(config_strval(cfg, cfg_eventdir),
	&save_earliest, &save_count))
    {
	int e = errno;
	config_put(cfg);
	errno = e;
	return NULL;
    }
    sg = mymalloc(size);
    if (! sg) {
	int e = errno;
	config_put(cfg);
	errno = e;
	return NULL;
    }
    strcpy(sg->name, config_strval(cfg, cfg_eventdir));
    sg->suffix = sg->name + len;
    *sg->suffix++ = '/';
    rptr = sg->suffix + SUFFIX_SIZE + 1;
    sg->root = rptr;
    strcpy(rptr, root);
    sg->namebuff = NULL;
    sg->namemax = 0;
    sg->fd = -1;
    sg->file_num = filenum;
    sg->file_pos = filepos;
#if NOTIFY == NOTIFY_INOTIFY
    sg->iwatch = inotify_init();
#endif
    config_put(cfg);
    return sg;
}

/* check if a name is inside a tree */

static int is_inside(const char * name, const char * tree) {
    if (*tree == '/' && ! tree[1]) return 1;
    while (*name && *tree) {
	if (*name != *tree) return 0;
	name++;
	tree++;
    }
    if (*tree) return 0;
    if (*name && *name != '/') return 0;
    return 1;
}

/* get next event from file; if there are no more events, waits for more
 * for up to "timeout" seconds or until there is activity on file descriptor
 * "fd". Returns 0 if OK, -1 if timeout, -2 if other error: in this case,
 * the error fields are filled with the message; if there is an event but its
 * variable part is larger than "size" bytes, returns the actual size of the
 * event */

int store_get(store_get_t * sg, notify_event_t * nev, int timeout, int size,
	      int wfd, char * errmsg, int errsize)
{
    int try_reread = 1;
    while (main_running) {
	struct pollfd pfd[2];
	int nfd;
	/* try reading an event from the file... */
	if (sg->fd >= 0) {
	    ssize_t nr;
	    event_t sev;
	    off_t fp = sg->file_pos;
	    int nl;
	    char * np;
	    if (lseek(sg->fd, fp, SEEK_SET) < 0) {
		error_sys_r(errmsg, errsize, "store_get", sg->name);
		return -2;
	    }
	    nr = read(sg->fd, &sev, sizeof(event_t));
	    if (nr < 0) {
		if (errno == EAGAIN) goto not_ready;
		error_sys_r(errmsg, errsize, "store_get", sg->name);
		return -2;
	    }
	    if (nr < sizeof(event_t))
		goto not_ready;
	    /* get this event */
	    nev->from_length = decode_32(sev.from_length);
	    nev->to_length = decode_32(sev.to_length);
	    if (size >= 0) {
		/* is this too big? */
		int evsize = 0;
		if (nev->from_length > 0) evsize += nev->from_length;
		if (nev->to_length > 0) evsize += nev->to_length;
		if (evsize > size)
		    return evsize;
	    }
	    fp += sizeof(event_t);
	    nev->event_type = sev.event_type;
	    nev->file_type = sev.file_type;
	    nev->stat_valid = sev.has_stat;
	    if (sev.has_stat) {
		stat_t sdata;
		nr = read(sg->fd, &sdata, sizeof(stat_t));
		if (nr < 0) {
		    if (errno == EAGAIN) goto not_ready;
		    error_sys_r(errmsg, errsize, "store_get", sg->name);
		    return -2;
		}
		if (nr < sizeof(stat_t))
		    goto not_ready;
		fp += sizeof(stat_t);
		nev->file_mode = decode_16(sdata.file_mode);
		nev->file_user = decode_32(sdata.file_user);
		nev->file_group = decode_32(sdata.file_group);
		if (nev->file_type == notify_filetype_device_block ||
		    nev->file_type == notify_filetype_device_char) {
		    int major = decode_32(sdata.file_size);
		    int minor = decode_32(sdata.file_size + 4);
		    nev->file_size = 0;
		    nev->file_device = makedev(major, minor);
		} else {
		    nev->file_size = decode_64(sdata.file_size);
		}
		nev->file_mtime = decode_64(sdata.file_mtime);
	    } else if (sev.event_type == notify_add_tree) {
		unsigned char ts[8];
		nr = read(sg->fd, ts, 8);
		if (nr < 0) {
		    if (errno == EAGAIN) goto not_ready;
		    error_sys_r(errmsg, errsize, "store_get", sg->name);
		    return -2;
		}
		if (nr < 8)
		    goto not_ready;
		fp += 8;
		nev->file_mtime = decode_64(ts);
	    }
	    nl = 0;
	    if (nev->from_length > 0) nl += 1 + nev->from_length;
	    if (nev->to_length > 0) nl += 1 + nev->to_length;
	    if (nl > sg->namemax) {
		if (sg->namebuff) myfree(sg->namebuff);
		sg->namemax = 0;
		nl += 1023;
		nl &= ~0x3ff;
		sg->namebuff = mymalloc(nl);
		if (! sg->namebuff) {
		    error_sys_r(errmsg, errsize, "store_get", sg->name);
		    return -2;
		}
		sg->namemax = nl;
	    }
	    np = sg->namebuff;
	    if (nev->from_length > 0) {
		nr = read(sg->fd, np, 1 + nev->from_length);
		if (nr < 0) {
		    if (errno == EAGAIN) goto not_ready;
		    error_sys_r(errmsg, errsize, "store_get", sg->name);
		    return -2;
		}
		if (nr < 1 + nev->from_length)
		    goto not_ready;
		nev->from_name = np;
		fp += 1 + nev->from_length;
		np += 1 + nev->from_length;
	    } else {
		nev->from_name = NULL;
	    }
	    if (nev->to_length > 0) {
		nr = read(sg->fd, np, 1 + nev->to_length);
		if (nr < 0) {
		    if (errno == EAGAIN) goto not_ready;
		    error_sys_r(errmsg, errsize, "store_get", sg->name);
		    return -2;
		}
		if (nr < 1 + nev->to_length)
		    goto not_ready;
		nev->to_name = np;
		fp += 1 + nev->to_length;
		np += 1 + nev->to_length;
	    } else {
		nev->to_name = NULL;
	    }
	    sg->file_pos = fp;
	    /* check if we want to return this event */
	    if (! nev->from_name)
		return 0;
	    if (nev->event_type == notify_add_tree) {
		if (is_inside(nev->from_name, sg->root))
		    return 0;
		if (is_inside(sg->root, nev->from_name)) {
		    /* adding a parent of root, report it as adding root */
		    nev->from_name = sg->root;
		    nev->from_length = strlen(sg->root);
		    return 0;
		}
	    } else if (nev->event_type == notify_rename ||
		       nev->event_type == notify_hardlink)
	    {
		int ok_from = is_inside(nev->from_name, sg->root);
		int ok_to = is_inside(nev->to_name, sg->root);
		if (ok_from && ok_to)
		    return 0;
		if (ok_from) {
		    /* rename outside subdir -> treat as delete */
		    nev->event_type = notify_delete;
		    nev->to_name = NULL;
		    nev->to_length = 0;
		    return 0;
		}
		if (ok_to) {
		    /* rename from outside subdir -> treat as create */
		    nev->event_type = notify_create;
		    nev->from_name = nev->to_name;
		    nev->from_length = nev->to_length;
		    nev->to_name = NULL;
		    nev->to_length = 0;
		    return 0;
		}
	    } else {
		if (is_inside(nev->from_name, sg->root))
		    return 0;
	    }
	    /* ignore this event and try the next one */
	    continue;
	}
	/* check if we need to open the file */
	if (sg->fd < 0) {
	    struct stat sbuff;
	    int rfd;
	    snprintf(sg->suffix, SUFFIX_SIZE, "ev%06d.log", sg->file_num);
	    rfd = open(sg->name, O_RDONLY|O_NONBLOCK);
	    if (rfd < 0) {
		error_sys_r(errmsg, errsize, "store_get", sg->name);
		return -2;
	    }
	    if (fstat(rfd, &sbuff) < 0) {
		error_sys_r(errmsg, errsize, "store_get", sg->name);
		close(rfd);
		return -2;
	    }
	    if (! S_ISREG(sbuff.st_mode)) {
		close(rfd);
		snprintf(errmsg, errsize, "Event log is not a regular file?");
		return -2;
	    }
	    sg->fd = rfd;
	    continue;
	}
    not_ready:
	/* if the file is not the current one, it may have been closed
	 * since; but we only try this once */
	if (sg->file_num < save_current) {
	    if (try_reread) {
		try_reread = 0;
		continue;
	    }
	    /* close the file and try the next one */
	    close(sg->fd);
	    sg->fd = -1;
	    sg->file_num ++;
	    sg->file_pos = 0;
	    try_reread = 1;
	    continue;
	}
	/* no events available right now */
	if (timeout == 0)
	    return -1;
	/* wait for an event - we need to watch for file changes in the
	 * event log,and poll on the watch, rather than polling directly
	 * on the file, because regular files are always "ready" */
	pfd[0].fd = wfd;
	pfd[0].events = POLLIN | POLLPRI | POLLHUP;
	nfd = 1;
#if NOTIFY == NOTIFY_INOTIFY
	if (sg->iwatch >= 0) {
	    pfd[1].fd = sg->iwatch;
	    pfd[1].events = POLLIN | POLLPRI | POLLHUP;
	    inotify_add_watch(pfd[1].fd, sg->name, IN_MODIFY|IN_ONESHOT);
	    nfd = 2;
	}
#endif
	if (poll(pfd, nfd, 1000) < 0) {
	    snprintf(errmsg, errsize, "Interrupt");
	    return -2;
	}
	if (pfd[0].revents) {
	    snprintf(errmsg, errsize, "Client closed connection");
	    return -2;
	}
	if (timeout > 0)
	    timeout--;
    }
    snprintf(errmsg, errsize, "Interrupt");
    return -2;
}

/* get file number and position */

int store_get_file(const store_get_t * sg) {
    return sg->file_num;
}

int store_get_pos(const store_get_t * sg) {
    return sg->file_pos;
}

/* finish reading events from store */

void store_finish(store_get_t * sg) {
    if (sg->fd >= 0) close(sg->fd);
    if (sg->namebuff) myfree(sg->namebuff);
    myfree(sg);
}
#endif /* NOTIFY != NOTIFY_NONE */

void store_printname(const char * name, char next) {
    const char * ptr;
    char quote = 0;
    for (ptr = name; *ptr; ptr++) {
	if (isgraph((int)*ptr)) continue;
	quote = '\'';
	break;
    }
    if (quote) putc(quote, stdout);
    for (ptr = name; *ptr; ptr++) {
	switch (*ptr) {
	    case '\n' :
		putc('\\', stdout);
		putc('n', stdout);
		break;
	    case '\t' :
		putc('\\', stdout);
		putc('t', stdout);
		break;
	    case '\\' :
	    case '\''  :
		putc('\\', stdout);
		putc(*ptr, stdout);
		break;
	    default   :
		if (isprint((int)*ptr))
		    putc(*ptr, stdout);
		else
		    printf("\\%03o", (unsigned char)*ptr);
	}
    }
    if (quote) putc(quote, stdout);
    if (next) putc(next, stdout);
}

void store_printevent(const notify_event_t * ev,
		      const char * user, const char * group)
{
    const char * evtype = "?";
    switch (ev->event_type) {
	case notify_change_meta : {
	    evtype = "CHANGE";
	    break;
	}
	case notify_change_data :
	    evtype = "WRITE";
	    break;
	case notify_create :
	    evtype = "CREATE";
	    break;
	case notify_delete :
	    evtype = "DELETE";
	    break;
	case notify_rename :
	    evtype = "RENAME";
	    break;
	case notify_hardlink :
	    evtype = "LINK";
	    break;
	case notify_overflow :
	    evtype = "OVERFLOW";
	    break;
	case notify_nospace :
	    evtype = "NOSPACE";
	    break;
	case notify_add_tree :
	    evtype = "ADD_TREE";
	    break;
    }
    printf("%-9s", evtype);
    if (ev->from_name)
	store_printname(ev->from_name, '\n');
    else
	putchar('\n');
    if (ev->to_name) {
	printf("%-9s", "TO");
	store_printname(ev->to_name, '\n');
    }
    evtype = NULL;
    if (ev->stat_valid) {
	char mode[11];
	switch (ev->file_type) {
	    case notify_filetype_regular      : mode[0] = '-'; break;
	    case notify_filetype_dir          : mode[0] = 'd'; break;
	    case notify_filetype_device_char  : mode[0] = 'c'; break;
	    case notify_filetype_device_block : mode[0] = 'b'; break;
	    case notify_filetype_fifo         : mode[0] = 'p'; break;
	    case notify_filetype_symlink      : mode[0] = 'l'; break;
	    case notify_filetype_socket       : mode[0] = '='; break;
	    case notify_filetype_unknown      : mode[0] = '?'; break;
	}
	mode[1] = ev->file_mode & S_IRUSR ? 'r' : '-';
	mode[2] = ev->file_mode & S_IWUSR ? 'w' : '-';
	switch (ev->file_mode & (S_IXUSR | S_ISUID)) {
	    case 0                 : mode[3] = '-'; break;
	    case S_IXUSR           : mode[3] = 'x'; break;
	    case S_ISUID           : mode[3] = 'S'; break;
	    case S_ISUID | S_IXUSR : mode[3] = 's'; break;
	}
	mode[4] = ev->file_mode & S_IRGRP ? 'r' : '-';
	mode[5] = ev->file_mode & S_IWGRP ? 'w' : '-';
	switch (ev->file_mode & (S_IXGRP | S_ISGID)) {
	    case 0                 : mode[6] = '-'; break;
	    case S_IXGRP           : mode[6] = 'x'; break;
	    case S_ISGID           : mode[6] = 'S'; break;
	    case S_ISGID | S_IXGRP : mode[6] = 's'; break;
	}
	mode[7] = ev->file_mode & S_IROTH ? 'r' : '-';
	mode[8] = ev->file_mode & S_IWOTH ? 'w' : '-';
	switch (ev->file_mode & (S_IXOTH | S_ISVTX)) {
	    case 0                 : mode[9] = '-'; break;
	    case S_IXOTH           : mode[9] = 'x'; break;
	    case S_ISVTX           : mode[9] = 'T'; break;
	    case S_ISVTX | S_IXOTH : mode[9] = 't'; break;
	}
	mode[10] = 0;
	printf("         mode=%04o (%s)\n", ev->file_mode, mode);
	if (user)
	    printf("         owner=%d (%s)\n", ev->file_user, user);
	else
	    printf("         owner=%d\n", ev->file_user);
	if (group)
	    printf("         group=%d (%s)\n", ev->file_group, group);
	else
	    printf("         group=%d\n", ev->file_group);
	if (ev->file_type == notify_filetype_device_block ||
	    ev->file_type == notify_filetype_device_char) {
	    printf("         device=%d,%d\n",
		   major(ev->file_device), minor(ev->file_device));
	} else {
	    printf("         size=%lld\n", ev->file_size);
	}
	evtype = "mtime";
    } else if (ev->event_type == notify_add_tree) {
	evtype = "add_time";
    }
    if (evtype) {
	char when[32];
	ctime_r(&ev->file_mtime, when);
	when[strlen(when) - 1] = 0;
	printf("         %s=%lld (%s)\n",
	       evtype, (long long)ev->file_mtime, when);
    }
}

