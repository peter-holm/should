/* should's store thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/mman.h>
#include <signal.h>
#include <syslog.h>
#include "store_thread.h"
#include "notify_thread.h"
#include "main_thread.h"
#include "config.h"
#include "error.h"
#include "mymalloc.h"
#include "socket.h"
#include "usermap.h"

#define SUFFIX_SIZE 32
#define BLOCK_ADD 512
#define TIMESTAMP 32

struct store_get_s {
    int file_num;
    int file_pos;
    int file_size;
    int page_size;
    unsigned char * mmap;
    size_t mlen;
    char * name;
    char * suffix;
    const char * root;
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
    const char * (*init)(const config_t *, const char *);
    const char * (*process)(const notify_event_t *);
    void (*flush)(void);
    void (*exit)(void);
} store_t;

static FILE * save_file;
static char * save_name, * save_suffix;
static int save_count, save_size, save_earliest, save_current, save_len;
static long save_pos;
static pthread_mutex_t save_lock;
static int optimise_count;

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

static const char * open_file(void) {
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
	while (en[ptr] && isdigit(en[ptr])) ptr++;
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

static const char * save_init(const config_t * cfg, const char * cmd) {
    int len = strlen(cfg->eventdir);
    const char * err;
    struct stat sbuff;
    int code = pthread_mutex_init(&save_lock, NULL);
    if (code)
	return error_sys_errno("save_init", "pthread_mutex_init", code);
    if (stat(cfg->eventdir, &sbuff) < 0) {
	if (mkdir(cfg->eventdir, 0700) < 0) {
	    int e = errno;
	    pthread_mutex_destroy(&save_lock);
	    return error_sys_errno("save_init", "mkdir", e);
	}
    } else {
	if (! S_ISDIR(sbuff.st_mode))
	    return "eventdir exists but is not a directory";
    }
    save_size = cfg->eventsize;
    save_len = len + SUFFIX_SIZE + 2;
    save_name = mymalloc(save_len);
    if (! save_name) {
	int e = errno;
	pthread_mutex_destroy(&save_lock);
	return error_sys_errno("save_init", "malloc", e);
    }
    strcpy(save_name, cfg->eventdir);
    save_suffix = save_name + len;
    *save_suffix++ = '/';
    if (! count_files(cfg->eventdir, &save_earliest, &save_count)) {
	int e = errno;
	myfree(save_name);
	pthread_mutex_destroy(&save_lock);
	return error_sys_errno("save_init", cfg->eventdir, e);
    }
    if (save_count <= 0)
	save_count = 1;
    save_file = NULL;
    err = open_file();
    if (err) {
	myfree(save_name);
	pthread_mutex_destroy(&save_lock);
	return err;
    }
    /* see if we are going to rotate the file */
    if (save_pos > (long)INT_MAX || save_pos >= save_size) {
	err = open_file();
	if (err) {
	    myfree(save_name);
	    pthread_mutex_destroy(&save_lock);
	    return err;
	}
    }
    if (save_earliest < 0)
	save_earliest = save_current;
    return NULL;
}

static const char * save_process(const notify_event_t * ev) {
    event_t sev;
    long pos;
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
    if (pos > INT_MAX || pos >= save_size)
	open_file();
    else
	save_pos = pos;
    return NULL;
}

static void save_exit(void) {
    if (save_file) fclose(save_file);
    if (save_name) myfree(save_name);
    pthread_mutex_destroy(&save_lock);
}

void store_printname(const char * name, char next) {
    const char * ptr;
    char quote = 0;
    for (ptr = name; *ptr; ptr++) {
	if (isgraph(*ptr)) continue;
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
		if (isprint(*ptr))
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

static const char * logfile_init(const config_t * cfg, const char * cmd) {
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
	if (isprint(*name) && *name != '\n' && *name != '\r' && *name != '%')
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

static const char * syslog_init(const config_t * cfg, const char * cmd) {
    int fac = LOG_LOCAL7 | LOG_INFO;
    if (cmd && cmd[0] && cmd[1]) {
	const char * err = config_getfacility(cmd + 1, &fac);
	if (err)
	    return err;
    }
    error_change_dest(info_changelog, error_dest_syslog, fac);
    return NULL;
}

static void syslog_sendname(const char * pre, notify_filetype_t type,
			    const char * name, int namelen)
{
    char buffer[3 * namelen + 1];
    int buflen = 0;
    const char * ft = filetype(type);
    while (namelen > 0) {
	if (isprint(*name) && *name != '\n' && *name != '\r' && *name != '%')
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

const char * store_init(const config_t * cfg) {
    int i, len;
    const char * colon = strchr(cfg->store, ':');
    if (colon)
	len = colon - cfg->store;
    else
	len = strlen(cfg->store);
    save_current = save_earliest = save_pos = -1;
    save_name = NULL;
    optimise_count = cfg->optimise_server;
    /* search for a predefined store method */
    for (i = 0; store_methods[i].name; i++) {
	if (strncmp(store_methods[i].name, cfg->store, len) == 0) {
	    if (! store_methods[i].name[len]) {
		store_data = store_methods[i];
		if (store_data.init)
		    return store_data.init(cfg, colon);
		return NULL;
	    }
	}
    }
    return "No such store method";
}

/* run store thread; returns NULL on normal termination,
 * or an error message */

const char * store_thread(void) {
    int ov, bsize = 0, do_flush = 0;
    char * buffer = NULL;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    while (main_running) {
	const char * err;
	notify_event_t ev;
	int reqsize = bsize;
	int g = notify_get(&ev, POLL_TIME, buffer, &reqsize);
	if (g == -3) {
	    if (buffer) myfree(buffer);
	    reqsize += BLOCK_ADD;
	    bsize = reqsize;
	    buffer = mymalloc(bsize);
	    if (! buffer)
		return error_sys("store_thread", "malloc");
	    g = notify_get(&ev, POLL_TIME, buffer, &reqsize);
	}
	if (g == -2) {
	    if (do_flush && store_data.flush) {
		store_data.flush();
		do_flush = 0;
	    }
	    continue;
	}
	if (g < 0) {
	    err = error_sys("store_thread", "notify_get");
	    if (buffer) myfree(buffer);
	    return err;
	}
	if (g == 0) {
	    if (buffer) myfree(buffer);
	    return NULL;
	}
	err = store_data.process(&ev);
	if (err) {
	    if (buffer) myfree(buffer);
	    return err;
	}
	do_flush = 1;
    }
    if (buffer) myfree(buffer);
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

int store_purge(const config_t * cfg, int days) {
    int len = strlen(cfg->eventdir), earliest, count;
    char name[len + SUFFIX_SIZE + 2], * suffix;
    time_t limit = time(NULL) - days * 86400;
    strcpy(name, cfg->eventdir);
    suffix = name + len;
    *suffix++ = '/';
    if (! count_files(cfg->eventdir, &earliest, &count))
	return 0;
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

store_get_t * store_prepare(const config_t * cfg,
			    int filenum, int filepos, const char * root)
{
    int len = strlen(cfg->eventdir);
    int size = sizeof(store_get_t) + strlen(root) + len + SUFFIX_SIZE + 3;
    char * rptr;
    store_get_t * sg;
    if (! count_files(cfg->eventdir, &save_earliest, &save_count))
	return NULL;
    sg = mymalloc(size);
    if (! sg) return NULL;
    sg->name = (void *)&sg[1];
    strcpy(sg->name, cfg->eventdir);
    sg->suffix = sg->name + len;
    *sg->suffix++ = '/';
    rptr = sg->suffix + SUFFIX_SIZE + 1;
    sg->root = rptr;
    strcpy(rptr, root);
    sg->mmap = NULL;
    sg->mlen = 0;
    sg->file_num = filenum;
    sg->file_pos = filepos;
    sg->page_size = getpagesize();
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
    while (main_running) {
	struct pollfd pfd;
	/* if using the current file and it has grown, reopen it */
	if (sg->file_num == save_current && sg->file_size < save_pos) {
	    munmap(sg->mmap, sg->mlen);
	    sg->mmap = NULL;
	}
	/* check if we need to mmap the file */
	if (! sg->mmap) {
	    struct stat sbuff;
	    int rfd;
	    snprintf(sg->suffix, SUFFIX_SIZE, "ev%06d.log", sg->file_num);
	    rfd = open(sg->name, O_RDONLY);
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
	    sg->file_size = sbuff.st_size;
	    sg->mlen = sg->file_size + sg->page_size - 1;
	    sg->mlen /= sg->page_size;
	    sg->mlen *= sg->page_size;
	    sg->mmap = mmap(NULL, sg->mlen, PROT_READ, MAP_SHARED, rfd, 0);
	    if (! sg->mmap) {
		error_sys_r(errmsg, errsize, "store_get", sg->name);
		close(rfd);
		return -2;
	    }
	    close(rfd);
	}
	/* see if we have reached the end of file */
	if (sg->file_pos < sg->file_size) {
	    /* get this event */
	    const event_t * sev = (const void *)(sg->mmap + sg->file_pos);
	    nev->from_length = decode_32(sev->from_length);
	    nev->to_length = decode_32(sev->to_length);
	    if (size >= 0) {
		/* is this too big? */
		int evsize = 0;
		if (nev->from_length > 0) evsize += nev->from_length;
		if (nev->to_length > 0) evsize += nev->to_length;
		if (evsize > size)
		    return evsize;
	    }
	    sg->file_pos += sizeof(event_t);
	    nev->event_type = sev->event_type;
	    nev->file_type = sev->file_type;
	    nev->stat_valid = sev->has_stat;
	    if (nev->stat_valid) {
		const stat_t * stat = (void *)(sg->mmap + sg->file_pos);
		sg->file_pos += sizeof(stat_t);
		nev->file_mode = decode_16(stat->file_mode);
		nev->file_user = decode_32(stat->file_user);
		nev->file_group = decode_32(stat->file_group);
		if (nev->file_type == notify_filetype_device_block ||
		    nev->file_type == notify_filetype_device_char) {
		    int major = decode_32(stat->file_size);
		    int minor = decode_32(stat->file_size + 4);
		    nev->file_size = 0;
		    nev->file_device = makedev(major, minor);
		} else {
		    nev->file_size = decode_64(stat->file_size);
		}
		nev->file_mtime = decode_64(stat->file_mtime);
	    } else if (nev->event_type == notify_add_tree) {
		nev->file_mtime = decode_64(sg->mmap + sg->file_pos);
		sg->file_pos += 8;
	    }
	    if (nev->from_length > 0) {
		nev->from_name = (char *)(sg->mmap + sg->file_pos);
		sg->file_pos += 1 + nev->from_length;
	    } else {
		nev->from_name = NULL;
	    }
	    if (nev->to_length > 0) {
		nev->to_name = (char *)(sg->mmap + sg->file_pos);
		sg->file_pos += 1 + nev->to_length;
	    } else {
		nev->to_name = NULL;
	    }
	    /* check if we want to return this event */
	    if (! nev->from_name)
		return 0;
	    if (nev->event_type == notify_add_tree) {
		if (is_inside(sg->root, nev->from_name))
		    return 0;
		if (is_inside(nev->from_name, sg->root))
		    return 0;
	    } else if (nev->event_type == notify_rename) {
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
	/* end of file: do we have another? */
	if (sg->file_num < save_current) {
	    munmap(sg->mmap, sg->mlen);
	    sg->mmap = NULL;
	    sg->file_num++;
	    sg->file_pos = 0;
	    /* try next file */
	    continue;
	}
	/* no events available right now */
	if (timeout == 0)
	    return -1;
	/* wait for an event */
	pfd.fd = wfd;
	pfd.events = POLLIN | POLLPRI | POLLHUP;
	poll(&pfd, 1, 1000);
	if (pfd.revents) {
	    snprintf(errmsg, errsize, "Client closed connection");
	    return -2;
	}
	if (timeout > 0)
	    timeout--;
    }
    snprintf(errmsg, errsize, "Interrupt");
    return -2;
}

#if 0

/* are there any events ready? */

typedef const event_t * event_pt;

static const char * check_events(store_get_t * sg,
				 event_pt * avail, int reopen)
{
    while (1) {
	/* if using the current file and it has grown, reopen it */
	if (reopen && sg->file_num == save_current && sg->file_size < save_pos)
	{
	    munmap(sg->mmap, sg->mlen);
	    sg->mmap = NULL;
	}
	/* check if we need to mmap the file */
	if (! sg->mmap) {
	    struct stat sbuff;
	    int rfd;
	    snprintf(sg->suffix, SUFFIX_SIZE, "ev%06d.log", sg->file_num);
	    rfd = open(sg->name, O_RDONLY);
	    if (rfd < 0)
		return error_sys("store_get", sg->name);
	    if (fstat(rfd, &sbuff) < 0) {
		const char * err = error_sys("store_get", sg->name);
		close(rfd);
		return err;
	    }
	    if (! S_ISREG(sbuff.st_mode)) {
		close(rfd);
		return "Event log is not a regular file?";
	    }
	    sg->file_size = sbuff.st_size;
	    sg->mlen = sg->file_size + sg->page_size - 1;
	    sg->mlen /= sg->page_size;
	    sg->mlen *= sg->page_size;
	    sg->mmap = mmap(NULL, sg->mlen, PROT_READ, MAP_SHARED, rfd, 0);
	    if (! sg->mmap) {
		const char * err = error_sys("store_get", sg->name);
		close(rfd);
		return err;
	    }
	    close(rfd);
	}
	/* see if we have reached the end of file */
	if (sg->file_pos < sg->file_size) {
	    *avail = (const void *)(sg->mmap + sg->file_pos);
	    return NULL;
	}
	/* end of file: do we have another? */
	if (sg->file_num < save_current) {
	    munmap(sg->mmap, sg->mlen);
	    sg->mmap = NULL;
	    sg->file_num++;
	    sg->file_pos = 0;
	    /* try next file */
	    continue;
	}
	/* no events available right now */
	*avail = NULL;
	return NULL;
    }
}

const char * store_poll(store_get_t * sg, int * avail) {
    const event_t * sev = NULL;
    const char * ret = check_events(sg, &sev, 0);
    if (ret) return ret;
    if (sev) {
	int fl = decode_32(sev->from_length);
	int tl = decode_32(sev->to_length);
	if (fl < 0) fl = 0;
	if (tl < 0) tl = 0;
	*avail = fl + tl + 2;
    } else {
	*avail = -1;
    }
    return NULL;
}

/* get next event from file; if there are no more events, waits for more
 * but will return with a timeout if there is activity on the file
 * descriptor fd before there are new events */

const char * store_get(store_get_t * sg, notify_event_t * nev, int wfd) {
    while (main_running) {
	const char * err;
	const event_t * sev;
	/* check for available events */
	err = check_events(sg, &sev, 1);
	if (err)
	    return err;
	if (! sev) {
	    /* wait for an event */
	    struct pollfd pfd;
	    pfd.fd = wfd;
	    pfd.events = POLLIN | POLLPRI | POLLHUP;
	    poll(&pfd, 1, 1000);
	    if (pfd.revents)
		return "Client closed connection";
	    continue;
	}
	/* get this event */
	sg->file_pos += sizeof(event_t);
	nev->event_type = sev->event_type;
	nev->file_type = sev->file_type;
	nev->stat_valid = sev->has_stat;
	nev->from_length = decode_32(sev->from_length);
	nev->to_length = decode_32(sev->to_length);
	if (nev->stat_valid) {
	    const stat_t * stat = (void *)(sg->mmap + sg->file_pos);
	    sg->file_pos += sizeof(stat_t);
	    nev->file_mode = decode_16(stat->file_mode);
	    nev->file_user = decode_32(stat->file_user);
	    nev->file_group = decode_32(stat->file_group);
	    if (nev->file_type == notify_filetype_device_block ||
		nev->file_type == notify_filetype_device_char) {
		int major = decode_32(stat->file_size);
		int minor = decode_32(stat->file_size + 4);
		nev->file_size = 0;
		nev->file_device = makedev(major, minor);
	    } else {
		nev->file_size = decode_64(stat->file_size);
	    }
	    nev->file_mtime = decode_64(stat->file_mtime);
	} else if (nev->event_type == notify_add_tree) {
	    nev->file_mtime = decode_64(sg->mmap + sg->file_pos);
	    sg->file_pos += 8;
	}
	if (nev->from_length > 0) {
	    nev->from_name = (char *)(sg->mmap + sg->file_pos);
	    sg->file_pos += 1 + nev->from_length;
	} else {
	    nev->from_name = NULL;
	}
	if (nev->to_length > 0) {
	    nev->to_name = (char *)(sg->mmap + sg->file_pos);
	    sg->file_pos += 1 + nev->to_length;
	} else {
	    nev->to_name = NULL;
	}
	/* check if we want to return this event */
	if (! nev->from_name)
	    return NULL;
	if (nev->event_type == notify_add_tree) {
	    if (is_inside(sg->root, nev->from_name))
		return NULL;
	    if (is_inside(nev->from_name, sg->root))
		return NULL;
	} else {
	    if (is_inside(nev->from_name, sg->root))
		goto consider_event;
	}
	if (nev->to_name)
	    if (is_inside(nev->to_name, sg->root))
		goto consider_event;
	/* don't want this, try the next one */
    ignore_event:
	continue;
    consider_event:
	/* collapse event with up to optimise_count events after it */
if (0) // XXX doesn't work
	if (nev->from_name && nev->event_type != notify_rename) {
	    int i, pos;
	    for (i = 0, pos = sg->file_pos;
		 i < optimise_count && pos < sg->file_size;
		 i++)
	    {
		int fl, tl;
		char * fn, * tn;
		sev = (void *)(sg->mmap + pos);
		pos += sizeof(event_t);
		fl = decode_32(sev->from_length);
		tl = decode_32(sev->to_length);
		if (fl > 0) {
		    fn = (char *)(sg->mmap + pos);
		    pos += 1 + fl;
		} else {
		    fn = NULL;
		}
		if (tl > 0) {
		    tn = (char *)(sg->mmap + pos);
		    pos += 1 + tl;
		} else {
		    tn = NULL;
		}
		if (! fn) continue;
		if (sev->event_type == notify_delete) {
		    if (strcmp(fn, nev->from_name) == 0) {
			/* no need to do anything, it'll be deleted immediately */
			goto ignore_event;
		    }
		    continue;
		}
		if (sev->event_type == notify_rename) {
		    if (strcmp(tn, nev->from_name) == 0) {
			/* another file will be renamed to this one, so this
			 * event can be ignored */
			goto ignore_event;
		    }
		    /* we don't check if this event will be renamed, to do so
		     * we would need to reorder events and this means updating
		     * the logfile; the client will do the reordering */
		    continue;
		}
	    }
	}
	return NULL;
    }
    return "Interrupt";
}

#endif

/* get file number and position */

int store_get_file(const store_get_t * sg) {
    return sg->file_num;
}

int store_get_pos(const store_get_t * sg) {
    return sg->file_pos;
}

/* finish reading events from store */

void store_finish(store_get_t * sg) {
    if (sg->mmap) munmap(sg->mmap, sg->mlen);
    myfree(sg);
}

