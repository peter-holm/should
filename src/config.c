/* data structure used to hold configuration information
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
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <pwd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include "config.h"
#include "error.h"
#include "main_thread.h"
#include "store_thread.h"
#include "compress.h"
#include "checksum.h"
#include "mymalloc.h"

#define IDENTIFY_COPY "# SHOULD STATE FILE %lf"
#define IDENTIFY_VERSION (double)1.0
#define IDENTIFY_MINIMUM (double)1.0

#define UPDATE_COUNT 5
#define LINE_SIZE 1024

/* local flags, used while parsing configuration / command line */

typedef enum {
    locfl_config      = 0x0001,
    locfl_version     = 0x0002,
    locfl_help        = 0x0004,
    locfl_warranty    = 0x0008,
    locfl_copyright   = 0x0010,
    locfl_defconfig   = 0x0020,
    locfl_defsocket   = 0x0040,
    locfl_deflogfile  = 0x0080,
    locfl_defeventdir = 0x0100,
    locfl_compress    = 0x0200,
    locfl_checksum    = 0x0400,
    locfl_notice      = 0x0800,
    locfl_has_socket  = 0x1000,
    locfl_NONE        = 0
} locfl_t;

typedef struct {
    int mul;
    const char * name_s;
    const char * name_p;
} unit_t;

typedef enum {
    include_none   = 0x00,
    include_silent = 0x01,
    include_state  = 0x02
} include_t;

static config_data_t configs[UPDATE_COUNT];
static int currnum, refcount[UPDATE_COUNT], in_use[UPDATE_COUNT], update_cn;
static pthread_mutex_t config_lock;
static char errbuff[LINE_SIZE];
static pthread_t update_thread;

/* initial values for integer data */

static int default_ints[cfg_int_COUNT] = {
    [cfg_client_mode]              = config_client_NONE,
#if USE_SHOULDBOX
    [cfg_server_mode]              = config_server_NONE,
#else
    [cfg_server_mode]              = config_server_detach,
#endif
    [cfg_flags]                    = config_flag_translate_ids
                                   | config_flag_skip_matching,
    [cfg_notify_queue_block]       = 1048576,
    [cfg_notify_initial]           = 2,
    [cfg_notify_max]               = 8,
    [cfg_notify_watch_block]       = 32,
    [cfg_notify_buffer]            = 1048576,
    [cfg_notify_name_block]        = 32758,
    [cfg_eventsize]                = 10485760,
    [cfg_checkpoint_events]        = 60,
    [cfg_checkpoint_time]          = 60,
    [cfg_from_length]              = 0,
    [cfg_to_length]                = 0,
    [cfg_bwlimit]                  = 0,
    [cfg_purge_days]               = 0,
    [cfg_autopurge_days]           = 14,
    [cfg_optimise_client]          = 128,
    [cfg_optimise_buffer]          = 262144,
    [cfg_nchecksums]               = 0,
    [cfg_ncompressions]            = 0,
    [cfg_dirsync_interval]         = 0,
    [cfg_dirsync_count]            = 0,
};

FILE * config_copy_file = NULL;
long config_copy_start = -1;

static unit_t intervals[] = {
    {      1,   "second",    "seconds" },
    {     60,   "minute",    "minutes" },
    {   3600,   "hour",      "hours"   },
    {  86400,   "day",       "days"    },
    { 604800,   "week",      "weeks"   },
    {      0,   NULL,        NULL      }
};

static unit_t sizes[] = {
    {          1,   "byte",      "bytes"     },
    {       1024,   "kilobyte",  "kilobytes" },
    {    1048576,   "megabyte",  "megabytes" },
    { 1073741824,   "gigabyte",  "gigabytes" },
    {          0,   NULL,        NULL        }
};

static const char * daynames[7] =
    { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

/* handles quoted strings and backslashes */

static void unquote_string(char * d) {
    const char * s = d;
    char q = 0;
    if (*s == '\'' || *s == '"')
	q = *s++;
    while (*s) {
	int n;
	if (*s == q) break;
	if (*s == '\\' && s[1]) {
	    s++;
	    switch (*s) {
		case 'n' : *d++ = '\n'; s++; break;
		case 't' : *d++ = '\t'; s++; break;
		case '0' : case '1' : case '2' : case '3' :
		case '4' : case '5' : case '6' : case '7' :
		    n = *s++ - '0';
		    if (*s && *s >= '0' && *s <= '7')
			n = n * 8 + *s++ - '0';
		    if (*s && *s >= '0' && *s <= '7')
			n = n * 8 + *s++ - '0';
		    *d++ = n;
		    break;
		default : *d++ = *s++; break;
	    }
	} else {
	    *d++ = *s++;
	}
    }
    *d = 0;
}

static int parse_units(const char * name, const unit_t * units,
		       const char ** err)
{
    char * ep;
    long lnum;
    int num;
    *err = NULL;
    if (! *name) {
	snprintf(errbuff, LINE_SIZE, "Invalid value (empty string)");
	*err = errbuff;
	return -1;
    }
    lnum = strtol(name, &ep, 0);
    if (lnum <= 0) {
	snprintf(errbuff, LINE_SIZE, "Value must be positive (%s)", name);
	*err = errbuff;
	return -1;
    }
    while (*ep && isspace((int)*ep)) ep++;
    if (*ep) {
	int len = strlen(ep);
	while (len > 1 && isspace((int)ep[len - 1])) len--;
	while (units->name_s) {
	    if ((len == strlen(units->name_p) &&
		 strncmp(ep, units->name_p, len) == 0) ||
		(len == strlen(units->name_s) &&
		 strncmp(ep, units->name_s, len) == 0))
	    {
		lnum *= units->mul;
		if (lnum <= 0) {
		    snprintf(errbuff, LINE_SIZE, "Number too large (%s)", name);
		    *err = errbuff;
		    return -1;
		}
		break;
	    }
	    units++;
	}
	if (! units->name_p) {
	    snprintf(errbuff, LINE_SIZE, "Invalid unit (%s)", name);
	    *err = errbuff;
	    return -1;
	}
    }
    num = lnum;
    if (lnum > 0 && num == lnum) return num;
    snprintf(errbuff, LINE_SIZE, "Number too large (%s)", name);
    *err = errbuff;
    return -1;
}

static const char * encode_units(int num, const unit_t * units) {
    static char unitbuff[512];
    const unit_t * found = NULL;
    /* find the best unit */
    while (units->name_s) {
	if (num % units->mul == 0)
	    if (! found || found->mul < units->mul)
		found = units;
	units++;
    }
    if (found) {
	num /= found->mul;
	snprintf(unitbuff, sizeof(unitbuff), "%d %s",
		 num, num == 1 ? found->name_s : found->name_p);
    } else {
	snprintf(unitbuff, sizeof(unitbuff), "%d", num);
    }
    return unitbuff;
}

/* parse a time interval and returns a number of seconds */

int config_parse_interval(const char * name) {
    const char * err = NULL;
    int rv = parse_units(name, intervals, &err);
    if (err) fprintf(stderr, "%s\n", err);
    return rv;
}

/* the opposite of the above */

const char * config_print_interval(int num) {
    return encode_units(num, intervals);
}

/* parse a size and returns a number of bytes */

int config_parse_size(const char * name) {
    const char * err = NULL;
    int rv = parse_units(name, sizes, &err);
    if (err) fprintf(stderr, "%s\n", err);
    return rv;
}

/* the opposite of the above */

const char * config_print_size(int num) {
    return encode_units(num, sizes);
}

/* parse a day range (mon-fri or tue,sat or sun,tue-thu,sat etc); returns
 * a pointer to the end of the parsed range and updates the second argument
 * with the corresponding mask; if the range is invalid, returns NULL */

const char * config_parse_dayrange(const char * dr, int * mask) {
    *mask = 0;
    while (*dr && isspace((int)*dr)) dr++;
    if (strncmp(dr, "never", 5) == 0) {
	dr += 5;
	while (*dr && isspace((int)*dr)) dr++;
	return dr;
    }
    while (*dr) {
	int start = 0, end;
	while (start < 7 && strncmp(dr, daynames[start], 3) != 0)
	    start++;
	if (start >= 7)
	    return NULL;
	dr += 3;
	while (*dr && isspace((int)*dr)) dr++;
	end = start;
	if (*dr == '-') {
	    dr++;
	    while (end < 7 && strncmp(dr, daynames[end], 3) != 0)
		end++;
	    if (end >= 7)
		return NULL;
	    dr += 3;
	    while (*dr && isspace((int)*dr)) dr++;
	}
	while (start <= end) {
	    *mask |= 1 << start;
	    start++;
	}
	while (*dr && isspace((int)*dr)) dr++;
	if (*dr != ',') return dr;
	dr++;
	while (*dr && isspace((int)*dr)) dr++;
    }
    return NULL;
}

/* the opposite of the above */

const char * config_print_dayrange(int dr) {
    static char buffer[32]; /* 7 * 4 + spare space */
    char * bp = buffer;
    int prev = -1, i, mask;
    for (i = 0, mask = 1; i < 8; i++, mask <<= 1) {
	if (i < 8 && (dr & mask)) {
	    if (prev < 0)
		prev = i;
	} else {
	    if (prev >= 0) {
		if (bp != buffer)
		    *bp++ = ',';
		strcpy(bp, daynames[prev]);
		bp += strlen(bp);
		if (prev < i - 1) {
		    *bp++ = '-';
		    strcpy(bp, daynames[i - 1]);
		    bp += strlen(bp);
		}
		prev = -1;
	    }
	}
    }
    if (bp == buffer)
	strcpy(bp, "never");
    return buffer;
}

/* try to assign a value */

static int assign_string(const char * line, const char * keyword,
			 int isdir, char ** result, const char ** err)
{
    int len = strlen(keyword);
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    while (*line && isspace((int)*line)) line++;
    if (*line != '=') {
	snprintf(errbuff, LINE_SIZE, "Missing '=' after %s", keyword);
	*err = errbuff;
	return 1;
    }
    line++;
    while (*line && isspace((int)*line)) line++;
    if (! *line) {
	snprintf(errbuff, LINE_SIZE, "Missing value after %s", keyword);
	*err = errbuff;
	return 1;
    }
    if (isdir && *line != '/') {
	snprintf(errbuff, LINE_SIZE,
		 "Value for %s is not an absolute path", keyword);
	*err = errbuff;
	return 1;
    }
    len = strlen(line);
    while (len > 0 && isspace((int)line[len - 1])) len--;
    if (*result) myfree(*result);
    *result = mymalloc(len + 1);
    if (! *result) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	return 1;
    }
    strncpy(*result, line, len);
    (*result)[len] = 0;
    unquote_string(*result);
    *err = NULL;
    return 1;
}

static int assign_int(const char * line, const char * keyword,
		      int * result, const char ** err)
{
    int len = strlen(keyword);
    char * endptr;
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    while (*line && isspace((int)*line)) line++;
    if (*line != '=') {
	snprintf(errbuff, LINE_SIZE, "Missing '=' after %s", keyword);
	*err = errbuff;
	return 1;
    }
    line++;
    while (*line && isspace((int)*line)) line++;
    if (! *line) {
	snprintf(errbuff, LINE_SIZE, "Missing value after %s", keyword);
	*err = errbuff;
	return 1;
    }
    *result = strtol(line, &endptr, 0);
    while (*endptr && isspace((int)*endptr)) endptr++;
    if (*endptr) {
	snprintf(errbuff, LINE_SIZE, "Invalid value after %s", keyword);
	*err = errbuff;
	return 1;
    }
    *err = NULL;
    return 1;
}

static int assign_unit(const char * line, const char * keyword,
		       const unit_t * units, int * result, const char ** err)
{
    int len = strlen(keyword);
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    while (*line && isspace((int)*line)) line++;
    if (*line != '=') {
	snprintf(errbuff, LINE_SIZE, "Missing '=' after %s", keyword);
	*err = errbuff;
	return 1;
    }
    line++;
    while (*line && isspace((int)*line)) line++;
    if (! *line) {
	snprintf(errbuff, LINE_SIZE, "Missing value after %s", keyword);
	*err = errbuff;
	return 1;
    }
    *result = parse_units(line, units, err);
    return 1;
}

static int assign_strlist(const char * line, const char * kw, int rev,
			  config_strlist_t ** sl, const char ** err)
{
    char * st = NULL;
    if (assign_string(line, kw, 0, &st, err)) {
	config_strlist_t * elem;
	if (* err) {
	    myfree(st);
	    return 1;
	}
	elem = mymalloc(sizeof(config_strlist_t));
	if (! elem) {
	    int e = errno;
	    myfree(st);
	    *err = error_sys_errno_r(errbuff, LINE_SIZE, "config", "malloc", e);
	    return 1;
	}
	elem->data = st;
	if (rev)  {
	    elem->next = *sl;
	    *sl = elem;
	} else {
	    elem->next = NULL;
	    if (*sl) {
		config_strlist_t * last = *sl;
		while (last->next)
		    last = last->next;
		last->next = elem;
	    } else {
		*sl = elem;
	    }
	}
	return 1;
    }
    return 0;
}

static error_message_t assign_error(const char * line, const char * keyword,
				    char ** result, const char ** err)
{
    int len = strlen(keyword), namelen;
    error_message_t erm;
    if (strncmp(line, keyword, len) != 0) return error_MAX;
    line += len;
    while (*line && isspace((int)*line)) line++;
    if (*line != ':') {
	snprintf(errbuff, LINE_SIZE, "Missing ':' after %s", keyword);
	*err = errbuff;
	return error_MAX;
    }
    line++;
    while (*line && isspace((int)*line)) line++;
    if (! *line) {
	snprintf(errbuff, LINE_SIZE, "Missing value after %s", keyword);
	*err = errbuff;
	return error_MAX;
    }
    namelen = 0;
    while (line[namelen] &&
	   ! isspace((int)line[namelen]) && line[namelen] != '=')
	namelen++;
    erm = error_code(line, namelen);
    if (erm == error_MAX) {
	snprintf(errbuff, LINE_SIZE,
		 "Invalid error code: %.*s", namelen, line);
	*err = errbuff;
	return error_MAX;
    }
    line += namelen;
    while (*line && isspace((int)*line)) line++;
    if (*line != '=') {
	snprintf(errbuff, LINE_SIZE, "Missing '=' after %s", keyword);
	*err = errbuff;
	return error_MAX;
    }
    line++;
    while (*line && isspace((int)*line)) line++;
    if (! *line) {
	snprintf(errbuff, LINE_SIZE, "Missing value after %s", keyword);
	*err = errbuff;
	return error_MAX;
    }
    if (*result) myfree(*result);
    *result = mystrdup(line);
    if (! *result) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	return error_invalid;
    }
    unquote_string(*result);
    *err = 0;;
    return erm;
}

/* parse facility:level */

const char * config_getfacility(const char * token, int * fp) {
    int facility = 0;
    if (strncmp(token, "auth:", 5) == 0) {
	facility = LOG_AUTH;
	token += 5;
    } else if (strncmp(token, "authpriv:", 9) == 0) {
	facility = LOG_AUTHPRIV;
	token += 9;
    } else if (strncmp(token, "cron:", 5) == 0) {
	facility = LOG_CRON;
	token += 5;
    } else if (strncmp(token, "daemon:", 7) == 0) {
	facility = LOG_DAEMON;
	token += 7;
    } else if (strncmp(token, "ftp:", 4) == 0) {
	facility = LOG_FTP;
	token += 4;
    } else if (strncmp(token, "kern:", 5) == 0) {
	facility = LOG_KERN;
	token += 5;
    } else if (strncmp(token, "lpr:", 4) == 0) {
	facility = LOG_LPR;
	token += 4;
    } else if (strncmp(token, "mail:", 5) == 0) {
	facility = LOG_MAIL;
	token += 5;
    } else if (strncmp(token, "news:", 5) == 0) {
	facility = LOG_NEWS;
	token += 5;
    } else if (strncmp(token, "syslog:", 7) == 0) {
	facility = LOG_SYSLOG;
	token += 7;
    } else if (strncmp(token, "user:", 5) == 0) {
	facility = LOG_USER;
	token += 5;
    } else if (strncmp(token, "uucp:", 5) == 0) {
	facility = LOG_UUCP;
	token += 5;
    } else if (strncmp(token, "local0:", 7) == 0) {
	facility = LOG_LOCAL0;
	token += 7;
    } else if (strncmp(token, "local1:", 7) == 0) {
	facility = LOG_LOCAL1;
	token += 7;
    } else if (strncmp(token, "local2:", 7) == 0) {
	facility = LOG_LOCAL2;
	token += 7;
    } else if (strncmp(token, "local3:", 7) == 0) {
	facility = LOG_LOCAL3;
	token += 7;
    } else if (strncmp(token, "local4:", 7) == 0) {
	facility = LOG_LOCAL4;
	token += 7;
    } else if (strncmp(token, "local5:", 7) == 0) {
	facility = LOG_LOCAL5;
	token += 7;
    } else if (strncmp(token, "local6:", 7) == 0) {
	facility = LOG_LOCAL6;
	token += 7;
    } else if (strncmp(token, "local7:", 7) == 0) {
	facility = LOG_LOCAL7;
	token += 7;
    } else {
	snprintf(errbuff, LINE_SIZE, "Invalid syslog destination: %s", token);
	return errbuff;
    }
    if (strcmp(token, "emerg") == 0) {
	facility |= LOG_EMERG;
    } else if (strcmp(token, "alert") == 0) {
	facility |= LOG_ALERT;
    } else if (strcmp(token, "crit") == 0) {
	facility |= LOG_CRIT;
    } else if (strcmp(token, "err") == 0) {
	facility |= LOG_ERR;
    } else if (strcmp(token, "error") == 0) {
	facility |= LOG_ERR;
    } else if (strcmp(token, "warn") == 0) {
	facility |= LOG_WARNING;
    } else if (strcmp(token, "warning") == 0) {
	facility |= LOG_WARNING;
    } else if (strcmp(token, "notice") == 0) {
	facility |= LOG_NOTICE;
    } else if (strcmp(token, "info") == 0) {
	facility |= LOG_INFO;
    } else if (strcmp(token, "debug") == 0) {
	facility |= LOG_DEBUG;
    } else {
	snprintf(errbuff, LINE_SIZE, "Invalid syslog level: %s", token);
	return errbuff;
    }
    *fp = facility;
    return NULL;
}

static const char * add_match(int cn, int which, char * st,
			      int match, int how, const char * name)
{
    config_match_t * el;
    if (! configs[cn].dirs) {
	myfree(st);
	snprintf(errbuff, LINE_SIZE, "%s must follow a dir", name);
	return errbuff;
    }
    el = mymalloc(sizeof(config_match_t));
    if (! el) {
	int e = errno;
	myfree(st);
	return error_sys_errno_r(errbuff, LINE_SIZE, "config", "malloc", e);
    }
    if (which) {
	el->next = configs[cn].dirs->find;
	configs[cn].dirs->find = el;
    } else {
	el->next = configs[cn].dirs->exclude;
	configs[cn].dirs->exclude = el;
    }
    el->pattern = st;
    el->match = match;
    el->how = how;
    return NULL;
}

/* forward declaration */

static const char * includefile(const char *, include_t, locfl_t *);

/* make me a configuration file */

static char * convertname(const char * name, char * dst) {
    const char * ptr;
    char quote = 0;
    for (ptr = name; *ptr; ptr++) {
	if (isgraph((int)*ptr)) continue;
	quote = '\'';
	break;
    }
    if (quote) *dst++ = quote;
    for (ptr = name; *ptr; ptr++) {
	switch (*ptr) {
	    case '\n' :
		*dst++ = '\\';
		*dst++ = 'n';
		break;
	    case '\t' :
		*dst++ = '\\';
		*dst++ = 't';
		break;
	    case '\\' :
	    case '\''  :
		*dst++ = '\\';
		*dst++ = *ptr;
		break;
	    default   :
		if (isprint((int)*ptr)) {
		    *dst++ = *ptr;
		} else {
		    sprintf(dst, "\\%03o", (unsigned char)*ptr);
		    dst += strlen(dst);
		}
	}
    }
    if (quote) *dst++ = quote;
    *dst = 0;
    return dst;
}

static int printname(int (*p)(void *, const char *), void * arg,
		     const char * title, const char * name)
{
    int tlen = strlen(title);
    char buffer[4 * strlen(name) + 10 + tlen];
    strcpy(buffer, title);
    convertname(name, buffer + tlen);
    return p(arg, buffer);
}

static int printname2(int (*p)(void *, const char *), void * arg,
		      const char * title1, const char * name1,
		      const char * title2, const char * name2)
{
    int tlen1 = strlen(title1), tlen2 = strlen(title2);
    char buffer[4 * strlen(name1) + 4 * strlen(name2) + 10 + tlen1 + tlen2];
    char * dst;
    strcpy(buffer, title1);
    dst = convertname(name1, buffer + tlen1);
    strcpy(dst, title2);
    convertname(name2, dst + tlen2);
    return p(arg, buffer);
}

static int printname1(int (*p)(void *, const char *), void * arg,
		      const char * title1, const char * name1,
		      const char * title2)
{
    int tlen1 = strlen(title1), tlen2 = strlen(title2);
    char buffer[4 * strlen(name1) + 10 + tlen1 + tlen2];
    char * dst;
    strcpy(buffer, title1);
    dst = convertname(name1, buffer + tlen1);
    *dst++ = ' ';
    strcpy(dst, title2);
    return p(arg, buffer);
}

static int print_match(int (*p)(void *, const char *), void * arg,
		       const char * type, const config_match_t * m)
{
    int ok = 1;
    while (m) {
	const char * icase = "", * how = "", * what = "";
	char mbuffer[64];
	switch (m->match) {
	    case config_match_name : what = ""; break;
	    case config_match_path : what = "_path"; break;
	}
	switch (m->how) {
	    case config_match_exact : icase = "";  how = ""; break;
	    case config_match_icase : icase = "i"; how = ""; break;
	    case config_match_glob  : icase = "";  how = "_glob"; break;
	    case config_match_iglob : icase = "i"; how = "_glob"; break;
	}
	sprintf(mbuffer, "%s%s%s%s = ", icase, type, what, how);
	if (! printname(p, arg, mbuffer, m->pattern)) ok = 0;
	m = m->next;
    }
    return ok;
}

static int print_dirs(int (*p)(void *, const char *), void * arg,
		      const char * name, const config_dir_t * d)
{
    char nbuff[10 + strlen(name)];
    int ok = 1;
    strcpy(nbuff, name);
    strcat(nbuff, " = ");
    while (d) {
	printname(p, arg, nbuff, d->path);
	if (! p(arg, d->crossmount ? "#mount" : "mount")) ok = 0;
	print_match(p, arg, "exclude", d->exclude);
	print_match(p, arg, "find", d->find);
	if (! p(arg, "")) ok = 0;
	d = d->next;
    }
    return ok;
}

static const char * print_facility(int fac) {
    fac &= LOG_AUTH | LOG_AUTHPRIV | LOG_CRON | LOG_DAEMON | LOG_FTP |
	   LOG_KERN | LOG_LPR | LOG_MAIL | LOG_NEWS | LOG_SYSLOG |
	   LOG_USER | LOG_UUCP | LOG_LOCAL0 | LOG_LOCAL1 | LOG_LOCAL2 |
	   LOG_LOCAL3 | LOG_LOCAL4 | LOG_LOCAL5 | LOG_LOCAL6 | LOG_LOCAL7;
    if (fac == LOG_AUTHPRIV) return "authpriv";
    if (fac == LOG_AUTH) return "auth";
    if (fac == LOG_CRON) return "cron";
    if (fac == LOG_DAEMON) return "daemon";
    if (fac == LOG_FTP) return "ftp";
    if (fac == LOG_KERN) return "kern";
    if (fac == LOG_LPR) return "lpr";
    if (fac == LOG_MAIL) return "mail";
    if (fac == LOG_NEWS) return "news";
    if (fac == LOG_SYSLOG) return "syslog";
    if (fac == LOG_USER) return "user";
    if (fac == LOG_UUCP) return "uucp";
    if (fac == LOG_LOCAL0) return "local0";
    if (fac == LOG_LOCAL1) return "local1";
    if (fac == LOG_LOCAL2) return "local2";
    if (fac == LOG_LOCAL3) return "local3";
    if (fac == LOG_LOCAL4) return "local4";
    if (fac == LOG_LOCAL5) return "local5";
    if (fac == LOG_LOCAL6) return "local6";
    if (fac == LOG_LOCAL7) return "local7";
    return "local7";
}

static const char * print_priority(int fac) {
    fac &= LOG_EMERG | LOG_ALERT | LOG_CRIT | LOG_ERR | LOG_WARNING |
	   LOG_NOTICE | LOG_INFO | LOG_DEBUG;
    if (fac == LOG_EMERG) return "emerg";
    if (fac == LOG_ALERT) return "alert";
    if (fac == LOG_CRIT) return "crit";
    if (fac == LOG_ERR) return "error";
    if (fac == LOG_WARNING) return "warning";
    if (fac == LOG_NOTICE) return "notice";
    if (fac == LOG_INFO) return "info";
    if (fac == LOG_DEBUG) return "debug";
    return "error";
}

static int sendformat(int (*p)(void *, const char *), void * arg,
		      const char * fmt, ...)
{
    va_list ap;
    char buffer[4096];
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);
    return p(arg, buffer);
}

static int sendout(void * _p, const char * l) {
    FILE * P = _p;
    if (fprintf(P, "%s\n", l) < 0)
	return 0;
    return 1;
}

static inline void add_string(char * buffer, int * len, const char * s) {
    if (buffer) strcpy(buffer + *len, s);
    *len += strlen(s);
}

static inline void add_char(char * buffer, int * len, char c) {
    if (buffer) buffer[*len] = c;
    (*len)++;
}

static inline void add_bit(char * buffer, int * len, char * sep,
			   config_filter_t a, config_filter_t b,
			   const char * name, const char * extra)
{
    if (a & b) {
	add_char(buffer, len, *sep);
	*sep = ',';
	add_char(buffer, len, ' ');
	add_string(buffer, len, name);
	if (extra) {
	    add_char(buffer, len, ':');
	    add_string(buffer, len, extra);
	}
    }
}

static inline void add_bits(char * buffer, int * len, char * sep,
			    config_filter_t a, const char * extra)
{
    add_bit(buffer, len, sep, a, config_file_regular, "file", extra);
    add_bit(buffer, len, sep, a, config_file_dir, "dir", extra);
    add_bit(buffer, len, sep, a, config_file_char, "char", extra);
    add_bit(buffer, len, sep, a, config_file_block, "block", extra);
    add_bit(buffer, len, sep, a, config_file_fifo, "fifo", extra);
    add_bit(buffer, len, sep, a, config_file_symlink, "symlink", extra);
    add_bit(buffer, len, sep, a, config_file_socket, "socket", extra);
    add_bit(buffer, len, sep, a, config_file_unknown, "unknown", extra);
}

static inline void add_event(char * buffer, int * len, char * sep,
			     config_filter_t all, config_filter_t this,
			     const char * name)
{
    if (all == config_file_all) {
	add_char(buffer, len, *sep);
	*sep = ',';
	add_char(buffer, len, ' ');
	add_string(buffer, len, name);
    } else 
	add_bits(buffer, len, sep, this, name);
}

static int convert_filters(const char * title, char * buffer,
			   const config_filter_t orig[config_event_COUNT])
{
    int i, len = 0;
    char sep = '=';
    config_filter_t all = config_file_all, list[config_event_COUNT];
    add_string(buffer, &len, title);
    add_string(buffer, &len, " = ");
    /* if a bit is present in all, use that first */
    for (i = 0; i < config_event_COUNT; i++) {
	list[i] = orig[i];
	all &= list[i];
    }
    if (all == config_file_all) {
	add_string(buffer, &len, "all");
	return len;
    }
    add_bits(buffer, &len, &sep, all, NULL);
    for (i = 0; i < config_event_COUNT; i++)
	list[i] &= ~all;
    /* do remaining bits */
    add_event(buffer, &len, &sep, orig[config_event_meta],
	      list[config_event_meta], "meta");
    add_event(buffer, &len, &sep, orig[config_event_data],
	      list[config_event_data], "data");
    add_event(buffer, &len, &sep, orig[config_event_create],
	      list[config_event_create], "create");
    add_event(buffer, &len, &sep, orig[config_event_delete],
	      list[config_event_delete], "delete");
    add_event(buffer, &len, &sep, orig[config_event_rename],
	      list[config_event_rename], "rename");
    if (sep == '=')
	add_string(buffer, &len, "none");
    return len;
}

static int print_filters(int (*p)(void *, const char *), void * arg,
			 const char * title,
			 const config_filter_t list[config_event_COUNT])
{
    int len = convert_filters(title, NULL, list);
    char buffer[len + 1];
    convert_filters(title, buffer, list);
    return p(arg, buffer);
}

static int print_list(int (*p)(void *, const char *), void * arg,
		      const char * title, const char * (*name)(int),
		      int num, const int * list)
{
    int len = strlen(title) + 10, i;
    if (num < 1) return 1;
    for (i = 0; i < num; i++) {
	const char * s = name(list[i]);
	if (s) len += 2 + strlen(s);
    }
    char buffer[len], * bp = buffer;
    strcpy(bp, title);
    bp += strlen(title);
    *bp++ = ' ';
    for (i = 0; i < num; i++) {
	const char * s = name(list[i]);
	if (s) {
	    *bp++ = i ? ',' : '=';
	    *bp++ = ' ';
	    strcpy(bp, s);
	    bp += strlen(s);
	}
    }
    return p(arg, buffer);
}

static int print_all(int (*p)(void *, const char *), void * arg,
		     const char * title, const char * (*name)(int), int num)
{
    int list[num], i;
    for (i = 0; i < num; i++)
	list[i] = i;
    return print_list(p, arg, title, name, num, list);
}

static int print_timed(int (*p)(void *, const char *), void * arg,
		       const char * title, int num,
		       const config_dirsync_t * list)
{
    int len = strlen(title) + 10, i;
    if (num < 1 || ! list) return 1;
    for (i = 0; i < num; i++) {
	const char * dr = config_print_dayrange(list[i].daymask);
	len += 9 + strlen(dr);
    }
    char buffer[len], * bp = buffer;
    strcpy(bp, title);
    bp += strlen(title);
    *bp++ = ' ';
    for (i = 0; i < num; i++) {
	const char * dr = config_print_dayrange(list[i].daymask);
	*bp++ = i ? ';' : '=';
	*bp++ = ' ';
	strcpy(bp, dr);
	bp += strlen(dr);
	bp += sprintf(bp, " %02d:%02d",
		      (list[i].start_time / 3600) % 24,
		      (list[i].start_time / 60) % 60);
    }
    return p(arg, buffer);
}

static int print_command(int (*p)(void *, const char *), void * arg,
			 const char * title, char * const * data)
{
    int len = strlen(title) + 3, i;
    if (! data || ! data[0]) return 1;
    for (i = 0; data[i]; i++)
	len += 1 + strlen(data[i]);
    char buffer[len], * bp = buffer;
    strcpy(bp, title);
    bp += strlen(title);
    *bp++ = ' ';
    *bp++ = '=';
    for (i = 0; data[i]; i++) {
	*bp++ = ' ';
	strcpy(bp, data[i]);
	bp += strlen(data[i]);
    }
    return p(arg, buffer);
}

/* stores copy data to a small configuration file, suitable for loading
 * by the copy thread */

int config_store_copy(int fnum, int fpos, const char * user, const char * pass)
{
    config_user_t * U;
    config_listen_t * l;
    FILE * S = NULL;
    int fd = open(configs[currnum].strval[cfg_copy_state],
		  O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0)
	goto problem;
    if (lseek(fd, (off_t)0, SEEK_SET) < 0)
	goto problem;
    if (lockf(fd, F_LOCK, (off_t)0) < 0)
	goto problem;
    S = fdopen(fd, "w");
    if (! S)
	goto problem;
    if (fprintf(S, IDENTIFY_COPY "\n", IDENTIFY_VERSION) < 0)
	goto problem;
    if (! printname(sendout, S, "from = ",
		    configs[currnum].strval[cfg_from_prefix]))
	goto problem;
    if (! printname(sendout, S, "to = ",
		    configs[currnum].strval[cfg_to_prefix]))
	goto problem;
    l = configs[currnum].listen;
    while (l) {
	if (l->port) {
	    char lhost[32 + strlen(l->host) + strlen(l->port)];
	    int c = strchr(l->host, ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", l->host,
		    c ? "]" : "", l->port);
	    if (! printname(sendout, S, "listen = ", lhost))
		goto problem;
	} else {
	    if (! printname(sendout, S, "listen = ", l->host))
		goto problem;
	}
	l = l->next;
    }
    U = configs[currnum].users;
    while (U) {
	if (U->pass) {
	    char up[strlen(U->user) + strlen(U->pass) + 2];
	    sprintf(up, "%s:%s", U->user, U->pass);
	    if (! printname(sendout, S, "allow_tcp = ", up))
		goto problem;
	} else {
	    if (! printname(sendout, S, "allow_unix = ", U->user))
		goto problem;
	}
	U = U->next;
    }
    if (configs[currnum].server.host) {
	if (configs[currnum].server.port) {
	    char server[2 + strlen(configs[currnum].server.host)
			  + strlen(configs[currnum].server.port)];
	    sprintf(server, "%s:%s",
		    configs[currnum].server.host, configs[currnum].server.port);
	    if (! printname(sendout, S, "server = ", server))
		goto problem;
	} else {
	    if (! printname(sendout, S, "server = ",
			    configs[currnum].server.host))
		goto problem;
	}
    }
    if (configs[currnum].tunnel &&
	! print_command(sendout, S, "tunnel", configs[currnum].tunnel))
	    goto problem;
    if (configs[currnum].remote_should &&
	! print_command(sendout, S, "remote_should",
			configs[currnum].remote_should))
	    goto problem;
    if (user && ! printname(sendout, S, "user = ", user))
	goto problem;
    if (pass && ! printname(sendout, S, "password = ", pass))
	goto problem;
    if (fprintf(S,
		(configs[currnum].intval[cfg_flags] & config_flag_translate_ids)
		    ? "translate_ids\n" : "keep_ids\n") < 0)
	goto problem;
    if (fprintf(S,
		(configs[currnum].intval[cfg_flags] & config_flag_skip_matching)
		    ? "skip_matching\n" : "copy_matching\n") < 0)
	goto problem;
    if (fprintf(S,
		(configs[currnum].intval[cfg_flags] &
			config_flag_initial_dirsync)
		    ? "do_initial_dirsync\n" : "skip_initial_dirsync\n") < 0)
	goto problem;
    if (fprintf(S,
		(configs[currnum].intval[cfg_flags] &
			config_flag_overflow_dirsync)
		    ? "do_overflow_dirsync\n" : "skip_overflow_dirsync\n") < 0)
	goto problem;
    if (fprintf(S,
		(configs[currnum].intval[cfg_flags] &
			config_flag_dirsync_delete)
		    ? "dirsync_delete\n" : "no_dirsync_delete\n") < 0)
	goto problem;
    if (configs[currnum]. intval[cfg_dirsync_interval] > 0 &&
	! sendformat(sendout, S, "dirsync_interval = %s",
		     config_print_interval(configs[currnum].
					   intval[cfg_dirsync_interval])))
	goto problem;
    if (! sendformat(sendout, S, "bwlimit = %d",
		     configs[currnum].intval[cfg_bwlimit]))
	goto problem;
    if (! sendformat(sendout, S, "optimise_client = %d",
		     configs[currnum].intval[cfg_optimise_client]))
	goto problem;
    if (! sendformat(sendout, S, "optimise_buffer = %s",
		     config_print_size(configs[currnum].
				       intval[cfg_optimise_buffer])))
	goto problem;
    print_list(sendout, S, "compression", compress_name,
	       configs[currnum].intval[cfg_ncompressions],
	       configs[currnum].compressions);
    print_list(sendout, S, "checksum", checksum_name,
	       configs[currnum].intval[cfg_nchecksums],
	       configs[currnum].checksums);
    if (! print_timed(sendout, S, "dirsync_timed",
		      configs[currnum].intval[cfg_dirsync_count],
		      configs[currnum].dirsync_timed))
	goto problem;
    if (! print_filters(sendout, S, "filter",
			configs[currnum].filter))
	goto problem;
    if (fprintf(S, "end_state\n") < 0)
	goto problem;
    if (fprintf(S, "%d %d\n", fnum, fpos) < 0)
	goto problem;
    if (fflush(S) < 0)
	goto problem;
    if (lseek(fd, (off_t)0, SEEK_SET) < 0)
	goto problem;
    if (lockf(fd, F_ULOCK, (off_t)0) < 0)
	goto problem;
    if (fclose(S) < 0) {
	S = NULL;
	goto problem;
    }
    return 1;
problem:
    error_report(error_setup, configs[currnum].strval[cfg_copy_state], errno);
    if (S)
	fclose(S);
    else if (fd >= 0)
	close(fd);
    return 0;
}

#define HASH \
    "######################################################################"

void print_one(int (*p)(void *, const char *), void * arg, int cn) {
    int seen_unix, seen_tcp;
    config_user_t * U;
    error_message_t E;
    p(arg, "# Configuration file for \"should\"");
    p(arg, "# Automatically generated from current options");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Notify thread");
    p(arg, "");
    p(arg, "# Size of the notify queue allocation block");
    sendformat(p, arg, "queue_block = %s",
	       config_print_size(configs[cn].intval[cfg_notify_queue_block]));
    p(arg, "");
    p(arg, "# Number of blocks allocated when the notify thread initialises");
    sendformat(p, arg, "initial_blocks = %d",
	       configs[cn].intval[cfg_notify_initial]);
    p(arg, "");
    p(arg, "# Maximum number of queue blocks the thread will allocate");
    sendformat(p, arg, "max_blocks = %d",
	       configs[cn].intval[cfg_notify_max]);
    p(arg, "");
    p(arg, "# Number of watches stored in one watch allocation block");
    sendformat(p, arg, "watch_block = %d",
	       configs[cn].intval[cfg_notify_watch_block]);
    p(arg, "");
    p(arg, "# Size of a watch name block");
    sendformat(p, arg, "watch_name_block = %s",
	       config_print_size(configs[cn].intval[cfg_notify_name_block]));
    p(arg, "");
    p(arg, "# Size of the buffer used to receive data from the kernel");
    sendformat(p, arg, "buffer = %s",
	       config_print_size(configs[cn].intval[cfg_notify_buffer]));
    p(arg, "");
    p(arg, "# Do we consider should's temporary files?");
    if (configs[cn].intval[cfg_flags] & config_flag_skip_should) {
	p(arg, "skip_should_temporary");
	p(arg, "#copy_should_temporary");
    } else {
	p(arg, "#skip_should_temporary");
	p(arg, "copy_should_temporary");
    }
    p(arg, "");
    p(arg, "# Filter events based on type");
    print_filters(p, arg, "filter", configs[cn].filter);
    p(arg, "#filter = all");
    p(arg, "#filter = all, !all:meta");
    p(arg, "#filter = all:data");
    p(arg, "#filter = all:create, all:delete, all:rename, ! symlink:rename");
    p(arg, "#filter = file:all, symlink:all");
    p(arg, "#filter = dir:all");
    p(arg, "#filter = char:all, block:all");
    p(arg, "#filter = fifo:all, socket:all, unknown:all");
    p(arg, "#filter = file:rename, dir:rename");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Control thread and communication with a running server");
    p(arg, "");
    p(arg, "# Debug communication protocol?");
    p(arg, configs[cn].intval[cfg_flags] & config_flag_debug_server
	    ? "debug_server"
	    : "no_debug_server");
    p(arg, configs[cn].intval[cfg_flags] & config_flag_debug_server
	    ? "#no_debug_server"
	    : "#debug_server");
    p(arg, "");
    p(arg, "# Interfaces and sockets to listen on");
    if (configs[cn].listen) {
	config_listen_t * l = configs[cn].listen;
	while (l) {
	    if (l->port) {
		char lhost[32 + strlen(l->host) + strlen(l->port)];
		int c = strchr(l->host, ':') != NULL;
		sprintf(lhost, "%s%s%s:%s",
			c ? "[" : "", l->host,
			c ? "]" : "", l->port);
		printname(p, arg, "listen = ", lhost);
	    } else {
		printname(p, arg, "listen = ", l->host);
	    }
	    l = l->next;
	}
    } else {
	p(arg, "#listen = 0.0.0.0:4567");
	p(arg, "#listen = [::0]:1234");
	p(arg, "#listen = ONE_OF_MY_IP_ADDRESSES:SOME_PORT_NUMBER");
	p(arg, "#listen = /var/run/socket-name");
    }
    p(arg, "");
    p(arg, "# Use connection to this server");
    if (configs[cn].server.host) {
	if (configs[cn].server.port) {
	    char lhost[32 + strlen(configs[cn].server.host)
			  + strlen(configs[cn].server.port)];
	    int c = strchr(configs[cn].server.host, ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", configs[cn].server.host,
		    c ? "]" : "", configs[cn].server.port);
	    printname(p, arg, "server = ", lhost);
	    p(arg, "#server = /PATH/TO/SOCKET");
	} else {
	    printname(p, arg, "server = ", configs[cn].server.host);
	    p(arg, "#server = HOSTNAME:PORT");
	}
    } else {
	p(arg, "#server = HOSTNAME:PORT");
	p(arg, "#server = /PATH/TO/SOCKET");
    }
    p(arg, "");
    p(arg, "# Use this program to set up a tunnel to connect to server");
    if (configs[cn].tunnel)
	print_command(p, arg, "tunnel", configs[cn].tunnel);
    else
	p(arg, "#tunnel = ssh user@host");
    p(arg, "");
    p(arg, "# Path (and extra args) to \"should\" at the other end of the tunnel");
    if (configs[cn].remote_should)
	print_command(p, arg, "remote_should", configs[cn].remote_should);
    else
	p(arg, "#remote_should = should");
    p(arg, "");
    p(arg, "# User name used to connect");
    if (configs[cn].strval[cfg_user])
	printname(p, arg, "user = ", configs[cn].strval[cfg_user]);
    else
	p(arg, "#user = yourname");
    p(arg, "");
    p(arg, "# Password name used to connect");
    if (configs[cn].strval[cfg_password])
	printname(p, arg, "password = ", configs[cn].strval[cfg_password]);
    else
	p(arg, "#password = 'your secrets'");
    p(arg, "");
    p(arg, "# Users accepted by the server");
    seen_unix = seen_tcp = 0;
    U = configs[cn].users;
    while (U) {
	if (U->pass) {
	    char up[strlen(U->user) + strlen(U->pass) + 2];
	    sprintf(up, "%s:%s", U->user, U->pass);
	    printname(p, arg, "allow_tcp = ", up);
	    seen_tcp = 1;
	} else {
	    printname(p, arg, "allow_unix = ", U->user);
	    seen_unix = 1;
	}
	U = U->next;
    }
    if (! seen_unix)
	p(arg, "#allow_unix = root");
    if (! seen_tcp)
	p(arg, "#allow_tcp = 'yourname:your secrets'");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Server: initial watches and operation mode");
    p(arg, "");
    if (! (configs[cn].intval[cfg_client_mode] & config_client_add) &&
	   configs[cn].dirs)
    {
	print_dirs(p, arg, "dir", configs[cn].dirs);
    } else {
	p(arg, "#dir = /some/path");
	p(arg, "#dir = /some/other/path");
	p(arg, "");
    }
    p(arg, "# Operation mode: detached or not detached?");
    if (configs[cn].intval[cfg_server_mode] & config_server_detach) {
	p(arg, "detach");
	p(arg, "#nodetach");
    } else {
	p(arg, "#detach");
	p(arg, "nodetach");
    }
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Store thread");
    p(arg, "");
    p(arg, "# Event directory");
    printname(p, arg, "eventdir = ", configs[cn].strval[cfg_eventdir]);
    p(arg, "");
    p(arg, "# Size of event file before it gets rotated");
    sendformat(p, arg, "eventfilesize = %s",
	       config_print_size(configs[cn].intval[cfg_eventsize]));
    p(arg, "");
    p(arg, "# If nonzero, automatically purge log files older than that number of days");
    sendformat(p, arg, "autopurge = %d",
	       configs[cn].intval[cfg_autopurge_days]);
    p(arg, "");
    p(arg, "# Store method");
    printname(p, arg, "store = ", configs[cn].strval[cfg_store]);
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Client mode: operations requested on server");
    p(arg, "");
    p(arg, "# add directories to watch");
    if ((configs[cn].intval[cfg_client_mode] & config_client_add) &&
	configs[cn].dirs)
    {
	print_dirs(p, arg, "add", configs[cn].dirs);
    } else {
	p(arg, "#add = /some/path");
	p(arg, "#add = /some/other/path");
	p(arg, "");
    }
    p(arg, "# remove directories from server's watch list");
    if ((configs[cn].intval[cfg_client_mode] & config_client_remove) &&
	configs[cn].remove)
    {
	print_dirs(p, arg, "remove", configs[cn].remove);
    } else {
	p(arg, "#remove = /some/path");
	p(arg, "#remove = /some/other/path");
	p(arg, "");
    }
    p(arg, "# Ask the server to purge event files older than the specified number of days");
    if (configs[cn].intval[cfg_client_mode] & config_client_purge)
	p(arg, "#purge = 2");
    else
	sendformat(p, arg, "purge = %d", configs[cn].intval[cfg_purge_days]);
    p(arg, "");
    p(arg, "# Get server's status");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_status
	    ? "status" : "#status");
    p(arg, "");
#if USE_SHOULDBOX
    p(arg, "# Get server's shouldbox");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_box
	    ? "box" : "#box");
    p(arg, "");
#endif
    p(arg, "# Get server's proces ID");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_getpid
	    ? "getpid" : "#getpid");
    p(arg, "");
    p(arg, "# Get list of watched directories and report to standard output");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_watches
	    ? "watches" : "#watches");
    p(arg, "");
    p(arg, "# Asks the server what compression methods it supports");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_listcompress
	    ? "servercompress" : "#servercompress");
    p(arg, "");
    p(arg, "# Asks the server what checksum methods it supports");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_listchecksum
	    ? "serverchecksum" : "#serverchecksum");
    p(arg, "");
    p(arg, "# Get server's configuration");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_config
	    ? "serverconfig" : "#serverconfig");
    p(arg, "");
    p(arg, "# Close logfiles (they will be reopened before next message)");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_closelog
	    ? "closelog" : "#closelog");
    p(arg, "");
    p(arg, "# Disable server's debugging mode for this connection");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_cleardebug
	    ? "cleardebug" : "#cleardebug");
    p(arg, "");
    p(arg, "# Enable server's debugging mode for this connection");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_setdebug
	    ? "setdebug" : "#setdebug");
    p(arg, "");
    p(arg, "# Stop running server");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_stop
	    ? "stop" : "#stop");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Copy setup mode");
    p(arg, "");
    p(arg, "# State file, containing copy information and checkpoints");
    if (configs[cn].intval[cfg_client_mode] & config_client_setup)
	printname(p, arg, "setup = ", configs[cn].strval[cfg_copy_state]);
    else
	p(arg, "#setup = /some/path");
    p(arg, "");
    p(arg, "# Translate user/group IDs during copy, or keep the numbers?");
    if (configs[cn].intval[cfg_flags] & config_flag_translate_ids) {
	p(arg, "translate_ids");
	p(arg, "#keep_ids");
    } else {
	p(arg, "#translate_ids");
	p(arg, "keep_ids");
    }
    p(arg, "");
    p(arg, "# Do we copy a file when mtime and size match?");
    if (configs[cn].intval[cfg_flags] & config_flag_skip_matching) {
	p(arg, "skip_matching");
	p(arg, "#copy_matching");
    } else {
	p(arg, "#skip_matching");
	p(arg, "copy_matching");
    }
    p(arg, "");
    p(arg, "# Number of events to read ahead by the client");
    sendformat(p, arg, "optimise_client = %d",
	       configs[cn].intval[cfg_optimise_client]);
    p(arg, "");
    p(arg, "# Buffer used by the client to optimise events");
    sendformat(p, arg, "optimise_buffer = %s",
	       config_print_size(configs[cn].intval[cfg_optimise_buffer]));
    p(arg, "");
    p(arg, "# Bandwidth limit (KB/s) for copy mode, 0 == no limits imposed");
    sendformat(p, arg, "bwlimit = %d", configs[cn].intval[cfg_bwlimit]);
    p(arg, "");
    p(arg, "# Preferred compression methods");
    print_list(p, arg, "compression", compress_name,
	       configs[cn].intval[cfg_ncompressions],
	       configs[cn].compressions);
    print_all(p, arg, "#compression", compress_name, compress_count());
    p(arg, "");
    p(arg, "# Preferred checksum methods");
    print_list(p, arg, "checksum", checksum_name,
	       configs[cn].intval[cfg_nchecksums],
	       configs[cn].checksums);
    print_all(p, arg, "#checksum", checksum_name, checksum_count());
    p(arg, "");
    p(arg, "# Select a subtree of files on the server");
    if (configs[cn].strval[cfg_from_prefix])
	printname(p, arg, "from = ", configs[cn].strval[cfg_from_prefix]);
    else
	p(arg, "#from = /some/path");
    p(arg, "");
    p(arg, "# Select the destination for the copy");
    if (configs[cn].strval[cfg_to_prefix])
	printname(p, arg, "to = ", configs[cn].strval[cfg_to_prefix]);
    else
	p(arg, "#to = /some/path");
    p(arg, "");
    p(arg, "# Do we start a dirsync initially?");
    if (configs[cn].intval[cfg_flags] & config_flag_initial_dirsync) {
	p(arg, "do_initial_dirsync");
	p(arg, "#skip_initial_dirsync");
    } else {
	p(arg, "#do_initial_dirsync");
	p(arg, "skip_initial_dirsync");
    }
    p(arg, "");
    p(arg, "# Do we start a dirsync if we notice an event queue overflow?");
    if (configs[cn].intval[cfg_flags] & config_flag_overflow_dirsync) {
	p(arg, "do_overflow_dirsync");
	p(arg, "#skip_overflow_dirsync");
    } else {
	p(arg, "#do_overflow_dirsync");
	p(arg, "skip_overflow_dirsync");
    }
    p(arg, "");
    p(arg, "# Do we do a periodic dirsync?");
    if (configs[cn].intval[cfg_dirsync_interval] > 0) {
	sendformat(p, arg, "dirsync_interval = %s",
		   config_print_interval(configs[cn].
					 intval[cfg_dirsync_interval]));
    } else {
	p(arg, "#dirsync_interval = 2 hours");
    }
    p(arg, "");
    p(arg, "# Do we do a timed dirsync?");
    if (configs[cn].dirsync_timed) {
	print_timed(p, arg, "dirsync_timed",
		    configs[cn].intval[cfg_dirsync_count],
		    configs[cn].dirsync_timed);
    } else {
	p(arg, "#dirsync_timed = tue-sat 03:00, sun,mon 05:00");
    }
    p(arg, "");
    p(arg, "# Do we let dirsync delete local files if the server does not have them?");
    if (configs[cn].intval[cfg_flags] & config_flag_dirsync_delete) {
	p(arg, "#dirsync_delete");
	p(arg, "no_dirsync_delete");
    } else {
	p(arg, "no_dirsync_delete");
	p(arg, "#dirsync_delete");
    }
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Copy mode");
    p(arg, "");
    p(arg, "# State file, containing copy information and checkpoints");
    if (configs[cn].intval[cfg_client_mode] & config_client_copy)
	printname(p, arg, "copy = ", configs[cn].strval[cfg_copy_state]);
    else
	p(arg, "#copy = /some/path");
    p(arg, "");
    p(arg, "# Maximum number of events to process before checkpointing to file");
    sendformat(p, arg, "checkpoint_events = %d",
	       configs[cn].intval[cfg_checkpoint_events]);
    p(arg, "");
    p(arg, "# Maximum time between checkpoints");
    sendformat(p, arg, "checkpoint_time = %s",
	       config_print_interval(configs[cn].intval[cfg_checkpoint_time]));
    p(arg, "");
    p(arg, "# One-shot mode: catch up with server and exit");
    p(arg, configs[cn].intval[cfg_flags] & config_flag_copy_oneshot
	    ? "oneshot" : "#oneshot");
    p(arg, "");
    p(arg, "# \"Peek\" mode, printing events to standard output");
    p(arg, configs[cn].intval[cfg_client_mode] & config_client_peek
	    ? "peek" : "#peek");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Error reporting");
    p(arg, "");
    p(arg, "# Program identity, used in syslog and log files");
    printname(p, arg, "ident = ", configs[cn].strval[cfg_error_ident]);
    p(arg, "");
    p(arg, "# Log file, for errors which are reported to file");
    printname(p, arg, "logfile = ", configs[cn].strval[cfg_error_logfile]);
    p(arg, "");
    p(arg, "# Email address and submit program, for errors which are emailed");
    if (configs[cn].strval[cfg_error_email])
	printname(p, arg, "email = ", configs[cn].strval[cfg_error_email]);
    else
	p(arg, "#email someuser@some.place.com");
    printname(p, arg, "email_submit = ", configs[cn].strval[cfg_error_submit]);
    p(arg, "");
    p(arg, "# Error messages and their reporting methods");
    p(arg, "");
    for (E = 0; E < error_MAX; E++) {
	const char * msg = error_get_message(E);
	const char * name = error_name(E);
	error_dest_t dest = error_get_dest(E);
	char comma = '=', buffer[128], * bptr = buffer;
	if (dest & error_dest_stderr) {
	    *bptr++ = comma;
	    strcpy(bptr, " stderr");
	    bptr += strlen(bptr);
	    comma = ',';
	}
	if (dest & error_dest_file) {
	    *bptr++ = comma;
	    strcpy(bptr, " file");
	    bptr += strlen(bptr);
	    comma = ',';
	}
	if (dest & error_dest_email) {
	    *bptr++ = comma;
	    strcpy(bptr, " email");
	    bptr += strlen(bptr);
	    comma = ',';
	}
	if (dest & error_dest_syslog) {
	    int facility = error_get_facility(E);
	    sprintf(bptr,
		    "%c %s:%s",
		    comma,
		    print_facility(facility),
		    print_priority(facility));
	    bptr += strlen(bptr);
	    comma = ',';
	}
	printname2(p, arg, "message : ", name, " = ", msg);
	printname1(p, arg, "report  : ", name, buffer);
	p(arg, "");
    }
}

void config_print(int (*p)(void *, const char *), void * arg) {
    print_one(p, arg, currnum);
}

/* people ask questions */

static void print_help(const char * bname) {
    printf(
	"Server mode usage:\n"
	"    should [config=FILE] [SERVER_OPTIONS] [/PATH]...\n"
	"\n"
	"Server control mode usage:\n"
	"    should [config=FILE] [CLIENT_OPTIONS] COMMAND...\n"
	"\n"
	"Client setup mode usage:\n"
	"    should [config=FILE] [CLIENT_OPTIONS] setup=STATE_FILE from=/PATH to=/PATH\n"
	"\n"
	"Client mode usage:\n"
	"    should [config=FILE] [CLIENT_OPTIONS] copy=STATE_FILE\n"
	"\n"
	"The \"config=FILE\" option(s) can load a configuration file to set defaults for\n"
	"items which should not be on a command line, such as passwords; additionally,\n"
	"a system and a user configuration will be read if found before processing any\n"
	"command-line arguments:\n"
	"system configuration file: %s\n"
	"user's configuration file: ~/%s\n"
	"\n"
	"The current client's configuration can be seen with:\n"
	"    should printconfig\n"
	"\n"
	"The current server's configuration can be seen with:\n"
	"    should serverconfig\n"
	"\n"
	"Commonly used Server options:\n"
	"    listen=HOST:PORT     listen (TCP) on interface corresponding to HOST:\n"
	"                         default is to accept Unix domain connections only;\n"
	"                         use \"listen=0.0.0.0:PORT\" or \"listen=[::0]:PORT\"\n"
	"                         to listen on all IPv4 or IPv6 interfaces respectively;\n"
	"                         this option can be repeated to listen on more than one\n"
	"                         port and/or more than one local interface\n"
	"    listen=/PATH         use a non-default Unix domain socket (default: below)\n"
	"    logfile=/PATH        use a non-default logfile (default: below)\n"
	"    eventdir=/PATH       use a non-default event directory (default: below)\n"
	"    allow_unix=NAME      allow Unix user NAME to connect\n"
	"    allow_tcp=NAME:PASS  allow TCP connections authenticated with NAME and PASS\n"
	"    detach               detach from the terminal"
#if ! USE_SHOULDBOX
	" (default)"
#endif
	"\n"
	"    nodetach             don't detach from the terminal"
#if USE_SHOULDBOX
	" (default)"
#endif
	"\n"
	"    start                start server: this is the default if no client commands\n"
	"                         or server control commands are provided\n"
	"allow_unix and allow_tcp can be repeated as required\n"
	"default socket for root user:          %s/should-%s.socket\n"
	"default socket for non-root:           ~/.should-%s.socket\n"
	"default logfile for root user:         %s/should-%s.log\n"
	"default logfile for non-root:          ~/.should-%s.log\n"
	"default event directory for root user: %s/should-%s.events\n"
	"default event directory for non-root:  ~/.should-%s.events\n"
	"\n"
	"Commonly used Client (including Server control mode and Client Setup) options:\n"
	"    server=HOST:PORT     connect via TCP to HOST, port PORT: default is to use\n"
	"                         Unix domain sockets\n"
	"    server=/PATH         use a non-default Unix domain socket (default: see\n"
	"                         server options above)\n"
	"    user=NAME            use specified username to authenticate TCP connections\n"
	"    password=WORD        use specified password to authenticate TCP connections\n"
	"\n"
	"Commonly used server control commands:\n"
	"    add=/PATH            add path to the list of watched directory trees\n"
	"    remove=/PATH         remove watch /PATH and all its subdirectories\n"
	"    watches              lists all current watches (may give a lot of output)\n"
	"    status               show server status\n"
	"    closelog             close/reopen logfile: use this after rotating logfiles\n"
	"    stop, kill           stop running server\n"
	"\n"
	"Add options, can be specified after a /PATH (server) or add=/PATH (server\n"
	"control) to further specify what directories to add:\n"
	"    exclude=NAME         exclude subdirectory /PATH/somewhere/NAME\n"
	"    exclude_glob=PATTERN ditto, but matches directory name by shell pattern\n"
	"    exclude_path=/SUBDIR exclude subdirectory /SUBDIR\n"
	"    exclude_path_glob=P  ditto, but matches full path by shell pattern\n"
	"    iexclude...          like exclude..., but ignores case\n"
	"    find=NAME            looks for /PATH/somewhere/NAME and adds these as\n"
	"                         separate directory trees, instead of adding /PATH\n"
	"    find_glob=PATTERN    ditto, but matches directory name by shell pattern\n"
	"    find_path_glob=PAT   ditto, but matches full path by shell pattern\n"
	"    ifind...             like find..., but ignores case\n"
	"    mount                prevent crossing mount points when recursing\n"
	,
	SYSTEM_CONFIG, USER_CONFIG,
	ROOT_SOCKET_DIR, bname, bname,
	ROOT_LOGFILE_DIR, bname, bname,
	ROOT_EVENTDIR_DIR, bname, bname);
}

static void print_compress(void) {
    int cnum, cmax = compress_count();
    printf("Compression methods supported by this client:\n");
    for (cnum = 0; cnum < cmax; cnum++)
	printf("%s\n", compress_name(cnum));
}

static void print_checksum(void) {
    int cnum, cmax = checksum_count();
    printf("Checksum methods supported by this client:\n");
    for (cnum = 0; cnum < cmax; cnum++)
	printf("%s\n", checksum_name(cnum));
}

static int get_event_filter(const char * token, int * eventmap) {
    while (*token && isspace((int)*token)) token++;
    if (! *token || strcmp(token, "all") == 0)
	*eventmap = config_event_all;
    else if (strcmp(token, "meta") == 0)
	*eventmap = 1 << config_event_meta;
    else if (strcmp(token, "change_data") == 0)
	*eventmap = 1 << config_event_data;
    else if (strcmp(token, "create") == 0)
	*eventmap = 1 << config_event_create;
    else if (strcmp(token, "delete") == 0)
	*eventmap = 1 << config_event_delete;
    else if (strcmp(token, "rename") == 0)
	*eventmap = 1 << config_event_rename;
    else
	return 0;
    return 1;
}

static int get_file_filter(const char * token, int * filemap) {
    while (*token && isspace((int)*token)) token++;
    if (! *token || strcmp(token, "all") == 0)
	*filemap = config_file_all;
    else if (strcmp(token, "file") == 0)
	*filemap = config_file_regular;
    else if (strcmp(token, "dir") == 0)
	*filemap = config_file_dir;
    else if (strcmp(token, "char") == 0)
	*filemap = config_file_char;
    else if (strcmp(token, "block") == 0)
	*filemap = config_file_block;
    else if (strcmp(token, "fifo") == 0)
	*filemap = config_file_fifo;
    else if (strcmp(token, "symlink") == 0)
	*filemap = config_file_symlink;
    else if (strcmp(token, "socket") == 0)
	*filemap = config_file_socket;
    else if (strcmp(token, "unknown") == 0)
	*filemap = config_file_unknown;
    else
	return 0;
    return 1;
}

static int get_filter(char * token, int * eventmap, int * filemap) {
    char * colon = strchr(token, ':');
    if (colon) {
	*colon++ = 0;
	if (! get_file_filter(token, filemap))
	    return 0;
	if (! get_event_filter(colon, eventmap))
	    return 0;
	return 1;
    }
    if (get_event_filter(token, eventmap)) {
	*filemap = config_file_all;
	return 1;
    }
    if (get_file_filter(token, filemap)) {
	*eventmap = config_event_all;
	return 1;
    }
    return 0;
}

static int assign_command(const char * line, const char * kw,
			  char *** result, const char ** err)
{
    char * st = NULL, * stp;
    int ncom = 1, ptr;
    if (! assign_string(line, kw, 0, &st, err)) return 0;
    if (*err) return 1;
    stp = st;
    while (*stp && ! isspace((int)*stp)) stp++;
    while (*stp) {
	while (*stp && isspace((int)*stp)) stp++;
	if (! *stp) break;
	ncom++;
	while (*stp && ! isspace((int)*stp)) stp++;
    }
    if (*result) {
	myfree((*result)[0]);
	myfree(*result);
    }
    *result = mymalloc((1 + ncom) * sizeof(char *));
    if (! *result) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	myfree(st);
	return 1;
    }
    stp = st;
    (*result)[0] = st;
    ptr = 1;
    while (*stp && ! isspace((int)*stp)) stp++;
    while (*stp) {
	*stp++ = 0;
	while (*stp && isspace((int)*stp)) stp++;
	if (! *stp) break;
	(*result)[ptr] = stp;
	ptr++;
	while (*stp && ! isspace((int)*stp)) stp++;
    }
    (*result)[ncom] = 0;
    *err = NULL;
    return 1;
}

/* parse single argument - things which make sense only during initial
 * configuration */

static const char * parsearg_initial(const char * line, locfl_t * locfl) {
    const char * err;
    char * st;
    int cn = currnum, iv;
    switch (line[0]) {
	case '/' : {
	    config_dir_t * dl;
	    st = mystrdup(line);
	    if (! st)
		return error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	add_watch :
	    dl = mymalloc(sizeof(config_dir_t));
	    if (! dl) {
		int e = errno;
		myfree(st);
		return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					 "malloc", e);
	    }
	    dl->crossmount = 1;
	    dl->next = configs[cn].dirs;
	    dl->find = NULL;
	    dl->exclude = NULL;
	    dl->path = st;
	    configs[cn].dirs = dl;
	    return NULL;
	}
	break;
	case 'a' :
	    st = NULL;
	    if (assign_string(line, "add_watch", 1, &st, &err)) {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_add;
		goto add_watch;
	    }
	    st = NULL;
	    if (assign_string(line, "add", 1, &st, &err)) {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_add;
		goto add_watch;
	    }
	    break;
	case 'b' :
	    if (assign_unit(line, "buffer", sizes, &configs[cn].
			    intval[cfg_notify_buffer], &err))
		return err;
	    if (assign_int(line, "bwlimit",
			   &configs[cn].intval[cfg_bwlimit], &err))
		return err;
	    if (strcmp(line, "box") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_box;
		return NULL;
	    }
	    break;
	case 'c' :
	    if (strcmp(line, "closelog") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_closelog;
		return NULL;
	    }
	    if (strcmp(line, "cleardebug") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_cleardebug;
		return NULL;
	    }
	    if (strcmp(line, "copyright") == 0) {
		*locfl |= locfl_copyright;
		return NULL;
	    }
	    if (strcmp(line, "clientcompress") == 0) {
		*locfl |= locfl_compress;
		return NULL;
	    }
	    if (strcmp(line, "client_compress") == 0) {
		*locfl |= locfl_compress;
		return NULL;
	    }
	    if (strcmp(line, "clientchecksum") == 0) {
		*locfl |= locfl_checksum;
		return NULL;
	    }
	    if (strcmp(line, "client_checksum") == 0) {
		*locfl |= locfl_checksum;
		return NULL;
	    }
	    st = NULL;
	    if (assign_string(line, "config", 0, &st, &err)) {
		if (err) return err;
		err = includefile(st, include_none, locfl);
		myfree(st);
		return err;
	    }
	    if (assign_string(line, "copy", 0,
			      &configs[cn].strval[cfg_copy_state], &err))
	    {
		if (err) return err;
		if (config_copy_file) {
		    int rv;
		    fseek(config_copy_file, 0L, SEEK_SET);
		    rv = lockf(fileno(config_copy_file), F_ULOCK, (off_t)0);
		    fclose(config_copy_file);
		    config_copy_file = NULL;
		}
		err = includefile(configs[cn].strval[cfg_copy_state],
				  include_state, locfl);
		if (err)
		    return err;
		configs[cn].intval[cfg_client_mode] |= config_client_copy;
		return NULL;
	    }
	    st = NULL;
	    if (assign_string(line, "compression", 0, &st, &err)) {
		char * saveptr = NULL, * token, * parse = st;
		if (err) return err;
		configs[cn].intval[cfg_ncompressions] = 0;
		while (! err &&
		       (token = strtok_r(parse, ",", &saveptr)) != NULL)
		{
		    int nc;
		    parse = NULL;
		    while (*token && isspace((int)*token)) token++;
		    nc = compress_byname(token);
		    if (nc < 0) {
			err = errbuff;
			snprintf(errbuff, LINE_SIZE,
				 "Unknown compression method \"%s\"", token);
		    } else {
			int k, found = 0;
			for (k = 0;
			     k < configs[cn].intval[cfg_ncompressions];
			     k++)
			    if (configs[cn].compressions[k] == nc)
				found = 1;
			if (found) {
			    snprintf(errbuff, LINE_SIZE,
				     "Compression method %s already specfied",
				     token);
			    err = errbuff;
#if USE_SHOULDBOX
			} else if (configs[cn].intval[cfg_ncompressions] >=
				    compress_count())
			{
			    snprintf(errbuff, LINE_SIZE,
				     "Internal error, "
				     "ncompressions = %d >= %d",
				     configs[cn].intval[cfg_ncompressions],
				     compress_count());
			    err = errbuff;
#endif
			} else {
			    configs[cn].compressions[configs[cn].
				intval[cfg_ncompressions]] = nc;
			    configs[cn].intval[cfg_ncompressions]++;
			}
		    }
		}
		myfree(st);
		return err;
	    }
	    st = NULL;
	    if (assign_string(line, "checksum", 0, &st, &err)) {
		char * saveptr = NULL, * token, * parse = st;
		if (err) return err;
		configs[cn].intval[cfg_nchecksums] = 0;
		while (! err &&
		       (token = strtok_r(parse, ",", &saveptr)) != NULL)
		{
		    int nc;
		    parse = NULL;
		    while (*token && isspace((int)*token)) token++;
		    nc = checksum_byname(token);
		    if (nc < 0) {
			err = errbuff;
			snprintf(errbuff, LINE_SIZE,
				 "Unknown checksum method \"%s\"", token);
		    } else {
			int k, found = 0;
			for (k = 0; k < configs[cn].intval[cfg_nchecksums]; k++)
			    if (configs[cn].checksums[k] == nc)
				found = 1;
			if (found) {
			    snprintf(errbuff, LINE_SIZE,
				     "Checksum method %s already specfied",
				     token);
			    err = errbuff;
#if USE_SHOULDBOX
			} else if (configs[cn].intval[cfg_nchecksums] >=
				    checksum_count())
			{
			    snprintf(errbuff, LINE_SIZE,
				     "Internal error, nchecksums = %d >= %d",
				     configs[cn].intval[cfg_nchecksums],
				     checksum_count());
			    err = errbuff;
#endif
			} else {
			    configs[cn].checksums[configs[cn].
				intval[cfg_nchecksums]] = nc;
			    configs[cn].intval[cfg_nchecksums]++;
			}
		    }
		}
		myfree(st);
		return err;
	    }
	    if (assign_strlist(line, "cp", 1,
		&configs[cn].strlist[cfg_cp_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_cp;
		return err;
	    }
	    break;
	case 'd' :
	    st = NULL;
	    if (assign_string(line, "dir", 1, &st, &err)) {
		if (err) return err;
		goto add_watch;
	    }
	    if (strcmp(line, "detach") == 0) {
		configs[cn].intval[cfg_server_mode] |= config_server_detach;
		return NULL;
	    }
	    if (assign_strlist(line, "df", 0,
		&configs[cn].strlist[cfg_df_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_df;
		return err;
	    }
	    if (strcmp(line, "defaultsocket") == 0) {
		*locfl |= locfl_defsocket;
		return NULL;
	    }
	    if (strcmp(line, "defaultlogfile") == 0) {
		*locfl |= locfl_deflogfile;
		return NULL;
	    }
	    if (strcmp(line, "defaultconfig") == 0) {
		*locfl |= locfl_defconfig;
		return NULL;
	    }
	    if (strcmp(line, "defaulteventdir") == 0) {
		*locfl |= locfl_defeventdir;
		return NULL;
	    }
	    break;
	case 'e' :
	    if (assign_string(line, "eventdir", 1,
			      &configs[cn].strval[cfg_eventdir], &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "exclude_path_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_path,
			         config_match_glob,
			         "exclude_path_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "exclude_path", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_path,
			         config_match_exact,
			         "exclude_path");
	    }
	    st = NULL;
	    if (assign_string(line, "exclude_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_name,
			         config_match_glob,
			         "exclude_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "exclude", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_name,
			         config_match_exact,
			         "exclude");
	    }
	    break;
	case 'f' :
	    st = NULL;
	    if (assign_string(line, "file", 0, &st, &err)) {
		if (err) return err;
		err = includefile(st, include_none, locfl);
		myfree(st);
		return err;
	    }
	    st = NULL;
	    if (assign_string(line, "find_path_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_path,
			         config_match_glob,
			         "find_path_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "find_path", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_path,
			         config_match_exact,
			         "find_path");
	    }
	    st = NULL;
	    if (assign_string(line, "find_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_name,
			         config_match_glob,
			         "find_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "find", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_name,
			         config_match_exact,
			         "find");
	    }
	    if (assign_string(line, "from", 0, &configs[cn].
			      strval[cfg_from_prefix], &err))
		return err;
	    if (strcmp(line, "follow") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_peek;
		return NULL;
	    }
	    break;
	case 'g' :
	    if (strcmp(line, "getpid") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_getpid;
		return NULL;
	    }
	    break;
	case 'h' :
	    if (strcmp(line, "help") == 0) {
		*locfl |= locfl_help;
		return NULL;
	    }
	    if (assign_string(line, "homedir", 1,
			   &configs[cn].strval[cfg_homedir], &err))
		return err;
	    break;
	case 'i' :
	    if (assign_int(line, "initial_blocks",
			   &configs[cn].intval[cfg_notify_initial], &err))
		return err;
	    if (assign_int(line, "initial",
			   &configs[cn].intval[cfg_notify_initial], &err))
		return err;
	    if (assign_string(line, "ident", 0,
			      &configs[cn].strval[cfg_error_ident], &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "iexclude_path_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_path,
			         config_match_iglob,
			         "iexclude_path_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude_path", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_path,
			         config_match_icase,
			         "iexclude_path");
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_name,
			         config_match_iglob,
			         "iexclude_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 0, st,
			         config_match_name,
			         config_match_icase,
			         "iexclude");
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_path_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_path,
			         config_match_iglob,
			         "ifind_path_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_path", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_path,
			         config_match_icase,
			         "ifind_path");
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_glob", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_name,
			         config_match_iglob,
			         "ifind_glob");
	    }
	    st = NULL;
	    if (assign_string(line, "ifind", 0, &st, &err)) {
		if (err) return err;
		return add_match(cn, 1, st,
			         config_match_name,
			         config_match_icase,
			         "ifind");
	    }
	    st = NULL;
	    if (assign_string(line, "include", 0, &st, &err)) {
		if (err) return err;
		err = includefile(st, include_none, locfl);
		myfree(st);
		return err;
	    }
	    break;
	case 'k' :
	    if (strcmp(line, "kill") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_stop;
		return NULL;
	    }
	    if (strcmp(line, "keep_ids") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_translate_ids;
		return NULL;
	    }
	    break;
	case 'l' :
	    st = NULL;
	    if (assign_string(line, "listen", 0, &st, &err)) {
		char * pb = NULL;
		config_listen_t * L;
		if (err) return err;
		if (st[0] != '/') {
		    pb = strrchr(st, ':');
		    if (! pb || pb == st) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid \"listen\": %s (missing port)", st);
			myfree(st);
			return errbuff;
		    }
		}
		L = mymalloc(sizeof(config_listen_t));
		if (! L) {
		    int e = errno;
		    myfree(st);
		    return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					     "malloc", e);
		}
		L->host = st;
		if (st[0] != '/') {
		    L->port = pb + 1;
		    *pb-- = 0;
		    if (st[0] == '[' && pb[0] == ']') {
			int i;
			pb[0] = 0;
			for (i = 0; st[i]; i++)
			    st[i] = st[i + 1];
		    }
		} else {
		    *locfl |= locfl_has_socket;
		    L->port = NULL;
		}
		L->next = configs[cn].listen;
		configs[cn].listen = L;
		return NULL;
	    }
	    if (assign_strlist(line, "ls", 0,
		&configs[cn].strlist[cfg_ls_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_ls;
		return err;
	    }
	    break;
	case 'm' :
	    if (strcmp(line, "mount") == 0) {
		if (! configs[cn].dirs)
		    return "mount must follow a dir";
		configs[cn].dirs->crossmount = 0;
		return NULL;
	    }
	    break;
	case 'n' :
	    if (assign_string(line, "name", 0,
			      &configs[cn].strval[cfg_base_name], &err))
		return err;
	    if (strcmp(line, "nodetach") == 0) {
		configs[cn].intval[cfg_server_mode] &= ~config_server_detach;
		return NULL;
	    }
	    break;
	case 'o' :
	    if (assign_unit(line, "optimise_buffer", sizes,
			    &configs[cn].intval[cfg_optimise_buffer], &err))
		return err;
	    if (assign_int(line, "optimise_client",
			   &configs[cn].intval[cfg_optimise_client], &err))
		return err;
	    if (strcmp(line, "oneshot") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_copy_oneshot;
		return NULL;
	    }
	    break;
	case 'p' :
	    if (assign_int(line, "password_from_stdin", &iv, &err)) {
		int done;
		if (err) return err;
		if (iv < 1) return "Invalid password length";
		st = mymalloc(1 + iv);
		if (! st)
		    return error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
		done = 0;
		while (done < iv) {
		    ssize_t nr = read(fileno(stdin), st + done, iv - done);
		    if (nr < 0) {
			int e = errno;
			myfree(st);
			return error_sys_errno_r(errbuff, LINE_SIZE, "config",
						 "read", e);
		    }
		    if (nr == 0) {
			myfree(st);
			return "Could not read password from stdin";
		    }
		    done += nr;
		}
		st[iv] = 0;
		if (configs[cn].strval[cfg_password])
		    myfree(configs[cn].strval[cfg_password]);
		configs[cn].strval[cfg_password] = st;
		return NULL;
	    }
	    if (assign_string(line, "password", 0,
			      &configs[cn].strval[cfg_password], &err))
		return err;
	    if (assign_string(line, "pass", 0,
			      &configs[cn].strval[cfg_password], &err))
		return err;
	    if (strcmp(line, "peek") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_peek;
		return NULL;
	    }
	    if (strcmp(line, "printconfig") == 0) {
		*locfl |= locfl_config;
		return NULL;
	    }
	    if (strcmp(line, "print") == 0) {
		*locfl |= locfl_config;
		return NULL;
	    }
	    if (assign_int(line, "purge",
			   &configs[cn].intval[cfg_purge_days], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_purge;
		return err;
	    }
	    if (strcmp(line, "pid") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_getpid;
		return NULL;
	    }
	    break;
	case 'q' :
	    if (assign_unit(line, "queue_block", sizes,
			    &configs[cn].intval[cfg_notify_queue_block], &err))
		return err;
	    break;
	case 'r' :
	    st = NULL;
	    if (assign_string(line, "remove", 1, &st, &err)) {
		config_dir_t * rl;
		if (err) return err;
		rl = mymalloc(sizeof(config_dir_t));
		if (! rl) {
		    int e = errno;
		    myfree(st);
		    return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					     "malloc", e);
		}
		rl->crossmount = 1;
		rl->next = configs[cn].remove;
		rl->exclude = NULL;
		rl->path = st;
		configs[cn].remove = rl;
		configs[cn].intval[cfg_client_mode] |= config_client_remove;
		return NULL;
	    }
	    if (assign_command(line, "remote_should",
			       &configs[cn].remote_should, &err))
		return err;
	    break;
	case 's' :
	    if (strcmp(line, "serverconfig") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_config;
		return NULL;
	    }
	    if (strcmp(line, "server_config") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_config;
		return NULL;
	    }
	    if (strcmp(line, "serverversion") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_version;
		return NULL;
	    }
	    if (strcmp(line, "server_version") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_version;
		return NULL;
	    }
	    if (strcmp(line, "servercompress") == 0) {
		configs[cn].intval[cfg_client_mode] |=
		    config_client_listcompress;
		return NULL;
	    }
	    if (strcmp(line, "server_compress") == 0) {
		configs[cn].intval[cfg_client_mode] |=
		    config_client_listcompress;
		return NULL;
	    }
	    if (strcmp(line, "serverchecksum") == 0) {
		configs[cn].intval[cfg_client_mode] |=
		    config_client_listchecksum;
		return NULL;
	    }
	    if (strcmp(line, "server_checksum") == 0) {
		configs[cn].intval[cfg_client_mode] |=
		    config_client_listchecksum;
		return NULL;
	    }
	    if (strcmp(line, "setdebug") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_setdebug;
		return NULL;
	    }
	    st = NULL;
	    if (assign_string(line, "server", 0, &st, &err)) {
		char * pb = NULL;
		if (err) return err;
		if (st[0] != '/') {
		    pb = strrchr(st, ':');
		    if (! pb || pb == st) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid \"server\": %s (missing port)", st);
			myfree(st);
			return errbuff;
		    }
		}
		configs[cn].intval[cfg_client_mode] |= config_client_client;
		configs[cn].intval[cfg_flags] |= config_flag_socket_changed;
		if (configs[cn].server.host)
		    myfree(configs[cn].server.host);
		configs[cn].server.host = st;
		if (st[0] != '/') {
		    configs[cn].server.port = pb + 1;
		    *pb-- = 0;
		    if (st[0] == '[' && pb[0] == ']') {
			int i;
			pb[0] = 0;
			for (i = 0; st[i]; i++)
			    st[i] = st[i + 1];
		    }
		} else {
		    configs[cn].server.port = NULL;
		}
		return NULL;
	    }
	    if (strcmp(line, "stop") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_stop;
		return NULL;
	    }
	    if (strcmp(line, "start") == 0) {
		configs[cn].intval[cfg_server_mode] |= config_server_start;
		return NULL;
	    }
	    if (strcmp(line, "status") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_status;
		return NULL;
	    }
	    if (assign_string(line, "store", 0,
			      &configs[cn].strval[cfg_store], &err))
		return err;
	    if (assign_string(line, "setup", 0,
			      &configs[cn].strval[cfg_copy_state], &err))
	    {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_setup;
		return NULL;
	    }
	    if (strcmp(line, "skip_notice") == 0) {
		*locfl |= locfl_notice;
		return NULL;
	    }
	    break;
	case 't' :
	    if (assign_string(line, "to", 0,
			      &configs[cn].strval[cfg_to_prefix], &err))
		return err;
	    if (strcmp(line, "translate_ids") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_translate_ids;
		return NULL;
	    }
	    if (strcmp(line, "telnet") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_telnet;
		return NULL;
	    }
	    if (assign_command(line, "tunnel", &configs[cn].tunnel, &err))
		return err;
	    break;
	case 'u' :
	    if (assign_string(line, "user", 0,
			      &configs[cn].strval[cfg_user], &err))
		return err;
	    if (assign_strlist(line, "update", 0,
		&configs[cn].strlist[cfg_update], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_update;
		return err;
	    }
	    break;
	case 'v' :
	    if (strcmp(line, "version") == 0) {
		*locfl |= locfl_version;
		return NULL;
	    }
	    break;
	case 'w' :
	    if (assign_int(line, "watch_block",
			   &configs[cn].intval[cfg_notify_watch_block], &err))
		return err;
	    if (assign_unit(line, "watch_name_block", sizes,
			    &configs[cn].intval[cfg_notify_name_block], &err))
		return err;
	    if (strcmp(line, "watches") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_watches;
		return NULL;
	    }
	    if (strcmp(line, "work") == 0) {
		return "*Whatever gave you this idea?";
	    }
	    if (strcmp(line, "warranty") == 0) {
		*locfl |= locfl_warranty;
		return NULL;
	    }
	    break;
    }
    snprintf(errbuff, LINE_SIZE, "Unknown option: %s", line);
    return errbuff;
}

/* parse single argument - initial configuration or reconfiguration */

static const char * parsearg(const char * line, locfl_t * locfl, int is_initial)
{
    const char * err;
    char * st, * pwd = NULL;
    error_message_t erm;
    int cn = is_initial ? currnum : update_cn;
    switch (line[0]) {
	case 'a' :
	    if (assign_int(line, "autopurge",
			   &configs[cn].intval[cfg_autopurge_days], &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "allow_unix", 0, &st, &err)) {
		if (err) return err;
		pwd = NULL;
		goto add_user;
	    }
	    st = NULL;
	    if (assign_string(line, "allow_tcp", 0, &st, &err)) {
		config_user_t * ul;
		if (err) return err;
		pwd = strchr(st, ':');
		if (pwd)
		    *pwd++ = 0;
		else
		    pwd = "";
	    add_user:
		ul = mymalloc(sizeof(config_user_t));
		if (! ul) {
		    int e = errno;
		    myfree(st);
		    return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					     "malloc", e);
		}
		ul->next = configs[cn].users;
		ul->user = st;
		ul->pass = pwd;
		configs[cn].users = ul;
		return NULL;
	    }
	    break;
	case 'c' :
	    if (assign_int(line, "checkpoint_events",
			   &configs[cn].intval[cfg_checkpoint_events], &err))
		return err;
	    if (assign_unit(line, "checkpoint_time", intervals,
			    &configs[cn].intval[cfg_checkpoint_time], &err))
		return err;
	    if (strcmp(line, "copy_matching") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_skip_matching;
		return NULL;
	    }
	    if (strcmp(line, "copy_should_temporary") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_skip_should;
		return NULL;
	    }
	    break;
	case 'd' :
	    if (assign_unit(line, "dirsync_interval", intervals,
			    &configs[cn].intval[cfg_dirsync_interval], &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "dirsync_timed", 0, &st, &err)) {
		char * saveptr = NULL, * token, * parse = st;
		config_dirsync_t * rs;
		int count, num;
		if (err) return err;
		for (token = st, count = 1; *token; token++)
		    if (*token == ';')
			count++;
		rs = mymalloc(count * sizeof(config_dirsync_t));
		if (! rs) {
		    int e = errno;
		    myfree(st);
		    return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					     "malloc", e);
		}
		num = 0;
		while ((token = strtok_r(parse, ";", &saveptr)) != NULL) {
		    const char * re;
		    char * te;
		    int hours, minutes = 0;
		    parse = NULL;
		    while (*token && isspace((int)*token)) token++;
		    re = config_parse_dayrange(token, &rs[num].daymask);
		    if (! re) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid day range: %s", token);
			myfree(rs);
			myfree(st);
			return errbuff;
		    }
		    while (*re && isspace((int)*re)) re++;
		    if (! *re) {
			snprintf(errbuff, LINE_SIZE,
				 "Missing start time: %s", token);
			myfree(rs);
			myfree(st);
			return errbuff;
		    }
		    while (*re == '0' && isdigit((int)re[1])) re++;
		    hours = strtol(re, &te, 0);
		    if (hours < 0 || hours > 23) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid start time: %s", token);
			myfree(rs);
			myfree(st);
			return errbuff;
		    }
		    re = te;
		    while (*re && isspace((int)*re)) re++;
		    if (*re == ':') {
			re++;
			while (*re && isspace((int)*re)) re++;
			minutes = strtol(re, &te, 0);
			if (minutes < 0 || minutes > 59) {
			    snprintf(errbuff, LINE_SIZE,
				     "Invalid start time: %s", token);
			    myfree(rs);
			    myfree(st);
			    return errbuff;
			}
			re = te;
			while (*re && isspace((int)*re)) re++;
		    }
		    if (*re && (re[1] == 'm' || re[1] == 'M')) {
			if (hours > 11) {
			    snprintf(errbuff, LINE_SIZE,
				     "Invalid start time: %s", token);
			    myfree(rs);
			    myfree(st);
			    return errbuff;
			}
			if (*re == 'p' || *re == 'P') {
			    hours += 12;
			} else if (*re != 'a' && *re != 'A') {
			    snprintf(errbuff, LINE_SIZE,
				     "Invalid start time: %s", token);
			    myfree(rs);
			    myfree(st);
			    return errbuff;
			}
			re += 2;
			while (*re && isspace((int)*re)) re++;
		    }
		    if (*re) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid start time: %s", token);
			myfree(rs);
			myfree(st);
			return errbuff;
		    }
		    rs[num].start_time = hours * 3600 + minutes * 60;
		    num++;
		}
		myfree(st);
		if (configs[cn].dirsync_timed)
		    myfree(configs[cn].dirsync_timed);
		configs[cn].dirsync_timed = rs;
		configs[cn].intval[cfg_dirsync_count] = num;
		return NULL;
	    }
	    st = NULL;
	    if (strcmp(line, "debug_server") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_debug_server;
		return NULL;
	    }
	    if (strcmp(line, "dirsync_delete") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_dirsync_delete;
		return NULL;
	    }
	    st = NULL;
	    if (assign_string(line, "disallow_unix", 0, &st, &err)) {
		if (err) return err;
		pwd = NULL;
		goto del_user;
	    }
	    st = NULL;
	    if (assign_string(line, "disallow_tcp", 0, &st, &err)) {
		config_user_t * ul, * prev;
		if (err) return err;
		pwd = strchr(st, ':');
		if (pwd)
		    *pwd++ = 0;
		else
		    pwd = "";
	    del_user:
		ul = configs[cn].users;
		prev = NULL;
		while (ul) {
		    if (strcmp(ul->user, st) == 0) {
			if ((ul->pass && pwd && strcmp(ul->pass, pwd) == 0) ||
			    (! ul->pass && ! pwd))
			{
			    if (prev)
				prev->next = ul->next;
			    else
				configs[cn].users = ul->next;
			    myfree(ul->user);
			    myfree(ul);
			    myfree(st);
			    return NULL;
			}
		    }
		    prev = ul;
		    ul = ul->next;
		}
		myfree(st);
		snprintf(errbuff, LINE_SIZE,
			 "%s user %s not found: cannot remove",
			 pwd ? "TCP" : "Unix", st);
		return errbuff;
	    }
	    break;
	case 'e' :
	    if (assign_unit(line, "eventfilesize",
			    sizes, &configs[cn].intval[cfg_eventsize], &err))
		return err;
	    if (assign_unit(line, "eventsize", sizes,
			    &configs[cn].intval[cfg_eventsize], &err))
		return err;
	    if (assign_string(line, "email_submit",
			    0, &configs[cn].strval[cfg_error_submit], &err))
		return err;
	    if (assign_string(line, "email", 0,
			      &configs[cn].strval[cfg_error_email], &err))
		return err;
	    break;
	case 'f' :
	    st = NULL;
	    if (assign_string(line, "filter", 0, &st, &err)) {
		int eventmap, filemap, i, mask;
		char * saveptr = NULL, * token, * parse = st;
		if (err) return err;
		for (i = 0; i < config_event_COUNT; i++)
		    configs[cn].filter[i] = 0;
		while ((token = strtok_r(parse, ",", &saveptr)) != NULL) {
		    int negate = 0;
		    parse = NULL;
		    while (*token && isspace((int)*token)) token++;
		    if (*token == '!') {
			negate = 1;
			token++;
			while (*token && isspace((int)*token)) token++;
		    }
		    if (! get_filter(token, &eventmap, &filemap)) {
			snprintf(errbuff, LINE_SIZE,
				 "Invalid filter: %s", token);
			myfree(st);
			return errbuff;
		    }
		    for (i = 0, mask = 1;
			i < config_event_COUNT;
			i++, mask <<= 1)
		    {
			if (eventmap & mask) {
			    if (negate)
				configs[cn].filter[i] &= ~filemap;
			    else
				configs[cn].filter[i] |= filemap;
			}
		    }
		}
		myfree(st);
		return NULL;
	    }
	    break;
	case 'l' :
	    if (assign_string(line, "logfile", 1,
			      &configs[cn].strval[cfg_error_logfile], &err))
		return err;
	    break;
	case 'm' :
	    if (assign_int(line, "max",
		&configs[cn].intval[cfg_notify_max], &err))
		    return err;
	    if (assign_int(line, "max_blocks",
		&configs[cn].intval[cfg_notify_max], &err))
		    return err;
	    st = NULL;
	    erm = assign_error(line, "message", &st, &err);
	    if (erm < error_MAX) {
		if (err) return err;
		err = error_change_message(erm, st);
		if (! err) return NULL;
		myfree(st);
		return err;
	    }
	    break;
	case 'n' :
	    if (strcmp(line, "no_debug_server") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_debug_server;
		return NULL;
	    }
	    if (strcmp(line, "no_dirsync_delete") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_dirsync_delete;
		return NULL;
	    }
	    break;
	case 'r' :
	    st = NULL;
	    erm = assign_error(line, "report", &st, &err);
	    if (erm < error_MAX) {
		int facility = 0;
		error_dest_t dest = 0;
		if (err) return err;
		if (strcmp(st, "none") != 0) {
		    char * saveptr = NULL, * token, * parse = st;
		    while ((token = strtok_r(parse, ",", &saveptr)) != NULL) {
			parse = NULL;
			while (*token && isspace((int)*token)) token++;
			if (strcmp(token, "stderr") == 0) {
			    dest |= error_dest_stderr;
			    continue;
			}
			if (strcmp(token, "email") == 0) {
			    dest |= error_dest_email;
			    continue;
			}
			if (strcmp(token, "file") == 0) {
			    dest |= error_dest_file;
			    continue;
			}
			err = config_getfacility(token, &facility);
			if (err) {
			    myfree(st);
			    return err;
			}
			dest |= error_dest_syslog;
		    }
		}
		myfree(st);
		error_change_dest(erm, dest, facility);
		return NULL;
	    }
	    break;
	case 's' :
	    if (assign_string(line, "submit", 0,
			      &configs[cn].strval[cfg_error_submit], &err))
		return err;
	    if (strcmp(line, "skip_matching") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_skip_matching;
		return NULL;
	    }
	    if (strcmp(line, "skip_should_temporary") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_skip_should;
		return NULL;
	    }
	    if (strcmp(line, "skip_initial_dirsync") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_initial_dirsync;
		return NULL;
	    }
	    if (strcmp(line, "skip_overflow_dirsync") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_overflow_dirsync;
		return NULL;
	    }
	    break;
    }
    if (is_initial)
	return parsearg_initial(line, locfl);
    snprintf(errbuff, LINE_SIZE, "Unknown option: %s", line);
    return errbuff;
}

/* read file and include it in configuration */

static const char * includefile(const char * name, include_t how,
				locfl_t * locfl)
{
    char buffer[CONFIG_LINESIZE];
    int check_state = how & include_state;
    FILE * IF = fopen(name, check_state ? "r+" : "r");
    const char * err = NULL;
    if (! IF) {
	if (how & include_silent)
	    return "";
	return error_sys_r(errbuff, LINE_SIZE, "config", name);
    }
    if (check_state) {
	if (fseek(IF, 0L, SEEK_SET) < 0) {
	    int e = errno;
	    fclose(IF);
	    return error_sys_errno_r(errbuff, LINE_SIZE, "config", "malloc", e);
	}
	if (lockf(fileno(IF), F_TLOCK, (off_t)0) < 0) {
	    int e = errno;
	    fclose(IF);
	    if (errno == EACCES || errno == EAGAIN) {
		snprintf(errbuff, LINE_SIZE, "%s: file is locked", name);
		return errbuff;
	    }
	    return error_sys_errno_r(errbuff, LINE_SIZE, "config", name, e);
	}
    }
    while (fgets(buffer, CONFIG_LINESIZE, IF)) {
	int le = strlen(buffer);
	char * line = buffer;
	while (le > 0 && isspace((int)buffer[le - 1])) le--;
	buffer[le] = 0;
	while (le > 0 && buffer[le - 1] == '\\') {
	    le--;
	    if (le >= CONFIG_LINESIZE - 10) {
		snprintf(errbuff, LINE_SIZE, "%s: line too long", name);
		err = errbuff;
		goto problem;
	    }
	    if (! fgets(buffer + le, CONFIG_LINESIZE - le, IF)) {
		snprintf(errbuff, LINE_SIZE,
			 "%s: backslash ends last line", name);
		err = errbuff;
		goto problem;
	    }
	    le += strlen(buffer + le);
	    while (le > 0 && isspace((int)buffer[le - 1])) le--;
	    buffer[le] = 0;
	}
	while (* line && isspace((int)*line)) line++;
	if (check_state) {
	    /* first line must have identification and version number */
	    double vn;
	    if (sscanf(line, IDENTIFY_COPY, &vn) < 1) {
		snprintf(errbuff, LINE_SIZE,
			 "%s: not a copy state file", name);
		err = errbuff;
		goto problem;
	    }
	    if (vn < IDENTIFY_MINIMUM) {
		snprintf(errbuff, LINE_SIZE,
			 "%s: version %lf is too old (minimum %lf)",
			 name, vn, IDENTIFY_MINIMUM);
		err = errbuff;
		goto problem;
	    }
	    check_state = 0;
	}
	if (! *line || *line == '#') continue;
	if ((how & include_state) && strcmp(line, "end_state") == 0) {
	    long fstart = ftell(IF);
	    if (fstart < 0) {
		err = error_sys_r(errbuff, LINE_SIZE, "config", name);
		goto problem;
	    }
	    config_copy_start = fstart;
	    config_copy_file = IF;
	    return NULL;
	}
	err = parsearg(buffer, locfl, 1);
	if (err)
	    goto problem;
    }
    fclose(IF);
    return NULL;
problem:
    if (how & include_state) {
	int rv;
	fseek(IF, 0L, SEEK_SET);
	rv = lockf(fileno(IF), F_ULOCK, (off_t)0);
    }
    fclose(IF);
    return err;
}

/* assign default value */

static int set_default(char ** result, const char * value) {
    if (*result) return 1;
    *result = mystrdup(value);
    if (*result) return 1;
    perror("strdup");
    return 0;
}

/* assign default value depending on whether the user is root or not */

static int set_default_user(char ** result, uid_t user, const char * homedir,
			    const char * root_dir, const char * base,
			    const char * name)
{
    /* set default result to be <dir>/should-<base>.<name> */
    int len;
    const char * should = "/should-";
    if (*result) return 1;
    if (user != 0) {
	if (! homedir) {
	    fprintf(stderr, "Cannot figure out user's home directory!\n");
	    return 0;
	}
	root_dir = homedir;
	should = "/.should-";
    }
    len = strlen(root_dir) + strlen(name) + strlen(base) + strlen(should) + 2;
    *result = mymalloc(len);
    if (! *result) {
	perror("malloc");
	return 0;
    }
    strcpy(*result, root_dir);
    strcat(*result, should);
    strcat(*result, base);
    strcat(*result, ".");
    strcat(*result, name);
    return 1;
}

/* prints the defaults which would be set by set_default_user for both
 * superuser and other users */

static void print_user(const char * title, const char * root_dir,
		       const char * base, const char * name)
{
    printf("%s for the root user: %s/should-%s.%s\n",
	   title, root_dir, base, name);
    printf("%s for nonroot users: ~/.should-%s.%s\n",
	   title, base, name);
}

static void show_copyright(const char * pname, locfl_t locfl) {
    printf("should %d.%d.%d  Copyright (c) 2009 Claudio Calvelli\n",
	   VERSION_MAJOR, VERSION_MINOR, VERSION_OFFSET);
    if (! locfl) {
	printf("This program comes with ABSOLUTELY NO WARRANTY:\n"
	       "for details use command \"%s warranty\"\n"
	       "This is free software, and you are welcome to\n"
	       "redistribute it under certain conditions:\n"
	       "for details use command \"%s copyright\"\n"
	       "\n", pname, pname);
	return;
    }
    if (locfl & locfl_warranty)
	printf("\n"
"THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY\n"
"APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT\n"
"HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY\n"
"OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,\n"
"THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n"
"PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM\n"
"IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF\n"
"ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\n"
"\n"
"IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING\n"
"WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS\n"
"THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY\n"
"GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE\n"
"USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF\n"
"DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD\n"
"PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),\n"
"EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF\n"
"SUCH DAMAGES.\n"
"\n");
    if (locfl & locfl_copyright)
	printf("\n"
"This program is free software: you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation, either version 3 of the License, or\n"
"(at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"
"\n");
}

/* initialises a configuration, given its number */

static int init_one(int cn) {
    int uc, ncompress = compress_count(), nchecksum = checksum_count();
    for (uc = 0; uc < cfg_int_COUNT; uc++)
	configs[cn].intval[uc] = default_ints[uc];
    for (uc = 0; uc < cfg_str_COUNT; uc++)
	configs[cn].strval[uc] = NULL;
    for (uc = 0; uc < cfg_strlist_COUNT; uc++)
	configs[cn].strlist[uc] = NULL;
    configs[cn].checksums = NULL;
    configs[cn].compressions = NULL;
    configs[cn].dirs = NULL;
    configs[cn].remove = NULL;
    configs[cn].server.host = NULL;
    configs[cn].server.port = NULL;
    configs[cn].tunnel = NULL;
    configs[cn].remote_should = NULL;
    configs[cn].listen = NULL;
    configs[cn].users = NULL;
    configs[cn].dirsync_timed = NULL;
    for (uc = 0; uc < config_event_COUNT; uc++)
	configs[cn].filter[uc] = config_file_all;
    in_use[cn] = 1;
    refcount[cn] = 1;
    configs[cn].checksums = mymalloc(nchecksum * sizeof(int *));
    if (! configs[cn].checksums)
	return 0;
    configs[cn].compressions = mymalloc(ncompress * sizeof(int *));
    if (! configs[cn].compressions)
	return 0;
    return 1;
}

static char ** array_dup(char * const * arr) {
    int nl = 0, i;
    char ** res;
    while (arr[nl]) nl++;
    res = mymalloc(sizeof(char *) * (nl + 1));
    if (! res) return NULL;
    for (i = 0; i < nl; i++) {
	int e;
	res[i] = mystrdup(arr[i]);
	if (res[i]) continue;
	e = errno;
	while (i > 0) {
	    i--;
	    myfree(res[i]);
	}
	myfree(res);
	errno = e;
	return NULL;
    }
    res[nl] = 0;
    return res;
}

static config_listen_t * listen_dup(const config_listen_t * ls) {
    config_listen_t * res = NULL;
    while (ls) {
	config_listen_t * this = mymalloc(sizeof(config_listen_t));
	int e;
	if (this) {
	    if (ls->port) {
		int len = 2 + strlen(ls->host) + strlen(ls->port);
		char * p = mymalloc(len);
		if (p) {
		    this->host = p;
		    strcpy(p, ls->host);
		    p += 1 + strlen(ls->host);
		    this->port = p;
		    strcpy(p, ls->port);
		    this->next = res;
		    res = this;
		    ls = ls->next;
		    continue;
		}
	    } else {
		this->host = mystrdup(ls->host);
		if (this->host) {
		    this->port = NULL;
		    this->next = res;
		    res = this;
		    ls = ls->next;
		    continue;
		}
	    }
	    e = errno;
	    myfree(this);
	    errno = e;
	}
	e = errno;
	while (res) {
	    config_listen_t * this = res;
	    res = res->next;
	    myfree(this->host);
	    myfree(this);
	}
	errno = e;
	return NULL;
    }
    return res;
}

static config_user_t * users_dup(const config_user_t * us) {
    config_user_t * res = NULL;
    while (us) {
	config_user_t * this = mymalloc(sizeof(config_user_t));
	int e;
	if (this) {
	    if (us->pass) {
		int len = 2 + strlen(us->user) + strlen(us->pass);
		char * p = mymalloc(len);
		if (p) {
		    this->user = p;
		    strcpy(p, us->user);
		    p += 1 + strlen(us->user);
		    this->pass = p;
		    strcpy(p, us->pass);
		    this->next = res;
		    res = this;
		    us = us->next;
		    continue;
		}
	    } else {
		this->user = mystrdup(us->user);
		if (this->user) {
		    this->pass = NULL;
		    this->next = res;
		    res = this;
		    us = us->next;
		    continue;
		}
	    }
	    e = errno;
	    myfree(this);
	    errno = e;
	}
	e = errno;
	while (res) {
	    config_user_t * this = res;
	    res = res->next;
	    myfree(this->user);
	    myfree(this);
	}
	errno = e;
	return NULL;
    }
    return res;
}

/* copies the current configuration to another one; dynamically allocated
 * data which is not used in server or copy mode is copied as NULL */

static int copy_current(int cn) {
    int uc;
    if (! init_one(cn)) return 0;
    for (uc = 0; uc < cfg_int_COUNT; uc++)
	configs[cn].intval[uc] = configs[currnum].intval[uc];
    for (uc = 0; uc < cfg_str_COUNT; uc++) {
	if (configs[currnum].strval[uc]) {
	    configs[cn].strval[uc] = mystrdup(configs[currnum].strval[uc]);
	    if (! configs[cn].strval[uc]) return 0;
	}
    }
    if (configs[currnum].server.host) {
	if (configs[currnum].server.port) {
	    int len = 2 + strlen(configs[currnum].server.host)
			+ strlen(configs[currnum].server.port);
	    char * p;
	    configs[cn].server.host = mymalloc(len);
	    if (! configs[cn].server.host) return 0;
	    strcpy(configs[cn].server.host, configs[currnum].server.host);
	    configs[cn].server.port = p = 
		configs[cn].server.host + 1 + strlen(configs[cn].server.host);
	    strcpy(p, configs[currnum].server.port);
	} else {
	    configs[cn].server.host = mystrdup(configs[currnum].server.host);
	    if (! configs[cn].server.host) return 0;
	    configs[cn].server.port = NULL;
	}
    }
    if (configs[currnum].tunnel) {
	configs[cn].tunnel = array_dup(configs[currnum].tunnel);
	if (! configs[cn].tunnel) return 0;
    }
    if (configs[currnum].remote_should) {
	configs[cn].remote_should = array_dup(configs[currnum].remote_should);
	if (! configs[cn].remote_should) return 0;
    }
    if (configs[currnum].listen) {
	configs[cn].listen = listen_dup(configs[currnum].listen);
	if (! configs[cn].listen) return 0;
    }
    if (configs[currnum].users) {
	configs[cn].users = users_dup(configs[currnum].users);
	if (! configs[cn].users) return 0;
    }
    if (configs[currnum].dirsync_timed) {
	int c;
	configs[cn].dirsync_timed =
	    mymalloc(configs[cn].intval[cfg_dirsync_count] *
		     sizeof(config_dirsync_t));
	if (! configs[cn].dirsync_timed) return 0;
	for (c = 0; c < configs[cn].intval[cfg_dirsync_count]; c++)
	    configs[cn].dirsync_timed[c] = configs[currnum].dirsync_timed[c];
    }
    for (uc = 0; uc < config_event_COUNT; uc++)
	configs[cn].filter[uc] = configs[currnum].filter[uc];
    for (uc = 0; uc < configs[currnum].intval[cfg_nchecksums]; uc++)
	configs[cn].checksums[uc] = configs[currnum].checksums[uc];
    for (uc = 0; uc < configs[currnum].intval[cfg_ncompressions]; uc++)
	configs[cn].compressions[uc] = configs[currnum].compressions[uc];
    return 1;
}

/* obtain configuration data; return NULL if OK or error message */

int config_init(int argc, char *argv[]) {
    int argn, uc;
    locfl_t locfl;
    char ubuffer[sysconf(_SC_GETPW_R_SIZE_MAX)];
    struct passwd pwd, * pwb;
    const char * cfg_file, * err, * pname = argv[0];
    uid_t user = getuid();
    const char * homedir = NULL;
    int code = pthread_mutex_init(&config_lock, NULL);
    if (code) {
	fprintf(stderr, "%s\n",
		error_sys_errno("config_init", "pthread_mutex_init", code));
	return 0;
    }
    config_copy_file = NULL;
    config_copy_start = -1;
    for (uc = 0; uc < UPDATE_COUNT; uc++) {
	refcount[uc] = 0;
	in_use[uc] = 0;
    }
    currnum = 0;
    update_cn = -1;
    if (getpwuid_r(user, &pwd, ubuffer, sizeof(ubuffer), &pwb) >= 0)
	homedir = pwd.pw_dir;
    /* clear data and set defaults */
    locfl = locfl_NONE;
    if (! init_one(currnum)) {
	perror("malloc");
	goto fail;
    }
    /* read configuration file, if found */
    cfg_file = getenv("SHOULD_USER");
    if (! cfg_file) cfg_file = USER_CONFIG;
    err = "";
    if (cfg_file[0] == '/') {
	err = includefile(cfg_file, include_silent, &locfl);
	if (err && *err) {
	    fprintf(stderr, "%s\n", err);
	    goto fail;
	}
    } else if (homedir) {
	char conf[strlen(homedir) + strlen(USER_CONFIG) + 2];
	sprintf(conf, "%s/%s", homedir, USER_CONFIG);
	err = includefile(conf, include_silent, &locfl);
	if (err && *err) {
	    fprintf(stderr, "%s\n", err);
	    goto fail;
	}
    }
    if (err && ! *err) {
	cfg_file = getenv("SHOULD_SYSTEM");
	if (! cfg_file) cfg_file = SYSTEM_CONFIG;
	if (cfg_file[0] == '/') {
	    err = includefile(cfg_file, include_silent, &locfl);
	    if (err && *err) {
		fprintf(stderr, "%s\n", err);
		goto fail;
	    }
	}
    }
    /* read command-line arguments */
    for (argn = 1; argn < argc; argn++) {
	err = parsearg(argv[argn], &locfl, 1);
	if (err) {
	    /* this is only so that "should work" produces correct output */
	    if (*err == '*')
		fprintf(stderr, "%s\n", err + 1);
	    else
		fprintf(stderr, "%s: %s\n", pname, err);
	    goto fail;
	}
    }
    /* check for consistency */
    if (configs[currnum].intval[cfg_client_mode] &&
	(configs[currnum].intval[cfg_server_mode] & ~config_server_detach))
    {
	fprintf(stderr, "Incompatible options: client and server\n");
	goto fail;
    }
    if (configs[currnum].intval[cfg_client_mode] & config_client_setup) {
	if (configs[currnum].intval[cfg_client_mode] &
	    ~(config_client_setup |
	      config_client_client |
	      config_client_setdebug |
	      config_client_cleardebug))
	{
	    fprintf(stderr,
		    "Incompatible options: setup and other client ops\n");
	    goto fail;
	}
	if (! configs[currnum].strval[cfg_from_prefix]) {
	    fprintf(stderr, "Setup requires \"from\"\n");
	    goto fail;
	}
	if (! configs[currnum].strval[cfg_to_prefix]) {
	    fprintf(stderr, "Setup requires \"to\"\n");
	    goto fail;
	}
    }
    if (configs[currnum].intval[cfg_client_mode] & config_client_copy) {
	if (configs[currnum].intval[cfg_client_mode] &
	    ~(config_client_copy |
	      config_client_setdebug |
	      config_client_client |
	      config_client_cleardebug))
	{
	    fprintf(stderr,
		    "Incompatible options: copy and other client ops\n");
	    goto fail;
	}
    }
    if (configs[currnum].intval[cfg_client_mode] & config_client_peek) {
	if (configs[currnum].intval[cfg_client_mode] &
	    ~(config_client_peek |
	      config_client_setdebug |
	      config_client_client |
	      config_client_cleardebug))
	{
	    fprintf(stderr,
		    "Incompatible options: peek and other client ops\n");
	    goto fail;
	}
    }
    if (configs[currnum].intval[cfg_client_mode] & config_client_telnet) {
	if (configs[currnum].intval[cfg_client_mode] &
	    ~(config_client_telnet |
	      config_client_setdebug |
	      config_client_client |
	      config_client_cleardebug))
	{
	    fprintf(stderr,
		    "Incompatible options: telnet and other client ops\n");
	    goto fail;
	}
    }
    if (configs[currnum].strval[cfg_from_prefix])
	configs[currnum].intval[cfg_from_length] =
	    strlen(configs[currnum].strval[cfg_from_prefix]);
    if (configs[currnum].strval[cfg_to_prefix])
	configs[currnum].intval[cfg_to_length] =
	    strlen(configs[currnum].strval[cfg_to_prefix]);
    /* set default values */
    if (homedir &&
	! set_default(&configs[currnum].strval[cfg_homedir], homedir))
	    goto fail;
    homedir = configs[currnum].strval[cfg_homedir];
    if (! set_default(&configs[currnum].strval[cfg_base_name],
		      (configs[currnum].intval[cfg_client_mode]
			    & config_client_copy)
			? "copy" : "server"))
	goto fail;
    if (! set_default_user(&configs[currnum].server.host,
			   user, homedir, ROOT_SOCKET_DIR,
			   configs[currnum].strval[cfg_base_name],
			   "socket"))
	goto fail;
    if (! (locfl & locfl_has_socket)) {
	/* need to add a control socket */
	config_listen_t * L = mymalloc(sizeof(config_listen_t));
	char * sh = NULL;
	if (! L) {
	    perror("malloc");
	    goto fail;
	}
	if (! set_default_user(&sh, user, homedir, ROOT_SOCKET_DIR,
			       configs[currnum].strval[cfg_base_name],
			       "socket"))
	{
	    myfree(L);
	    goto fail;
	}
	L->next = configs[currnum].listen;
	L->host = sh;
	L->port = NULL;
	configs[currnum].listen = L;
    }
    locfl &= ~locfl_has_socket;
    if (! set_default(&configs[currnum].strval[cfg_error_ident], "should"))
	goto fail;
    if (! set_default_user(&configs[currnum].strval[cfg_error_logfile],
			   user, homedir, ROOT_LOGFILE_DIR,
			   configs[currnum].strval[cfg_base_name], "log"))
	goto fail;
    if (! set_default(&configs[currnum].strval[cfg_error_submit], MAILER))
	goto fail;
    if (! set_default_user(&configs[currnum].strval[cfg_eventdir],
			   user, homedir, ROOT_EVENTDIR_DIR,
			   configs[currnum].strval[cfg_base_name],
			   "events"))
	goto fail;
    if (! set_default(&configs[currnum].strval[cfg_store], "save"))
	goto fail;
    /* show short copyright notice if interactive */
    if (locfl & (locfl_version | locfl_copyright | locfl_warranty))
	show_copyright(pname, locfl);
    else if (! (locfl & locfl_notice) && isatty(fileno(stdout)))
	show_copyright(pname, locfl_NONE);
    locfl &= ~locfl_notice;
    /* if "print" options were specified, do them and exit */
    if (locfl & locfl_defconfig)
	printf("Default user configuration file:   ~/%s\n"
	       "Default system configuration file: %s\n",
	       USER_CONFIG, SYSTEM_CONFIG);
    if (locfl & locfl_defsocket)
	print_user("Control socket", ROOT_SOCKET_DIR,
		   configs[currnum].strval[cfg_base_name], "socket");
    if (locfl & locfl_deflogfile)
	print_user("Log file", ROOT_LOGFILE_DIR,
		   configs[currnum].strval[cfg_base_name], "log");
    if (locfl & locfl_defeventdir)
	print_user("Event directory", ROOT_EVENTDIR_DIR,
		   configs[currnum].strval[cfg_base_name], "events");
    if (locfl & locfl_compress)
	print_compress();
    if (locfl & locfl_checksum)
	print_checksum();
    if (locfl & locfl_help)
	print_help(configs[currnum].strval[cfg_base_name]);
    if (locfl & locfl_config)
	print_one(sendout, stdout, currnum);
    if (locfl != locfl_NONE)
	goto fail;
    /* if not detaching, send all messages to stderr unless they specified
     * a different destination */
    if (configs[currnum].intval[cfg_client_mode] ||
	! (configs[currnum].intval[cfg_server_mode] & config_server_detach))
    {
	error_message_t E;
	for (E = 0; E < error_MAX; E++)
	    if (error_dest_changed(E) == 0)
		error_change_dest(E, error_dest_stderr, 0);
    }
    return 1;
fail:
    pthread_mutex_destroy(&config_lock);
    config_free();
    return 0;
}

/* free a single directory tree */

void config_dir_free(config_dir_t * this) {
    while (this->exclude) {
	config_match_t * ex = this->exclude;
	this->exclude = this->exclude->next;
	myfree(ex->pattern);
	myfree(ex);
    }
    while (this->find) {
	config_match_t * fi = this->find;
	this->find = this->find->next;
	myfree(fi->pattern);
	myfree(fi);
    }
    myfree(this->path);
    myfree(this);
}

/* free configuration data */

void free_one(int cn) {
    int uc;
    for (uc = 0; uc < cfg_str_COUNT; uc++)
	if (configs[cn].strval[uc])
	    myfree(configs[cn].strval[uc]);
    for (uc = 0; uc < cfg_strlist_COUNT; uc++) {
	while (configs[cn].strlist[uc]) {
	    config_strlist_t * this = configs[cn].strlist[uc];
	    configs[cn].strlist[uc] = configs[cn].strlist[uc]->next;
	    myfree(this->data);
	    myfree(this);
	}
    }
    if (configs[cn].server.host)
	myfree(configs[cn].server.host);
    if (configs[cn].tunnel) {
	myfree(configs[cn].tunnel[0]);
	myfree(configs[cn].tunnel);
    }
    if (configs[cn].remote_should) {
	myfree(configs[cn].remote_should[0]);
	myfree(configs[cn].remote_should);
    }
    while (configs[cn].dirs) {
	config_dir_t * this = configs[cn].dirs;
	configs[cn].dirs = configs[cn].dirs->next;
	config_dir_free(this);
    }
    while (configs[cn].remove) {
	config_dir_t * this = configs[cn].remove;
	configs[cn].remove = configs[cn].remove->next;
	config_dir_free(this);
    }
    while (configs[cn].users) {
	config_user_t * this = configs[cn].users;
	configs[cn].users = configs[cn].users->next;
	if (this->user) myfree(this->user);
	myfree(this);
    }
    while (configs[cn].listen) {
	config_listen_t * this = configs[cn].listen;
	configs[cn].listen = configs[cn].listen->next;
	myfree(this->host);
	myfree(this);
    }
    if (configs[cn].dirsync_timed)
	myfree(configs[cn].dirsync_timed);
    if (configs[cn].checksums)
	myfree(configs[cn].checksums);
    if (configs[cn].compressions)
	myfree(configs[cn].compressions);
    in_use[cn] = refcount[cn] = 0;
}

void config_free(void) {
    int cn;
    refcount[currnum]--;
    for (cn = 0; cn < UPDATE_COUNT; cn++) {
	if (! in_use[cn]) continue;
	if (refcount[cn] > 0)
	    fprintf(stderr,
		    "Warning, freeing configuration %d with refcount %d\n",
		    cn, refcount[cn]);
	free_one(cn);
    }
    if (config_copy_file) {
	int rv;
	fseek(config_copy_file, 0L, SEEK_SET);
	rv = lockf(fileno(config_copy_file), F_ULOCK, (off_t)0);
	fclose(config_copy_file);
    }
}

/* obtain a read-only copy of the current configuration; this is guaranteed
 * not to change even if the configuration gets updated; however a second
 * call to config_get may return different data */

const config_data_t * config_get(void) {
    int errcode = pthread_mutex_lock(&config_lock);
    if (errcode) {
	/* this is a critical error, the code should make sure never to
	 * get into a deadlock situation here */
	error_report(error_internal, "config_get", "cannot acquire lock");
	return NULL;
    }
    if (update_cn >= 0 && update_cn < UPDATE_COUNT && update_cn != currnum) {
	if (pthread_kill(update_thread, 0) != 0) {
	    free_one(update_cn);
	    update_cn = -1;
	}
    }
    refcount[currnum]++;
    pthread_mutex_unlock(&config_lock);
    return &configs[currnum];
}

/* stop using a read-only copy of the configuration */

void config_put(const config_data_t * cfg) {
    int cn, errcode;
    cn = cfg - configs;
    if (cn < 0 || cn >= UPDATE_COUNT) return;
    errcode = pthread_mutex_lock(&config_lock);
    if (errcode) {
	/* this is a critical error, the code should make sure never to
	 * get into a deadlock situation here */
	error_report(error_internal, "config_put", "cannot acquire lock");
	return;
    }
    if (update_cn >= 0 && update_cn < UPDATE_COUNT && update_cn != currnum) {
	if (pthread_kill(update_thread, 0) != 0) {
	    free_one(update_cn);
	    update_cn = -1;
	}
    }
    if (refcount[cn] > 0) refcount[cn]--;
    if (refcount[cn] < 1 && cn != currnum)
	free_one(cn);
    pthread_mutex_unlock(&config_lock);
}

/* makes a copy of the configuration which will allow updates; returns an
 * error message, or NULL if OK */
 
const char * config_start_update(void) {
    int errcode = pthread_mutex_lock(&config_lock), cn;
    if (errcode)
	return "Cannot lock configuration for update";
    if (update_cn >= 0 && update_cn < UPDATE_COUNT && update_cn != currnum) {
	if (pthread_kill(update_thread, 0) != 0) {
	    free_one(update_cn);
	    update_cn = -1;
	}
    }
    if (update_cn >= 0) {
	pthread_mutex_unlock(&config_lock);
	return "Update already in progress, try again later";
    }
    cn = 0;
    while (cn < UPDATE_COUNT && in_use[cn]) cn++;
    if (cn >= UPDATE_COUNT) {
	pthread_mutex_unlock(&config_lock);
	return "No update space left, try again later";
    }
    if (! copy_current(cn)) {
	free_one(cn);
	pthread_mutex_unlock(&config_lock);
	return "Cannot initialise update buffer, try again later";
    }
    update_cn = cn;
    update_thread = pthread_self();
    pthread_mutex_unlock(&config_lock);
    return NULL;
}

/* updates the configuration; this only works if config_update has been
 * called and also the update is valid; returns an error message or NULL
 * if the update succeeded */

const char * config_do_update(const char * line) {
    int errcode = pthread_mutex_lock(&config_lock);
    locfl_t locfl = locfl_NONE;
    const char * err;
    if (errcode)
	return "Cannot lock configuration for update";
    if (update_cn < 0 || update_cn >= UPDATE_COUNT) {
	pthread_mutex_unlock(&config_lock);
	return "config_start_update was not called";
    }
    if (! pthread_equal(update_thread, pthread_self())) {
	pthread_mutex_unlock(&config_lock);
	return "config_start_update was called by a different thread";
    }
    err = parsearg(line, &locfl, 0);
    pthread_mutex_unlock(&config_lock);
    return err;
}

/* commits the configuration update; the next call to config_get() will
 * get the new configuration */
 
const char * config_commit_update(void) {
    int errcode = pthread_mutex_lock(&config_lock);
    if (errcode)
	return "Cannot lock configuration for update";
    if (update_cn < 0 || update_cn >= UPDATE_COUNT) {
	pthread_mutex_unlock(&config_lock);
	return "config_start_update was not called";
    }
    if (! pthread_equal(update_thread, pthread_self())) {
	pthread_mutex_unlock(&config_lock);
	return "config_start_update was called by a different thread";
    }
    in_use[update_cn] = 1;
    refcount[update_cn] = 1;
    refcount[currnum]--;
    currnum = update_cn;
    update_cn = -1;
    pthread_mutex_unlock(&config_lock);
    return NULL;
}

/* cancels the update */

void config_cancel_update(void) {
    int errcode = pthread_mutex_lock(&config_lock);
    if (errcode)
	return;
    if (update_cn < 0 || update_cn >= UPDATE_COUNT) {
	pthread_mutex_unlock(&config_lock);
	return;
    }
    if (! pthread_equal(update_thread, pthread_self())) {
	if (pthread_kill(update_thread, 0) == 0) {
	    pthread_mutex_unlock(&config_lock);
	    return;
	}
    }
    free_one(update_cn);
    update_cn = -1;
    pthread_mutex_unlock(&config_lock);
}

