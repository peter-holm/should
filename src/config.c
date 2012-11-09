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

#define _GNU_SOURCE /* undo some of glibc's brain damage; works fine
                     * on BSD and other real OSs without this */
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
#include <fnmatch.h>
#include <arpa/inet.h>
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
#define INITIAL_COMMENTS_CONFIG \
	"# Copy configuration file for \"should\"\n" \
	"# This file is sourced by %s: use the command\n" \
	"#     should copy=%s\n" \
	"# to start the copy\n"
#define INITIAL_COMMENTS_STATE \
	"# Plese do not alter or delete the previous line\n" \
	"# Plese do not modify this file while the program is running\n"
#define CONFIG_COMMENTS_STATE \
	"# See file %s for editable configuration\n"
#define FINAL_COMMENTS \
	"# Plese do not alter or delete anything after this line\n"

#define UPDATE_COUNT 5
#define LINE_SIZE 1024

typedef struct {
    char * message;
    int dest;
    int facility;
} errdata_t;

struct config_data_s {
    int intval[cfg_int_COUNT];
    int intarrlen[cfg_intarr_COUNT];
    int * intarrval[cfg_intarr_COUNT];
    int strlength[cfg_str_COUNT];
    char * strval[cfg_str_COUNT];
    config_strlist_t * strlist[cfg_strlist_COUNT];
    char ** strarrval[cfg_strarr_COUNT];
    config_acl_t * aclval[cfg_acl_COUNT];
    errdata_t errdata[error_MAX];
};

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

typedef enum {
    include_silent = 0x01,
    include_state  = 0x02,
    include_none   = 0x00
} include_t;

typedef enum {
    assign_isdir   = 0x01,
    assign_nodups  = 0x02,
    assign_none    = 0x00
} assign_t;

/* table of user permissions */

static struct {
    const char * name;
    config_userop_t perms;
} user_perms[] = {
    { "all",       config_op_all },
    { "status",    config_op_status },
    { "watches",   config_op_watches },
    { "add",       config_op_add },
    { "remove",    config_op_remove },
    { "closelog",  config_op_closelog },
    { "purge",     config_op_purge },
    { "getconf",   config_op_getconf },
    { "setconf",   config_op_setconf },
    { "read",      config_op_read },
    { "ignore",    config_op_ignore },
    { "dirsync",   config_op_dirsync },
    { "debug",     config_op_debug },
    { "stop",      config_op_stop },
    { NULL,        0 }
};

static config_data_t configs[UPDATE_COUNT];
static int currnum, refcount[UPDATE_COUNT], in_use[UPDATE_COUNT], update_cn;
static pthread_mutex_t config_lock;
static char errbuff[LINE_SIZE];
static pthread_t update_thread;

/* initial values for integer data */

static const int default_ints[cfg_int_COUNT] = {
    [cfg_event_meta]               = config_file_all,
    [cfg_event_data]               = config_file_all,
    [cfg_event_create]             = config_file_all,
    [cfg_event_delete]             = config_file_all,
    [cfg_event_rename]             = config_file_all,
    [cfg_flags]                    = config_flag_translate_ids
                                   | config_flag_skip_matching,
                                   // | config_flag_use_librsync,
    [cfg_client_mode]              = config_client_NONE,
#if USE_SHOULDBOX
    [cfg_server_mode]              = config_server_NONE,
#else
    [cfg_server_mode]              = config_server_detach,
#endif
    [cfg_notify_queue_block]       = 1048576,
    [cfg_notify_initial]           = 2,
    [cfg_notify_max]               = 8,
    [cfg_notify_watch_block]       = 32,
    [cfg_notify_buffer]            = 1048576,
    [cfg_notify_name_block]        = 32758,
    [cfg_eventsize]                = 10485760,
    [cfg_checkpoint_events]        = 60,
    [cfg_checkpoint_time]          = 60,
    [cfg_bwlimit]                  = 0,
    [cfg_purge_days]               = 0,
    [cfg_autopurge_days]           = 14,
    [cfg_optimise_client]          = 128,
    [cfg_optimise_buffer]          = 262144,
    [cfg_dirsync_interval]         = 0,
};

FILE * config_copy_file = NULL;
long config_copy_start = -1;

const config_unit_t config_intervals[] = {
    {      1,   "second",    "seconds" },
    {     60,   "minute",    "minutes" },
    {   3600,   "hour",      "hours"   },
    {  86400,   "day",       "days"    },
    { 604800,   "week",      "weeks"   },
    {      0,   NULL,        NULL      }
};

const config_unit_t config_sizes[] = {
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

static int parse_units(const char * name, const config_unit_t * units,
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
	while (units->name_singular) {
	    if ((len == strlen(units->name_plural) &&
		 strncmp(ep, units->name_plural, len) == 0) ||
		(len == strlen(units->name_singular) &&
		 strncmp(ep, units->name_singular, len) == 0))
	    {
		lnum *= units->multiply;
		if (lnum <= 0) {
		    snprintf(errbuff, LINE_SIZE, "Number too large (%s)", name);
		    *err = errbuff;
		    return -1;
		}
		break;
	    }
	    units++;
	}
	if (! units->name_plural) {
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

/* parse a number + unit and returns a plain number */

int config_parse_units(const config_unit_t units[], const char * name) {
    const char * err = NULL;
    int rv = parse_units(name, units, &err);
    if (err) fprintf(stderr, "%s\n", err);
    return rv;
}

/* the opposite of the above */

const char * config_print_unit(const config_unit_t units[], int num) {
    static char unitbuff[512];
    const config_unit_t * found = NULL;
    /* find the best unit */
    while (units->name_singular) {
	if (num % units->multiply == 0)
	    if (! found || found->multiply < units->multiply)
		found = units;
	units++;
    }
    if (found) {
	num /= found->multiply;
	snprintf(unitbuff, sizeof(unitbuff), "%d %s",
		 num, num == 1 ? found->name_singular : found->name_plural);
    } else {
	snprintf(unitbuff, sizeof(unitbuff), "%d", num);
    }
    return unitbuff;
}

/* parse a day range (mon-fri or tue,sat or sun,tue-thu,sat etc); returns
 * a pointer to the end of the parsed range and updates the second argument
 * with the corresponding mask; if the range is invalid, returns NULL */

static const char * parse_dayrange(const char * dr, int * mask) {
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

static const char * print_dayrange(int dr) {
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
			 assign_t flags, char ** result, int * reslen,
			 const char ** err)
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
    if ((flags & assign_isdir) && *line != '/') {
	snprintf(errbuff, LINE_SIZE,
		 "Value for %s is not an absolute path", keyword);
	*err = errbuff;
	return 1;
    }
    len = strlen(line);
    while (len > 0 && isspace((int)line[len - 1])) len--;
    if (*result) {
	if (flags & assign_nodups) {
	    snprintf(errbuff, LINE_SIZE,
		     "Repeated value for %s", keyword);
	    *err = errbuff;
	    return 1;
	}
	myfree(*result);
    }
    *result = mymalloc(len + 1);
    if (! *result) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	return 1;
    }
    strncpy(*result, line, len);
    (*result)[len] = 0;
    if (reslen) *reslen = len;
    unquote_string(*result);
    *err = NULL;
    return 1;
}

static int assign_strval(const char * line, const char * keyword,
			 assign_t flags, int cn, config_str_names_t sv,
			 const char ** err)
{
    return assign_string(line, keyword, flags, &configs[cn].strval[sv],
			 &configs[cn].strlength[sv], err);
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
		       const config_unit_t * units, int * result,
		       const char ** err)
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
			  const char * (*check)(char *, void *), void * arg,
			  config_strlist_t ** sl, const char ** err)
{
    char * st = NULL;
    int slen;
    if (assign_string(line, kw, assign_none, &st, &slen, err)) {
	config_strlist_t * elem;
	if (* err)
	    return 1;
	if (check) {
	    *err = check(st, arg);
	    if (* err) {
		myfree(st);
		return 1;
	    }
	}
	elem = mymalloc(sizeof(config_strlist_t) + slen + 1);
	if (! elem) {
	    int e = errno;
	    myfree(st);
	    *err = error_sys_errno_r(errbuff, LINE_SIZE, "config", "malloc", e);
	    return 1;
	}
	memcpy(elem->data, st, slen);
	elem->data[slen] = 0;
	elem->datalen = slen;
	elem->privdata = NULL;
	elem->freepriv = NULL;
	elem->duppriv = NULL;
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
	myfree(st);
	return 1;
    }
    return 0;
}

/* frees an ACL / condition */

void config_free_acl_cond(config_acl_cond_t * list) {
    while (list) {
	config_acl_cond_t * this = list;
	list = list->next;
	if (this->how == cfg_acl_call_or || this->how == cfg_acl_call_and)
	    config_free_acl_cond(this->subcond);
	myfree(this);
    }
}

/* functions to handle with hashed passwords */

#ifdef THEY_HAVE_SSL
void config_hash_user(const char * user, const char * pass, int ctype,
		      const unsigned char * challenge, unsigned char * hash)
{
    int ulen = user ? strlen(user) : 0, plen = pass ? strlen(pass) : 0;
    char data[2 + CHALLENGE_SIZE + ulen + plen], * dptr = data;
    if (user) {
	strcpy(dptr, user);
	dptr += ulen;
    }
    memcpy(dptr, challenge, CHALLENGE_SIZE);
    dptr += CHALLENGE_SIZE;
    if (pass) {
	strcpy(dptr, pass);
	dptr += plen;
    }
    checksum_data(ctype, data, ulen + plen + CHALLENGE_SIZE, hash);
}

static int hash_and_compare(const char * password, const char * hashed,
			    const char * data[], int datasize)
{
    int ctype = *(int *)data[cfg_uacl_checksum];
    int cslen = checksum_size(ctype);
    unsigned char hashcmp[cslen];
    config_hash_user(data[cfg_uacl_user], password, ctype,
		     (unsigned char *)data[cfg_uacl_challenge], hashcmp);
    if (memcmp(data[cfg_uacl_pass], hashcmp, cslen) == 0)
	return 1;
    return 0;
}
#else
static int hash_and_compare(const char * password, const char * hashed,
			    const char * data[], int datasize)
{
    return 0;
}
#endif

/* parse a user spec and make it into an ACL */

static int assign_user(const char * line, const char * kw, int is_tcp,
		       int hostacl, config_acl_t * acl, const char ** err)
{
    char * st = NULL, * colon, * base;
    config_acl_cond_t * last = NULL, * host = NULL, * hostadd = NULL;
    int len;
    if (! assign_string(line, kw, assign_none, &st, NULL, err)) return 0;
    if (*err) return 1;
    acl->next = NULL;
    acl->cond = NULL;
    acl->result = 0;
    /* allocate ACL element for user */
    colon = strchr(st, ':');
    if (colon) {
	len = colon - st;
	colon++;
    } else {
	len = strlen(st);
    }
    last = mymalloc(sizeof(config_acl_cond_t) + len + 1);
    if (! last) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	myfree(st);
	return 1;
    }
    last->next = NULL;
    last->how = cfg_acl_exact;
    last->data_index = cfg_uacl_user;
    last->negate = 0;
    strncpy(last->pattern, st, len);
    last->pattern[len] = 0;
    acl->cond = last;
    base = colon;
    if (is_tcp) {
	/* allocate ACL element for password */
	config_acl_cond_t * pwd;
	if (base) {
	    colon = strchr(base, ':');
	    if (colon)  {
		len = colon - base;
		colon++;
	    } else {
		len = strlen(base);
	    }
	} else {
	    colon = NULL;
	    len = 0;
	}
	pwd = mymalloc(sizeof(config_acl_cond_t) + 1 + len);
	if (! pwd) {
	    *err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	    myfree(last);
	    myfree(st);
	    acl->cond = NULL;
	    return 1;
	}
	pwd->next = NULL;
	pwd->how = cfg_acl_function;
	pwd->data_index = cfg_uacl_pass;
	pwd->negate = 0;
	pwd->func = hash_and_compare;
	if (len > 0)
	    strncpy(pwd->pattern, base, len);
	pwd->pattern[len] = 0;
	last->next = pwd;
	last = pwd;
	base = colon;
    }
    /* now check for permissions / further conditions */
    while (base) {
	int neg = 0, aslen;
	char * as = NULL;
	while (*base && isspace((int)*base)) base++;
	if (*base == '!') {
	    neg = 1;
	    base++;
	    while (*base && isspace((int)*base)) base++;
	}
	colon = strchr(base, ',');
	if (colon)  {
	    len = colon - base;
	    colon++;
	} else {
	    len = strlen(base);
	}
	while (len > 0 && isspace((int)base[len - 1])) base--;
	if (len > 0) {
	    config_userop_t add = 0;
	    int n;
	    base[len] = 0;
	    for (n = 0; user_perms[n].name && ! add; n++)
		if (strcmp(base, user_perms[n].name) == 0)
		    add = user_perms[n].perms;
	    if (add) {
		if (neg)
		    acl->result &= ~add;
		else
		    acl->result |= add;
	    } else if (is_tcp && hostacl &&
		       assign_string(base, "host", assign_none,
				     &as, &aslen, err))
	    {
		config_acl_cond_t * h;
		char * slash, * dash, * name;
		unsigned char addr1[16], addr2[16];
		int addrlen, how, index, bits = 0xff;
		if (*err) goto error;
		/* see if it is an IPv4 or IPv6 range */
		slash = strchr(as, '/');
		dash = strchr(as, '-');
		if (slash) *slash++ = 0;
		else if (dash) *dash++ = 0;
		name = as;
		addrlen = strlen(as);
		if (addrlen > 2 && as[0] == '[' && as[addrlen - 1] == ']') {
		    name++;
		    as[addrlen - 1] = 0;
		}
		if (dash) {
		    addrlen = strlen(dash);
		    if (addrlen > 2 &&
			dash[0] == '[' &&
			dash[addrlen - 1] == ']')
		    {
			dash[addrlen - 1] = 0;
			dash++;
		    }
		}
		if (inet_pton(AF_INET, name, addr1) > 0) {
		    addrlen = 4;
		    how = cfg_acl_ip4range;
		    index = cfg_uacl_ipv4;
		    if (dash)
			if (inet_pton(AF_INET, name = dash, addr2) <= 0)
			    goto invadd;
		} else if (inet_pton(AF_INET6, name, addr1) > 0) {
		    addrlen = 16;
		    how = cfg_acl_ip6range;
		    index = cfg_uacl_ipv6;
		    if (dash)
			if (inet_pton(AF_INET6, name = dash, addr2) <= 0)
			    goto invadd;
		} else {
		invadd:
		    snprintf(errbuff, LINE_SIZE, "Invalid address: %s", name);
		    *err = errbuff;
		    myfree(as);
		    goto error;
		}
		if (slash) {
		    int bytes, rbits;
		    bits = atoi(slash);
		    if (bits < 0 || bits > addrlen * 8) {
			snprintf(errbuff, LINE_SIZE, "Invalid mask: %s", slash);
			*err = errbuff;
			myfree(as);
			goto error;
		    }
		    memcpy(addr2, addr1, addrlen);
		    bytes = bits / 8;
		    rbits = bits - 8 * bytes;
		    if (rbits) {
			unsigned char mask = 0xff >> rbits;
			addr1[bytes] &= mask;
			addr2[bytes] |= ~mask;
			bytes++;
		    }
		    while (bytes < addrlen) {
			addr1[bytes] = 0;
			addr2[bytes] = 0xff;
			bytes++;
		    }
		} else if (! dash) {
		    memcpy(addr2, addr1, addrlen);
		}
		h = mymalloc(sizeof(config_acl_cond_t) + 2 * addrlen + 1);
		if (! h) {
		    *err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
		    myfree(as);
		    goto error;
		}
		h->next = NULL;
		h->how = how;
		h->data_index = index;
		h->negate = neg;
		memcpy(h->pattern, addr1, addrlen);
		memcpy(h->pattern + addrlen, addr2, addrlen);
		h->pattern[2 * addrlen] = bits;
		if (hostadd)
		    hostadd->next = h;
		else
		    host = h;
		hostadd = h;
		myfree(as);
	    } else if (! is_tcp && hostacl &&
		       assign_string(base, "socket", assign_none,
				     &as, &aslen, err))
	    {
		config_acl_cond_t * h;
		if (*err) goto error;
		h = mymalloc(sizeof(config_acl_cond_t) + 1 + aslen);
		if (! h) {
		    *err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
		    myfree(as);
		    goto error;
		}
		h->next = host;
		h->how = cfg_acl_exact;
		h->data_index = cfg_uacl_path;
		h->negate = 0;
		strcpy(h->pattern, as);
		host = h;
		myfree(as);
	    } else {
		snprintf(errbuff, LINE_SIZE, "Unknown action: %s", base);
		*err = errbuff;
	    error:
		config_free_acl_cond(acl->cond);
		config_free_acl_cond(host);
		acl->cond = NULL;
		myfree(st);
		return 1;
	    }
	}
	base = colon;
    }
    if (host) {
	last->next = mymalloc(sizeof(config_acl_cond_t));
	if (last->next) {
	    last = last->next;
	    last->next = NULL;
	    last->how = cfg_acl_call_or;
	    last->data_index = 0;
	    last->negate = 0;
	    last->subcond = host;
	} else {
	    *err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	    config_free_acl_cond(acl->cond);
	    config_free_acl_cond(host);
	    acl->cond = NULL;
	}
    }
    myfree(st);
    return 1;
}

static error_message_t assign_error(const char * line, const char * keyword,
				    char ** result, const char ** err,
				    int * byclass)
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
	int fail = 1;
	if (byclass) {
	    fail = 0;
	    if (namelen == 4 && strncmp(line, "info", 4) == 0)
		*byclass = error_level_info;
	    else if (namelen == 4 && strncmp(line, "warn", 4) == 0)
		*byclass = error_level_warn;
	    else if (namelen == 7 && strncmp(line, "warning", 7) == 0)
		*byclass = error_level_warn;
	    else if (namelen == 3 && strncmp(line, "err", 3) == 0)
		*byclass = error_level_err;
	    else if (namelen == 5 && strncmp(line, "error", 5) == 0)
		*byclass = error_level_err;
	    else if (namelen == 4 && strncmp(line, "crit", 4) == 0)
		*byclass = error_level_crit;
	    else if (namelen == 8 && strncmp(line, "critical", 8) == 0)
		*byclass = error_level_crit;
	    else
		fail = 1;
	}
	if (fail) {
	    snprintf(errbuff, LINE_SIZE,
		     "Invalid error code: %.*s", namelen, line);
	    *err = errbuff;
	    return error_MAX;
	}
	erm = 0;
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
    *err = NULL;;
    if (*byclass) *byclass = -1;
    return erm;
}

/* parse facility:level */

static const char * getfacility(const char * token, int * fp) {
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

/* used by the store thread to change its error dest to syslog; to be
 * called during initialisation only. Not thread-safe */

const char * config_change_error_dest(error_message_t E, const char * fm) {
    const char * err;
    if (E >= error_MAX)
	return "Invalid error code";
    err = getfacility(fm, &configs[currnum].errdata[E].facility);
    if (err) return err;
    configs[currnum].errdata[E].dest = error_dest_syslog;
    return NULL;
}

static int assign_match(const char * line, const char * kw, int cn, int which,
			config_dir_acl_t match, int how, const char ** err)
{
    config_acl_cond_t * el;
    char * st = NULL;
    int stlen;
    config_add_t * av;
    if (! assign_string(line, kw, assign_none, &st, &stlen, err))
	return 0;
    if (*err) return 1;
    if (! configs[cn].strlist[cfg_add_path] ||
	! configs[cn].strlist[cfg_add_path]->privdata)
    {
	myfree(st);
	snprintf(errbuff, LINE_SIZE, "%s must follow a dir", kw);
	*err = errbuff;
	return 1;
    }
    el = mymalloc(sizeof(config_acl_cond_t) + stlen + 1);
    if (! el) {
	*err = error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	myfree(st);
	return 1;
    }
    av = configs[cn].strlist[cfg_add_path]->privdata;
    if (which) {
	el->next = av->find;
	av->find = el;
    } else {
	el->next = av->exclude;
	av->exclude = el;
    }
    strcpy(el->pattern, st);
    myfree(st);
    el->data_index = match;
    el->how = how;
    el->negate = 0;
    return 1;
}

/* forward declaration */

static const char * includefile(const char *, include_t, locfl_t *);

/* add quotes etc to a name so it can be added to a configuration file */

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

/* print "keyword = name" after quoting the name */

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
		       const char * type, const config_acl_cond_t * m)
{
    int ok = 1;
    while (m) {
	const char * icase = "", * how = "", * what = "";
	char mbuffer[64];
	switch (m->data_index) {
	    case cfg_dacl_name : what = ""; break;
	    case cfg_dacl_path : what = "_path"; break;
	}
	switch (m->how) {
	    case cfg_acl_exact : icase = "";  how = ""; break;
	    case cfg_acl_icase : icase = "i"; how = ""; break;
	    case cfg_acl_glob  : icase = "";  how = "_glob"; break;
	    case cfg_acl_iglob : icase = "i"; how = "_glob"; break;
	    default            : break;
	}
	sprintf(mbuffer, "%s%s%s%s = ", icase, type, what, how);
	if (! printname(p, arg, mbuffer, m->pattern)) ok = 0;
	m = m->next;
    }
    return ok;
}

static int print_dirs(int (*p)(void *, const char *), void * arg,
		      const char * name, const config_strlist_t * d)
{
    char nbuff[10 + strlen(name)];
    int ok = 1;
    strcpy(nbuff, name);
    strcat(nbuff, " = ");
    while (d) {
	const config_add_t * av = d->privdata;
	printname(p, arg, nbuff, d->data);
	print_match(p, arg, "exclude", av->exclude);
	print_match(p, arg, "find", av->find);
	if (! p(arg, av->crossmount ? "#mount" : "mount")) ok = 0;
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

static int convert_filters(const char * title, char * buffer, const int orig[])
{
    int i, len = 0;
    char sep = '=';
    config_filter_t all = config_file_all, list[cfg_event_COUNT];
    add_string(buffer, &len, title);
    add_char(buffer, &len, ' ');
    /* if a bit is present in all, use that first */
    for (i = 0; i < cfg_event_COUNT; i++) {
	list[i] = orig[i];
	all &= list[i];
    }
    if (all == config_file_all) {
	add_string(buffer, &len, "= all");
	return len;
    }
    add_bits(buffer, &len, &sep, all, NULL);
    for (i = 0; i < cfg_event_COUNT; i++)
	list[i] &= ~all;
    /* do remaining bits */
    add_event(buffer, &len, &sep, orig[cfg_event_meta],
	      list[cfg_event_meta], "meta");
    add_event(buffer, &len, &sep, orig[cfg_event_data],
	      list[cfg_event_data], "data");
    add_event(buffer, &len, &sep, orig[cfg_event_create],
	      list[cfg_event_create], "create");
    add_event(buffer, &len, &sep, orig[cfg_event_delete],
	      list[cfg_event_delete], "delete");
    add_event(buffer, &len, &sep, orig[cfg_event_rename],
	      list[cfg_event_rename], "rename");
    if (sep == '=')
	add_string(buffer, &len, "none");
    return len;
}

static int print_filters(int (*p)(void *, const char *), void * arg,
			 const char * title, const int list[])
{
    int len = convert_filters(title, NULL, list);
    char buffer[len + 1];
    convert_filters(title, buffer, list);
    return p(arg, buffer);
}

static int print_list(int (*p)(void *, const char *), void * arg,
		      const char * title, const char * (*name)(int),
		      int num, const int * list, char sep)
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
	const char * s = name(list[i + 1]);
	if (s) {
	    *bp++ = i ? sep : '=';
	    *bp++ = ' ';
	    strcpy(bp, s);
	    bp += strlen(s);
	}
    }
    return p(arg, buffer);
}

static int print_all(int (*p)(void *, const char *), void * arg,
		     const char * title, const char * (*name)(int),
		     int num, char sep)
{
    int list[num], i;
    for (i = 0; i < num; i++)
	list[i] = i;
    return print_list(p, arg, title, name, num, list, sep);
}

static const char * int_to_timed(int spec) {
    static char result[64];
    int daymask = spec >> 24;
    int start_time = spec & 0xffffff;
    const char * dr = print_dayrange(daymask);
    snprintf(result, sizeof(result), "%s %02d:%02d",
	     dr, (start_time / 3600) % 24, (start_time / 60) % 60);
    return result;
}

static int print_command(int (*p)(void *, const char *), void * arg,
			 const char * title, char * const * data)
{
    int len = strlen(title) + 3, i;
    if (! data || ! data[0]) return 1;
    for (i = 0; data[i]; i++) {
	const char * dp = data[i];
	len++;
	if (*dp) {
	    int p, sp;
	    for (p = sp = 0; dp[p]; p++) {
		if (isspace((int)dp[p]))
		    sp = 1;
		if (dp[p] == '"' || dp[p] == '\\') len++;
		len++;
	    }
	    if (sp) len += 2;
	} else {
	    len += 2;
	}
    }
    char buffer[len], * bp = buffer;
    strcpy(bp, title);
    bp += strlen(title);
    *bp++ = ' ';
    *bp++ = '=';
    for (i = 0; data[i]; i++) {
	const char * dp = data[i];
	*bp++ = ' ';
	if (*dp) {
	    int p, sp;
	    for (p = sp = 0; dp[p]; p++)
		if (isspace((int)dp[p]))
		    sp = 1;
	    if (sp) *bp++ = '"';
	    for (p = 0; dp[p]; p++) {
		if (dp[p] == '"' || dp[p] == '\\')
		    *bp++ = '\\';
		*bp++ = dp[p];
	    }
	    if (sp) *bp++ = '"';
	} else {
	    *bp++ = '"';
	    *bp++ = '"';
	}
    }
    *bp = 0;
    return p(arg, buffer);
}

/* interprets an ACL as a users list and prints it */

static inline int store_subcond(const config_acl_cond_t * host,
				char * rp, char * sep)
{
    int len = 0;
    if (host && host->how == cfg_acl_call_or && host->subcond) {
	host = host->subcond;
	while (host) {
	    if (host->data_index == cfg_uacl_path) {
		char buffer[20 + 4 * strlen(host->pattern)];
		convertname(host->pattern, buffer);
		if (rp) {
		    rp[len] = *sep;
		    strcpy(rp + len + 1, "socket=");
		    strcpy(rp + len + 8, buffer);
		    *sep = ',';
		}
		len += 8 + strlen(buffer);
	    } else if (host->data_index == cfg_uacl_ipv4) {
		int bits = host->pattern[8];
		if (bits >= 0 && bits <= 32) {
		    char buffer[40];
		    int bl;
		    inet_ntop(AF_INET, host->pattern, buffer, 32);
		    bl = strlen(buffer);
		    sprintf(buffer + bl, "/%d", bits);
		    if (rp) {
			rp[len] = *sep;
			strcpy(rp + len + 1, "host=");
			strcpy(rp + len + 6, buffer);
			*sep = ',';
		    }
		    len += 6 + strlen(buffer);
		} else {
		    char buffer[32];
		    inet_ntop(AF_INET, host->pattern, buffer, 32);
		    if (rp) {
			rp[len] = *sep;
			strcpy(rp + len + 1, "host=");
			strcpy(rp + len + 6, buffer);
			*sep = ',';
		    }
		    len += 6 + strlen(buffer);
		    inet_ntop(AF_INET, host->pattern + 4, buffer, 32);
		    if (rp) {
			rp[len] = '-';
			strcpy(rp + len + 1, buffer);
		    }
		    len += 1 + strlen(buffer);
		}
	    } else if (host->data_index == cfg_uacl_ipv6) {
		int bits = host->pattern[32];
		if (bits >= 0 && bits <= 128) {
		    char buffer[80];
		    int bl;
		    inet_ntop(AF_INET6, host->pattern, buffer, 72);
		    bl = strlen(buffer);
		    sprintf(buffer + bl, "/%d", bits);
		    if (rp) {
			rp[len] = *sep;
			strcpy(rp + len + 1, "host=");
			strcpy(rp + len + 6, buffer);
			*sep = ',';
		    }
		    len += 6 + strlen(buffer);
		} else {
		    char buffer[72];
		    inet_ntop(AF_INET6, host->pattern, buffer, 72);
		    if (rp) {
			rp[len] = *sep;
			strcpy(rp + len + 1, "host=");
			strcpy(rp + len + 6, buffer);
			*sep = ',';
		    }
		    len += 6 + strlen(buffer);
		    inet_ntop(AF_INET6, host->pattern + 16, buffer, 72);
		    if (rp) {
			rp[len] = '-';
			strcpy(rp + len + 1, buffer);
		    }
		    len += 1 + strlen(buffer);
		}
	    }
	    host = host->next;
	}
    }
    return len;
}

static int print_userslist(int (*p)(void *, const char *), void * arg,
			   const config_acl_t * U, int is_tcp, int mask)
{
    int ok = 1, n, totlen = 0;
    for (n = 0; user_perms[n].name; n++)
	totlen += 1 + strlen(user_perms[n].name);
    while (U) {
	const config_acl_cond_t * cond = U->cond;
	if (cond &&
	    cond->how == cfg_acl_exact &&
	    cond->data_index == cfg_uacl_user &&
	    (! is_tcp ||
	     (cond->next &&
	      cond->next->how == cfg_acl_function &&
	      cond->next->data_index == cfg_uacl_pass)))
	{
	    const char * user = cond->pattern, * title;
	    const char * pass = is_tcp ? cond->next->pattern : "";
	    const config_acl_cond_t * host =
		is_tcp ? cond->next->next : cond->next;
	    int sclen = store_subcond(host, NULL, NULL);
	    char up[strlen(user) + strlen(pass) + totlen + sclen + 50], * ep;
	    char sep = ':';
	    strcpy(up, user);
	    ep = up + strlen(up);
	    if (is_tcp) {
		title = "allow_tcp = ";
		*ep++ = ':';
		strcpy(ep, mask ? "*" : pass);
		ep += strlen(ep);
	    } else {
		title = "allow_unix = ";
	    }
	    /* add any host= and socket= conditions */
	    store_subcond(host, ep, &sep);
	    ep += sclen;
	    if (U->result != config_op_all) {
		for (n = 0; user_perms[n].name; n++) {
		    if (user_perms[n].perms == config_op_all) continue;
		    if (! (U->result & user_perms[n].perms)) continue;
		    *ep++ = sep;
		    sep = ',';
		    strcpy(ep, user_perms[n].name);
		    ep += strlen(ep);
		}
	    }
	    if (! printname(p, arg, title, up))
		ok = 0;
	}
	U = U->next;
    }
    return ok;
}

/* stores copy data to a small configuration file, suitable for loading
 * by the copy thread */

int config_store_copy(int fnum, int fpos, const char * user, const char * pass)
{
    config_strlist_t * l;
    FILE * SF = NULL, * CF = NULL;
    int cfd = -1, sfd, use_extra = 0;
    const char * sname, * cname;
    sname = configs[currnum].strval[cfg_copy_state];
    cname = configs[currnum].strval[cfg_copy_config];
    sfd = open(sname, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (sfd < 0)
	goto problem_s;
    if (lseek(sfd, (off_t)0, SEEK_SET) < 0)
	goto problem_s;
    if (lockf(sfd, F_LOCK, (off_t)0) < 0)
	goto problem_s;
    SF = fdopen(sfd, "w");
    if (! SF)
	goto problem_s;
    if (cname) {
	cfd = open(cname, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (cfd < 0)
	    goto problem_c;
	if (lseek(cfd, (off_t)0, SEEK_SET) < 0)
	    goto problem_c;
	if (lockf(cfd, F_LOCK, (off_t)0) < 0)
	    goto problem_c;
	CF = fdopen(cfd, "w");
	if (! CF)
	    goto problem_c;
	if (fprintf(CF, INITIAL_COMMENTS_CONFIG, sname, sname) < 0)
	    goto problem_c;
	use_extra = 1;
    } else {
	cfd = -1;
	CF = SF;
	cname = sname;
    }
    if (fprintf(SF, IDENTIFY_COPY "\n", IDENTIFY_VERSION) < 0)
	goto problem_s;
    if (fprintf(SF, INITIAL_COMMENTS_STATE) < 0)
	goto problem_s;
    if (use_extra) {
	if (fprintf(SF, CONFIG_COMMENTS_STATE, cname) < 0)
	    goto problem_s;
	if (! printname(sendout, SF, "include = ", cname))
	    goto problem_s;
    }
    if (! printname(sendout, CF, "from = ",
		    configs[currnum].strval[cfg_from_prefix]))
	goto problem_c;
    if (! printname(sendout, CF, "to = ",
		    configs[currnum].strval[cfg_to_prefix]))
	goto problem_c;
    l = configs[currnum].strlist[cfg_listen];
    while (l) {
	if (l->data[0] != '/') {
	    int hlen = strlen(l->data);
	    const char * port = l->data + 1 + hlen;
	    char lhost[32 + hlen + strlen(port)];
	    int c = strchr(l->data, ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", l->data, c ? "]" : "", port);
	    if (! printname(sendout, CF, "listen = ", lhost))
		goto problem_c;
	} else {
	    if (! printname(sendout, CF, "listen = ", l->data))
		goto problem_c;
	}
	l = l->next;
    }
    if (! print_userslist(sendout, CF,
			  configs[currnum].aclval[cfg_acl_local], 0, 0))
	goto problem_c;
    if (! print_userslist(sendout, CF,
			  configs[currnum].aclval[cfg_acl_tcp], 1, 0))
	goto problem_c;
    if (configs[currnum].intval[cfg_flags] & config_flag_socket_changed) {
	if (configs[currnum].strval[cfg_server][0] != '/') {
	    int hlen = strlen(configs[currnum].strval[cfg_server]);
	    const char * port = configs[currnum].strval[cfg_server] + 1 + hlen;
	    char lhost[32 + hlen + strlen(port)];
	    int c = strchr(configs[currnum].strval[cfg_server], ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", configs[currnum].strval[cfg_server],
		    c ? "]" : "", port);
	    if (! printname(sendout, CF, "server = ", lhost))
		goto problem_c;
	} else {
	    if (! printname(sendout, CF, "server = ",
			    configs[currnum].strval[cfg_server]))
		goto problem_c;
	}
    }
    if (configs[currnum].strarrval[cfg_strarr_extcopy] &&
	! print_command(sendout, CF, "external_copy",
			configs[currnum].strarrval[cfg_strarr_extcopy]))
	    goto problem_c;
    if (configs[currnum].strarrval[cfg_strarr_tunnel] &&
	! print_command(sendout, CF, "tunnel",
			configs[currnum].strarrval[cfg_strarr_tunnel]))
	    goto problem_c;
    if (configs[currnum].strarrval[cfg_strarr_remote_should] &&
	! print_command(sendout, CF, "remote_should",
			configs[currnum].strarrval[cfg_strarr_remote_should]))
	    goto problem_c;
    if (user && ! printname(sendout, CF, "user = ", user))
	goto problem_c;
    if (pass && ! printname(sendout, CF, "password = ", pass))
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] & config_flag_translate_ids)
		    ? "translate_ids\n" : "keep_ids\n") < 0)
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] & config_flag_skip_matching)
		    ? "skip_matching\n" : "copy_matching\n") < 0)
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] & config_flag_use_librsync)
		    ? "enable_librsync\n" : "disable_librsync\n") < 0)
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] &
			config_flag_initial_dirsync)
		    ? "do_initial_dirsync\n" : "skip_initial_dirsync\n") < 0)
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] &
			config_flag_overflow_dirsync)
		    ? "do_overflow_dirsync\n" : "skip_overflow_dirsync\n") < 0)
	goto problem_c;
    if (fprintf(CF,
		(configs[currnum].intval[cfg_flags] &
			config_flag_dirsync_delete)
		    ? "dirsync_delete\n" : "no_dirsync_delete\n") < 0)
	goto problem_c;
    if (configs[currnum]. intval[cfg_dirsync_interval] > 0 &&
	! sendformat(sendout, CF, "dirsync_interval = %s",
		     config_print_unit(config_intervals,
			configs[currnum].intval[cfg_dirsync_interval])))
	goto problem_c;
    if (! sendformat(sendout, CF, "bwlimit = %d",
		     configs[currnum].intval[cfg_bwlimit]))
	goto problem_c;
    if (! sendformat(sendout, CF, "optimise_client = %d",
		     configs[currnum].intval[cfg_optimise_client]))
	goto problem_c;
    if (! sendformat(sendout, CF, "optimise_buffer = %s",
		     config_print_unit(config_sizes,
			configs[currnum].intval[cfg_optimise_buffer])))
	goto problem_c;
    if (! print_list(sendout, CF, "compression", compress_name,
		     configs[currnum].intarrlen[cfg_compressions],
		     configs[currnum].intarrval[cfg_compressions],
		     ','))
	goto problem_c;
    if (! print_list(sendout, CF, "checksum", checksum_name,
		     configs[currnum].intarrlen[cfg_checksums],
		     configs[currnum].intarrval[cfg_checksums],
		     ','))
	goto problem_c;
    if (! print_list(sendout, CF, "dirsync_timed", int_to_timed,
		      configs[currnum].intarrlen[cfg_dirsync_timed],
		      configs[currnum].intarrval[cfg_dirsync_timed],
		      ';'))
	goto problem_c;
    if (! print_filters(sendout, CF, "filter", configs[currnum].intval))
	goto problem_c;
    if (fprintf(SF, FINAL_COMMENTS) < 0)
	goto problem_s;
    if (fprintf(SF, "end_state\n") < 0)
	goto problem_s;
    if (fprintf(SF, "%d %d\n", fnum, fpos) < 0)
	goto problem_s;
    if (fflush(SF) < 0)
	goto problem_s;
    if (lseek(sfd, (off_t)0, SEEK_SET) < 0)
	goto problem_s;
    if (lockf(sfd, F_ULOCK, (off_t)0) < 0)
	goto problem_s;
    if (fclose(SF) < 0) {
	SF = NULL;
	goto problem_s;
    }
    sfd = -1;
    if (use_extra) {
	if (fflush(CF) < 0)
	    goto problem_c;
	if (lseek(cfd, (off_t)0, SEEK_SET) < 0)
	    goto problem_c;
	if (lockf(cfd, F_ULOCK, (off_t)0) < 0)
	    goto problem_c;
	if (fclose(CF) < 0) {
	    CF = NULL;
	    goto problem_c;
	}
    }
    return 1;
problem_s:
    error_report(error_setup, sname, errno);
    goto problem_both;
problem_c:
    error_report(error_setup, cname, errno);
problem_both:
    if (SF)
	fclose(SF);
    else if (sfd >= 0)
	close(sfd);
    if (use_extra) {
	if (CF)
	    fclose(CF);
	else if (cfd >= 0)
	    close(cfd);
    }
    return 0;
}

#define HASH \
    "######################################################################"

void print_one(int (*p)(void *, const char *), void * arg, int cn) {
    error_message_t E;
    p(arg, "# Configuration file for \"should\"");
    p(arg, "# Automatically generated from current options");
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Notify thread");
    p(arg, "");
    p(arg, "# Size of the notify queue allocation block");
    sendformat(p, arg, "queue_block = %s",
	       config_print_unit(config_sizes,
				 configs[cn].intval[cfg_notify_queue_block]));
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
	       config_print_unit(config_sizes,
				 configs[cn].intval[cfg_notify_name_block]));
    p(arg, "");
    p(arg, "# Size of the buffer used to receive data from the kernel");
    sendformat(p, arg, "buffer = %s",
	       config_print_unit(config_sizes,
				 configs[cn].intval[cfg_notify_buffer]));
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
    print_filters(p, arg, "filter", configs[cn].intval);
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
    if (configs[cn].strlist[cfg_listen]) {
	config_strlist_t * l = configs[cn].strlist[cfg_listen];
	while (l) {
	    if (l->data[0] != '/') {
		int hlen = strlen(l->data);
		const char * port = l->data + 1 + hlen;
		char lhost[32 + hlen + strlen(port)];
		int c = strchr(l->data, ':') != NULL;
		sprintf(lhost, "%s%s%s:%s",
			c ? "[" : "", l->data, c ? "]" : "", port);
		printname(p, arg, "listen = ", lhost);
	    } else {
		printname(p, arg, "listen = ", l->data);
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
    if (configs[cn].strval[cfg_server]) {
	if (configs[cn].strval[cfg_server][0] != '/') {
	    int hlen = strlen(configs[cn].strval[cfg_server]);
	    const char * port = configs[cn].strval[cfg_server] + 1 + hlen;
	    char lhost[32 + hlen + strlen(port)];
	    int c = strchr(configs[cn].strval[cfg_server], ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", configs[cn].strval[cfg_server],
		    c ? "]" : "", port);
	    printname(p, arg, "server = ", lhost);
	    p(arg, "#server = /PATH/TO/SOCKET");
	} else {
	    printname(p, arg, "server = ", configs[cn].strval[cfg_server]);
	    p(arg, "#server = HOSTNAME:PORT");
	}
    } else {
	p(arg, "#server = HOSTNAME:PORT");
	p(arg, "#server = /PATH/TO/SOCKET");
    }
    p(arg, "");
    p(arg, "# Use this program to set up a tunnel to connect to server");
    if (configs[cn].strarrval[cfg_strarr_tunnel])
	print_command(p, arg, "tunnel",
		      configs[cn].strarrval[cfg_strarr_tunnel]);
    else
	p(arg, "#tunnel = ssh user@host");
    p(arg, "");
    p(arg, "# Path (and extra args) to \"should\" at the other end of the tunnel");
    if (configs[cn].strarrval[cfg_strarr_remote_should])
	print_command(p, arg, "remote_should",
		      configs[cn].strarrval[cfg_strarr_remote_should]);
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
    if (configs[cn].aclval[cfg_acl_local]) {
	print_userslist(p, arg, configs[cn].aclval[cfg_acl_local], 0, 1);
    } else {
	p(arg, "#allow_unix = root");
	p(arg, "#allow_unix = user:status,closelog");
    }
    if (configs[cn].aclval[cfg_acl_tcp]) {
	print_userslist(p, arg, configs[cn].aclval[cfg_acl_tcp], 1, 1);
    } else {
	p(arg, "#allow_tcp = 'yourname:your secrets'");
	p(arg, "#allow_tcp = 'theirname:their secrets:all,!read,!remove,!setconf'");
    }
    p(arg, "");
    p(arg, HASH);
    p(arg, "# Server");
    p(arg, "");
    p(arg, "# Initial watches and operation mode");
    if (! (configs[cn].intval[cfg_client_mode] & config_client_add) &&
	   configs[cn].strlist[cfg_add_path])
    {
	print_dirs(p, arg, "dir", configs[cn].strlist[cfg_add_path]);
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
	       config_print_unit(config_sizes,
				 configs[cn].intval[cfg_eventsize]));
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
	configs[cn].strlist[cfg_add_path])
    {
	print_dirs(p, arg, "add", configs[cn].strlist[cfg_add_path]);
    } else {
	p(arg, "#add = /some/path");
	p(arg, "#add = /some/other/path");
	p(arg, "");
    }
    p(arg, "# remove directories from server's watch list");
    if ((configs[cn].intval[cfg_client_mode] & config_client_remove) &&
	configs[cn].strlist[cfg_remove_path])
    {
	config_strlist_t * r = configs[cn].strlist[cfg_remove_path];
	while (r) {
	    printname(p, arg, "remove = ", r->data);
	    r = r->next;
	}
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
	       config_print_unit(config_sizes,
				 configs[cn].intval[cfg_optimise_buffer]));
    p(arg, "");
    p(arg, "# Bandwidth limit (KB/s) for copy mode, 0 == no limits imposed");
    sendformat(p, arg, "bwlimit = %d", configs[cn].intval[cfg_bwlimit]);
    p(arg, "");
    p(arg, "# Preferred compression methods");
    print_list(p, arg, "compression", compress_name,
	       configs[cn].intarrlen[cfg_compressions],
	       configs[cn].intarrval[cfg_compressions],
	       ',');
    print_all(p, arg, "#compression", compress_name, compress_count(), ',');
    p(arg, "");
    p(arg, "# Preferred checksum methods");
    print_list(p, arg, "checksum", checksum_name,
	       configs[cn].intarrlen[cfg_checksums],
	       configs[cn].intarrval[cfg_checksums],
	       ',');
    print_all(p, arg, "#checksum", checksum_name, checksum_count(), ',');
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
		   config_print_unit(config_intervals,
		    configs[cn].intval[cfg_dirsync_interval]));
    } else {
	p(arg, "#dirsync_interval = 2 hours");
    }
    p(arg, "");
    p(arg, "# Do we do a timed dirsync?");
    if (configs[cn].intarrval[cfg_dirsync_timed]) {
	print_list(p, arg, "dirsync_timed", int_to_timed,
		   configs[cn].intarrlen[cfg_dirsync_timed],
		   configs[cn].intarrval[cfg_dirsync_timed],
		   ';');
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
    p(arg, "# Use this program to copy files (default: use internal copy)");
    if (configs[cn].strarrval[cfg_strarr_extcopy])
	print_command(p, arg, "external_copy",
		      configs[cn].strarrval[cfg_strarr_extcopy]);
    else
	p(arg, "#external_copy = rsync -aq0 --files-from - user@host:/from/ /to/");
    p(arg, "");
#if THEY_HAVE_LIBRSYNC
    p(arg, "# Use librsync for file copy?\n");
    if (configs[cn].intval[cfg_flags] & config_flag_use_librsync) {
	p(arg, "#disable_librsync");
	p(arg, "enable_librsync");
    } else {
	p(arg, "disable_librsync");
	p(arg, "#enable_librsync");
    }
    p(arg, "");
#endif
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
	       config_print_unit(config_intervals,
				 configs[cn].intval[cfg_checkpoint_time]));
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
    print_command(p, arg, "email_submit",
		  configs[cn].strarrval[cfg_strarr_email_submit]);
    p(arg, "");
    p(arg, "# Error messages and their reporting methods");
    p(arg, "");
    for (E = 0; E < error_MAX; E++) {
	const char * name = error_name(E);
	error_dest_t dest = configs[cn].errdata[E].dest;
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
	    int facility = configs[cn].errdata[E].facility;
	    sprintf(bptr,
		    "%c %s:%s",
		    comma,
		    print_facility(facility),
		    print_priority(facility));
	    bptr += strlen(bptr);
	    comma = ',';
	}
	if (comma == '=')
	    strcpy(buffer, "= none");
	printname2(p, arg, "message : ", name, " = ",
		   configs[cn].errdata[E].message);
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
	*eventmap = cfg_event_all;
    else if (strcmp(token, "meta") == 0)
	*eventmap = 1 << cfg_event_meta;
    else if (strcmp(token, "change_data") == 0)
	*eventmap = 1 << cfg_event_data;
    else if (strcmp(token, "create") == 0)
	*eventmap = 1 << cfg_event_create;
    else if (strcmp(token, "delete") == 0)
	*eventmap = 1 << cfg_event_delete;
    else if (strcmp(token, "rename") == 0)
	*eventmap = 1 << cfg_event_rename;
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
	*eventmap = cfg_event_all;
	return 1;
    }
    return 0;
}

static int split_command(char * st, char ** result, const char ** err) {
    int ptr = 0, ncom = 1;
    char in_quote = 0, * dest = NULL;
    if (result) result[0] = dest = st;
    while (st[ptr]) {
	char c = st[ptr++];
	if (c == '\\') {
	    if (! st[ptr]) {
		snprintf(errbuff, LINE_SIZE,
			 "Invalid command: end with backslash\n");
		*err = errbuff;
		return -1;
	    }
	    c = st[ptr++];
	    if (dest) *dest++ = c;
	    continue;
	}
	if (in_quote) {
	    if (c == in_quote)
		in_quote = 0;
	    else if (dest)
		*dest++ = c;
	    continue;
	}
	if (c == '"' || c == '\'') {
	    in_quote = c;
	    continue;
	}
	if (! isspace((int)c)) {
	    if (dest) *dest++ = c;
	    continue;
	}
	if (dest) *dest = 0;
	dest = NULL;
	while (st[ptr] && isspace((int)st[ptr])) ptr++;
	if (st[ptr]) {
	    if (result) result[ncom] = dest = st + ptr;
	    ncom++;
	}
    }
    if (in_quote) {
	snprintf(errbuff, LINE_SIZE,
		 "Invalid command: closing quote (%c) not found\n", in_quote);
	*err = errbuff;
	return -1;
    }
    if (dest) *dest = 0;
    if (result) result[ncom] = NULL;
    return ncom;
}

static int assign_command(const char * line, const char * kw,
			  char *** result, const char ** err)
{
    int ncom;
    char * st = NULL;
    if (! assign_string(line, kw, assign_none, &st, NULL, err)) return 0;
    if (*err) return 1;
    ncom = split_command(st, NULL, err);
    if (ncom < 0) return 1;
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
    ncom = split_command(st, *result, err);
    if (ncom < 0) {
	myfree(st);
	myfree(*result);
	*result = NULL;
	return 1;
    }
    *err = NULL;
    return 1;
}

static const char * check_socket(char * st, void * arg) {
    if (st[0] != '/') {
	int hlen;
	char * pb = strrchr(st, ':');
	if (! pb) {
	    snprintf(errbuff, LINE_SIZE,
		     "Invalid \"server\": %s (missing port)", st);
	    return errbuff;
	}
	hlen = pb - st;
	if (hlen > 2 && st[0] == '[' && st[hlen - 1] == ']') {
	    int i;
	    hlen--;
	    for (i = 0; i < hlen; i++)
		st[i] = st[i + 1];
	    st[hlen - 1] = 0;
	    strcpy(st + hlen, pb + 1);
	} else {
	    *pb = 0;
	}
    } else if (arg) {
	locfl_t *locfl = arg;
	*locfl |= locfl_has_socket;
    }
    return NULL;
}

/* free a private data for add / dir */

void config_free_add(config_add_t * this) {
    config_free_acl_cond(this->exclude);
    config_free_acl_cond(this->find);
    myfree(this);
}

static void free_add(void * _p) {
    config_free_add(_p);
}

/* copies a private data for add / dir */

static void * dup_add(const void * _p) {
    const config_add_t * old = _p;
    config_add_t * av = mymalloc(sizeof(config_add_t));
    if (av) {
	av->crossmount = old->crossmount;
	if (old->exclude) {
	    av->exclude = config_copy_acl_cond(old->exclude);
	    if (! av->exclude) {
		int e = errno;
		myfree(av);
		errno = e;
		return NULL;
	    }
	} else {
	    av->exclude = NULL;
	}
	if (old->find) {
	    av->find = config_copy_acl_cond(old->find);
	    if (! av->find) {
		int e = errno;
		config_free_acl_cond(av->exclude);
		myfree(av);
		errno = e;
		return NULL;
	    }
	} else {
	    av->find = NULL;
	}
    }
    return av;
}

/* parse single argument - things which make sense only during initial
 * configuration */

static const char * parsearg_initial(const char * line, locfl_t * locfl) {
    const char * err;
    char * st;
    int cn = currnum, iv;
    switch (line[0]) {
	case '/' : {
	    int slen = strlen(line);
	    config_strlist_t * dl =
		mymalloc(sizeof(config_strlist_t) + slen + 1);
	    config_add_t * al;
	    if (! dl)
		return error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	    memcpy(dl->data, line, slen);
	    dl->data[slen] = 0;
	    dl->datalen = slen;
	    dl->next = configs[cn].strlist[cfg_add_path];
	    configs[cn].strlist[cfg_add_path] = dl;
	add_watch :
	    dl = configs[cn].strlist[cfg_add_path];
	    dl->freepriv = free_add;
	    dl->duppriv = dup_add;
	    al = dl->privdata = mymalloc(sizeof(config_add_t));
	    if (! dl->privdata)
		return error_sys_r(errbuff, LINE_SIZE, "config", "malloc");
	    al->crossmount = 1;
	    al->find = NULL;
	    al->exclude = NULL;
	    return NULL;
	}
	break;
	case 'a' :
	    if (assign_strlist(line, "add_watch", 1, NULL, NULL,
		&configs[cn].strlist[cfg_add_path], &err))
	    {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_add;
		goto add_watch;
	    }
	    if (assign_strlist(line, "add", 1, NULL, NULL,
		&configs[cn].strlist[cfg_add_path], &err))
	    {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_add;
		goto add_watch;
	    }
	    break;
	case 'b' :
	    if (assign_unit(line, "buffer", config_sizes, &configs[cn].
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
	    if (assign_string(line, "config", assign_none, &st, NULL, &err)) {
		if (err) return err;
		err = includefile(st, include_none, locfl);
		myfree(st);
		return err;
	    }
	    if (assign_strval(line, "copy_config", assign_nodups,
			      cn, cfg_copy_config, &err))
		return err;
	    if (assign_strval(line, "copy", assign_nodups,
			      cn, cfg_copy_state, &err))
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
	    if (assign_string(line, "compression", assign_none,
			      &st, NULL, &err))
	    {
		char * saveptr = NULL, * token, * parse = st;
		int max = compress_count(), arr[max], num = 0;
		if (err) return err;
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
			for (k = 0; k < num; k++)
			    if (arr[k] == nc)
				found = 1;
			if (found) {
			    snprintf(errbuff, LINE_SIZE,
				     "Compression method %s already specfied",
				     token);
			    err = errbuff;
#if USE_SHOULDBOX
			} else if (num >= max) {
			    main_shouldbox++;
			    snprintf(errbuff, LINE_SIZE,
				     "Internal error, ncompressions = %d >= %d",
				     num, max);
			    err = errbuff;
#endif
			} else {
			    arr[num] = nc;
			    num++;
			}
		    }
		}
		myfree(st);
		if (! err) {
		    if (configs[cn].intarrval[cfg_compressions])
			myfree(configs[cn].intarrval[cfg_compressions]);
		    configs[cn].intarrval[cfg_compressions] =
			mymalloc(num * sizeof(int));
		    if (configs[cn].intarrval[cfg_compressions]) {
			int k;
			configs[cn].intarrlen[cfg_compressions] = num;
			for (k = 0; k < num; k++)
			    configs[cn].intarrval[cfg_compressions][k] =
				arr[k];
		    } else {
			err = error_sys_r(errbuff, LINE_SIZE,
					  "config", "malloc");
		    }
		}
		return err;
	    }
	    st = NULL;
	    if (assign_string(line, "checksum", assign_none, &st, NULL, &err)) {
		char * saveptr = NULL, * token, * parse = st;
		int max = checksum_count(), arr[max], num = 0;
		if (err) return err;
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
			for (k = 0; k < num; k++)
			    if (arr[k] == nc)
				found = 1;
			if (found) {
			    snprintf(errbuff, LINE_SIZE,
				     "Checksum method %s already specfied",
				     token);
			    err = errbuff;
#if USE_SHOULDBOX
			} else if (num >= max) {
			    main_shouldbox++;
			    snprintf(errbuff, LINE_SIZE,
				     "Internal error, nchecksums = %d >= %d",
				     num, max);
			    err = errbuff;
#endif
			} else {
			    arr[num] = nc;
			    num++;
			}
		    }
		}
		myfree(st);
		if (! err) {
		    if (configs[cn].intarrval[cfg_checksums])
			myfree(configs[cn].intarrval[cfg_checksums]);
		    configs[cn].intarrval[cfg_checksums] =
			mymalloc(num * sizeof(int));
		    if (configs[cn].intarrval[cfg_checksums]) {
			int k;
			configs[cn].intarrlen[cfg_checksums] = num;
			for (k = 0; k < num; k++)
			    configs[cn].intarrval[cfg_checksums][k] =
				arr[k];
		    } else {
			err = error_sys_r(errbuff, LINE_SIZE,
					  "config", "malloc");
		    }
		}
		return err;
	    }
	    if (assign_strlist(line, "cp", 1, NULL, NULL,
		&configs[cn].strlist[cfg_cp_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_cp;
		return err;
	    }
	    break;
	case 'd' :
	    if (assign_strlist(line, "dirsync", 0, NULL, NULL,
		&configs[cn].strlist[cfg_dirsync_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_dirsync;
		return err;
	    }
	    if (assign_strlist(line, "dir", 1, NULL, NULL,
		&configs[cn].strlist[cfg_add_path], &err))
	    {
		if (err) return err;
		goto add_watch;
	    }
	    if (strcmp(line, "detach") == 0) {
		configs[cn].intval[cfg_server_mode] |= config_server_detach;
		return NULL;
	    }
	    if (assign_strlist(line, "df", 0, NULL, NULL,
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
	    if (assign_strval(line, "eventdir", assign_isdir,
			      cn, cfg_eventdir, &err))
		return err;
	    if (assign_match(line, "exclude_path_glob", cn, 0, cfg_dacl_path,
			     cfg_acl_glob, &err))
		return err;
	    if (assign_match(line, "exclude_path", cn, 0, cfg_dacl_path,
			     cfg_acl_exact, &err))
		return err;
	    if (assign_match(line, "exclude_glob", cn, 0, cfg_dacl_name,
			     cfg_acl_glob, &err))
		return err;
	    if (assign_match(line, "exclude", cn, 0, cfg_dacl_name,
			     cfg_acl_exact, &err))
		return err;
	    if (assign_command(line, "external_copy",
			       &configs[cn].strarrval[cfg_strarr_extcopy],
			       &err))
		return err;
	    break;
	case 'f' :
	    st = NULL;
	    if (assign_string(line, "file", assign_none, &st, NULL, &err)) {
		if (err) return err;
		err = includefile(st, include_none, locfl);
		myfree(st);
		return err;
	    }
	    if (assign_match(line, "find_path_glob", cn, 1, cfg_dacl_path,
			     cfg_acl_glob, &err))
		return err;
	    if (assign_match(line, "find_path", cn, 1, cfg_dacl_path,
			     cfg_acl_exact, &err))
		return err;
	    if (assign_match(line, "find_glob", cn, 1, cfg_dacl_name,
			     cfg_acl_glob, &err))
		return err;
	    if (assign_match(line, "find", cn, 1, cfg_dacl_name,
			     cfg_acl_exact, &err))
		return err;
	    if (assign_strval(line, "from", assign_isdir,
			      cn, cfg_from_prefix, &err))
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
	    if (assign_strval(line, "homedir", assign_isdir,
			   cn, cfg_homedir, &err))
		return err;
	    break;
	case 'i' :
	    if (assign_int(line, "initial_blocks",
			   &configs[cn].intval[cfg_notify_initial], &err))
		return err;
	    if (assign_int(line, "initial",
			   &configs[cn].intval[cfg_notify_initial], &err))
		return err;
	    if (assign_strval(line, "ident", assign_none,
			      cn, cfg_error_ident, &err))
		return err;
	    if (assign_match(line, "iexclude_path_glob", cn, 0, cfg_dacl_path,
			     cfg_acl_iglob, &err))
		return err;
	    if (assign_match(line, "iexclude_path", cn, 0, cfg_dacl_path,
			     cfg_acl_icase, &err))
		return err;
	    if (assign_match(line, "iexclude_glob", cn, 0, cfg_dacl_name,
			     cfg_acl_iglob, &err))
		return err;
	    if (assign_match(line, "iexclude", cn, 0, cfg_dacl_name,
			     cfg_acl_icase, &err))
		return err;
	    if (assign_match(line, "ifind_path_glob", cn, 1, cfg_dacl_path,
			     cfg_acl_iglob, &err))
		return err;
	    if (assign_match(line, "ifind_path", cn, 1, cfg_dacl_path,
			     cfg_acl_icase, &err))
		return err;
	    if (assign_match(line, "ifind_glob", cn, 1, cfg_dacl_name,
			     cfg_acl_iglob, &err))
		return err;
	    if (assign_match(line, "ifind", cn, 1, cfg_dacl_name,
			     cfg_acl_icase, &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "include", assign_none, &st, NULL, &err)) {
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
	    if (assign_strlist(line, "listen", 0, check_socket, locfl,
		&configs[cn].strlist[cfg_listen], &err))
	    {
		return err;
	    }
	    if (assign_strlist(line, "ls", 0, NULL, NULL,
		&configs[cn].strlist[cfg_ls_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_ls;
		return err;
	    }
	    break;
	case 'm' :
	    if (strcmp(line, "mount") == 0) {
		config_add_t * al;
		if (! configs[cn].strlist[cfg_add_path])
		    return "mount must follow a dir";
		al = configs[cn].strlist[cfg_add_path]->privdata;
		al->crossmount = 0;
		return NULL;
	    }
	    break;
	case 'n' :
	    if (assign_strval(line, "name", assign_none,
			      cn, cfg_base_name, &err))
		return err;
	    if (strcmp(line, "nodetach") == 0) {
		configs[cn].intval[cfg_server_mode] &= ~config_server_detach;
		return NULL;
	    }
	    if (strcmp(line, "not") == 0)
		return "*Of course it shouldn't";
	    break;
	case 'o' :
	    if (assign_unit(line, "optimise_buffer", config_sizes,
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
	    if (assign_strval(line, "password", assign_none,
			      cn, cfg_password, &err))
		return err;
	    if (assign_strval(line, "pass", assign_none,
			      cn, cfg_password, &err))
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
	    if (assign_unit(line, "queue_block", config_sizes,
			    &configs[cn].intval[cfg_notify_queue_block], &err))
		return err;
	    break;
	case 'r' :
	    if (assign_strlist(line, "remove", 0, NULL, NULL,
		&configs[cn].strlist[cfg_remove_path], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_remove;
		return err;
	    }
	    if (assign_command(line, "remote_should",
			       &configs[cn].strarrval[cfg_strarr_remote_should],
			       &err))
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
	    if (assign_strval(line, "server", assign_none,
			      cn, cfg_server, &err))
	    {
		if (err) return err;
		err = check_socket(configs[cn].strval[cfg_server], NULL);
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_client;
		configs[cn].intval[cfg_flags] |= config_flag_socket_changed;
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
	    if (assign_strval(line, "store", assign_none,
			      cn, cfg_store, &err))
		return err;
	    if (assign_strval(line, "setup", assign_nodups,
			      cn, cfg_copy_state, &err))
	    {
		if (err) return err;
		configs[cn].intval[cfg_client_mode] |= config_client_setup;
		return NULL;
	    }
	    if (strcmp(line, "skip_notice") == 0) {
		*locfl |= locfl_notice;
		return NULL;
	    }
	    if (strcmp(line, "skip_extra_fork") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_extra_fork;
		return NULL;
	    }
	    break;
	case 't' :
	    if (assign_strval(line, "to", assign_isdir,
			      cn, cfg_to_prefix, &err))
		return err;
	    if (strcmp(line, "translate_ids") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_translate_ids;
		return NULL;
	    }
	    if (strcmp(line, "telnet") == 0) {
		configs[cn].intval[cfg_client_mode] |= config_client_telnet;
		return NULL;
	    }
	    if (assign_command(line, "tunnel",
			       &configs[cn].strarrval[cfg_strarr_tunnel], &err))
		return err;
	    break;
	case 'u' :
	    if (assign_strval(line, "user", assign_none,
			      cn, cfg_user, &err))
		return err;
	    if (assign_strlist(line, "update", 0, NULL, NULL,
		&configs[cn].strlist[cfg_update], &err))
	    {
		configs[cn].intval[cfg_client_mode] |= config_client_update;
		return err;
	    }
	    if (strcmp(line, "use_extra_fork") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_extra_fork;
		return NULL;
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
	    if (assign_unit(line, "watch_name_block", config_sizes,
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

static int is_same_user(const config_acl_t * a,
			const config_acl_t * b, int is_tcp)
{
    /* same user means username is identical; additionally, for TCP
     * users, password is identical or b's password is "*" */
    if (strcmp(a->cond->pattern, b->cond->pattern) != 0) return 0;
    if (! is_tcp) return 1;
    if (b->cond->next->pattern[0] == '*' && ! b->cond->next->pattern[1])
	return 1;
    if (strcmp(a->cond->next->pattern, b->cond->next->pattern) != 0) return 0;
    return 1;
}

/* parse single argument - initial configuration or reconfiguration */

static const char * parsearg(const char * line, locfl_t * locfl, int is_initial)
{
    const char * err;
    char * st;
    error_message_t erm;
    config_acl_t udata;
    int cn = is_initial ? currnum : update_cn, elv;
    switch (line[0]) {
	case 'a' :
	    if (assign_int(line, "autopurge",
			   &configs[cn].intval[cfg_autopurge_days], &err))
		return err;
	    if (assign_user(line, "allow_unix", 0, 1, &udata, &err) ||
		assign_user(line, "allow_local", 0, 1, &udata, &err) ||
		assign_user(line, "allow_tcp", 1, 1, &udata, &err))
	    {
		config_acl_t * ul, * prev = NULL;
		int is_tcp;
		if (err) return err;
		/* if the user is already defined, just add the actions */
		is_tcp = udata.cond &&
			 udata.cond->next &&
			 udata.cond->next->data_index == cfg_uacl_pass;
		ul = configs[cn].aclval[is_tcp ? cfg_acl_tcp : cfg_acl_local];
		while (ul) {
		    if (is_same_user(ul, &udata, is_tcp)) {
			/* add the permissions and any extra host/socket
			 * conditions */
			config_acl_cond_t * newhost = udata.cond;
			config_acl_cond_t * oldhost = ul->cond;
			if (is_tcp) {
			    newhost = newhost->next;
			    oldhost = oldhost->next;
			}
			if (newhost->next && newhost->next->subcond) {
			    if (oldhost->next) {
				/* append to the end of the existing list */
				config_acl_cond_t * endlist = oldhost->next;
				if (endlist->subcond) {
				    endlist = endlist->subcond;
				    while (endlist->next)
					endlist = endlist->next;
				    endlist->next = newhost->next->subcond;
				} else {
				    endlist->subcond = newhost->next->subcond;
				}
				/* prevent freeing of the conditions */
				newhost->next->subcond = NULL;
			    } else {
				/* no pre-existing conditions: just put the
				 * new conditions in place */
				oldhost->next = newhost->next;
				/* prevent freeing of the conditions */
				newhost->next = NULL;
			    }
			} else if (! udata.result) {
			    /* they did not provide a host/socket list,
			     * and no actions, so they must mean full
			     * control */
			    udata.result = config_op_all;
			}
			ul->result |= udata.result;
			config_free_acl_cond(udata.cond);
			return NULL;
		    }
		    prev = ul;
		    ul = ul->next;
		}
		/* not defined - add a new user */
		ul = mymalloc(sizeof(config_acl_t));
		if (! ul) {
		    int e = errno;
		    config_free_acl_cond(udata.cond);
		    return error_sys_errno_r(errbuff, LINE_SIZE, "config",
					     "malloc", e);
		}
		udata.next = NULL;
		if (! udata.result)
		    /* for a new user, no actions means full control */
		    udata.result = config_op_all;
		*ul = udata;
		if (prev)
		    prev->next = ul;
		else if (is_tcp)
		    configs[cn].aclval[cfg_acl_tcp] = ul;
		else
		    configs[cn].aclval[cfg_acl_local] = ul;
		return NULL;
	    }
	    break;
	case 'c' :
	    if (assign_int(line, "checkpoint_events",
			   &configs[cn].intval[cfg_checkpoint_events], &err))
		return err;
	    if (assign_unit(line, "checkpoint_time", config_intervals,
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
	    if (assign_unit(line, "dirsync_interval", config_intervals,
			    &configs[cn].intval[cfg_dirsync_interval], &err))
		return err;
	    st = NULL;
	    if (assign_string(line, "dirsync_timed", assign_none,
			      &st, NULL, &err))
	    {
		char * saveptr = NULL, * token, * parse = st;
		int * rs;
		int count, num;
		if (err) return err;
		for (token = st, count = 1; *token; token++)
		    if (*token == ';')
			count++;
		rs = mymalloc(count * sizeof(int));
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
		    int hours, minutes = 0, daymask;
		    parse = NULL;
		    while (*token && isspace((int)*token)) token++;
		    re = parse_dayrange(token, &daymask);
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
		    rs[num] = (hours * 3600 + minutes * 60) | (daymask << 24);
		    num++;
		}
		myfree(st);
		if (configs[cn].intarrval[cfg_dirsync_timed])
		    myfree(configs[cn].intarrval[cfg_dirsync_timed]);
		configs[cn].intarrval[cfg_dirsync_timed] = rs;
		configs[cn].intarrlen[cfg_dirsync_timed] = num;
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
	    if (strcmp(line, "disable_librsync") == 0) {
		configs[cn].intval[cfg_flags] &= ~config_flag_use_librsync;
		return NULL;
	    }
	    if (strcmp(line, "do_initial_dirsync") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_initial_dirsync;
		return NULL;
	    }
	    if (assign_user(line, "disallow_unix", 0, 0, &udata, &err) ||
		assign_user(line, "disallow_local", 0, 0, &udata, &err) ||
		assign_user(line, "disallow_tcp", 1, 0, &udata, &err))
	    {
		config_acl_t * ul, * prev = NULL;
		int is_tcp;
		if (err) return err;
		/* find the user and remove these privileges */
		is_tcp = udata.cond &&
			 udata.cond->next &&
			 udata.cond->next->data_index == cfg_uacl_pass;
		if (! udata.result)
		    /* since we don't allow to remove host/socket entries,
		     * an empty action list always means remove all */
		    udata.result = config_op_all;
		ul = configs[cn].aclval[is_tcp ? cfg_acl_tcp : cfg_acl_local];
		while (ul) {
		    if (is_same_user(ul, &udata, is_tcp)) {
			ul->result &= ~udata.result;
			config_free_acl_cond(udata.cond);
			if (! ul->result) {
			    /* no privileges left, remove this user */
			    if (prev)
				prev->next = ul->next;
			    else if (is_tcp)
				configs[cn].aclval[cfg_acl_tcp] = ul->next;
			    else
				configs[cn].aclval[cfg_acl_local] = ul->next;
			    config_free_acl_cond(ul->cond);
			    myfree(ul);
			}
			return NULL;
		    }
		    prev = ul;
		    ul = ul->next;
		}
		/* not found */
		snprintf(errbuff, LINE_SIZE,
			 "%s user %s not found: cannot remove",
			 is_tcp ? "TCP" : "Unix", udata.cond->pattern);
		config_free_acl_cond(udata.cond);
		return errbuff;
	    }
	    break;
	case 'e' :
	    if (assign_unit(line, "eventfilesize",
			    config_sizes, &configs[cn].intval[cfg_eventsize],
			    &err))
		return err;
	    if (assign_unit(line, "eventsize", config_sizes,
			    &configs[cn].intval[cfg_eventsize], &err))
		return err;
	    if (assign_command(line, "email_submit",
			       &configs[cn].strarrval[cfg_strarr_email_submit],
			       &err))
		return err;
	    if (assign_strval(line, "email", assign_none,
			      cn, cfg_error_email, &err))
		return err;
	    if (strcmp(line, "enable_librsync") == 0) {
		configs[cn].intval[cfg_flags] |= config_flag_use_librsync;
		return NULL;
	    }
	    break;
	case 'f' :
	    st = NULL;
	    if (assign_string(line, "filter", assign_none, &st, NULL, &err)) {
		int eventmap, filemap, i, mask;
		char * saveptr = NULL, * token, * parse = st;
		if (err) return err;
		for (i = 0; i < cfg_event_COUNT; i++)
		    configs[cn].intval[i] = 0;
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
			i < cfg_event_COUNT;
			i++, mask <<= 1)
		    {
			if (eventmap & mask) {
			    if (negate)
				configs[cn].intval[i] &= ~filemap;
			    else
				configs[cn].intval[i] |= filemap;
			}
		    }
		}
		myfree(st);
		return NULL;
	    }
	    break;
	case 'l' :
	    if (assign_strval(line, "logfile", assign_isdir,
			      cn, cfg_error_logfile, &err))
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
	    erm = assign_error(line, "message", &st, &err, NULL);
	    if (erm < error_MAX) {
		int ac, i, mc;
		if (err) return err;
		ac = error_argcount(erm);
		for (i = mc = 0; st[i]; i++) {
		    if (st[i] == '%') {
			i++;
			if (st[i] != '%') {
			    if (st[i] == '-') i++;
			    while (st[i] && isdigit((int)st[i])) i++;
			    if (st[i] != 's')
				return "Invalid conversion, use %s";
			    mc++;
			}
		    }
		}
		if (ac != mc) {
		    snprintf(errbuff, LINE_SIZE,
			     "Invalid messsage: requires %d conversions", ac);
		    return errbuff;
		}
		if (configs[cn].errdata[erm].message)
		    myfree(configs[cn].errdata[erm].message);
		configs[cn].errdata[erm].message = st;
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
	    erm = assign_error(line, "report", &st, &err, &elv);
	    if (erm < error_MAX) {
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
			err = getfacility(token,
					  &configs[cn].errdata[erm].facility);
			if (err) {
			    myfree(st);
			    return err;
			}
			dest |= error_dest_syslog;
		    }
		}
		myfree(st);
		if (elv < 0)
		    configs[cn].errdata[erm].dest = dest;
		else
		    for (erm = 0; erm < error_MAX; erm++)
			if (error_level(erm) == elv)
			    configs[cn].errdata[erm].dest = dest;
		return NULL;
	    }
	    break;
	case 's' :
	    if (assign_command(line, "submit",
			       &configs[cn].strarrval[cfg_strarr_email_submit],
			       &err))
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
    int check_state = how & include_state, lineno = 0;
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
	lineno++;
	while (le > 0 && isspace((int)buffer[le - 1])) le--;
	buffer[le] = 0;
	while (le > 0 && buffer[le - 1] == '\\') {
	    le--;
	    if (le >= CONFIG_LINESIZE - 10) {
		snprintf(errbuff, LINE_SIZE,
			 "%s.%d: line too long", name, lineno);
		err = errbuff;
		goto problem;
	    }
	    if (! fgets(buffer + le, CONFIG_LINESIZE - le, IF)) {
		snprintf(errbuff, LINE_SIZE,
			 "%s.%d: backslash ends last line", name, lineno);
		err = errbuff;
		goto problem;
	    }
	    lineno++;
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
			 "%s.%d: not a copy state file", name, lineno);
		err = errbuff;
		goto problem;
	    }
	    if (vn < IDENTIFY_MINIMUM) {
		snprintf(errbuff, LINE_SIZE,
			 "%s.%d: version %lf is too old (minimum %lf)",
			 name, lineno, vn, IDENTIFY_MINIMUM);
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
	if (err) {
	    /* copy error message in case it is in errbuff */
	    strncpy(buffer, err, sizeof(buffer));
	    buffer[sizeof(buffer) - 1] = 0;
	    snprintf(errbuff, LINE_SIZE, "%s.%d: %s", name, lineno, buffer);
	    err = errbuff;
	    goto problem;
	}
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

static int set_strval(int cn, config_str_names_t sv, const char * value) {
    if (configs[cn].strval[sv]) return 1;
    configs[cn].strlength[sv] = strlen(value);
    configs[cn].strval[sv] = mymalloc(1 + configs[cn].strlength[sv]);
    if (configs[cn].strval[sv]) {
	strcpy(configs[cn].strval[sv], value);
	return 1;
    }
    perror("malloc");
    return 0;
}

/* assign default value depending on whether the user is root or not */

static int set_default_user(char ** result, int * len_p, uid_t user,
			    const char * homedir, const char * root_dir,
			    const char * base, const char * name)
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
    if (len_p) *len_p = strlen(*result);
    return 1;
}

static int set_strval_user(int cn, config_str_names_t sv, uid_t user,
			    const char * homedir, const char * root_dir,
			    const char * base, const char * name)
{
    return set_default_user(&configs[cn].strval[sv], &configs[cn].strlength[sv],
			    user, homedir, root_dir, base, name);
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
    int uc;
    for (uc = 0; uc < cfg_int_COUNT; uc++)
	configs[cn].intval[uc] = default_ints[uc];
    for (uc = 0; uc < cfg_str_COUNT; uc++) {
	configs[cn].strval[uc] = NULL;
	configs[cn].strlength[uc] = 0;
    }
    for (uc = 0; uc < cfg_strlist_COUNT; uc++)
	configs[cn].strlist[uc] = NULL;
    for (uc = 0; uc < cfg_strarr_COUNT; uc++)
	configs[cn].strarrval[uc] = NULL;
    for (uc = 0; uc < cfg_intarr_COUNT; uc++) {
	configs[cn].intarrval[uc] = NULL;
	configs[cn].intarrlen[uc] = 0;
    }
    for (uc = 0; uc < cfg_acl_COUNT; uc++)
	configs[cn].aclval[uc] = NULL;
    for (uc = 0; uc < error_MAX; uc++) {
	configs[cn].errdata[uc].message = NULL;
	configs[cn].errdata[uc].dest = -1;
	configs[cn].errdata[uc].facility = -1;
    }
    in_use[cn] = 1;
    refcount[cn] = 1;
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

static config_strlist_t * strlist_dup(const config_strlist_t * ls) {
    config_strlist_t * res = NULL, * last = NULL;
    while (ls) {
	config_strlist_t * new =
	    mymalloc(sizeof(config_strlist_t) + 1 + ls->datalen);
	int e;
	if (new) {
	    if (ls->privdata && ls->duppriv) {
		new->privdata = ls->duppriv(ls->privdata);
		if (! new->privdata) {
		    e = errno;
		    myfree(new);
		    errno = e;
		    goto fail;
		}
	    } else {
		new->privdata = ls->privdata;
	    }
	    new->freepriv = ls->freepriv;
	    new->duppriv = ls->duppriv;
	    new->datalen = ls->datalen;
	    new->next = NULL;
	    strncpy(new->data, ls->data, ls->datalen);
	    new->data[ls->datalen] = 0;
	    if (last)
		last->next = new;
	    else
		res = new;
	    last = new;
	    ls = ls->next;
	    continue;
	}
    fail:
	e = errno;
	while (res) {
	    config_strlist_t * this = res;
	    res = res->next;
	    if (this->privdata && this->freepriv)
		this->freepriv(this->privdata);
	    myfree(this);
	}
	errno = e;
	return NULL;
    }
    return res;
}

static int acl_condlen(const config_acl_cond_t * cond) {
    switch (cond->how) {
	case cfg_acl_exact :
	case cfg_acl_icase :
	case cfg_acl_glob :
	case cfg_acl_iglob :
	case cfg_acl_function :
	    return 1 + strlen(cond->pattern);
	case cfg_acl_ip4range :
	    return 9;
	case cfg_acl_ip6range :
	    return 33;
	case cfg_acl_call_or :
	case cfg_acl_call_and :
	    return 0;
    }
    return 0;
}

/* copies an ACL / condition (deep copy) */

config_acl_cond_t * config_copy_acl_cond(const config_acl_cond_t * cond) {
    config_acl_cond_t * res = NULL, * last = NULL;
    while (cond) {
	int xlen = acl_condlen(cond);
	config_acl_cond_t * this = mymalloc(sizeof(config_acl_cond_t) + xlen);
	int e;
	if (this) {
	    int ok = 1;
	    memcpy(this, cond, sizeof(config_acl_cond_t) + xlen);
	    if (cond->how == cfg_acl_call_or || cond->how == cfg_acl_call_and) {
		this->subcond = config_copy_acl_cond(cond->subcond);
		ok = this->subcond != NULL;
	    }
	    if (ok) {
		this->next = NULL;
		if (last)
		    last->next = this;
		else
		    res = this;
		last = this;
		cond = cond->next;
		continue;
	    }
	    e = errno;
	    myfree(this);
	    errno = e;
	}
	e = errno;
	config_free_acl_cond(res);
	errno = e;
	return NULL;
    }
    return res;
}

config_acl_t * config_copy_acl(const config_acl_t * acl) {
    config_acl_t * res = NULL, * last = NULL;
    while (acl) {
	config_acl_t * this = mymalloc(sizeof(config_acl_t));
	int e;
	if (this) {
	    int ok = 1;
	    if (acl->cond) {
		this->cond = config_copy_acl_cond(acl->cond);
		ok = this->cond != NULL;
	    }
	    if (ok) {
		this->next = NULL;
		this->result = acl->result;
		if (last)
		    last->next = this;
		else
		    res = this;
		last = this;
		acl = acl->next;
		continue;
	    }
	    e = errno;
	    myfree(this);
	    errno = e;
	}
	e = errno;
	while (res) {
	    config_acl_t * this = res;
	    res = res->next;
	    config_free_acl_cond(this->cond);
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
	    configs[cn].strval[uc] =
		mymalloc(1 + configs[currnum].strlength[uc]);
	    if (! configs[cn].strval[uc]) return 0;
	    memcpy(configs[cn].strval[uc], configs[currnum].strval[uc],
		   configs[currnum].strlength[uc] + 1);
	    configs[cn].strlength[uc] = configs[currnum].strlength[uc];
	}
    }
    for (uc = 0; uc < cfg_strarr_COUNT; uc++) {
	if (configs[currnum].strarrval[uc]) {
	    configs[cn].strarrval[uc] =
		array_dup(configs[currnum].strarrval[uc]);
	    if (! configs[cn].strarrval[uc]) return 0;
	}
    }
    for (uc = 0; uc < cfg_strlist_COUNT; uc++) {
	if (configs[currnum].strlist[uc]) {
	    configs[cn].strlist[uc] =
		strlist_dup(configs[currnum].strlist[uc]);
	    if (! configs[cn].strlist[uc]) return 0;
	}
    }
    for (uc = 0; uc < cfg_intarr_COUNT; uc++) {
	if (configs[currnum].intarrval[uc]) {
	    int nel = configs[currnum].intarrlen[uc], en;
	    configs[cn].intarrval[uc] =
		mymalloc(nel * sizeof(int));
	    if (! configs[cn].intarrval[uc]) return 0;
	    for (en = 0; en < nel; en++)
		configs[cn].intarrval[uc][en] =
		    configs[currnum].intarrval[uc][en];
	    configs[cn].intarrlen[uc] =
		configs[currnum].intarrlen[uc];
	}
    }
    for (uc = 0; uc < cfg_acl_COUNT; uc++) {
	if (configs[currnum].aclval[uc]) {
	    configs[cn].aclval[uc] =
		config_copy_acl(configs[currnum].aclval[uc]);
	    if (! configs[cn].aclval[uc]) return 0;
	}
    }
    for (uc = 0; uc < error_MAX; uc++) {
	if (configs[currnum].errdata[uc].message) {
	    configs[cn].errdata[uc] = configs[currnum].errdata[uc];
	    configs[cn].errdata[uc].message =
		mystrdup(configs[currnum].errdata[uc].message);
	    if (! configs[cn].errdata[uc].message) return 0;
	}
    }
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
    error_dest_t ed;
    error_message_t em;
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
    /* set default values */
    if (homedir &&
	! set_strval(currnum, cfg_homedir, homedir))
	    goto fail;
    homedir = configs[currnum].strval[cfg_homedir];
    if (! set_strval(currnum, cfg_base_name,
		      (configs[currnum].intval[cfg_client_mode]
			    & config_client_copy)
			? "copy" : "server"))
	goto fail;
    if (! set_strval_user(currnum, cfg_server, user, homedir, ROOT_SOCKET_DIR,
			  configs[currnum].strval[cfg_base_name], "socket"))
	goto fail;
    if (! (locfl & locfl_has_socket)) {
	/* need to add a control socket */
	config_strlist_t * L;
	char * sh = NULL;
	int slen;
	if (! set_default_user(&sh, NULL, user, homedir, ROOT_SOCKET_DIR,
			       configs[currnum].strval[cfg_base_name],
			       "socket"))
	    goto fail;
	slen = strlen(sh);
	L = mymalloc(sizeof(config_strlist_t) + slen + 1);
	if (! L) {
	    perror("malloc");
	    myfree(sh);
	    goto fail;
	}
	L->next = configs[currnum].strlist[cfg_listen];
	memcpy(L->data, sh, slen);
	L->data[slen] = 0;
	L->datalen = slen;
	L->privdata = NULL;
	L->freepriv = NULL;
	L->duppriv = NULL;
	configs[currnum].strlist[cfg_listen] = L;
	myfree(sh);
    }
    locfl &= ~locfl_has_socket;
    if (! set_strval(currnum, cfg_error_ident, "should"))
	goto fail;
    if (! set_strval_user(currnum, cfg_error_logfile, user, homedir,
			  ROOT_LOGFILE_DIR,
			  configs[currnum].strval[cfg_base_name], "log"))
	goto fail;
    if (! configs[currnum].strarrval[cfg_strarr_email_submit]) {
	assign_command("submit = " MAILER, "submit",
		       &configs[currnum].strarrval[cfg_strarr_email_submit],
		       &err);
	if (err) {
	    fprintf(stderr, "%s\n", err);
	    goto fail;
	}
    }
    if (! set_strval_user(currnum, cfg_eventdir, user, homedir,
			  ROOT_EVENTDIR_DIR,
			  configs[currnum].strval[cfg_base_name], "events"))
	goto fail;
    if (! set_strval(currnum, cfg_store, "save"))
	goto fail;
    /* if not detaching, send all messages to stderr unless they specified
     * a different destination */
    ed = configs[currnum].intval[cfg_client_mode] ||
	 ! (configs[currnum].intval[cfg_server_mode] & config_server_detach)
       ? error_dest_stderr
       : error_dest_file;
    for (em = 0; em < error_MAX; em++) {
	if (! configs[currnum].errdata[em].message) {
	    const char * msg = error_defmsg(em);
	    if (msg) {
		configs[currnum].errdata[em].message = mystrdup(msg);
		if (! configs[currnum].errdata[em].message)
		    goto fail;
	    }
	}
	if (configs[currnum].errdata[em].dest < 0) {
	    if (em == info_detach)
		configs[currnum].errdata[em].dest = error_dest_stderr;
	    else
		configs[currnum].errdata[em].dest = ed;
	}
	if (configs[currnum].errdata[em].facility < 0)
	    switch (error_level(em)) {
		case error_level_info :
		    configs[currnum].errdata[em].facility =
			LOG_LOCAL0 | LOG_INFO;
		    break;
		case error_level_warn :
		    configs[currnum].errdata[em].facility =
			LOG_LOCAL0 | LOG_WARNING;
		    break;
		case error_level_err :
		    configs[currnum].errdata[em].facility =
			LOG_LOCAL0 | LOG_ERR;
		    break;
		case error_level_crit :
		    configs[currnum].errdata[em].facility =
			LOG_LOCAL0 | LOG_CRIT;
		    break;
	    }
    }
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
    return 1;
fail:
    pthread_mutex_destroy(&config_lock);
    config_free();
    return 0;
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
	    if (this->privdata && this->freepriv)
		this->freepriv(this->privdata);
	    myfree(this);
	}
    }
    for (uc = 0; uc < cfg_strarr_COUNT; uc++) {
	if (configs[cn].strarrval[uc]) {
	    myfree(configs[cn].strarrval[uc][0]);
	    myfree(configs[cn].strarrval[uc]);
	}
    }
    for (uc = 0; uc < cfg_intarr_COUNT; uc++)
	if (configs[cn].intarrval[uc])
	    myfree(configs[cn].intarrval[uc]);
    for (uc = 0; uc < cfg_acl_COUNT; uc++) {
	while (configs[cn].aclval[uc]) {
	    config_acl_t * this = configs[cn].aclval[uc];
	    configs[cn].aclval[uc] = configs[cn].aclval[uc]->next;
	    config_free_acl_cond(this->cond);
	    myfree(this);
	}
    }
    for (uc = 0; uc < error_MAX; uc++)
	if (configs[cn].errdata[uc].message)
	    myfree(configs[cn].errdata[uc].message);
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

/* obtain values */

int config_intval(const config_data_t * cfg, config_int_names_t iv) {
    return iv < 0 || iv >= cfg_int_COUNT ? -1 : cfg->intval[iv];
}

int config_intarr_len(const config_data_t * cfg, config_intarr_names_t iv) {
    return iv < 0 || iv >= cfg_intarr_COUNT ? 0 : cfg->intarrlen[iv];
}

const int * config_intarr_data(const config_data_t * cfg,
			       config_intarr_names_t iv)
{
    return iv < 0 || iv >= cfg_intarr_COUNT ? NULL : cfg->intarrval[iv];
}

int config_strlen(const config_data_t * cfg, config_str_names_t sv) {
    return sv < 0 || sv >= cfg_str_COUNT ? 0 : cfg->strlength[sv];
}

const char * config_strval(const config_data_t * cfg, config_str_names_t sv) {
    return sv < 0 || sv >= cfg_str_COUNT ? NULL : cfg->strval[sv];
}

char * const * config_strarr(const config_data_t * cfg,
			     config_strarr_names_t sv)
{
    return sv < 0 || sv >= cfg_strarr_COUNT ? NULL : cfg->strarrval[sv];
}

int config_strarr_len(const config_data_t * cfg, config_strarr_names_t sv) {
    int len = 0;
    char * const * p;
    if (sv < 0 || sv >= cfg_strarr_COUNT) return 0;
    p = cfg->strarrval[sv];
    while (p[len]) len++;
    return len;
}

const config_strlist_t * config_strlist(const config_data_t * cfg,
					config_strlist_names_t sv)
{
    return sv < 0 || sv >= cfg_strlist_COUNT ? NULL : cfg->strlist[sv];
}

const config_acl_t * config_aclval(const config_data_t * cfg,
				   config_acl_names_t av)
{
    return av < 0 || av >= cfg_acl_COUNT ? NULL : cfg->aclval[av];
}

/* check an ACL condition; if is_and is nonzero, all the element must
 * return true; if is_and is zero, the first which matches decides whether
 * the result is true (if it is not negated) or false (if it is negated) */

int config_check_acl_cond(const config_acl_cond_t * cond, int is_and,
			  const char *data[], int datasize)
{
    while (cond) {
	int val = 0;
	const char * dp = cond->data_index >= 0 && cond->data_index < datasize
			? data[cond->data_index]
			: NULL;
	switch (cond->how) {
	    case cfg_acl_exact :
		if (dp) val = strcmp(cond->pattern, dp) == 0;
		break;
	    case cfg_acl_icase :
		if (dp) val = strcasecmp(cond->pattern, dp) == 0;
		break;
	    case cfg_acl_glob :
		if (dp) val = fnmatch(cond->pattern, dp, 0) == 0;
		break;
	    case cfg_acl_iglob :
		if (dp) val = fnmatch(cond->pattern, dp, FNM_CASEFOLD) == 0;
		break;
	    case cfg_acl_ip4range :
		/* data must be between pattern and pattern+4 */
		if (dp) val = memcmp(cond->pattern, dp, 4) <= 0 &&
			      memcmp(cond->pattern + 4, dp, 4) >= 0;
		break;
	    case cfg_acl_ip6range :
		/* data must be between pattern and pattern+16 */
		if (dp) val = memcmp(cond->pattern, dp, 16) <= 0 &&
			      memcmp(cond->pattern + 16, dp, 16) >= 0;
		break;
	    case cfg_acl_function :
		val = cond->func(cond->pattern, dp, data, datasize);
		break;
	    case cfg_acl_call_or :
		val = config_check_acl_cond(cond->subcond, 0, data, datasize);
		break;
	    case cfg_acl_call_and :
		val = config_check_acl_cond(cond->subcond, 1, data, datasize);
		break;
	}
	if (cond->negate) {
	    if (val) return 0;
	} else if (is_and) {
	    if (! val) return 0;
	} else {
	    if (val) return 1;
	}
	cond = cond->next;
    }
    return is_and;
}

/* check an ACL */

int config_check_acl(const config_acl_t * acl,
		     const char *data[], int datasize, int notfound)
{
    while (acl) {
	if (config_check_acl_cond(acl->cond, 1, data, datasize))
	    return acl->result;
	acl = acl->next;
    }
    return notfound;
}

/* user-editable error message data */

const char * config_error_message(const config_data_t * cfg, error_message_t em)
{
    return em < error_MAX ? cfg->errdata[em].message : NULL;
}

error_dest_t config_error_destination(const config_data_t * cfg,
				      error_message_t em)
{
    return em < error_MAX ? cfg->errdata[em].dest : error_dest_none;
}

int config_error_facility(const config_data_t * cfg, error_message_t em) {
    return em < error_MAX ? cfg->errdata[em].facility : -1;
}

