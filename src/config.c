/* data structure used to hold configuration information
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "site.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <pwd.h>
#include <stdarg.h>
#include "config.h"
#include "error.h"
#include "main_thread.h"
#include "store_thread.h"
#include "compress.h"
#include "mymalloc.h"

typedef enum {
    prn_config  = 1,
    prn_version = 2,
    prn_help    = 4,
    prn_NONE    = 0
} prn_t;

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

/* try to assign a value */

static int assign_string(const char * line, const char * keyword,
			 int isdir, char ** result, int * ok)
{
    int len = strlen(keyword);
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    *ok = 0;
    while (*line && isspace(*line)) line++;
    if (*line != '=') {
	fprintf(stderr, "Missing '=' after %s\n", keyword);
	return 1;
    }
    line++;
    while (*line && isspace(*line)) line++;
    if (! *line) {
	fprintf(stderr, "Missing value after %s\n", keyword);
	return 1;
    }
    if (isdir && *line != '/') {
	fprintf(stderr, "Value for %s is not an absolute path\n", keyword);
	return 1;
    }
    len = strlen(line);
    while (len > 0 && isspace(line[len - 1])) len--;
    if (*result) myfree(*result);
    *result = mymalloc(len + 1);
    if (! *result) {
	perror("malloc");
	return 1;
    }
    strncpy(*result, line, len);
    (*result)[len] = 0;
    unquote_string(*result);
    *ok = 1;
    return 1;
}

static int assign_int(const char * line, const char * keyword,
		      int * result, int * ok)
{
    int len = strlen(keyword);
    char * endptr;
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    while (*line && isspace(*line)) line++;
    *ok = 0;
    if (*line != '=') {
	fprintf(stderr, "Missing '=' after %s\n", keyword);
	return 1;
    }
    line++;
    while (*line && isspace(*line)) line++;
    if (! *line) {
	fprintf(stderr, "Missing value after %s\n", keyword);
	return 1;
    }
    *result = strtol(line, &endptr, 0);
    while (*endptr && isspace(*endptr)) endptr++;
    if (*endptr) {
	fprintf(stderr, "Invalid value after %s\n", keyword);
	return 1;
    }
    *ok = 1;
    return 1;
}

static error_message_t assign_error(const char * line, const char * keyword,
				    char ** result, int * ok)
{
    int len = strlen(keyword), namelen;
    error_message_t erm;
    if (strncmp(line, keyword, len) != 0) return error_MAX;
    line += len;
    *ok = 0;
    while (*line && isspace(*line)) line++;
    if (*line != ':') {
	fprintf(stderr, "Missing ':' after %s\n", keyword);
	return error_MAX;
    }
    line++;
    while (*line && isspace(*line)) line++;
    if (! *line) {
	fprintf(stderr, "Missing value after %s\n", keyword);
	return error_MAX;
    }
    namelen = 0;
    while (line[namelen] && ! isspace(line[namelen]) && line[namelen] != '=')
	namelen++;
    erm = error_code(line, namelen);
    if (erm == error_MAX) {
	fprintf(stderr, "Invalid error code: %.*s\n", namelen, line);
	return error_MAX;
    }
    line += namelen;
    while (*line && isspace(*line)) line++;
    if (*line != '=') {
	fprintf(stderr, "Missing '=' after %s\n", keyword);
	return error_MAX;
    }
    line++;
    while (*line && isspace(*line)) line++;
    if (! *line) {
	fprintf(stderr, "Missing value after %s\n", keyword);
	return error_MAX;
    }
    if (*result) myfree(*result);
    *result = mystrdup(line);
    if (! *result) {
	perror("strdup");
	return error_invalid;
    }
    unquote_string(*result);
    *ok = 1;
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
	return "Invalid syslog destination";
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
	return "Invalid syslog level";
    }
    *fp = facility;
    return NULL;
}

static int add_match(config_t * cfg, int which, char * st,
		     int match, int how, const char * name)
{
    config_match_t * el;
    if (! cfg->dirs) {
	myfree(st);
	fprintf(stderr, "%s must follow a dir\n", name);
	return 0;
    }
    el = mymalloc(sizeof(config_match_t));
    if (! el) {
	perror("malloc");
	myfree(st);
	return 0;
    }
    if (which) {
	el->next = cfg->dirs->find;
	cfg->dirs->find = el;
    } else {
	el->next = cfg->dirs->exclude;
	cfg->dirs->exclude = el;
    }
    el->pattern = st;
    el->match = match;
    el->how = how;
    return 1;
}

/* forward declaration */

static int includefile(config_t *, const char *, int, prn_t *);

/* make me a configuration file */

static char * convertname(const char * name, char * dst) {
    const char * ptr;
    char quote = 0;
    for (ptr = name; *ptr; ptr++) {
	if (isgraph(*ptr)) continue;
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
		if (isprint(*ptr)) {
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

static void printname(int (*p)(void *, const char *), void * arg,
		      const char * title, const char * name)
{
    int tlen = strlen(title);
    char buffer[4 * strlen(name) + 10 + tlen];
    strcpy(buffer, title);
    convertname(name, buffer + tlen);
    p(arg, buffer);
}

static void printname2(int (*p)(void *, const char *), void * arg,
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
    p(arg, buffer);
}

static void printname1(int (*p)(void *, const char *), void * arg,
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
    p(arg, buffer);
}

static void print_match(int (*p)(void *, const char *), void * arg,
			const char * type, const config_match_t * m)
{
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
	printname(p, arg, mbuffer, m->pattern);
	m = m->next;
    }
}

static void print_dirs(int (*p)(void *, const char *), void * arg,
		       const char * name, const config_dir_t * d)
{
    char nbuff[10 + strlen(name)];
    strcpy(nbuff, name);
    strcat(nbuff, " = ");
    while (d) {
	printname(p, arg, nbuff, d->path);
	p(arg, d->crossmount ? "#mount" : "mount");
	print_match(p, arg, "exclude", d->exclude);
	print_match(p, arg, "find", d->find);
	p(arg, "");
	d = d->next;
    }
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

static void sendformat(int (*p)(void *, const char *), void * arg,
		       const char * fmt, ...)
{
    va_list ap;
    char buffer[4096];
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);
    p(arg, buffer);
}

void config_print(int (*p)(void *, const char *), void * arg,
		  const config_t * cfg)
{
    int seen_unix, seen_tcp, cnum, cmax;
    config_user_t * U;
    error_message_t E;
    p(arg, "# Configuration file for \"should\"");
    p(arg, "# Automatically generated from current options");
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Notify thread");
    p(arg, "");
    p(arg, "# Size of the notify queue allocation block, in bytes");
    sendformat(p, arg, "queue_block = %d", cfg->notify_queue_block);
    p(arg, "");
    p(arg, "# Number of blocks allocated when the notify thread initialises");
    sendformat(p, arg, "initial_blocks = %d", cfg->notify_initial);
    p(arg, "");
    p(arg, "# Maximum number of queue blocks the thread will allocate");
    sendformat(p, arg, "max_blocks = %d", cfg->notify_max);
    p(arg, "");
    p(arg, "# Number of watches stored in one watch allocation block");
    sendformat(p, arg, "watch_block = %d", cfg->notify_watch_block);
    p(arg, "");
    p(arg, "# Number of bytes stored in one watch name block");
    sendformat(p, arg, "watch_name_block = %d", cfg->notify_name_block);
    p(arg, "");
    p(arg, "# Size of the buffer used to receive data from the kernel, in bytes");
    sendformat(p, arg, "buffer = %d", cfg->notify_buffer);
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Control thread and communication with a running server");
    p(arg, "");
    p(arg, "# Debug communication protocol?");
    p(arg, cfg->flags & config_flag_debug_server ? "debug_server"
						 : "no_debug_server");
    p(arg, "");
    p(arg, "# Unix domain socket to the running program");
    printname(p, arg, "socket = ", cfg->control_socket);
    p(arg, "");
    p(arg, "# Listen to TCP connections on this interface");
    if (cfg->listen) {
	config_listen_t * l = cfg->listen;
	while (l) {
	    char lhost[32 + strlen(l->host) + strlen(l->port)];
	    int c = strchr(l->host, ':') != NULL;
	    sprintf(lhost, "%s%s%s:%s",
		    c ? "[" : "", l->host,
		    c ? "]" : "", l->port);
	    printname(p, arg, "listen = ", lhost);
	    l = l->next;
	}
    } else {
	p(arg, "#listen = 0.0.0.0:4567");
	p(arg, "#listen = [::0]:1234");
	p(arg, "#listen = ONE_OF_MY_IP_ADDRESSES:SOME_PORT_NUMBER");
    }
    p(arg, "");
    p(arg, "# Use TCP connection to this server");
    if (cfg->server.host) {
	char lhost[32 + strlen(cfg->server.host) + strlen(cfg->server.port)];
	int c = strchr(cfg->server.host, ':') != NULL;
	sprintf(lhost, "%s%s%s:%s",
		c ? "[" : "", cfg->server.host,
		c ? "]" : "", cfg->server.port);
	printname(p, arg, "server = ", lhost);
    } else {
	p(arg, "#server = HOSTNAME:PORT");
    }
    p(arg, "");
    p(arg, "# User name used to connect");
    if (cfg->user)
	printname(p, arg, "user = ", cfg->user);
    else
	p(arg, "#user = yourname");
    p(arg, "");
    p(arg, "# Password name used to connect");
    if (cfg->password)
	printname(p, arg, "password = ", cfg->password);
    else
	p(arg, "#password = 'your secrets'");
    p(arg, "");
    p(arg, "# Users accepted by the server");
    seen_unix = seen_tcp = 0;
    U = cfg->users;
    while (U) {
	if (U->pass) {
	    char up[strlen(U->user) + strlen(U->pass) + 2];
	    sprintf(up, "%s:%s", U->user, U->pass);
	    printname(p, arg, "allow_tcp = ", up);
	    seen_tcp = 1;
	} else {
	    printname(p, arg, "allow_udp = ", U->user);
	    seen_unix = 1;
	}
	U = U->next;
    }
    if (! seen_unix)
	p(arg, "#allow_unix = root");
    if (! seen_tcp)
	p(arg, "#allow_tcp = 'yourname:your secrets'");
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Server: initial watches and operation mode");
    p(arg, "");
    if (! (cfg->client_mode & config_client_add) && cfg->dirs) {
	print_dirs(p, arg, "dir", cfg->dirs);
    } else {
	p(arg, "#dir = /some/path");
	p(arg, "#dir = /some/other/path");
	p(arg, "");
    }
    p(arg, "# Operation mode: detached or not detached?");
    if (cfg->server_mode & config_server_detach) {
	p(arg, "detach");
	p(arg, "#nodetach");
    } else {
	p(arg, "#detach");
	p(arg, "nodetach");
    }
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Store thread");
    p(arg, "");
    p(arg, "# Event directory");
    printname(p, arg, "eventdir = ", cfg->eventdir);
    p(arg, "");
    p(arg, "# Size of event file before it gets rotated");
    sendformat(p, arg, "eventfilesize = %d", cfg->eventsize);
    p(arg, "");
    p(arg, "# Store method");
    printname(p, arg, "store = ", cfg->store);
    p(arg, "");
    p(arg, "# Number of events to read ahead when serving client requests");
    sendformat(p, arg, "optimise_server = %d", cfg->optimise_server);
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Client mode: operations requested on server");
    p(arg, "");
    p(arg, "# add directories to watch");
    if ((cfg->client_mode & config_client_add) && cfg->dirs) {
	print_dirs(p, arg, "add", cfg->dirs);
    } else {
	p(arg, "#add = /some/path");
	p(arg, "#add = /some/other/path");
	p(arg, "");
    }
    p(arg, "# remove directories from server's watch list");
    if ((cfg->client_mode & config_client_remove) && cfg->remove) {
	print_dirs(p, arg, "remove", cfg->remove);
    } else {
	p(arg, "#remove = /some/path");
	p(arg, "#remove = /some/other/path");
	p(arg, "");
    }
    p(arg, "# Ask the server to purge event files older than the specified number of days");
    if (cfg->client_mode & config_client_purge)
	p(arg, "#purge = 2");
    else
	sendformat(p, arg, "purge = %d", cfg->purge_days);
    p(arg, "");
    p(arg, "# Get server's status");
    p(arg, cfg->client_mode & config_client_status ? "status" : "#status");
    p(arg, "");
#if USE_SHOULDBOX
    p(arg, "# Get server's shouldbox");
    p(arg, cfg->client_mode & config_client_box ? "box" : "#box");
    p(arg, "");
#endif
    p(arg, "# Get server's proces ID");
    p(arg, cfg->client_mode & config_client_getpid ? "getpid" : "#getpid");
    p(arg, "");
    p(arg, "# Get list of watched directories and report to standard output");
    p(arg, cfg->client_mode & config_client_watches ? "watches" : "#watches");
    p(arg, "");
    p(arg, "# Asks the server what compression method it supports");
    p(arg, cfg->client_mode & config_client_listcompress ? "listcompress" : "#listcompress");
    p(arg, "");
    p(arg, "# Get server's configuration");
    p(arg, cfg->client_mode & config_client_config ? "serverconfig" : "#serverconfig");
    p(arg, "");
    p(arg, "# Close logfiles (they will be reopened before next message)");
    p(arg, cfg->client_mode & config_client_closelog ? "closelog" : "#closelog");
    p(arg, "");
    p(arg, "# Stop running server");
    p(arg, cfg->client_mode & config_client_stop ? "stop" : "#stop");
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Copy setup mode");
    p(arg, "");
    p(arg, "# State file, containing copy information and checkpoints");
    if (cfg->client_mode & config_client_setup)
	printname(p, arg, "setup = ", cfg->copy_state);
    else
	p(arg, "#setup = /some/path");
    p(arg, "");
    p(arg, "# Translate user/group IDs during copy, or keep the numbers?");
    if (cfg->flags & config_flag_translate_ids) {
	p(arg, "translate_ids");
	p(arg, "#keep_ids");
    } else {
	p(arg, "#translate_ids");
	p(arg, "keep_ids");
    }
    p(arg, "");
    p(arg, "# Do we copy a file when mtime and size match?");
    if (cfg->flags & config_flag_skip_matching) {
	p(arg, "skip_matching");
	p(arg, "#copy_matching");
    } else {
	p(arg, "#skip_matching");
	p(arg, "copy_matching");
    }
    p(arg, "");
    p(arg, "# Number of events to read ahead by the client");
    sendformat(p, arg, "optimise_client = %d", cfg->optimise_client);
    p(arg, "");
    p(arg, "# Buffer used by the client to optimise events");
    sendformat(p, arg, "optimise_buffer = %d", cfg->optimise_buffer);
    p(arg, "");
    p(arg, "# Bandwidth limit (KB/s) for copy mode, 0 == no limits imposed");
    sendformat(p, arg, "bwlimit = %d", cfg->bwlimit);
    p(arg, "");
    p(arg, "# Compression method to use for file data copy");
    cmax = compress_count();
    for (cnum = 0; cnum < cmax; cnum++)
	sendformat(p, arg, "%scompression = %s",
		   cfg->compression == cnum ? "" : "#",
		   compress_name(cnum));
    p(arg, "");
    p(arg, "# Select a subtree of files on the server");
    if (cfg->from_prefix)
	printname(p, arg, "from = ", cfg->from_prefix);
    else
	p(arg, "#from = /some/path");
    p(arg, "");
    p(arg, "# Select the destination for the copy");
    if (cfg->to_prefix)
	printname(p, arg, "to = ", cfg->to_prefix);
    else
	p(arg, "#to = /some/path");
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Copy mode");
    p(arg, "");
    p(arg, "# State file, containing copy information and checkpoints");
    if (cfg->client_mode & config_client_copy)
	printname(p, arg, "copy = ", cfg->copy_state);
    else
	p(arg, "#copy = /some/path");
    p(arg, "");
    p(arg, "# Maximum number of events to process before checkpointing to file");
    sendformat(p, arg, "checkpoint_events = %d", cfg->checkpoint_events);
    p(arg, "");
    p(arg, "# Maximum time (in seconds) between checkpoints");
    sendformat(p, arg, "checkpoint_time = %d", cfg->checkpoint_time);
    p(arg, "");
    p(arg, "# \"Peek\" mode, printing events to standard output");
    p(arg, cfg->client_mode & config_client_peek ? "peek" : "#peek");
    p(arg, "");
    p(arg, "######################################################################");
    p(arg, "# Error reporting");
    p(arg, "");
    p(arg, "# Program identity, used in syslog and log files");
    printname(p, arg, "ident = ", cfg->error_ident);
    p(arg, "");
    p(arg, "# Log file, for errors which are reported to file");
    printname(p, arg, "logfile = ", cfg->error_logfile);
    p(arg, "");
    p(arg, "# Email address and submit program, for errors which are emailed");
    if (cfg->error_email)
	printname(p, arg, "email = ", cfg->error_email);
    else
	p(arg, "#email someuser@some.place.com");
    printname(p, arg, "email_submit = ", cfg->error_submit);
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

/* people ask questions */

static void print_help(void) {
    fprintf(stderr,
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
	"The current configuration can be seen with:\n"
	"    should printconfig\n"
	"\n"
	"Commonly used Server options:\n"
	"    listen=HOST:PORT     listen (TCP) on interface corresponding to HOST:\n"
	"                         default is to accept Unix domain connections only;\n"
	"                         use \"listen=0.0.0.0:PORT\" or \"listen=[::0]:PORT\"\n"
	"                         to listen on all IPv4 or IPv6 interfaces respectively\n"
	"    socket=/PATH         use a non-default Unix domain socket (default: below)\n"
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
	"default socket path for root user: %s\n"
	"default socket path for non-root:  ~/%s\n"
	"\n"
	"Commonly used Client (including Server control mode and Client Setup) options:\n"
	"    server=HOST:PORT     connect via TCP to HOST, port PORT: default is to use\n"
	"                         Unix domain sockets\n"
	"    socket=/PATH         use a non-default Unix domain socket (default: see\n"
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
	, SYSTEM_CONFIG, USER_CONFIG, ROOT_SOCKET, USER_SOCKET);
}

/* parse single argument */

static int parsearg(config_t * cfg, const char * line, prn_t * prn) {
    int ok;
    char * st, * pwd = NULL;
    error_message_t erm;
    while (*line && isspace(*line)) line++;
    if (! *line || *line == '#') return 1;
    switch (line[0]) {
	case '/' : {
	    config_dir_t * dl;
	    st = mystrdup(line);
	    if (! st)
		return 0;
	add_watch :
	    dl = mymalloc(sizeof(config_dir_t));
	    if (! dl) {
		perror("malloc");
		myfree(st);
		return 0;
	    }
	    dl->crossmount = 1;
	    dl->next = cfg->dirs;
	    dl->find = NULL;
	    dl->exclude = NULL;
	    dl->path = st;
	    cfg->dirs = dl;
	    return 1;
	}
	case 'a' :
	    st = NULL;
	    if (assign_string(line, "add_watch", 1, &st, &ok)) {
		if (! ok) return ok;
		cfg->client_mode |= config_client_add;
		goto add_watch;
	    }
	    st = NULL;
	    if (assign_string(line, "add", 1, &st, &ok)) {
		if (! ok) return ok;
		cfg->client_mode |= config_client_add;
		goto add_watch;
	    }
	    st = NULL;
	    if (assign_string(line, "allow_unix", 0, &st, &ok)) {
		if (! ok) return ok;
		pwd = NULL;
		goto add_user;
	    }
	    st = NULL;
	    if (assign_string(line, "allow_tcp", 0, &st, &ok)) {
		config_user_t * ul;
		if (! ok) return ok;
		pwd = strchr(st, ':');
		if (pwd)
		    *pwd++ = 0;
		else
		    pwd = "";
	    add_user:
		ul = mymalloc(sizeof(config_user_t));
		if (! ul) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		ul->next = cfg->users;
		ul->user = st;
		ul->pass = pwd;
		cfg->users = ul;
		return 1;
	    }
	    break;
	case 'b' :
	    if (assign_int(line, "buffer", &cfg->notify_buffer, &ok))
		return ok;
	    if (assign_int(line, "bwlimit", &cfg->bwlimit, &ok))
		return ok;
	    if (strcmp(line, "box") == 0) {
		cfg->client_mode |= config_client_box;
		return 1;
	    }
	    break;
	case 'c' :
	    if (strcmp(line, "closelog") == 0) {
		cfg->client_mode |= config_client_closelog;
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "config", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = includefile(cfg, st, 0, prn);
		myfree(st);
		return ok;
	    }
	    if (assign_string(line, "copy", 0, &cfg->copy_state, &ok)) {
		if (! ok) return ok;
		cfg->client_mode |= config_client_copy;
		return ok;
	    }
	    if (assign_int(line, "checkpoint_events", &cfg->checkpoint_events, &ok))
		return ok;
	    if (assign_int(line, "checkpoint_time", &cfg->checkpoint_time, &ok))
		return ok;
	    if (strcmp(line, "copy_matching") == 0) {
		cfg->flags &= ~config_flag_skip_matching;
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "compression", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = compress_byname(st);
		if (ok < 0) {
		    ok = 0;
		    fprintf(stderr, "Unknown compression method \"%s\"\n", st);
		} else {
		    ok = 1;
		}
		myfree(st);
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "cp", 0, &st, &ok)) {
		config_path_t * path;
		if (! ok) return ok;
		path = mymalloc(sizeof(config_path_t));
		if (! path) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		path->path = st;
		path->next = cfg->cp_path;
		cfg->cp_path = path;
		cfg->client_mode |= config_client_cp;
		return 1;
	    }
	    break;
	case 'd' :
	    st = NULL;
	    if (assign_string(line, "dir", 1, &st, &ok)) {
		if (! ok) return ok;
		goto add_watch;
	    }
	    if (strcmp(line, "detach") == 0) {
		cfg->server_mode |= config_server_detach;
		return 1;
	    }
	    if (strcmp(line, "debug_server") == 0) {
		cfg->flags |= config_flag_debug_server;
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "df", 0, &st, &ok)) {
		config_path_t * path;
		if (! ok) return ok;
		path = mymalloc(sizeof(config_path_t));
		if (! path) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		path->path = st;
		path->next = cfg->df_path;
		cfg->df_path = path;
		cfg->client_mode |= config_client_df;
		return 1;
	    }
	    break;
	case 'e' :
	    if (assign_string(line, "eventdir", 1, &cfg->eventdir, &ok))
		return ok;
	    if (assign_int(line, "eventfilesize", &cfg->eventsize, &ok))
		return ok;
	    if (assign_int(line, "eventsize", &cfg->eventsize, &ok))
		return ok;
	    if (assign_string(line, "email_submit", 0, &cfg->error_submit, &ok))
		return ok;
	    if (assign_string(line, "email", 0, &cfg->error_email, &ok))
		return ok;
	    st = NULL;
	    if (assign_string(line, "exclude_path_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_path,
			       config_match_glob,
			       "exclude_path_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "exclude_path", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_path,
			       config_match_exact,
			       "exclude_path");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "exclude_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_name,
			       config_match_glob,
			       "exclude_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "exclude", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_name,
			       config_match_exact,
			       "exclude");
		return ok;
	    }
	    break;
	case 'f' :
	    st = NULL;
	    if (assign_string(line, "file", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = includefile(cfg, st, 0, prn);
		myfree(st);
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "find_path_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_path,
			       config_match_glob,
			       "find_path_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "find_path", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_path,
			       config_match_exact,
			       "find_path");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "find_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_name,
			       config_match_glob,
			       "find_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "find", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_name,
			       config_match_exact,
			       "find");
		return ok;
	    }
	    if (assign_string(line, "from", 0, &cfg->from_prefix, &ok))
		return ok;
	    if (strcmp(line, "follow") == 0) {
		cfg->client_mode |= config_client_peek;
		return 1;
	    }
	    break;
	case 'g' :
	    if (strcmp(line, "getpid") == 0) {
		cfg->client_mode |= config_client_getpid;
		return 1;
	    }
	    break;
	case 'h' :
	    if (strcmp(line, "help") == 0) {
		*prn |= prn_help;
		return 1;
	    }
	    break;
	case 'i' :
	    if (assign_int(line, "initial", &cfg->notify_initial, &ok))
		return ok;
	    if (assign_int(line, "initial_blocks", &cfg->notify_initial, &ok))
		return ok;
	    if (assign_string(line, "ident", 0, &cfg->error_ident, &ok))
		return ok;
	    st = NULL;
	    if (assign_string(line, "iexclude_path_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_path,
			       config_match_iglob,
			       "iexclude_path_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude_path", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_path,
			       config_match_icase,
			       "iexclude_path");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_name,
			       config_match_iglob,
			       "iexclude_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "iexclude", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 0, st,
			       config_match_name,
			       config_match_icase,
			       "iexclude");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_path_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_path,
			       config_match_iglob,
			       "ifind_path_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_path", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_path,
			       config_match_icase,
			       "ifind_path");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "ifind_glob", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_name,
			       config_match_iglob,
			       "ifind_glob");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "ifind", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = add_match(cfg, 1, st,
			       config_match_name,
			       config_match_icase,
			       "ifind");
		return ok;
	    }
	    st = NULL;
	    if (assign_string(line, "include", 0, &st, &ok)) {
		if (! ok) return ok;
		ok = includefile(cfg, st, 0, prn);
		myfree(st);
		return ok;
	    }
	    break;
	case 'k' :
	    if (strcmp(line, "kill") == 0) {
		cfg->client_mode |= config_client_stop;
		return 1;
	    }
	    if (strcmp(line, "keep_ids") == 0) {
		cfg->flags &= ~config_flag_translate_ids;
		return 1;
	    }
	    break;
	case 'l' :
	    if (assign_string(line, "logfile", 1, &cfg->error_logfile, &ok))
		return ok;
	    st = NULL;
	    if (assign_string(line, "listen", 0, &st, &ok)) {
		char * pb = rindex(st, ':');
		config_listen_t * L;
		if (! ok) return 0;
		if (! pb || pb == st) {
		    fprintf(stderr,
			    "Invalid listen specification: missing port: \"%s\"\n",
			    st);
		    myfree(st);
		    return 0;
		}
		L = mymalloc(sizeof(config_listen_t));
		if (! L) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		L->port = pb + 1;
		*pb-- = 0;
		if (st[0] == '[' && pb[0] == ']') {
		    int i;
		    pb[0] = 0;
		    for (i = 0; st[i]; i++)
			st[i] = st[i + 1];
		}
		L->host = st;
		L->next = cfg->listen;
		cfg->listen = L;
		return 1;
	    }
	    if (strcmp(line, "listcompress") == 0) {
		cfg->client_mode |= config_client_listcompress;
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "ls", 0, &st, &ok)) {
		config_path_t * path;
		if (! ok) return ok;
		path = mymalloc(sizeof(config_path_t));
		if (! path) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		path->path = st;
		path->next = cfg->ls_path;
		cfg->ls_path = path;
		cfg->client_mode |= config_client_ls;
		return 1;
	    }
	    break;
	case 'm' :
	    if (assign_int(line, "max", &cfg->notify_max, &ok))
		return ok;
	    if (assign_int(line, "max_blocks", &cfg->notify_max, &ok))
		return ok;
	    st = NULL;
	    erm = assign_error(line, "message", &st, &ok);
	    if (erm < error_MAX) {
		const char * prob;
		if (! ok) return ok;
		prob = error_change_message(erm, st);
		if (! prob) return 1;
		fprintf(stderr, "Invalid error message (%s): %s\n", st, prob);
		myfree(st);
		return 0;
	    }
	    if (strcmp(line, "mount") == 0) {
		if (! cfg->dirs) {
		    fprintf(stderr, "mount must follow a dir\n");
		    return 0;
		}
		cfg->dirs->crossmount = 0;
		return 1;
	    }
	    break;
	case 'n' :
	    if (strcmp(line, "nodetach") == 0) {
		cfg->server_mode &= ~config_server_detach;
		return 1;
	    }
	    if (strcmp(line, "no_debug_server") == 0) {
		cfg->flags &= ~config_flag_debug_server;
		return 1;
	    }
	    break;
	case 'o' :
	    if (assign_int(line, "optimise_buffer", &cfg->optimise_buffer, &ok))
		return ok;
	    if (assign_int(line, "optimise_server", &cfg->optimise_server, &ok))
		return ok;
	    if (assign_int(line, "optimise_client", &cfg->optimise_client, &ok))
		return ok;
	    break;
	case 'p' :
	    if (assign_string(line, "password", 0, &cfg->password, &ok))
		return ok;
	    if (assign_string(line, "pass", 0, &cfg->password, &ok))
		return ok;
	    if (strcmp(line, "peek") == 0) {
		cfg->client_mode |= config_client_peek;
		return 1;
	    }
	    if (strcmp(line, "printconfig") == 0 || strcmp(line, "print") == 0)
	    {
		*prn |= prn_config;
		return 1;
	    }
	    if (assign_int(line, "purge", &cfg->purge_days, &ok)) {
		cfg->client_mode |= config_client_purge;
		return ok;
	    }
	    if (strcmp(line, "pid") == 0) {
		cfg->client_mode |= config_client_getpid;
		return 1;
	    }
	    break;
	case 'q' :
	    if (assign_int(line, "queue_block", &cfg->notify_queue_block, &ok))
		return ok;
	    break;
	case 'r' :
	    st = NULL;
	    erm = assign_error(line, "report", &st, &ok);
	    if (erm < error_MAX) {
		const char * err;
		int facility = 0;
		error_dest_t dest = 0;
		if (! ok) return ok;
		if (strcmp(st, "none") != 0) {
		    char * saveptr, * token, * parse = st;
		    while ((token = strtok_r(parse, ",", &saveptr)) != NULL) {
			parse = NULL;
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
			    fprintf(stderr, "%s\n", err);
			    myfree(st);
			    return 0;
			}
			dest |= error_dest_syslog;
			return 0;
		    }
		}
		myfree(st);
		error_change_dest(erm, dest, facility);
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "remove", 1, &st, &ok)) {
		config_dir_t * rl;
		if (! ok) return ok;
		rl = mymalloc(sizeof(config_dir_t));
		if (! rl) {
		    perror("malloc");
		    myfree(st);
		    return 0;
		}
		rl->crossmount = 1;
		rl->next = cfg->remove;
		rl->exclude = NULL;
		rl->path = st;
		cfg->remove = rl;
		cfg->client_mode |= config_client_remove;
		return 1;
	    }
	    break;
	case 's' :
	    if (strcmp(line, "serverconfig") == 0 ||
		strcmp(line, "server_config") == 0)
	    {
		cfg->client_mode |= config_client_config;
		return 1;
	    }
	    if (strcmp(line, "serverversion") == 0 ||
		strcmp(line, "server_version") == 0) {
		cfg->client_mode |= config_client_version;
		return 1;
	    }
	    st = NULL;
	    if (assign_string(line, "server", 0, &st, &ok)) {
		char * pb = rindex(st, ':');
		if (! ok) return 0;
		if (! pb || pb == st) {
		    fprintf(stderr,
			    "Invalid server specification: missing port: \"%s\"\n",
			    st);
		    myfree(st);
		    return 0;
		}
		cfg->client_mode |= config_client_client;
		cfg->server.port = pb + 1;
		*pb-- = 0;
		if (st[0] == '[' && pb[0] == ']') {
		    int i;
		    pb[0] = 0;
		    for (i = 0; st[i]; i++)
			st[i] = st[i + 1];
		}
		cfg->server.host = st;
		return 1;
	    }
	    if (assign_string(line, "socket", 1, &cfg->control_socket, &ok))
		return ok;
	    if (assign_string(line, "submit", 0, &cfg->error_submit, &ok))
		return ok;
	    if (strcmp(line, "stop") == 0) {
		cfg->client_mode |= config_client_stop;
		return 1;
	    }
	    if (strcmp(line, "start") == 0) {
		cfg->server_mode |= config_server_start;
		return 1;
	    }
	    if (strcmp(line, "status") == 0) {
		cfg->client_mode |= config_client_status;
		return 1;
	    }
	    if (assign_string(line, "store", 0, &cfg->store, &ok))
		return ok;
	    if (assign_string(line, "setup", 0, &cfg->copy_state, &ok)) {
		if (! ok) return ok;
		cfg->client_mode |= config_client_setup;
		return ok;
	    }
	    if (strcmp(line, "skip_matching") == 0) {
		cfg->flags |= config_flag_skip_matching;
		return 1;
	    }
	    break;
	case 't' :
	    if (assign_string(line, "to", 0, &cfg->to_prefix, &ok))
		return ok;
	    if (strcmp(line, "translate_ids") == 0) {
		cfg->flags |= config_flag_translate_ids;
		return 1;
	    }
	    if (strcmp(line, "telnet") == 0) {
		cfg->client_mode |= config_client_telnet;
		return 1;
	    }
	    break;
	case 'u' :
	    if (assign_string(line, "user", 0, &cfg->user, &ok))
		return ok;
	    break;
	case 'v' :
	    if (strcmp(line, "version") == 0) {
		*prn |= prn_version;
		return 1;
	    }
	    break;
	case 'w' :
	    if (assign_int(line, "watch_block", &cfg->notify_watch_block, &ok))
		return ok;
	    if (assign_int(line, "watch_name_block", &cfg->notify_name_block, &ok))
		return ok;
	    if (strcmp(line, "watches") == 0) {
		cfg->client_mode |= config_client_watches;
		return 1;
	    }
	    if (strcmp(line, "work") == 0) {
		fprintf(stderr, "Whatever gave you this idea?\n");
		return 0;
	    }
	    break;
    }
    fprintf(stderr, "Unknown option: %s\n", line);
    return 0;
}

/* read file and include it in configuration */

static int includefile(config_t * cfg, const char * name,
		       int silent, prn_t * prn)
{
    FILE * IF = fopen(name, "r");
    char buffer[CONFIG_LINESIZE];
    if (! IF) {
	if (silent)
	    return -1;
	perror(name);
	return 0;
    }
    while (fgets(buffer, CONFIG_LINESIZE, IF)) {
	int le = strlen(buffer);
	while (le > 0 && isspace(buffer[le - 1])) le--;
	buffer[le] = 0;
	if (! parsearg(cfg, buffer, prn)) {
	    fclose(IF);
	    return 0;
	}
    }
    fclose(IF);
    return 1;
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
			    const char * root_value, const char * user_value)
{
    if (*result) return 1;
    if (user == 0) {
	*result = mystrdup(root_value);
	if (*result) return 1;
	perror("strdup");
	return 0;
    }
    if (homedir) {
	*result = mymalloc(strlen(homedir) + strlen(user_value) + 2);
	if (! *result) {
	    perror("malloc");
	    return 0;
	}
	sprintf(*result, "%s/%s", homedir, user_value);
	return 1;
    } else {
	fprintf(stderr, "Cannot figure out user's home directory!\n");
	return 0;
    }
}

static int sendout(void * _p, const char * l) {
    printf("%s\n", l);
    return 0;
}

/* obtain configuration data */

int config_init(config_t * cfg, int argc, char *argv[]) {
    int argn, uc;
    prn_t prn = prn_NONE;
    char ubuffer[sysconf(_SC_GETPW_R_SIZE_MAX)];
    struct passwd pwd, * pwb;
    const char * homedir = NULL;
    uid_t user;
    /* clear data and set defaults */
    cfg->client_mode = config_client_NONE;
#if USE_SHOULDBOX
    cfg->server_mode = config_server_NONE;
#else
    cfg->server_mode = config_server_detach;
#endif
    cfg->notify_queue_block = 1048576;
    cfg->notify_initial = 2;
    cfg->notify_max = 8;
    cfg->notify_watch_block = 32;
    cfg->notify_name_block = 32768;
    cfg->notify_buffer = 1048576;
    cfg->control_socket = NULL;
    cfg->error_ident = NULL;
    cfg->error_logfile = NULL;
    cfg->error_email = NULL;
    cfg->error_submit = NULL;
    cfg->dirs = NULL;
    cfg->remove = NULL;
    cfg->eventdir = NULL;
    cfg->eventsize = 10485760;
    cfg->checkpoint_events = 60;
    cfg->checkpoint_time = 60;
    cfg->store = NULL;
    cfg->server.host = NULL;
    cfg->server.port = NULL;
    cfg->listen = NULL;
    cfg->user = NULL;
    cfg->password = NULL;
    cfg->users = NULL;
    cfg->from_prefix = NULL;
    cfg->to_prefix = NULL;
    cfg->copy_state = NULL;
    cfg->flags = config_flag_translate_ids | config_flag_skip_matching;
    cfg->bwlimit = 0;
    cfg->compression = -1;
    cfg->optimise_server = 8;
    cfg->optimise_client = 128;
    cfg->optimise_buffer = 262144;
    cfg->purge_days = 0;
    cfg->cp_path = NULL;
    cfg->ls_path = NULL;
    cfg->df_path = NULL;
    /* read configuration file, if found */
    uc = -1;
    user = getuid();
    if (getpwuid_r(user, &pwd, ubuffer, sizeof(ubuffer), &pwb) >= 0) {
	char conf[strlen(pwd.pw_dir) + strlen(USER_CONFIG) + 2];
	homedir = pwd.pw_dir;
	sprintf(conf, "%s/%s", pwd.pw_dir, USER_CONFIG);
	uc = includefile(cfg, conf, 1, &prn);
	if (! uc)
	    return 0;
    }
    if (uc < 0) {
	uc = includefile(cfg, SYSTEM_CONFIG, 1, &prn);
	if (! uc)
	    return 0;
    }
    /* read command-line arguments */
    for (argn = 1; argn < argc; argn++)
	if (! parsearg(cfg, argv[argn], &prn))
	    return 0;
    /* check for consistency */
    if (cfg->client_mode && (cfg->server_mode & ~config_server_detach)) {
	fprintf(stderr, "Incompatible options: client and server\n");
	return 0;
    }
    if (cfg->client_mode & config_client_setup) {
	if (cfg->client_mode & ~config_client_setup) {
	    fprintf(stderr, "Incompatible options: setup and other client ops\n");
	    return 0;
	}
	if (! cfg->from_prefix) {
	    fprintf(stderr, "Setup requires \"from\"\n");
	    return 0;
	}
	if (! cfg->to_prefix) {
	    fprintf(stderr, "Setup requires \"to\"\n");
	    return 0;
	}
    }
    if (cfg->client_mode & config_client_peek) {
	if (cfg->client_mode & ~config_client_peek) {
	    fprintf(stderr, "Incompatible options: peek and other client ops\n");
	    return 0;
	}
    }
    if (cfg->client_mode & config_client_telnet) {
	if (cfg->client_mode & ~config_client_telnet) {
	    fprintf(stderr, "Incompatible options: telnet and other client ops\n");
	    return 0;
	}
    }
    if (cfg->from_prefix)
	cfg->from_length = strlen(cfg->from_prefix);
    if (cfg->to_prefix)
	cfg->to_length = strlen(cfg->to_prefix);
    /* set default values */
    if (! set_default_user(&cfg->control_socket, user, homedir,
			   ROOT_SOCKET, USER_SOCKET))
	return 0;
    if (! set_default(&cfg->error_ident, "should"))
	return 0;
    if (! set_default_user(&cfg->error_logfile, user, homedir,
			   ROOT_LOGFILE, USER_LOGFILE))
	return 0;
    if (! set_default(&cfg->error_submit, MAILER))
	return 0;
    if (! set_default_user(&cfg->eventdir, user, homedir,
			   ROOT_EVENTDIR, USER_EVENTDIR))
	return 0;
    if (! set_default(&cfg->store, "save"))
	return 0;
    /* if "print" options were specified, do them and exit */
    if (prn & prn_help)
	print_help();
    if (prn & prn_config)
	config_print(sendout, NULL, cfg);
    if (prn & prn_version)
	printf("should version %d.%d.%d\n",
	       VERSION_MAJOR, VERSION_MINOR, VERSION_OFFSET);
    if (prn != prn_NONE)
	return 0;
    /* if not detaching, send all messages to stderr unless they specified
     * a different destination */
    if (cfg->client_mode || ! (cfg->server_mode & config_server_detach)) {
	error_message_t E;
	for (E = 0; E < error_MAX; E++)
	    if (error_dest_changed(E) == 0)
		error_change_dest(E, error_dest_stderr, 0);
    }
    return 1;
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

void config_free(config_t * cfg) {
    if (cfg->control_socket)
	myfree(cfg->control_socket);
    if (cfg->error_ident)
	myfree(cfg->error_ident);
    if (cfg->error_logfile)
	myfree(cfg->error_logfile);
    if (cfg->error_email)
	myfree(cfg->error_email);
    if (cfg->error_submit)
	myfree(cfg->error_submit);
    if (cfg->eventdir)
	myfree(cfg->eventdir);
    if (cfg->store)
	myfree(cfg->store);
    if (cfg->server.host)
	myfree(cfg->server.host);
    if (cfg->user)
	myfree(cfg->user);
    if (cfg->password)
	myfree(cfg->password);
    if (cfg->from_prefix)
	myfree(cfg->from_prefix);
    if (cfg->to_prefix)
	myfree(cfg->to_prefix);
    if (cfg->copy_state)
	myfree(cfg->copy_state);
    while (cfg->dirs) {
	config_dir_t * this = cfg->dirs;
	cfg->dirs = cfg->dirs->next;
	config_dir_free(this);
    }
    while (cfg->remove) {
	config_dir_t * this = cfg->remove;
	cfg->remove = cfg->remove->next;
	config_dir_free(this);
    }
    while (cfg->users) {
	config_user_t * this = cfg->users;
	cfg->users = cfg->users->next;
	if (this->user) myfree(this->user);
	myfree(this);
    }
    while (cfg->listen) {
	config_listen_t * this = cfg->listen;
	cfg->listen = cfg->listen->next;
	myfree(this->host);
	myfree(this);
    }
    while (cfg->cp_path) {
	config_path_t * this = cfg->cp_path;
	cfg->cp_path = cfg->cp_path->next;
	myfree(this->path);
	myfree(this);
    }
    while (cfg->ls_path) {
	config_path_t * this = cfg->ls_path;
	cfg->ls_path = cfg->ls_path->next;
	myfree(this->path);
	myfree(this);
    }
    while (cfg->df_path) {
	config_path_t * this = cfg->df_path;
	cfg->df_path = cfg->df_path->next;
	myfree(this->path);
	myfree(this);
    }
}

