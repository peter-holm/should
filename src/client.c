/* SHOULD's client
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

#define _BSD_SOURCE /* to undo some of glibc's brain damage */
#include "site.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <utime.h>
#include <locale.h>
#include <limits.h>
#include <fcntl.h>
#if DIRENT_TYPE == DIRENT
#include <dirent.h>
#else
#include <sys/dirent.h>
#endif
#include <sys/wait.h>
#include "config.h"
#include "error.h"
#include "socket.h"
#include "mymalloc.h"
#include "protocol.h"
#include "compress.h"
#include "checksum.h"
#include "usermap.h"
#include "main_thread.h"
#include "copy_thread.h"
#include "client.h"

#define REPLSIZE 256

#if ! defined NAME_MAX && defined MAXNAMLEN
#define NAME_MAX MAXNAMLEN
#endif

static inline void print_line(const char * a, const char * b) {
    int dist = 45 - strlen(a) - strlen(b);
    printf("    %s%*c%s\n", a, dist, ' ', b);
}

static void print_time(const char * d, const struct timespec * t,
		       const char * point, int precision)
{
    char buffer[128];
    if (t->tv_sec < 60)
	sprintf(buffer, "%d", (int)t->tv_sec);
    else if (t->tv_sec < 3600)
	sprintf(buffer, "%d:%02d",
		(int)t->tv_sec / 60,
		(int)t->tv_sec % 60);
    else if (t->tv_sec < 86400)
	sprintf(buffer, "%d:%02d:%02d",
		(int)t->tv_sec / 3600,
		((int)t->tv_sec / 60) % 60,
		(int)t->tv_sec % 60);
    else
	sprintf(buffer, "%dd %02d:%02d:%02d",
		(int)t->tv_sec / 86400,
		((int)t->tv_sec / 3600) % 24,
		((int)t->tv_sec / 60) % 60,
		(int)t->tv_sec % 60);
    if (point) {
	long v = t->tv_nsec;
	int i;
	for (i = precision; i < 9; i++) v /= 10;
	sprintf(buffer + strlen(buffer), "%s%0*ld", point, precision, v);
    }
    print_line(d, buffer);
}

static inline void print_numbers(const char * t, char * d, int len,
				 const char * comma, const char * grouping)
{
    int cl = strlen(comma), sd, dig, add = 0;
    /* figure out how many "commas" we need to add */
    sd = dig = 0;
    while (sd < len) {
	if (grouping[dig] == CHAR_MAX) break;
	if (sd) add += cl;
	sd += (unsigned char)grouping[dig];
	if (grouping[dig + 1]) dig++;
    }
    d[len + add + 1] = 0;
    dig = sd = 0;
    while (add > 0) {
	d[len + add] = d[len];
	len--;
	sd++;
	if (sd > (unsigned char)grouping[dig]) {
	    int i = cl;
	    sd -= (unsigned char)grouping[dig];
	    while (i > 0) {
		i--;
		d[len + add] = comma[i];
		add--;
	    }
	}
    }
    print_line(t, d);
}

static void print_long_long(const char * t, long long n,
			    const char * comma, const char * grouping)
{
    char d[(1 + strlen(comma)) * 32];
    int len = sprintf(d, "%lld", n);
    print_numbers(t, d, len, comma, grouping);
}

static void print_int(const char * t, int n,
		      const char * comma, const char * grouping)
{
    char d[(1 + strlen(comma)) * 16];
    int len = sprintf(d, "%d", n);
    print_numbers(t, d, len, comma, grouping);
}

static void print_list(const char * t, const int * l, int n, const char * p) {
    char d[24 * n];
    int len = 0, i;
    for (i = 0; i < n; i++)
	len += sprintf(d + len, "%s%d", i ? p : "", l[i]);
    print_line(t, d);
}

/* sends a command to the server and verifies error code; if OK, returns
 * 1; otherwise it reports the error and returns 0; the data argument, if
 * not NULL, is sent immediately after the command, without terminating
 * CRLF; if the last argument is not NULL, the OK reply from the server
 * is copied there */

int client_send_command(socket_t * p, const char * _command,
		 	const char * data, char * replbuff)
{
    int datalen = data ? strlen(data) : 0, df = -1, cmdlen = strlen(_command);
    char cbuff[cmdlen + 32], repl[REPLSIZE], * rptr;
    char ebuff[cmdlen + 256];
    const char * command, * cmderr;
    if (data && (rptr = strchr(_command, '%')) != NULL) {
	df = rptr - _command;
	command = cbuff;
	strncpy(cbuff, _command, df);
	sprintf(cbuff + df, "%d", datalen);
	strcat(cbuff + df, _command + df + 1);
	cmderr = ebuff;
	strncpy(ebuff, _command, df);
	if (datalen < 255) {
	    strcpy(ebuff + df, data);
	    rptr = ebuff + df + datalen;
	} else {
	    strncpy(ebuff + df, data, 252);
	    ebuff[df + 252] = '.';
	    ebuff[df + 253] = '.';
	    ebuff[df + 254] = '.';
	    rptr = ebuff + df + 255;
	}
	strcpy(rptr, _command + df + 1);
    } else {
	cmderr = command = _command;
    }
    if (! socket_puts(p, command)) {
	error_report(error_client, cmderr, errno);
	return 0;
    }
    if (data && ! socket_put(p, data, datalen)) {
	error_report(error_client, cmderr, errno);
	return 0;
    }
    rptr = replbuff ? replbuff : repl;
    errno = 0;
    rptr[0] = 0;
    if (! socket_gets(p, rptr, REPLSIZE)) {
	if (replbuff && errno == EINTR)
	    return 1;
	if (errno == 0)
	    error_report(error_client_msg, "socket_gets", "no data");
	else
	    error_report(error_client, "socket_gets", errno);
	return 0;
    }
    errno = 0;
    if (rptr[0] == 'O' && rptr[1] == 'K')
	return 1;
    if (replbuff && strncasecmp(rptr, "Interrupt", 9) == 0) {
	errno = EINTR;
	return 1;
    }
    error_report(error_client_msg, cmderr, rptr);
    return 0;
}

/* ask the server for a list of extension and return the ones this client
 * knows about */

client_extensions_t client_get_extensions(socket_t * p) {
    char repl[REPLSIZE];
    client_extensions_t result = client_ext_none;
    if (! socket_puts(p, "EXTENSIONS")) {
	error_report(error_client, "EXTENSIONS", errno);
	return client_ext_none;
    }
    errno = 0;
    repl[0] = 0;
    if (! socket_gets(p, repl, REPLSIZE)) {
	if (errno == 0)
	    error_report(error_client_msg, "socket_gets", "no data");
	else
	    error_report(error_client, "socket_gets", errno);
	return client_ext_none;
    }
    if (repl[0] != 'O' || repl[1] != 'K')
	return client_ext_none;
    while (socket_gets(p, repl, REPLSIZE)) {
	int rlen = strlen(repl);
	while (rlen > 0 && isspace((int)repl[rlen])) rlen--;
	repl[rlen] = 0;
	if (rlen == 1 && repl[0] == '.')
	    break;
	switch (repl[0]) {
	    case 'C' : case 'c' :
		if (rlen == 8 && strcasecmp(repl, "CHECKSUM") == 0)
		    result |= client_ext_checksum;
		break;
	    case 'E' : case 'e' :
		if (rlen == 7 && strcasecmp(repl, "ENCRYPT") == 0)
		    result |= client_ext_encrypt;
		if (rlen == 7 && strcasecmp(repl, "EVBATCH") == 0)
		    result |= client_ext_evbatch;
		break;
	    case 'I' : case 'i' :
		if (rlen == 6 && strcasecmp(repl, "IGNORE") == 0)
		    result |= client_ext_ignore;
		break;
	    case 'R' : case 'r' :
		if (rlen == 5 && strcasecmp(repl, "RSYNC") == 0)
		    result |= client_ext_rsync;
		break;
	}
    }
    return result;
}

static inline int get_status(socket_t * p, protocol_status_t * status) {
    const char * err;
    if (! client_send_command(p, "STATUS", NULL, NULL))
	return 0;
    err = protocol_status_receive(p, status);
    if (err) {
	error_report(error_client_msg, "status", err);
	return 0;
    }
    return 1;
}

static int print_status(socket_t * p, config_client_t mode) {
    protocol_status_t status;
    struct lconv * lc = localeconv();
    /* locales don't seem to define non-monetary values; probably
     * because this would break just about every program */
    const char * comma = lc && lc->mon_thousands_sep && *lc->mon_thousands_sep
		       ? lc->mon_thousands_sep : ",";
    const char * grouping = lc && lc->mon_grouping && *lc->mon_grouping
			  ? lc->mon_grouping : "\003";
    const char * point = lc && lc->mon_decimal_point && *lc->mon_decimal_point
		       ? lc->mon_decimal_point : ".";
    if (! get_status(p, &status))
	return 0;
    if (mode & config_client_status) {
	printf("SHOULD server status:\n");
    }
    if (mode & config_client_status) {
	print_list("Server version:", status.version, 3, point);
	print_line("Server mode:", status.server_mode ? "Server" : "Copy");
    } else if (mode & config_client_version) {
	printf("Server: should %d%s%d%s%d\n",
	       status.version[0], point, status.version[1],
	       point, status.version[2]);
    }
    if (mode & config_client_status) {
	char buffer[32];
	sprintf(buffer, "%d", status.server_pid);
	print_line("Server PID:", buffer);
    } else if (mode & config_client_getpid) {
	printf("%d\n", status.server_pid);
    }
    if (mode & config_client_status) {
	print_time("Running time:", &status.running, point, 2);
	print_time("User CPU time:", &status.usertime, point, 2);
	print_time("System CPU time:", &status.systime, point, 2);
	print_int("Client requests:", status.clients, comma, grouping);
	print_long_long("Memory usage:", status.memory, comma, grouping);
    }
    if (mode & (config_client_status | config_client_box)) {
	if (status.shouldbox >= 0) {
	    char buffer[32];
	    const char * curr;
	    if (lc) {
		if (lc->currency_symbol && *lc->currency_symbol) {
		    curr =  lc->currency_symbol;
		} else {
		    curr = "";
		}
	    } else {
		curr = "£";
	    }
	    if (lc->frac_digits > 0) {
		int d = lc->frac_digits < 10 ? lc->frac_digits - 1 : 1;
		int l = sprintf(buffer, "%s%d%s%d",
				curr, status.shouldbox / 10, point,
				status.shouldbox % 10);
		while (d-- > 0)
		    buffer[l++] = '0';
		buffer[l] = 0;
	    } else {
		sprintf(buffer, "%s%d", curr, status.shouldbox);
	    }
	    if (mode & config_client_status)
		print_line("Should Box", buffer);
	    else
		printf("%s\n", buffer);
	} else if (mode & config_client_box) {
	    printf("Server does not have a shouldbox\n");
	}
    }
    if (status.has_status && (mode & config_client_status)) {
	print_int("Events in queue:", status.notify.queue_events,
		  comma, grouping);
	print_int("Queue size:", status.notify.queue_bytes,
		  comma, grouping);
	print_int("Minimum queue size:", status.notify.queue_min,
		  comma, grouping);
	print_int("Allocated queue space:", status.notify.queue_min,
		  comma, grouping);
	print_int("Maximum queue size:", status.notify.queue_max,
		  comma, grouping);
	print_int("Max events in queue:", status.notify.max_events,
		  comma, grouping);
	print_int("Max queue size:", status.notify.max_bytes,
		  comma, grouping);
	if (status.notify.kernel_max_events >= 0)
	    print_int("Kernel event queue size:",
		      status.notify.kernel_max_events,
		      comma, grouping);
	print_int("Overflow events:", status.notify.overflow,
		  comma, grouping);
	print_int("Events too large for buffer:", status.notify.too_big,
		  comma, grouping);
	print_int("Active watches:", status.notify.watches,
		  comma, grouping);
	if (status.notify.kernel_max_watches >= 0)
	    print_int("Kernel max watches:", status.notify.kernel_max_watches,
		      comma, grouping);
	print_int("Allocated watch space:", status.notify.watchmem,
		  comma, grouping);
	print_int("Events since startup:", status.notify.events,
		  comma, grouping);
	print_int("Earliest event file:", status.store.file_earliest,
		  comma, grouping);
	print_int("Current event file:", status.store.file_current,
		  comma, grouping);
	print_int("Event file position:", status.store.file_pos,
		  comma, grouping);
	putchar('\n');
    }
    if (! status.server_mode && (mode & config_client_status)) {
	struct timespec eps;
	long long td;
	print_int("Event file procesed:", status.copy.file_current,
		  comma, grouping);
	print_int("Event file position:", status.copy.file_pos,
		  comma, grouping);
	print_int("Events since startup:", status.copy.events,
		  comma, grouping);
	print_time("Time spent processing events:", &status.copy.etime,
		   point, 3);
	if (status.copy.events > 0) {
	    eps.tv_sec = status.copy.etime.tv_sec / status.copy.events;
	    td = (long long)status.copy.etime.tv_sec * 1000000000LL
	       + (long long)status.copy.etime.tv_nsec;
	    td /= (long long)status.copy.events;
	    eps.tv_nsec = td / 1000000000LL;
	    eps.tv_nsec = td % 1000000000LL;
	    print_time("Time per event:", &eps, point, 6);
	}
	print_int("Pending dir syncs:", status.copy.dirsyncs,
		  comma, grouping);
	print_long_long("Bytes received from server:", status.copy.rbytes,
			comma, grouping);
	print_long_long("Bytes sent to server:", status.copy.wbytes,
			comma, grouping);
	print_long_long("Total size of files copied:", status.copy.tbytes,
			comma, grouping);
	print_long_long("File data actually copied:", status.copy.xbytes,
			comma, grouping);
	putchar('\n');
    }
    return 1;
}

static int print_list_type1(socket_t * p, const char * name) {
    char list[REPLSIZE], * nptr = NULL;
    int nsize = 0;
    while (1) {
	int len;
	if (! socket_gets(p, list, REPLSIZE)) {
	    error_report(error_client, name, errno);
	    if (nptr) myfree(nptr);
	    return 0;
	}
	len = atoi(list);
	if (len < 0) {
	    error_report(error_client_msg, name, "Invalid length");
	    if (nptr) myfree(nptr);
	    return 0;
	}
	if (len == 0) {
	    if (nptr) myfree(nptr);
	    putchar('\n');
	    return 1;
	}
	if (nsize < len + 1) {
	    if (nptr) myfree(nptr);
	    nsize = len + 512;
	    nptr = mymalloc(nsize);
	    if (! nptr) {
		error_report(error_client, name, errno);
		return 0;
	    }
	}
	if (! socket_get(p, nptr, len)) {
	    error_report(error_client, name, errno);
	    return 0;
	}
	nptr[len] = 0;
	printf("    ");
	store_printname(nptr, '\n');
    }
}

static int print_watches(socket_t * p) {
    if (! client_send_command(p, "WATCHES", NULL, NULL))
	return 0;
    printf("Watches:\n");
    return print_list_type1(p, "watches");
}

static int print_list_type2(socket_t * p, const char * name) {
    char list[REPLSIZE];
    int nl = 1;
    while (1) {
	if (! socket_gets(p, list, REPLSIZE)) {
	    error_report(error_client, name, errno);
	    return 0;
	}
	if (strcmp(list, "__END__") == 0) {
	    if (nl) putchar('\n');
	    return 1;
	}
	printf("%s\n", list);
	nl = list[0];
    }
}

static int print_config(socket_t * p) {
    if (! client_send_command(p, "CONFIG", NULL, NULL))
	return 0;
    printf("# Server Configuration:\n");
    return print_list_type2(p, "config");
}

static int print_compress(socket_t * p) {
    if (! client_send_command(p, "LISTCOMPRESS", NULL, NULL))
	return 0;
    printf("Compression methods supported by the server:\n");
    return print_list_type2(p, "compression methods");
}

static int print_checksum(socket_t * p) {
    if (! client_send_command(p, "LISTCHECKSUM", NULL, NULL))
	return 0;
    printf("Checksum methods supported by the server:\n");
    return print_list_type2(p, "checksum methods");
}

static int send_list(socket_t * p, const char * name,
		     const config_acl_cond_t * data)
{
    while (data) {
	const char * match = NULL;
	const char * how = NULL;
	char buffer[256];
	switch (data->data_index) {
	    case cfg_dacl_name  : match = "NAME"; break;
	    case cfg_dacl_path  : match = "PATH"; break;
	    default :
		error_report(error_internal, "send_list", "invalid match");
		return 0;
	}
	switch (data->how) {
	    case cfg_acl_exact : how = "EXACT"; break;
	    case cfg_acl_icase : how = "ICASE"; break;
	    case cfg_acl_glob  : how = "GLOB";  break;
	    case cfg_acl_iglob : how = "IGLOB"; break;
	    default :
		error_report(error_internal, "send_list", "invalid how");
		return 0;
	}
	sprintf(buffer, "%s %% %s %s", name, match, how);
	if (! client_send_command(p, buffer, data->pattern, NULL))
	    return 0;
	data = data->next;
    }
    return 1;
}

static int setup_client(socket_t * p) {
    protocol_status_t status;
    if (! get_status(p, &status))
	return 0;
    /* check that the server is a real server */
    if (! status.server_mode) {
	error_report(error_notserver);
	return 0;
    }
    /* and that it does support replication */
    if (! status.has_status) {
	error_report(error_nonotify);
	return 0;
    }
    return config_store_copy(status.store.file_current,
			     status.store.file_pos,
			     socket_user(p), socket_password(p));
}

/* set connection parameters for file copy etc. */

int client_set_parameters(socket_t * p) {
    const config_data_t * cfg = config_get();
    char command[REPLSIZE];
    if (config_intval(cfg, cfg_bwlimit)) {
	sprintf(command, "BWLIMIT %d", config_intval(cfg, cfg_bwlimit));
	config_put(cfg);
	if (! client_send_command(p, command, NULL, NULL))
	    return 0;
    }
    config_put(cfg);
    return 1;
}

static void copy_name(socket_t * p, int len) {
    while (len-- > 0) {
	int c = socket_getc(p);
	if (c == EOF) return;
	if (isgraph(c) && c != '%')
	    putc(c, stdout);
	else
	    printf("%%%02X", c);
    }
}

static int do_update(socket_t * p, const config_data_t * cfg) {
    const config_strlist_t * P = config_strlist(cfg, cfg_update);
    if (! P) return 1;
    while (P) {
	if (! client_send_command(p, "UPDATE %", P->data, NULL)) {
	    client_send_command(p, "UPDATE %", "rollback", NULL);
	    return 0;
	}
	P = P->next;
    }
    return client_send_command(p, "UPDATE %", "commit", NULL);
}

static int do_dirsync(socket_t * p, const config_data_t * cfg) {
    const config_strlist_t * P = config_strlist(cfg, cfg_dirsync_path);
    if (! P) return 1;
    while (P) {
	if (! client_send_command(p, "DIRSYNC %", P->data, NULL))
	    return 0;
	P = P->next;
    }
    return 1;
}

static int do_df(socket_t * p, const config_data_t * cfg) {
    const config_strlist_t * P = config_strlist(cfg, cfg_df_path);
    char command[REPLSIZE];
    printf("          disk space, megabytes              files, x 1000\n");
    printf("Mode  Total    Free    Used   Avail    Total   Used   Free  Avail  Path\n");
    while (P) {
	unsigned long bsize, btotal, bfree, bused, bavail, itotal, ifree, iused, iavail;
	int mode;
	if (! client_send_command(p, "STATFS %", P->data, command))
	    return 0;
	if (sscanf(command + 2,
		   "%lu %lu %lu %lu %lu %lu %lu %d",
		   &bsize, &btotal, &bfree, &bavail,
		   &itotal, &ifree, &iavail, &mode) < 8) {
	    fprintf(stderr, "Invalid data received from server\n");
	    return 0;
	}
	bused = btotal - bfree;
	iused = itotal - ifree;
	if (bsize >= 1048576) {
	    bsize /= 1048576;
	    btotal *= bsize;
	    bfree *= bsize;
	    bused *= bsize;
	    bavail *= bsize;
	} else {
	    bsize = 1048576 / bsize;
	    btotal /= bsize;
	    bfree /= bsize;
	    bused += bsize - 1;
	    bused /= bsize;
	    bavail /= bsize;
	}
	iused += 1023;
	iused /= 1024;
	iavail /= 1024;
	itotal /= 1024;
	ifree /= 1024;
	printf(" %s %7lu %7lu %7lu %7lu %8lu %6lu %6lu %6lu  %s\n",
	       mode ? "rw" : "ro", btotal, bfree, bused, bavail,
	       itotal, iused, ifree, iavail, P->data);
	P = P->next;
    }
    return 1;
}

static int do_ls(socket_t * p, const config_data_t * cfg) {
    const config_strlist_t * P = config_strlist(cfg, cfg_ls_path);
    char command[REPLSIZE];
    int tr_ids = config_intval(cfg, cfg_flags) & config_flag_translate_ids;
    static const char * ftype = "-dcbpls?";
    while (P) {
	sprintf(command, "GETDIR %% %d", tr_ids);
	if (! client_send_command(p, command, P->data, NULL))
	    return 0;
	printf("ls(%s):\n", P->data);
	while (1) {
	    int ft, dev, ino, mode, uid, gid, major, minor, nl, tl;
	    long long size;
	    char mtime[REPLSIZE], ctime[REPLSIZE], perms[11];
	    char uname[REPLSIZE], gname[REPLSIZE], * colon;
	    if (! socket_gets(p, command, sizeof(command))) {
		perror("socket_gets");
		return 0;
	    }
	    if (command[0] == '.') break;
	    if (tr_ids) {
		int l;
		if (sscanf(command,
			   "%d %d %d %o %s %d %s %d %lld %s %s %d %d %d %d",
			   &ft, &dev, &ino, &mode, uname, &uid, gname, &gid,
			   &size, mtime, ctime, &major, &minor, &nl, &tl) < 15)
		    break;
		l = strlen(uname);
		while (l < 10) uname[l++] = ' ';
		uname[l] = 0;
		l = strlen(gname);
		while (l < 10) gname[l++] = ' ';
		gname[l] = 0;
	    } else {
		if (sscanf(command,
			   "%d %d %d %o %d %d %lld %s %s %d %d %d %d",
			   &ft, &dev, &ino, &mode, &uid, &gid,
			   &size, mtime, ctime, &major, &minor, &nl, &tl) < 13)
		    break;
		sprintf(uname, "%5d", uid);
		sprintf(gname, "%5d", gid);
	    }
	    perms[0] = ft >= 0 && ft < 7 ? ftype[ft] : '?';
	    perms[1] = mode & 00400 ? 'r' : '-';
	    perms[2] = mode & 00200 ? 'w' : '-';
	    perms[3] = mode & 00100 ? (mode & 04000 ? 's' : 'x') : (mode & 04000 ? 'S' : '-');
	    perms[4] = mode & 00040 ? 'r' : '-';
	    perms[5] = mode & 00020 ? 'w' : '-';
	    perms[6] = mode & 00010 ? (mode & 02000 ? 's' : 'x') : (mode & 02000 ? 'S' : '-');
	    perms[7] = mode & 00004 ? 'r' : '-';
	    perms[8] = mode & 00002 ? 'w' : '-';
	    perms[9] = mode & 00001 ? (mode & 01000 ? 't' : 'x') : (mode & 01000 ? 'T' : '-');
	    perms[10] = 0;
	    colon = strchr(mtime, ':');
	    if (colon) *colon = ' ';
	    printf("%s %s %s %10lld %s ", perms, uname, gname, size, mtime);
	    copy_name(p, nl);
	    if (tl) printf(" -> ");
	    copy_name(p, tl);
	    printf("\n");
	}
	printf("\n");
	P = P->next;
    }
    return 1;
}

static int do_cp(socket_t * p, const config_data_t * cfg,
		 int compression, int checksum, pipe_t * extcopy,
		 client_extensions_t extensions)
{
    const config_strlist_t * P = config_strlist(cfg, cfg_cp_path);
    struct stat sbuff;
    int is_dir;
    const char * dest;
    int tr_ids = config_intval(cfg, cfg_flags) & config_flag_translate_ids;
    int use_librsync =
	(config_intval(cfg, cfg_flags) & config_flag_use_librsync) &&
	(extensions & client_ext_rsync);
    if (! P || ! P->next) {
	fprintf(stderr, "Please specify at least two names for \"cp\"\n");
	return 0;
    }
    dest = P->data;
    P = P->next;
    if (P->next) {
	if (stat(dest, &sbuff) < 0) {
	    perror(dest);
	    return 0;
	}
	if (! S_ISDIR(sbuff.st_mode)) {
	    fprintf(stderr, "%s: not a directory\n", dest);
	    return 0;
	}
	is_dir = 1;
    } else {
	is_dir = stat(dest, &sbuff) >= 0 && S_ISDIR(sbuff.st_mode);
    }
    if (is_dir) {
	int len = strlen(dest);
	char dfn[len + NAME_MAX + 3];
	strcpy(dfn, dest);
	dfn[len++] = '/';
	while (P) {
	    const char * slash = strrchr(P->data, '/');
	    if (slash) slash++;
	    strncpy(dfn + len, slash, NAME_MAX);
	    dfn[len + NAME_MAX] = 0;
	    copy_file(p, P->data, dfn, tr_ids, compression, checksum,
		      extcopy, use_librsync);
	    P = P->next;
	}
    } else {
	while (P) {
	    copy_file(p, P->data, dest, tr_ids, compression, checksum,
		      extcopy, use_librsync);
	    P = P->next;
	}
    }
    return 1;
}

static void do_telnet(socket_t * p) {
    struct pollfd pfd[2];
    char buffer[DATA_BLOCKSIZE];
    int go = 3;
    pfd[0].fd = fileno(stdin);
    pfd[0].events = POLLIN|POLLERR|POLLHUP|POLLNVAL;
    pfd[0].revents = 0;
    pfd[1].fd = socket_poll(p);
    pfd[1].events = POLLIN|POLLERR|POLLHUP|POLLNVAL;
    pfd[1].revents = 0;
    while (go && poll(pfd, 2, -1) >= 0) {
	if (pfd[0].revents & POLLIN) {
	    ssize_t nr = read(pfd[0].fd, buffer, sizeof(buffer));
	    if (nr > 0) {
		if (! socket_put(p, buffer, nr))
		    fprintf(stderr, "\nWarning: could not send to server\n");
	    } else {
		go &= 2;
		pfd[0].events = 0;
	    }
	}
	if (pfd[1].revents & POLLIN) {
	    int nr = socket_getdata(p, buffer, sizeof(buffer));
	    if (nr > 0) {
		if (fwrite(buffer, nr, 1, stdout) < 1)
		    fprintf(stderr, "\nWarning: previous result truncated\n");
		fflush(stdout);
	    }
	    if (nr < 0) {
		go &= 1;
		pfd[1].events = 0;
	    }
	}
	if (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)) {
	    go = 0;
	    pfd[0].events = 0;
	}
	if (pfd[1].revents & (POLLERR|POLLHUP|POLLNVAL)) {
	    go = 0;
	    pfd[1].events = 0;
	}
    }
    if (go) perror("poll");
}

static int set_checksum(socket_t * p, int nchecksum) {
    const char * cn = checksum_name(nchecksum);
    if (cn) {
	char command[20 + strlen(cn)];
	sprintf(command, "SETCHECKSUM %s", cn);
	if (! client_send_command(p, command, NULL, NULL))
	    return -1;
	return nchecksum;
    }
    return -1;
}

/* determine which checksum methods are supported by both server and client,
 * and returns the ID for the preferred one (or -1 if none found) */

int client_find_checksum(socket_t * p, client_extensions_t extensions) {
    int max = checksum_count(), chk[max], i, nv;
    char list[REPLSIZE];
    const config_data_t * cfg;
    /* if server has no checksum support, we won't use it */
    if (! (extensions & client_ext_checksum))
	return -1;
    /* ask the server for a list of checksum methods, and see if
     * we recognise any of them */
    if (! client_send_command(p, "LISTCHECKSUM", NULL, NULL))
	return -1;
    for (i = 0; i < max; i++)
	chk[i] = 0;
    while (1) {
	int nc;
	if (! socket_gets(p, list, REPLSIZE)) {
	    error_report(error_client, "LISTCHECKSUMS", errno);
	    return -1;
	}
	if (strcmp(list, "__END__") == 0)
	    break;
	nc = checksum_byname(list);
	if (nc < 0 || nc >= max) continue;
	chk[nc] = 1;
    }
    /* if we have a preference list, and it lists a method known to the
     * server, use it */
    cfg = config_get();
    nv = config_intarr_len(cfg, cfg_checksums);
    if (nv > 0) {
	const int * vals = config_intarr_data(cfg, cfg_checksums);
	for (i = 0; i < nv; i++) {
	    if (vals[i] >= 0 && vals[i] < max && chk[vals[i]]) {
		config_put(cfg);
		return set_checksum(p, vals[i]);
	    }
	}
    }
    config_put(cfg);
    /* if not, just take the lowest numbered */
    for (i = 0; i < max; i++)
	if (chk[i])
	    return set_checksum(p, i);
    /* if all else fails... */
    return -1;
}

static int set_compress(socket_t * p, int ncompress) {
    const char * cn = compress_name(ncompress);
    if (cn) {
	char command[20 + strlen(cn)];
	sprintf(command, "COMPRESS %s", cn);
	if (! client_send_command(p, command, NULL, NULL))
	    return -1;
	return ncompress;
    }
    return -1;
}

/* determine which compression methods are supported by both server and client,
 * and returns the ID for the preferred one (or -1 if none found) */

int client_find_compress(socket_t * p) {
    int max = compress_count(), com[max], i, nv;
    char list[REPLSIZE];
    const config_data_t * cfg;
    /* ask the server for a list of compression methods, and see if
     * we recognise any of them */
    if (! client_send_command(p, "LISTCOMPRESS", NULL, NULL))
	return -1;
    for (i = 0; i < max; i++)
	com[i] = 0;
    while (1) {
	int nc;
	if (! socket_gets(p, list, REPLSIZE)) {
	    error_report(error_client, "LISTCOMPRESS", errno);
	    return -1;
	}
	if (strcmp(list, "__END__") == 0)
	    break;
	nc = compress_byname(list);
	if (nc < 0 || nc >= max) continue;
	com[nc] = 1;
    }
    /* if we have a preference list, and it lists a method known to the
     * server, use it */
    cfg = config_get();
    nv = config_intarr_len(cfg, cfg_compressions);
    if (nv > 0) {
	const int * vals = config_intarr_data(cfg, cfg_compressions);
	for (i = 0; i < nv; i++) {
	    if (vals[i] >= 0 && vals[i] < max && com[vals[i]]) {
		config_put(cfg);
		return set_compress(p, vals[i]);
	    }
	}
    }
    config_put(cfg);
    /* if not, just take the lowest numbered */
    for (i = 0; i < max; i++)
	if (com[i])
	    return set_compress(p, i);
    /* if all else fails... */
    return -1;
}

int client_run(void) {
    int status = 1;
    client_extensions_t extensions;
    const config_data_t * cfg = config_get();
    socket_t * p = socket_connect();
    config_client_t cm;
    char repl[REPLSIZE];
    if (! p) {
	error_report(error_client, "connect", errno);
	config_put(cfg);
	return 1;
    }
    cm = config_intval(cfg, cfg_client_mode);
    if (cm & config_client_cleardebug)
	if (! client_send_command(p, "NODEBUG", NULL, NULL))
	    goto out;
    if (cm & config_client_setdebug) 
	if (! client_send_command(p, "DEBUG", NULL, NULL))
	    goto out;
    extensions = client_get_extensions(p);
    if (cm & config_client_remove) {
	const config_strlist_t * d = config_strlist(cfg, cfg_remove_path);
	while (d) {
	    if (! client_send_command(p, "REMOVE %", d->data, NULL))
		goto out;
	    d = d->next;
	}
    }
    if (cm & config_client_add) {
	const config_strlist_t * d = config_strlist(cfg, cfg_add_path);
	while (d) {
	    char repl[REPLSIZE];
	    const config_add_t * av = d->privdata;
	    if (! client_send_command(p, "ADD %", d->data, NULL))
		goto out;
	    if (! send_list(p, "EXCL", av->exclude))
		goto out;
	    if (! send_list(p, "FIND", av->find))
		goto out;
	    if (! client_send_command(p, av->crossmount ? "CROSS" : "NOCROSS",
				      NULL, repl))
		goto out;
	    printf("Added %d watches under %s\n", atoi(repl + 2), d->data);
	    d = d->next;
	}
    }
    if (cm & config_client_rotatelog)
	if (! client_send_command(p, "ROTATELOG", NULL, NULL))
	    goto out;
    if (cm & config_client_closelog)
	if (! client_send_command(p, "CLOSELOG", NULL, NULL))
	    goto out;
    if (cm & config_client_purge) {
	sprintf(repl, "PURGE %d", config_intval(cfg, cfg_purge_days));
	if (! client_send_command(p, repl, NULL, NULL))
	    goto out;
    }
    if (cm & config_client_setup)
	if (! setup_client(p))
	    goto out;
    if (cm &
	(config_client_status |
	 config_client_box |
	 config_client_version |
	 config_client_getpid))
    {
	if (! print_status(p, cm))
	    goto out;
    }
    if (cm & config_client_watches)
	if (! print_watches(p))
	    goto out;
    if (cm & config_client_listcompress)
	if (! print_compress(p))
	    goto out;
    if (cm & config_client_listchecksum)
	if (! print_checksum(p))
	    goto out;
    if (cm & config_client_dirsync)
	if (! do_dirsync(p, cfg))
	    goto out;
    if (cm & config_client_update)
	if (! do_update(p, cfg))
	    goto out;
    if (cm & config_client_config)
	if (! print_config(p))
	    goto out;
    if (cm & config_client_ls)
	if (! do_ls(p, cfg))
	    goto out;
    if (cm & config_client_cp) {
	int checksum = client_find_checksum(p, extensions);
	int compress = client_find_compress(p);
	int ok;
	pipe_t P;
	if (! client_setup_extcopy(&P)) {
	    perror("external_copy");
	    goto out;
	}
	ok = do_cp(p, cfg, compress, checksum, &P, extensions);
	pipe_close(&P);
	if (! ok)
	    goto out;
    }
    if (cm & config_client_df)
	if (! do_df(p, cfg))
	    goto out;
    if (cm & config_client_telnet) {
	do_telnet(p);
	status = 0;
	goto out_noquit;
    }
    if (cm & config_client_stop) {
	socket_puts(p, "STOP");
	goto out_noquit;
    }
    status = 0;
out:
    socket_puts(p, "QUIT");
out_noquit:
    socket_gets(p, repl, REPLSIZE);
    socket_disconnect(p);
    config_put(cfg);
    return status;
}

/* set up an external copy program, if configured; returns 1 if OK, 0
 * if an error occurred (errno will be set accordingly) */

int client_setup_extcopy(pipe_t * P) {
    const config_data_t * cfg = config_get();
    char * const * ecprog = config_strarr(cfg, cfg_strarr_extcopy);
    P->fromchild = P->tochild = -1;
    P->pid = -1;
    if (ecprog && ecprog[0]) {
	if (! pipe_opento(ecprog, P)) {
	    int e = errno;
	    config_put(cfg);
	    errno = e;
	    return 0;
	}
    }
    config_put(cfg);
    return 1;
}

