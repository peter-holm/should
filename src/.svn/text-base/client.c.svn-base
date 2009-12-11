/* SHOULD's client
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#define _GNU_SOURCE
#include "site.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <utime.h>
#include <limits.h>
#include "client.h"
#include "main_thread.h"
#include "config.h"
#include "error.h"
#include "socket.h"
#include "mymalloc.h"
#include "protocol.h"
#include "compress.h"
#include "usermap.h"

#define REPLSIZE 256
#define MAX_POS 4096

static inline void print_line(const char * a, const char * b) {
    int dist = 40 - strlen(a) - strlen(b);
    printf("    %s%*c%s\n", a, dist, ' ', b);
}

static void print_time(const char * d, const struct timespec * t, int frac) {
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
    if (frac)
	sprintf(buffer + strlen(buffer), ".%02d",
	       (int)t->tv_nsec / 10000000);
    print_line(d, buffer);
}

static inline void print_numbers(const char * t, char * d, int len) {
    int add = (len - 1) / 3, dig = 0;
    d[len + add + 1] = 0;
    while (add > 0) {
	d[len + add] = d[len];
	len--;
	dig++;
	if (dig > 3) {
	    dig -= 3;
	    d[len + add] = ',';
	    add --;
	}
    }
    print_line(t, d);
}

static void print_long_long(const char * t, long long n) {
    char d[128];
    int len = sprintf(d, "%lld", n);
    print_numbers(t, d, len);
}

static void print_int(const char * t, int n) {
    char d[128];
    int len = sprintf(d, "%d", n);
    print_numbers(t, d, len);
}

static void print_list(const char * t, const int * l, int n) {
    char d[24 * n];
    int len = 0, i;
    for (i = 0; i < n; i++)
	len += sprintf(d + len, "%s%d", i ? "." : "", l[i]);
    print_line(t, d);
}

static int send_command(socket_t * p, const char * command,
		 	const char * data, char * replbuff)
{
    char repl[REPLSIZE], * rptr;
    if (! socket_puts(p, command)) {
	error_report(error_client, command, errno);
	return 0;
    }
    if (data && ! socket_put(p, data, strlen(data))) {
	error_report(error_client, command, errno);
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
    error_report(error_client_msg, command, rptr);
    return 0;
}

static inline int get_status(socket_t * p, protocol_status_t * status) {
    const char * err;
    if (! send_command(p, "STATUS", NULL, NULL))
	return 0;
    err = protocol_status_receive(p, status);
    if (err) {
	error_report(error_client_msg, "status", err);
	return 0;
    }
    return 1;
}

static int print_status(socket_t * p, config_client_t mode,
			int * fnum, int * fpos)
{
    protocol_status_t status;
    if (! get_status(p, &status))
	return 0;
    *fnum = status.cs.file_current;
    *fpos = status.cs.file_pos;
    if (mode & config_client_status) {
	printf("SHOULD server status:\n");
    }
    if (mode & config_client_status) {
	print_list("Server version:", status.version, 3);
    } else if (mode & config_client_version) {
	printf("Server: should %d.%d.%d\n",
	       status.version[0], status.version[1], status.version[2]);
    }
    if (mode & config_client_status) {
	char buffer[32];
	sprintf(buffer, "%d", status.server_pid);
	print_line("Server PID:", buffer);
    } else if (mode & config_client_getpid) {
	printf("%d\n", status.server_pid);
    }
    if (mode & config_client_status) {
	print_time("Running time:", &status.running, 1);
	print_time("User CPU time:", &status.usertime, 1);
	print_time("System CPU time:", &status.systime, 1);
	print_int("Client requests:", status.clients);
	print_long_long("Memory usage:", status.memory);
    }
    if (mode & (config_client_status | config_client_box)) {
	if (status.shouldbox >= 0) {
	    char buffer[32];
	    sprintf(buffer, "£%d.%d0",
		    status.shouldbox / 10, status.shouldbox % 10);
	    if (mode & config_client_status)
		print_line("Should Box", buffer);
	    else
		printf("%s\n", buffer);
	} else if (mode & config_client_box) {
	    printf("Server does not have a shouldbox\n");
	}
    }
    if (mode & config_client_status) {
	print_int("Events in queue:", status.ns.queue_events);
	print_int("Queue size:", status.ns.queue_bytes);
	print_int("Minimum queue size:", status.ns.queue_min);
	print_int("Allocated queue space:", status.ns.queue_min);
	print_int("Maximum queue size:", status.ns.queue_min);
	print_int("Max events in queue:", status.ns.max_events);
	print_int("Max queue size:", status.ns.max_bytes);
	print_int("Kernel event queue size:", status.ns.kernel_max_events);
	print_int("Overflow events:", status.ns.overflow);
	print_int("Events too large for buffer:", status.ns.too_big);
	print_int("Active watches:", status.ns.watches);
	print_int("Kernel max watches:", status.ns.kernel_max_watches);
	print_int("Allocated watch space:", status.ns.watchmem);
	print_int("Events since startup:", status.ns.events);
	print_int("Earliest event file:", status.cs.file_earliest);
	print_int("Current event file:", status.cs.file_current);
	print_int("Event file position:", status.cs.file_pos);
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
    if (! send_command(p, "WATCHES", NULL, NULL))
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
    if (! send_command(p, "CONFIG", NULL, NULL))
	return 0;
    printf("Server Configuration:\n");
    return print_list_type2(p, "config");
}

static int print_compress(socket_t * p) {
    if (! send_command(p, "LISTCOMPRESS", NULL, NULL))
	return 0;
    printf("Compression methods supported:\n");
    return print_list_type2(p, "compression methods");
}

static int send_list(socket_t * p, const char * name,
		     const config_match_t * data)
{
    while (data) {
	int len = strlen(data->pattern);
	const char * match = NULL;
	const char * how = NULL;
	char buffer[256];
	switch (data->match) {
	    case config_match_name  : match = "NAME"; break;
	    case config_match_path  : match = "PATH"; break;
	}
	if (! match) {
	    error_report(error_internal, "send_list", "invalid match");
	    return 0;
	}
	switch (data->how) {
	    case config_match_exact : how = "EXACT"; break;
	    case config_match_icase : how = "ICASE"; break;
	    case config_match_glob  : how = "GLOB";  break;
	    case config_match_iglob : how = "IGLOB"; break;
	}
	if (! how) {
	    error_report(error_internal, "send_list", "invalid how");
	    return 0;
	}
	sprintf(buffer, "%s %d %s %s", name, len, match, how);
	if (! send_command(p, buffer, data->pattern, NULL))
	    return 0;
	data = data->next;
    }
    return 1;
}

static inline int put_name(FILE * S, const char * name, const char * value) {
    if (value)
	return fprintf(S, "%s %d\n%s\n", name, (int)strlen(value), value) >= 0;
    else
	return fprintf(S, "%s -1\n", name) >= 0;
}

static int setup_client(socket_t * p, const config_t * cfg) {
    int fd;
    FILE * S = NULL;
    protocol_status_t status;
    if (! get_status(p, &status))
	return 0;
    fd = open(cfg->copy_state, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0)
	goto problem;
    if (lseek(fd, (off_t)0, SEEK_SET) < 0)
	goto problem;
    if (lockf(fd, F_LOCK, (off_t)0) < 0)
	goto problem;
    S = fdopen(fd, "w");
    if (! S)
	goto problem;
    if (fprintf(S, "SHOULD STATE FILE\n") < 0)
	goto problem;
    if (! put_name(S, "FROM", cfg->from_prefix))
	goto problem;
    if (! put_name(S, "TO", cfg->to_prefix))
	goto problem;
    if (! put_name(S, "SOCKET", cfg->control_socket))
	goto problem;
    if (cfg->server.host) {
	char server[2 + strlen(cfg->server.host) + strlen(cfg->server.port)];
	sprintf(server, "%s:%s", cfg->server.host, cfg->server.port);
	if (! put_name(S, "SERVER", server))
	    goto problem;
    }
    if (! put_name(S, "USER", cfg->user))
	goto problem;
    if (! put_name(S, "PASSWORD", cfg->password))
	goto problem;
    if (fprintf(S, "TRANSLATE_IDS %d\n",
		(cfg->flags & config_flag_translate_ids) ? 1 : 0) < 0)
	goto problem;
    if (fprintf(S, "SKIP_MATCHING %d\n",
		(cfg->flags & config_flag_skip_matching) ? 1 : 0) < 0)
	goto problem;
    if (fprintf(S, "BWLIMIT %d\n", cfg->bwlimit) < 0)
	goto problem;
    if (fprintf(S, "OPTIMISE_COUNT %d\n", cfg->optimise_client) < 0)
	goto problem;
    if (fprintf(S, "OPTIMISE_SIZE %d\n", cfg->optimise_buffer) < 0)
	goto problem;
    if (cfg->compression >= 0) {
	const char * name = compress_name(cfg->compression);
	if (name) {
	    fprintf(S, "COMPRESS %s\n", name);
#if USE_SHOULDBOX
	} else {
	    main_shouldbox++;
	    error_report(error_shouldbox_null, "setup_client", "compression");
#endif
	}
    }
    if (fprintf(S, "END STATE\n") < 0)
	goto problem;
    if (fprintf(S, "%d %d\n",
	        status.cs.file_current, status.cs.file_pos) < 0)
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
    error_report(error_setup, cfg->copy_state, errno);
    if (S)
	fclose(S);
    else if (fd >= 0)
	close(fd);
    return 0;
}

static inline int assign_number(const char * line, const char * keyword,
				int * result, int * err)
{
    int len = strlen(keyword);
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    *err = 1;
    if (! *line || ! isspace(*line)) return 1;
    while (*line && isspace(*line)) line++;
    if (! *line || ! (isdigit(*line) ||*line == '-')) return 1;
    *result = atoi(line);
    *err = 0;
    return 1;
}

static inline int assign_flag(const char * line, const char * keyword,
			      config_flags_t * result, config_flags_t value ,
			      int * err)
{
    int len = strlen(keyword);
    if (strncmp(line, keyword, len) != 0) return 0;
    line += len;
    *err = 1;
    if (! *line || ! isspace(*line)) return 1;
    while (*line && isspace(*line)) line++;
    if (! *line || ! (isdigit(*line) ||*line == '-')) return 1;
    if (atoi(line)) {
	*result |= value;
    } else {
	*result &= ~value;
    }
    *err = 0;
    return 1;
}

static inline int assign_string(const char * line, FILE * S,
				const char * keyword, char ** result,
				int * length, int * err)
{
    int len;
    if (! assign_number(line, keyword, &len, err)) return 0;
    if (* err) return 1;
    if (*result) myfree(*result);
    if (len < 0) {
	*result = NULL;
	if (length) *length = 0;
    } else {
	*result = mymalloc(len + 1);
	if (! *result) {
	    *err = 2;
	    return 1;
	}
	if (fread(*result, len + 1, 1, S) < 1) {
	    *err = 2;
	    return 1;
	}
	(*result)[len] = 0;
	if (length) *length = len;
    }
    *err = 0;
    return 1;
}

static FILE * read_copy_state(config_t * cfg, long * fstart,
			      int * fnum, int * fpos)
{
    FILE * S = fopen(cfg->copy_state, "r+");
    char linebuff[REPLSIZE], * compression = NULL;
    int len, err;
    if (! S)
	goto problem;
    if (fseek(S, 0L, SEEK_SET) < 0)
	goto problem;
    if (lockf(fileno(S), F_TLOCK, (off_t)0) < 0) {
	if (errno != EACCES && errno != EAGAIN)
	    goto problem;
	error_report(error_readcopy_locked, cfg->copy_state);
	fclose(S);
	return NULL;
    }
    if (! fgets(linebuff, sizeof(linebuff), S))
	goto problem;
    if (strcmp(linebuff, "SHOULD STATE FILE\n") != 0)
	goto format;
#define READLINE(name, element, length) \
    if (assign_string(linebuff, S, name, &cfg->element, length, &err)) \
	goto check_result;
#define READNUM(name, element) \
    if (assign_number(linebuff, name, &cfg->element, &err)) \
	goto check_result;
#define READFLAG(name, flagname) \
    if (assign_flag(linebuff, name, &cfg->flags, config_flag_##flagname, &err)) \
	goto check_result;
    while (fgets(linebuff, sizeof(linebuff), S)) {
	READLINE("FROM", from_prefix, &cfg->from_length);
	READLINE("TO", to_prefix, &cfg->to_length);
	READLINE("SOCKET", control_socket, NULL);
	READLINE("SERVER", server.host, NULL);
	READLINE("USER", user, NULL);
	READLINE("PASSWORD", password, NULL);
	READFLAG("TRANSLATE_IDS", translate_ids);
	READFLAG("SKIP_MATCHING", skip_matching);
	READNUM("BWLIMIT", bwlimit);
	READNUM("OPTIMISE_COUNT", optimise_client);
	READNUM("OPTIMISE_SIZE", optimise_buffer);
	if (assign_string(linebuff, S, "COMPRESSION", &compression, NULL, &err))
	    goto check_result;
	if (strncmp(linebuff, "END STATE", 9) == 0) break;
	goto format;
    check_result:
	if (! err) continue;
	if (err == 1) goto format;
	goto problem;
    }
#undef READLINE
#undef READNUM
    if (cfg->server.host) {
	char * c = rindex(cfg->server.host, ':');
	if (c) *c++ = 0;
	cfg->server.port = c;
    }
    if (compression) {
	int num = compress_byname(compression);
	if (num < 0) {
	    error_report(error_readcopy_compress, cfg->copy_state, compression);
	    fclose(S);
	    myfree(compression);
	    return NULL;
	}
	cfg->compression = num;
	myfree(compression);
    }
    *fstart = ftell(S);
    if (*fstart < 0)
	goto problem;
    len = 0;
    while (fgets(linebuff, sizeof(linebuff), S)) {
	if (sscanf(linebuff, "%d %d\n", fnum, fpos) < 0)
	    continue;
	len++;
    }
    if (len < 1)
	goto format;
    if (len > MAX_POS) {
	long pos;
	/* write back to position pos and truncate file */
	if (fseek(S, *fstart, SEEK_SET) < 0)
	    goto problem;
	if (fprintf(S, "%d %d\n", *fnum, *fpos) < 0)
	    goto problem;
	fflush(S);
	pos = ftell(S);
	if (pos < 0)
	    goto problem;
	if (ftruncate(fileno(S), pos) < 0)
	    goto problem;
    }
    return S;
format:
    error_report(error_readcopy_fmt, cfg->copy_state);
    fclose(S);
    return NULL;
problem:
    error_report(error_readcopy, cfg->copy_state, errno);
    if (S)
	fclose(S);
    return NULL;
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

int copy_file_data(socket_t * p, int flen, const char * fname,
		   const notify_event_t * ev, struct stat * exists,
		   notify_filetype_t filetype, int compression)
{
    switch (ev->file_type) {
	case notify_filetype_regular : {
	    int ffd;
	    char tempname[flen + 9], * dp = tempname, cmdbuff[64];
	    const char * sl;
	    long long done;
	    sprintf(cmdbuff, "OPEN %d", (int)strlen(ev->from_name));
	    if (! send_command(p, cmdbuff, ev->from_name, NULL))
		return 1;
	    sl = strrchr(fname, '/');
	    if (sl) {
		int len = sl - fname + 1;
		strncpy(dp, fname, len);
		dp += len;
		sl++;
	    } else {
		sl = fname;
		*dp++ = '/';
	    }
	    *dp = 0;
	    if (! mkpath(tempname)) {
		error_report(error_copy_sys, tempname, errno);
		send_command(p, "CLOSEFILE", NULL, NULL);
		return 1;
	    }
	    *dp++ = '.';
	    strcpy(dp, sl);
	    strcat(dp, ".XXXXXX");
	    ffd = mkstemp(tempname);
	    if (ffd < 0)
		goto error_tempname;
	    fchmod(ffd, ev->file_mode); /* just in case */
	    done = 0L;
	    /* do the actual file data copy to ffd */
	    while (done < ev->file_size) {
		long long block = ev->file_size - done, realsize;
		char repl[REPLSIZE], data[DATA_BLOCKSIZE], ud[DATA_BLOCKSIZE];
		const char * dp;
		int nf;
		if (block > DATA_BLOCKSIZE) block = DATA_BLOCKSIZE;
		sprintf(cmdbuff, "DATA %lld %lld", done, block);
		if (! send_command(p, cmdbuff, NULL, repl))
		    goto error_tempname_noreport;
		if (errno == EINTR)
		    goto error_tempname_noreport;
		nf = sscanf(repl + 2, "%lld %lld", &block, &realsize);
		if (nf < 1 || block < 0 || block > DATA_BLOCKSIZE) {
		    error_report(error_copy_invalid, fname, repl);
		    goto error_tempname_noreport;
		}
		if (nf >= 2) {
		    if (realsize < 0 || realsize > block) {
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
		if (write(ffd, dp, realsize) < 0) {
		    error_report(error_copy_sys, tempname, errno);
		    goto error_tempname_noreport;
		}
		done += block;
	    }
	    if (close(ffd) < 0) {
		error_report(error_copy_sys, tempname, errno);
		unlink(tempname);
		send_command(p, "CLOSEFILE", NULL, NULL);
		return 1;
	    }
	    ffd = -1;
	    if (exists && filetype != notify_filetype_regular)
		filetype == notify_filetype_dir ? rmdir(fname) : unlink(fname);
	    if (rename(tempname, fname) < 0)
		goto error_tempname;
	    if (! send_command(p, "CLOSEFILE", NULL, NULL))
		return 1;
	    return 2;
	error_tempname:
	    error_report(error_copy_sys, tempname, errno);
	error_tempname_noreport:
	    if (ffd >= 0) {
		close(ffd);
		unlink(tempname);
	    }
	    return 1;
	}
	case notify_filetype_dir :
	    if (exists) {
		if (filetype == ev->file_type)
		    return 2;
		filetype == notify_filetype_dir ? rmdir(fname) : unlink(fname);
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
		filetype == notify_filetype_dir ? rmdir(fname) : unlink(fname);
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
		filetype == notify_filetype_dir ? rmdir(fname) : unlink(fname);
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
		filetype == notify_filetype_dir ? rmdir(fname) : unlink(fname);
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

static int copy_file(socket_t * p, const config_t * cfg,
		     const notify_event_t * ev)
{
    int do_lstat = 1, fstat_valid, ok, clen;
    struct stat sbuff;
    /* translate server's names to local names */
    int flen = ev->from_name && ev->from_length >= cfg->from_length
	     ? ev->from_length + 1 + cfg->to_length - cfg->from_length
	     : 1;
    int tlen = ev->to_name && ev->to_length >= cfg->to_length
	     ? ev->to_length + 1 + cfg->to_length - cfg->from_length
	     : 1;
    char fname[flen], tname[tlen];
    const char * cptr;
    if (ev->from_name && ev->from_length >= cfg->from_length) {
	if (ev->from_length >= cfg->from_length) {
	    strncpy(fname, cfg->to_prefix, cfg->to_length);
	    strcpy(fname + cfg->to_length, ev->from_name + cfg->from_length);
	} else {
	    fname[0] = 0;
	}
    }
    if (ev->to_name && ev->to_length >= cfg->to_length) {
	if (ev->to_length >= cfg->to_length) {
	    strncpy(tname, cfg->to_prefix, cfg->to_length);
	    strcpy(tname + cfg->to_length, ev->to_name + cfg->from_length);
	} else {
	    tname[0] = 0;
	}
    }
    /* duplicate event */
    switch (ev->event_type) {
	case notify_change_meta :
	    /* change metadata: uid, gid, mode, mtime */
	    if (! ev->stat_valid)
		/* means file was deleted before we got to it */
		return 1;
	adjust_meta:
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
	case notify_create :
	    cptr = fname;
	    clen = flen;
	copy_data:
	    /* file was created or modified */
	    if (! ev->stat_valid)
		/* means file was deleted before we got to it */
		return 1;
	    fstat_valid = lstat(cptr, &sbuff) >= 0;
	    /* if file exists, mtime & size are identical, and the user want
	     * to skip matching files, skip them */
	    if (fstat_valid &&
		(cfg->flags & config_flag_skip_matching) &&
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
printf("copy (%s, %lld)\n", cptr, ev->file_size); // XXX
	    ok = copy_file_data(p, clen, cptr, ev, fstat_valid ? &sbuff : NULL,
				fstat_valid ? notify_filetype(sbuff.st_mode)
					    : notify_filetype_unknown,
				cfg->compression);
	    if (! ok)
		return 0;
	    if (ok == 1)
		return 1;
	    goto adjust_meta;
	case notify_delete :
printf("delete (%s)\n", fname); // XXX
	    if (lstat(fname, &sbuff) >= 0 && S_ISDIR(sbuff.st_mode)) {
		if (rmdir(fname) < 0 && errno != ENOENT)
		    goto error_fname;
	    } else {
		if (unlink(fname) < 0 && errno != ENOENT)
		    goto error_fname;
	    }
	    return 1;
	case notify_rename :
printf("rename (%s, %s)\n", fname, tname); // XXX
	    if (rename(fname, tname) < 0) {
		if (errno == ENOENT) {
		    int se = errno;
		    if (lstat(fname, &sbuff) < 0) {
			/* try executing it as a copy */
			cptr = tname;
			clen = tlen;
			goto copy_data;
		    }
		    errno = se;
		}
		error_report(error_copy_rename, fname, tname, errno);
	    }
	    return 1;
	case notify_overflow :
	    error_report(error_unimplemented, "overflow"); // XXX
	    return 1;
	case notify_nospace :
	    error_report(error_unimplemented, "nospace"); // XXX
	    return 1;
	case notify_add_tree :
	    error_report(error_unimplemented, "add_tree"); // XXX
	    return 1;
    }
    return 1;
error_fname :
    error_report(error_copy_sys, fname, errno);
    return 1;
}

static int get_next_event(socket_t * p, char ** evstart, int * evspace,
			  char ** freeit, int * fnum, int * fpos,
			  notify_event_t * ev, int tr_ids, int limits)
{
    int etype, ftype, tvalid, rsz, csz;
    char * buffer, command[REPLSIZE], uname[REPLSIZE], gname[REPLSIZE];
    sprintf(uname, "EVENT %d %d",
	    limits ? 0 : -1,
	    limits ? *evspace - 2 : -1);
    if (! send_command(p, uname, NULL, command))
	return 0;
    if (errno == EINTR)
	return 1;
    buffer = command + 2;
    while (*buffer && isspace(*buffer)) buffer++;
    if (buffer[0] == 'N' && buffer[1] == 'O')
	return 2;
    if (buffer[0] == 'B' && buffer[1] == 'I')
	return 3;
    if (buffer[0] != 'E' || buffer[1] != 'V') {
	error_report(error_client_msg, uname, command);
	return 0;
    }
    if (sscanf(buffer + 2, "%d %d %d %d %d %d %d %d",
	       fnum, fpos, &etype, &ftype, &ev->stat_valid,
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
	rsz += ev->from_length;
	buffer[rsz++] = 0;
    } else {
	ev->from_name = NULL;
    }
    if (ev->to_length > 0) {
	ev->to_name = buffer + rsz;
	if (! socket_get(p, buffer + rsz, ev->to_length)) {
	    error_report(error_event, errno);
	    return 0;
	}
	rsz += ev->to_length;
	buffer[rsz++] = 0;
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
	    while (*c && isspace(*c)) c++;
	    e = strptime(c, "%Y-%m-%d:%H:%M:%S", &tm);
	    if (e) while (*e && isspace(*e)) e++;
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
    return 4;
}

static int set_parameters(socket_t * p, const config_t * cfg,
			  char command[REPLSIZE])
{
    if (cfg->compression >= 0) {
	const char * name = compress_name(cfg->compression);
	if (name) {
#if USE_SHOULDBOX
	    if (strlen(name) > REPLSIZE - 30) {
		main_shouldbox++;
		error_report(error_shouldbox_more,
			     "set_parameters", "compression",
			     (int)strlen(name), REPLSIZE - 30);
		return 0;
	    }
	    sprintf(command, "compress %s", name);
	    if (! send_command(p, command, NULL, NULL))
		return 0;
#endif
#if USE_SHOULDBOX
	} else {
	    main_shouldbox++;
	    error_report(error_shouldbox_null,
			 "set_parameters", "compression");
#endif
	}
    }
    if (cfg->bwlimit) {
	sprintf(command, "BWLIMIT %d", cfg->bwlimit);
	if (! send_command(p, command, NULL, NULL))
	    return 0;
    }
    return 1;
}

static int do_copy(socket_t * p, FILE * S, const config_t * cfg,
		   long fstart, int fnum, int fpos)
{
    int check_events = cfg->checkpoint_events, ok = 1;
    time_t check_time = cfg->checkpoint_time + time(NULL);
    char command[REPLSIZE];
    const char * fp = cfg->from_prefix ? cfg->from_prefix : "/";
    int fnum_cp = fnum, fpos_cp = fpos;
    int evbuff = cfg->optimise_buffer + 2;
    int evmax = cfg->optimise_client < 1 ? 1 : cfg->optimise_client;
    int tr_ids = (cfg->flags & config_flag_translate_ids) || S == NULL;
    if (! set_parameters(p, cfg, command))
	goto out;
    sprintf(command, "SETROOT %d %d %d %d",
	    fnum, fpos, (int)strlen(fp), tr_ids);
    if (! send_command(p, command, fp, NULL))
	goto out;
    main_running = 1;
    main_setup_signals();
    while (main_running) {
	notify_event_t evlist[evmax];
	char evarea[evbuff], * evstart = evarea, * freeit = NULL;
	int evspace = evbuff, evcount = 1, evnum, valid[evmax], cmdok;
	/* read first event */
	cmdok = get_next_event(p, &evstart, &evspace, &freeit, &fnum, &fpos,
			       &evlist[0], tr_ids, 0);
	if (cmdok == 1) break;
	if (cmdok != 4) goto out;
	valid[0] = 1;
	check_events--;
	/* read as many events as will fit in the buffer */
	while (evcount < evmax) {
	    /* read next event */
	    cmdok = get_next_event(p, &evstart, &evspace, NULL, &fnum, &fpos,
				   &evlist[evcount], tr_ids, 1);
	    if (cmdok != 4) break;
	    valid[evcount] = 1;
	    check_events--;
	    evcount++;
	}
	/* update state file, if required */
	if (S) {
	    time_t now = time(NULL);
	    if (check_events <= 0 || now >= check_time) {
		check_events = cfg->checkpoint_events;
		check_time = now + cfg->checkpoint_time;
		if (fnum != fnum_cp || fpos != fpos_cp) {
		    long pos;
		    fprintf(S, "%d %d\n", fnum, fpos);
		    fflush(S);
		    pos = ftell(S);
		    if (pos <= MAX_POS) continue;
		    if (fseek(S, fstart, SEEK_SET) < 0) continue;
		    fprintf(S, "%d %d\n", fnum, fpos);
		    fflush(S);
		    pos = ftell(S);
		    if (pos >= 0)
			(void)ftruncate(fileno(S), pos);
		    fnum_cp = fnum;
		    fpos_cp = fpos;
		}
	    }
	}
	// XXX here we would optimise these events
	/* execute all the events */
	for (evnum = 0; evnum < evcount; evnum++) {
	    if (valid[evnum]) {
		if (S) {
		    if (! copy_file(p, cfg, &evlist[evnum]))
			goto out;
		} else {
		    store_printevent(&evlist[evnum], NULL, NULL);
		}
	    }
	}
	if (freeit) myfree(freeit);
    }
    if (main_signal_seen)
	error_report(info_signal_received, main_signal_seen);
    else
	goto ok;
out:
    ok = 0;
ok:
    if (S && (fnum != fnum_cp || fpos != fpos_cp))
	fprintf(S, "%d %d\n", fnum, fpos);
    return ok;
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

static int do_df(socket_t * p, const config_t * cfg) {
    config_path_t * P = cfg->df_path;
    char command[REPLSIZE];
    printf("          disk space, megabytes              files, x 1000\n");
    printf("Mode  Total    Free    Used   Avail    Total   Used   Free  Avail  Path\n");
    while (P) {
	unsigned long bsize, btotal, bfree, bused, bavail, itotal, ifree, iused, iavail;
	int mode;
	sprintf(command, "STATFS %d", (int)strlen(P->path));
	if (! send_command(p, command, P->path, command))
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
	       itotal, iused, ifree, iavail, P->path);
	P = P->next;
    }
    return 1;
}

static int do_ls(socket_t * p, const config_t * cfg) {
    config_path_t * P = cfg->ls_path;
    char command[REPLSIZE];
    int tr_ids = cfg->flags & config_flag_translate_ids;
    static const char * ftype = "-dcbpls?";
    while (P) {
	sprintf(command, "GETDIR %d %d", (int)strlen(P->path), tr_ids);
	if (! send_command(p, command, P->path, NULL))
	    return 0;
	printf("ls(%s):\n", P->path);
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

static void do_cp_1(socket_t * p, const char * from, const char * to,
		    int tr_ids, const config_t * cfg)
{
    char command[REPLSIZE], target[DATA_BLOCKSIZE + 1];
    long long size;
    int ft, dev, ino, mode, uid, gid, major, minor, tl;
    char mtime[REPLSIZE], ctime[REPLSIZE];
    struct tm tm;
    struct utimbuf ut;
    struct stat _oldsbuff, * oldsbuff = NULL;
    notify_filetype_t ot = notify_filetype_unknown;
    notify_event_t ev;
    sprintf(command, "STAT %d %d", (int)strlen(from), tr_ids);
    if (! send_command(p, command, from, command))
	return;
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
	return;
    }
    if (tl > 0)
	if (! socket_gets(p, target, tl))
	    goto invalid;
    strptime(mtime, "%Y-%m-%d:%H:%M:%S", &tm);
    ut.actime = ut.modtime = timegm(&tm);
    if (! set_parameters(p, cfg, command))
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
    if (! copy_file_data(p, strlen(to), to, &ev,
			 oldsbuff, ot, cfg->compression))
	return;
    (void)chown(to, uid, gid);
    (void)chmod(to, mode);
    (void)utime(to, &ut);
    return;
invalid:
    fprintf(stderr, "Invalid data received from server\n");
    return;
}

static int do_cp(socket_t * p, const config_t * cfg) {
    config_path_t * P = cfg->cp_path;
    struct stat sbuff;
    int is_dir;
    const char * dest;
    int tr_ids = cfg->flags & config_flag_translate_ids;
    if (! P || ! P->next) {
	fprintf(stderr, "Please specify at least two names for \"cp\"\n");
	return 0;
    }
    dest = P->path;
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
	char dname[len + NAME_MAX + 3];
	strcpy(dname, dest);
	dname[len++] = '/';
	while (P) {
	    const char * slash = rindex(P->path, '/');
	    if (slash) slash++;
	    strncpy(dname + len, slash, NAME_MAX);
	    dname[len + NAME_MAX] = 0;
	    do_cp_1(p, P->path, dname, tr_ids, cfg);
	    P = P->next;
	}
    } else {
	while (P) {
	    do_cp_1(p, P->path, dest, tr_ids, cfg);
	    P = P->next;
	}
    }
    return 1;
}

static void do_telnet(socket_t * p) {
    struct pollfd pfd[2];
    char buffer[DATA_BLOCKSIZE];
    int go = 1;
    printf("Connected to server...\n");
    pfd[0].fd = fileno(stdin);
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;
    pfd[1].fd = socket_poll(p);
    pfd[1].events = POLLIN;
    pfd[1].revents = 0;
    while (go && poll(pfd, 2, -1) >= 0) {
	if (pfd[0].revents & POLLIN) {
	    if (fgets(buffer, sizeof(buffer) - 2, stdin)) {
		int len = strlen(buffer);
		if (len > 0 && buffer[len - 1] == '\n') len--;
		if (len > 0 && buffer[len - 1] == '*')
		    socket_put(p, buffer, len - 1);
		else
		    socket_puts(p, buffer);
	    } else {
//		go &= 2;
//		pfd[0].events = 0;
	    }
	}
	if (pfd[1].revents & POLLIN) {
	    int nr = socket_getdata(p, buffer, sizeof(buffer));
	    if (nr > 0) {
		(void)fwrite(buffer, nr, 1, stdout);
		fflush(stdout);
	    }
	    if (nr < 0) {
//		go &= 1;
//		pfd[1].events = 0;
	    }
	}
	if (pfd[1].revents & (POLLERR|POLLHUP|POLLNVAL)) {
	    go = 0;
	    pfd[1].events = 0;
	}
    }
    if (go) perror("poll");
}

int client_run(config_t * cfg) {
    FILE * S = NULL;
    int status = 1, fnum = 0, fpos = 0;
    long fstart = 0;
    socket_t * p;
    if (cfg->client_mode & config_client_copy) {
	S = read_copy_state(cfg, &fstart, &fnum, &fpos);
	if (! S)
	    return 1;
    }
    p = socket_connect(cfg);
    if (! p) {
	error_report(error_client, "connect", errno);
	return 1;
    }
    if (cfg->client_mode & config_client_remove) {
	config_dir_t * d = cfg->remove;
	while (d) {
	    char buffer[256];
	    sprintf(buffer, "REMOVE %d", (int)strlen(d->path));
	    if (! send_command(p, buffer, d->path, NULL))
		goto out;
	    d = d->next;
	}
    }
    if (cfg->client_mode & config_client_add) {
	config_dir_t * d = cfg->dirs;
	while (d) {
	    char buffer[256], repl[REPLSIZE];
	    sprintf(buffer, "ADD %d", (int)strlen(d->path));
	    if (! send_command(p, buffer, d->path, NULL))
		goto out;
	    if (! send_list(p, "EXCL", d->exclude))
		goto out;
	    if (! send_list(p, "FIND", d->find))
		goto out;
	    if (! send_command(p, d->crossmount ? "CROSS" : "NOCROSS",
			       NULL, repl))
		goto out;
	    printf("Added %d watches under %s\n", atoi(repl + 2), d->path);
	    d = d->next;
	}
    }
    if (cfg->client_mode & config_client_closelog) {
	if (! send_command(p, "CLOSELOG", NULL, NULL))
	    goto out;
    }
    if (cfg->client_mode & config_client_purge) {
	char purge[32];
	sprintf(purge, "PURGE %d", cfg->purge_days);
	if (! send_command(p, purge, NULL, NULL))
	    goto out;
    }
    if (cfg->client_mode & config_client_setup) {
	if (! setup_client(p, cfg))
	    goto out;
    }
    if (cfg->client_mode & config_client_copy) {
	if (! do_copy(p, S, cfg, fstart, fnum, fpos))
	    goto out;
    }
    if (cfg->client_mode &
	(config_client_status | config_client_peek |
	 config_client_box | config_client_version |
	 config_client_getpid))
    {
	if (! print_status(p, cfg->client_mode, &fnum, &fpos))
	    goto out;
    }
    if (cfg->client_mode & config_client_peek) {
	if (! do_copy(p, NULL, cfg, 0L, fnum, fpos))
	    goto out;
    }
    if (cfg->client_mode & config_client_watches) {
	if (! print_watches(p))
	    goto out;
    }
    if (cfg->client_mode & config_client_listcompress) {
	if (! print_compress(p))
	    goto out;
    }
    if (cfg->client_mode & config_client_config) {
	if (! print_config(p))
	    goto out;
    }
    if (cfg->client_mode & config_client_ls)
	if (! do_ls(p, cfg))
	    goto out;
    if (cfg->client_mode & config_client_cp)
	if (! do_cp(p, cfg))
	    goto out;
    if (cfg->client_mode & config_client_df)
	if (! do_df(p, cfg))
	    goto out;
    if (cfg->client_mode & config_client_telnet)
	do_telnet(p);
    if (! send_command(p,
		       cfg->client_mode & config_client_stop ? "STOP"
							     : "QUIT",
		       NULL, NULL))
	goto out;
    status = 0;
out:
    if (S) {
	fseek(S, 0L, SEEK_SET);
	(void)lockf(fileno(S), F_ULOCK, (off_t)0);
	fclose(S);
    }
    socket_disconnect(p);
    return status;
}

