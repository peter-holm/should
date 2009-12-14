/* communicate with a running server: either via a local UNIX domain socket,
 * or via a network connection
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

#define _GNU_SOURCE /* undo some of glibc's brain damage */
#include "site.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/wait.h>
#ifdef THEY_HAVE_SSL
#include <openssl/rand.h>
#include "checksum.h"
#endif
#include "socket.h"
#include "mymalloc.h"
#include "config.h"
#include "notify_thread.h"
#include "main_thread.h"
#include "error.h"
#include "usermap.h"

#define AUXSIZE 256
#define PACKETSIZE 8192

/* define a few macros to simplify sending/receiving of credentials on
 * UNIX domains sockets; if no mechanism is supported, don't use credentials
 * but make socket accessible to owner (and root) only */
#if defined SO_PASSCRED
# define UCRED    struct ucred
# undef  GETCRED
# define SENDOPTS SO_PASSCRED
# define RECVOPTS SO_PASSCRED
# define OPTLEVEL SOL_SOCKET
# define SENDCRED 1
# define RECVCRED 1
# undef  SENDNOP
# define CREDTYPE SCM_CREDENTIALS
# define PIDFIELD pid
# define UIDFIELD uid
# define GIDFIELD gid
# undef  SOCKMODE
#else
# if defined LOCAL_PEEREID && 0
#  define UCRED    struct unpcbid
#  define GETCRED  LOCAL_PEEREID
#  undef  SENDCRED
#  undef  RECVCRED
#  undef  SENDNOP
#  undef  SENDOPTS
#  undef  RECVOPTS
#  define OPTLEVEL 0
#  undef  CREDTYPE
#  define PIDFIELD unp_pid
#  define UIDFIELD unp_euid
#  define GIDFIELD unp_egid
#  undef  SOCKMODE
# else
#  if defined LOCAL_CREDS
#   define UCRED    struct sockcred
#   undef  GETCRED
#   define SENDOPTS LOCAL_CREDS
#   define RECVOPTS LOCAL_CREDS
#   define OPTLEVEL 0
#   undef  SENDCRED
#   define RECVCRED 1
#   define SENDNOP 1
#   define CREDTYPE SCM_CREDS
#   undef  PIDFIELD
#   define UIDFIELD sc_uid
#   define GIDFIELD sc_gid
#   undef  SOCKMODE
#  else
#   undef  UCRED
#   undef  GETCRED
#   undef  SENDCRED
#   undef  RECVCRED
#   undef  SENDNOP
#   undef  SENDOPTS
#   undef  RECVOPTS
#   undef  CREDTYPE
#   undef  PIDFIELD
#   undef  UIDFIELD
#   undef  GIDFIELD
#   define SOCKMODE 0600
#  endif
# endif
#endif

/* used to represent a running connection */

struct socket_s {
    int r_fd, w_fd;
    int family;
    enum { TYPE_CLIENT, TYPE_SERVER, TYPE_LISTEN } type;
    struct sockaddr_storage addr;
    int count;
#if defined UCRED
    UCRED creds;
#endif
    config_userop_t actions;
    char * username;
    char * password;
    char * user;
    pid_t pid;
    int debug;
    int b_in;
    int r_in;
    int b_out;
    int autoflush;
    long long recv;
    long long sent;
    char p_in[PACKETSIZE];
    char p_out[PACKETSIZE];
};

/* prepare a socket suitable for listening on a UNIX path */

static int listen_unix(socket_t * p, const char * path) {
    struct sockaddr_un * bindaddr;
    bindaddr = (struct sockaddr_un *)&p->addr;
    p->r_fd = p->w_fd = -1;
    memset(&p->addr, 0, sizeof(p->addr));
    if (strlen(path) >= sizeof(bindaddr->sun_path)) {
	errno = ENAMETOOLONG;
	return 0;
    }
    if (! *path) {
	errno = EINVAL;
	return 0;
    }
    p->r_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (p->r_fd < 0)
	return 0;
    bindaddr->sun_family = AF_UNIX;
    strcpy(bindaddr->sun_path, path);
    if (bind(p->r_fd, (struct sockaddr *)bindaddr, sizeof(*bindaddr)) < 0)
	return 0;
#if defined SOCKMODE
    chmod(path, SOCKMODE);
#endif
    if (listen(p->r_fd, SOMAXCONN) < 0)
	return 0;
    p->family = PF_UNIX;
    p->type = TYPE_LISTEN;
    p->debug = 0;
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    p->username = p->password = NULL;
    p->user = NULL;
    p->recv = 0;
    p->sent = 0;
    return 1;
}

/* prepare a socket suitable for listening on a TCP port */

#ifdef THEY_HAVE_SSL
static int listen_tcp(socket_t * p, const struct addrinfo * addr) {
    int one = 1;
    memset(&p->addr, 0, sizeof(p->addr));
    p->w_fd = -1;
    p->r_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (p->r_fd < 0)
	return 0;
    setsockopt(p->r_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(p->r_fd, addr->ai_addr, addr->ai_addrlen) < 0)
	return 0;
    if (listen(p->r_fd, SOMAXCONN) < 0)
	return 0;
    memcpy(&p->addr, addr->ai_addr, addr->ai_addrlen);
    p->family = addr->ai_family;
    p->type = TYPE_LISTEN;
    p->debug = 0;
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    p->username = p->password = NULL;
    p->user = NULL;
    p->recv = 0;
    p->sent = 0;
    return 1;
}
#endif

/* prepare a socket suitable for listening on a UNIX path or TCP port */

socket_t * socket_listen(void) {
    int count, acount;
    const config_data_t * cfg = config_get();
    const config_strlist_t * L = config_strlist(cfg, cfg_listen);
    socket_t * r;
#ifdef THEY_HAVE_SSL
    typedef struct ailist_s ailist_t;
    struct ailist_s {
	ailist_t * next;
	struct addrinfo * this;
    };
    ailist_t * ai_all = NULL;
#endif
    count = 0;
    while (L) {
	if (L->data[0] == '/') {
	    count++;
	} else {
#ifdef THEY_HAVE_SSL
	    int errcode;
	    struct addrinfo hints, * ptr;
	    const char * port, * host;
	    ailist_t * ai = mymalloc(sizeof(ailist_t));
	    if (! ai) {
		config_put(cfg);
		return NULL;
	    }
	    memset(&hints, 0, sizeof(hints));
	    hints.ai_family = AF_UNSPEC;
	    hints.ai_socktype = SOCK_STREAM;
	    hints.ai_protocol = IPPROTO_TCP;
	    hints.ai_flags = AI_PASSIVE;
	    host = L->data;
	    port = host + 1 + strlen(host);
	    if (! *host) {
		host = NULL;
#ifndef __NetBSD__
		hints.ai_family = AF_INET6;
#endif
	    }
	    errcode = getaddrinfo(host, port, &hints, &ai->this);
	    if (errcode) {
		int e = EINVAL;
		switch (errcode) {
#ifdef EAI_ADDRFAMILY
		    case EAI_ADDRFAMILY :
#endif
		    case EAI_FAIL :
#ifdef EAI_NODATA
		    case EAI_NODATA :
#endif
		    case EAI_NONAME :
		    case EAI_SERVICE :
			e = ENOENT;
			break;
		    case EAI_AGAIN :
			e = EAGAIN;
			break;
		    case EAI_SYSTEM :
			e = errno;
			break;
		    case EAI_MEMORY :
			e = ENOMEM;
			break;
		    default :
			e = EINVAL;
			break;
		}
		myfree(ai);
		config_put(cfg);
		errno = e;
		return NULL;
	    }
	    for (ptr = ai->this; ptr; ptr = ptr->ai_next)
		count++;
	    ai->next = ai_all;
	    ai_all = ai;
#else /* THEY_HAVE_SSL */
	    config_put(cfg);
	    errno = ENOSYS;
	    return NULL;
#endif /* THEY_HAVE_SSL */
	}
	L = L->next;
    }
    if (count < 1) {
	config_put(cfg);
	errno = EINVAL;
	return NULL;
    }
    r = mymalloc(count * sizeof(socket_t));
    if (! r) {
	config_put(cfg);
	return NULL;
    }
    L = config_strlist(cfg, cfg_listen);
    acount = 0;
    while (L) {
	int ok;
	if (L->data[0] == '/') {
	    ok = listen_unix(&r[acount], L->data);
	    if (! ok) {
		int e = errno;
		if (r[acount].r_fd >= 0) close(r[acount].r_fd);
		myfree(r);
		L = config_strlist(cfg, cfg_listen);
		while (L && acount > 0) {
		    if (L->data[0] == '/') {
			acount--;
			if (r[acount].r_fd >= 0) close(r[acount].r_fd);
			unlink(L->data);
		    }
		    L = L->next;
		}
		config_put(cfg);
#ifdef THEY_HAVE_SSL
		while (ai_all) {
		    ailist_t * ai = ai_all;
		    ai_all = ai_all->next;
		    freeaddrinfo(ai->this);
		    myfree(ai);
		}
#endif
		errno = e;
		return NULL;
	    }
	    acount++;
	}
	L = L->next;
    }
#ifdef THEY_HAVE_SSL
    while (ai_all) {
	struct addrinfo * ptr;
	ailist_t * ai = ai_all;
	ai_all = ai_all->next;
	for (ptr = ai->this; ptr; ptr = ptr->ai_next, acount++) {
	    int ok = listen_tcp(&r[acount], ptr);
	    if (! ok) {
		int e = errno;
		if (r[acount].r_fd) close(r[acount].r_fd);
		while (acount > 0) {
		    acount--;
		    if (r[acount].r_fd) close(r[acount].r_fd);
		}
		L = config_strlist(cfg, cfg_listen);
		while (L) {
		    if (L->data[0] == '/')
			unlink(L->data);
		    L = L->next;
		}
		myfree(r);
		config_put(cfg);
		freeaddrinfo(ai->this);
		myfree(ai);
		while (ai_all) {
		    ai = ai_all;
		    ai_all = ai_all->next;
		    freeaddrinfo(ai->this);
		    myfree(ai);
		}
		errno = e;
		return NULL;
	    }
	}
	freeaddrinfo(ai->this);
	myfree(ai);
    }
#endif /* THEY_HAVE_SSL */
    r->count = count;
    r->type = TYPE_LISTEN;
    config_put(cfg);
    return r;
}

/* receive credentials from a UNIX domain socket */

static int receive_credentials_unix(const config_data_t * cfg, socket_t * p) {
    int got_creds = 0;
    struct sockaddr_un * A = (struct sockaddr_un *)&p->addr;
    int len = 0;
#if defined RECVOPTS
    int one = 1;
#endif
#if defined RECVCRED
    struct msghdr auxdata;
    struct iovec buffers;
    char buffvec[AUXSIZE], buffmsg[AUXSIZE];
    struct cmsghdr * cmsg;
#endif
    const config_acl_t * allow = config_aclval(cfg, cfg_acl_local);
#if defined RECVOPTS
    if (setsockopt(p->r_fd, OPTLEVEL, RECVOPTS, &one, sizeof(int)) < 0)
	return 0;
#endif
#if defined RECVCRED
    buffers.iov_base = buffvec;
    buffers.iov_len = AUXSIZE;
    auxdata.msg_name = NULL;
    auxdata.msg_namelen = 0;
    auxdata.msg_iov = &buffers;
    auxdata.msg_iovlen = 1;
    auxdata.msg_control = buffmsg;
    auxdata.msg_controllen = AUXSIZE;
    auxdata.msg_flags = 0;
    if (recvmsg(p->r_fd, &auxdata, 0) < 0)
	return 0;
    for (cmsg = CMSG_FIRSTHDR(&auxdata);
	 cmsg != NULL;
	 cmsg = CMSG_NXTHDR(&auxdata, cmsg))
    {
	if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == CREDTYPE) {
	    /* the extra variable is needed to keep gcc from throwing a fit */
	    UCRED * ucred = (UCRED *)CMSG_DATA(cmsg);
	    p->creds = *ucred;
	    got_creds = 1;
	}
    }
#endif
#if defined GETCRED
    if (! got_creds) {
	socklen_t sl = sizeof(p->creds);
	if (getsockopt(p->r_fd, OPTLEVEL, GETCRED, &p->creds, &sl) < 0)
	    return 0;
	got_creds = 1;
    }
#endif /* GETCRED */
    if (! got_creds) {
	if (allow) {
	    socket_puts(p, "EPERM Invalid username or password");
	    errno = EPERM;
	    return 0;
	}
	A->sun_path[len] = 0;
	if (! socket_puts(p, "OK welcome"))
	    return 0;
	p->actions = config_op_all;
	return 1;
    }
#if defined PIDFIELD
    snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
	     "pid#%d", p->creds.PIDFIELD);
    len += strlen(A->sun_path + len) + 1;
#endif
#if defined UIDFIELD
    p->actions = config_op_all;
    if (usermap_fromid(p->creds.UIDFIELD,
		       A->sun_path + len,
		       sizeof(A->sun_path) - len) > 0)
    {
	p->user = mystrdup(A->sun_path + len);
	if (allow) {
	    const char * data[cfg_uacl_COUNT];
	    /* compare with stored userlist */
	    data[cfg_uacl_ipv4] = NULL;
	    data[cfg_uacl_ipv6] = NULL;
	    data[cfg_uacl_path] = A->sun_path;
	    data[cfg_uacl_user] = p->user;
	    data[cfg_uacl_pass] = NULL;
	    data[cfg_uacl_challenge] = NULL;
	    data[cfg_uacl_checksum] = NULL;
	    p->actions = config_check_acl(allow, data, cfg_uacl_COUNT, 0);
	    if (! p->actions) {
		socket_puts(p, "EPERM Invalid username or password");
		errno = EPERM;
		return 0;
	    }
	}
	len += strlen(A->sun_path + len);
	A->sun_path[len++] = ':';
    } else {
	snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
		 "uid#%d:", p->creds.UIDFIELD);
	if (allow) {
	    /* we have user checking, but no way to check */
	    errno = EPERM;
	    return 0;
	}
	len += strlen(A->sun_path + len);
    }
#else /* UIDFIELD */
    while (allow) {
	if (! allow->pass) {
	    socket_puts(p, "EPERM Invalid username or password");
	    errno = EPERM;
	    return 0;
	}
	allow = allow->next;
    }
#endif /* UIDFIELD */
#if defined GIDFIELD
    if (groupmap_fromid(p->creds.GIDFIELD,
			A->sun_path + len,
			sizeof(A->sun_path) - len) <= 0)
	snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
		 "gid#%d", p->creds.GIDFIELD);
#endif
    if (! socket_puts(p, "OK welcome"))
	return 0;
    return 1;
}

/* receive credentials from a TCP socket */

#ifdef THEY_HAVE_SSL
static inline int max_csize(int count) {
    int i, max = 0;
    for (i = 0; i < count; i++) {
	int s = checksum_size(i);
	if (s > max) max = s;
    }
    return max;
}

static inline int cnamesize(int count) {
    int i, len = 0;
    for (i = 0; i < count; i++) {
	const char * cn = checksum_name(i);
	if (cn) len += strlen(cn) + 1;
    }
    return len;
}

static int receive_credentials_tcp(const config_data_t * cfg, socket_t * p) {
    int count = checksum_count(), cname = cnamesize(count);
    int csmax = max_csize(count), i, wp = 0, ulen, ctype, cslen;
    char welcome[2 * CHALLENGE_SIZE + 2 * csmax + cname + 32];
    unsigned char challenge[CHALLENGE_SIZE], hash[csmax];
    const char * data[cfg_uacl_COUNT];
    RAND_bytes(challenge, CHALLENGE_SIZE);
    /* send welcome string, challenge and supported checksum methods */
    wp += sprintf(welcome + wp, "SHOULD [");
    for (i = 0; i < CHALLENGE_SIZE; i++)
	wp += sprintf(welcome + wp, "%02X", (unsigned int)challenge[i]);
    wp += sprintf(welcome + wp, "]");
    for (i = 0; i < count; i++) {
	const char * cn = checksum_name(i);
	if (cn) wp += sprintf(welcome + wp, " %s", cn);
    }
    if (! socket_puts(p, welcome))
	return 0;
    /* receive username, [checksum type] and hash */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    wp = 0;
    while (welcome[wp] && ! isspace((int)welcome[wp])) wp++;
    if (wp == 0)
	goto invalid;
    ulen = wp;
    while (welcome[wp] && isspace((int)welcome[wp])) wp++;
    if (welcome[wp] == '[') {
	const char * hn = &welcome[++wp];
	while (welcome[wp] && welcome[wp] != ']') wp++;
	if (! welcome[wp])
	    goto invalid;
	welcome[wp++] = 0;
	while (welcome[wp] && isspace((int)welcome[wp])) wp++;
	ctype = checksum_byname(hn);
    } else {
	ctype = checksum_byname("md5");
    }
    if (ctype < 0 || ctype >= count) goto invalid;
    cslen = checksum_size(ctype);
    if (cslen < 0 || cslen >= csmax) goto invalid;
    for (i = 0; i < 2 * cslen; i++) {
	if (! welcome[wp + i] || ! isxdigit((int)welcome[wp + i]))
	    goto invalid;
    }
    for (i = 0; i < cslen; i++) {
	char val[3] = "00";
	val[0] = welcome[wp++];
	val[1] = welcome[wp++];
	hash[i] = strtol(val, NULL, 16);
    }
    p->user = mymalloc(1 + ulen);
    if (! p->user)
	return 0;
    strncpy(p->user, welcome, ulen);
    p->user[ulen] = 0;
    /* compare with stored userlist */
    if (p->family == AF_INET) {
	const struct sockaddr_in * S = (const struct sockaddr_in *)&p->addr;
	data[cfg_uacl_ipv4] = (char *)&S->sin_addr;
	data[cfg_uacl_ipv6] = NULL;
    } else {
	const struct sockaddr_in6 * S = (const struct sockaddr_in6 *)&p->addr;
	data[cfg_uacl_ipv4] = NULL;
	data[cfg_uacl_ipv6] = (char *)&S->sin6_addr;
    }
    data[cfg_uacl_path] = NULL;
    data[cfg_uacl_user] = p->user;
    data[cfg_uacl_pass] = (char *)hash;
    data[cfg_uacl_challenge] = (char *)challenge;
    data[cfg_uacl_checksum] = (char *)&ctype;
    p->actions = config_check_acl(config_aclval(cfg, cfg_acl_tcp),
				  data, cfg_uacl_COUNT, 0);
    if (p->actions) {
	if (! socket_puts(p, "OK welcome"))
	    return 0;
	return 1;
    }
    socket_puts(p, "EPERM Invalid username or password");
    errno = EPERM;
    return 0;
invalid:
    socket_puts(p, "EINVAL Invalid reply");
    errno = EBADF;
    return 0;
}
#endif

/* accept next connection */

socket_t * socket_accept(socket_t * p, int timeout) {
    socket_t * c, * s;
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct pollfd pfd[p->count];
    const config_data_t * cfg;
    if (p->type != TYPE_LISTEN) {
	errno = EINVAL;
	return NULL;
    }
    for (fd = 0; fd < p->count; fd++) {
	pfd[fd].fd = p[fd].r_fd;
	pfd[fd].events = POLLIN;
	pfd[fd].revents = 0;
    }
    fd = poll(pfd, p->count, timeout);
    if (fd < 0)
	return NULL;
    if (fd < 1) {
	errno = ETIMEDOUT;
	return NULL;
    }
    for (fd = 0; fd < p->count; fd++)
	if (pfd[fd].revents & POLLIN)
	    break;
    if (fd >= p->count) {
	errno = ETIMEDOUT;
	return NULL;
    }
    s = &p[fd];
    fd = accept(s->r_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0)
	return NULL;
    c = mymalloc(sizeof(socket_t));
    if (! c) {
	int e = errno;
	close(fd);
	errno = e;
	return NULL;
    }
    memset(&c->addr, 0, sizeof(c->addr));
    memcpy(&c->addr, &addr, addrlen);
    c->w_fd = c->r_fd = fd;
    c->family = s->family;
    c->type = TYPE_SERVER;
    c->count = 1;
    c->addr = addr;
    c->autoflush = 1;
    c->b_in = 0;
    c->r_in = 0;
    c->b_out = 0;
    c->username = c->password = NULL;
    c->user = NULL;
    c->recv = 0;
    c->sent = 0;
    cfg = config_get();
    c->debug = config_intval(cfg, cfg_flags) & config_flag_debug_server;
    if (c->family == PF_UNIX) {
	if (! receive_credentials_unix(cfg, c)) {
	    int e = errno;
	    close(fd);
	    if (c->user) myfree(c->user);
	    myfree(c);
	    config_put(cfg);
	    errno = e;
	    return NULL;
	}
    }
#ifdef THEY_HAVE_SSL
    if (c->family == PF_INET || c->family == PF_INET6) {
	if (! receive_credentials_tcp(cfg, c)) {
	    int e = errno;
	    close(fd);
	    if (c->user) myfree(c->user);
	    myfree(c);
	    config_put(cfg);
	    errno = e;
	    return NULL;
	}
    }
#endif
    config_put(cfg);
    return c;
}

/* make sure we do have a username and password */

static int get_user(socket_t * p, const config_data_t * cfg) {
    static char ubuffer[AUXSIZE], pbuffer[AUXSIZE];
    const char * user, * pass, * server;
    user = config_strval(cfg, cfg_user);
    server = config_strval(cfg, cfg_server);
    if (! user) {
	int i;
	fprintf(stderr, "User for %s: ", server);
	fflush(stderr);
	if (! fgets(ubuffer, sizeof(ubuffer), stdin))
	    return 0;
	i = strlen(ubuffer);
	if (i > 0 && ubuffer[i - 1] == '\n') ubuffer[i - 1] = 0;
	user = ubuffer;
    }
    p->username = mystrdup(user);
    if (! p->username)
	return 0;
    pass = config_strval(cfg, cfg_password);
    if (! pass) {
	struct termios T;
	int ok, ok2, i;
	fprintf(stderr, "Password for %s@%s: ", user, server);
	fflush(stderr);
	ok = tcgetattr(fileno(stdin), &T) >= 0;
	if (ok) {
	    struct termios n = T;
	    n.c_lflag &= ~ECHO;
	    tcsetattr(fileno(stdin), TCSAFLUSH, &n);
	}
	ok2 = fgets(pbuffer, sizeof(pbuffer), stdin) != NULL;
	if (ok) {
	    fprintf(stderr, "\n");
	    tcsetattr(fileno(stdin), TCSAFLUSH, &T);
	}
	if (! ok2) return 0;
	i = strlen(pbuffer);
	if (i > 0 && pbuffer[i - 1] == '\n') pbuffer[i - 1] = 0;
	pass = pbuffer;
    }
    p->password = mystrdup(pass);
    if (! p->password)
	return 0;
    return 1;
}

/* open a tunnel to another copy of should somewhere */

static int connect_tunnel(const config_data_t * cfg, socket_t * p) {
    int fromchild[2], tochild[2], cmdlen = 0, shouldlen = 0, connlen;
    pid_t pid;
    char * const * tptr = config_strarr(cfg, cfg_strarr_tunnel);
    while (tptr[cmdlen]) cmdlen++;
    tptr = config_strarr(cfg, cfg_strarr_remote_should);
    if (tptr && tptr[0])
	while (tptr[shouldlen]) shouldlen++;
    else
	shouldlen = 1;
    if (config_intval(cfg, cfg_flags) & config_flag_socket_changed)
	connlen = 8 + config_strlen(cfg, cfg_server);
    else
	connlen = 1;
    if (pipe(fromchild) < 0) {
	perror("pipe");
	return 0;
    }
    if (pipe(tochild) < 0) {
	perror("pipe");
	close(fromchild[0]);
	close(fromchild[1]);
	return 0;
    }
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
	perror("fork");
	close(fromchild[0]);
	close(fromchild[1]);
	close(tochild[0]);
	close(tochild[1]);
	return 0;
    }
    if (pid == 0) {
	/* child process */
	char * command[cmdlen + shouldlen + 6];
	char conndata[connlen], * ecd;
	int i, ptr;
	close(fromchild[0]);
	close(tochild[1]);
	fclose(stdin);
	if (dup2(tochild[0], 0) < 0) {
	    perror("dup2");
	    close(fromchild[1]);
	    close(tochild[0]);
	    exit(1);
	}
	fclose(stdout);
	if (dup2(fromchild[1], 1) < 0) {
	    perror("dup2");
	    close(0);
	    close(fromchild[1]);
	    close(tochild[0]);
	    exit(1);
	}
	ecd = conndata;
	ptr = 0;
	tptr = config_strarr(cfg, cfg_strarr_tunnel);
	for (i = 0; i < cmdlen; i++)
	    command[ptr++] = tptr[i];
	tptr = config_strarr(cfg, cfg_strarr_remote_should);
	if (tptr && tptr[0])
	    for (i = 0; i < shouldlen; i++)
		command[ptr++] = tptr[i];
	else
	    command[ptr++] = "should";
	if (config_intval(cfg, cfg_flags) & config_flag_socket_changed) {
	    const char * sp = config_strval(cfg, cfg_server);
	    if (sp[0] == '/') {
		sprintf(ecd, "server=%s", sp);
	    } else {
		const char * pn = sp + 1 + strlen(sp);
		sprintf(ecd, "server=%s:%s", sp, pn);
	    }
	    command[ptr++] = ecd;
	    ecd += 1 + strlen(ecd);
	}
	if (p->username) {
	    sprintf(ecd, "user=%s", p->username);
	    command[ptr++] = ecd;
	    ecd += 1 + strlen(ecd);
	}
	if (p->password) {
	    sprintf(ecd, "password_from_stdin=%d", (int)strlen(p->password));
	    command[ptr++] = ecd;
	    ecd += 1 + strlen(ecd);
	}
	command[ptr++] = "skip_notice";
	command[ptr++] = "telnet";
	command[ptr++] = NULL;
	execvp(command[0], command);
	perror(command[0]);
	exit(2);
    }
    /* parent */
    close(fromchild[1]);
    close(tochild[0]);
    p->r_fd = fromchild[0];
    p->w_fd = tochild[1];
    p->pid = pid;
    if (p->password && ! socket_put(p, p->password, strlen(p->password)))
	return 0;
    return 1;
}

/* connect to a running server using UNIX domain sockets */

static int connect_unix(const config_data_t * cfg, socket_t * p) {
    char welcome[32 + AUXSIZE];
    struct sockaddr_un * addr = (struct sockaddr_un *)&p->addr;
#if defined SENDCRED
    struct msghdr auxdata;
    struct iovec buffers;
    char buffvec[AUXSIZE], buffmsg[AUXSIZE];
    struct cmsghdr * cmsg;
    UCRED * ucred;
#endif
#if defined SENDOPTS
    int one;
#endif
    if (config_strlen(cfg, cfg_server) >= sizeof(addr->sun_path)) {
	errno = ENAMETOOLONG;
	return 0;
    }
    p->family = PF_UNIX;
    p->w_fd = p->r_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (p->r_fd < 0)
	return 0;
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, config_strval(cfg, cfg_server));
    if (connect(p->r_fd, (struct sockaddr *)addr, sizeof(*addr)) < 0)
	return 0;
#if defined SENDOPTS
    one = 1;
    if (setsockopt(p->r_fd, OPTLEVEL, SENDOPTS, &one, sizeof(int)) < 0)
	return 0;
#endif
#if defined SENDCRED
    buffers.iov_base = buffvec;
    buffers.iov_len = AUXSIZE;
    auxdata.msg_name = NULL;
    auxdata.msg_namelen = 0;
    auxdata.msg_iov = &buffers;
    auxdata.msg_iovlen = 1;
    auxdata.msg_control = buffmsg;
    auxdata.msg_controllen = AUXSIZE;
    auxdata.msg_flags = 0;
    cmsg = CMSG_FIRSTHDR(&auxdata);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = CREDTYPE;
    cmsg->cmsg_len = CMSG_LEN(sizeof(UCRED));
    ucred = (UCRED *)CMSG_DATA(cmsg);
#if defined PIDFIELD
    ucred->PIDFIELD = getpid();
#endif
    ucred->UIDFIELD = getuid();
    ucred->GIDFIELD = getgid();
    ucred->UIDFIELD = getuid();
    auxdata.msg_controllen = cmsg->cmsg_len;
    if (sendmsg(p->r_fd, &auxdata, 0) < 0)
	return 0;
#endif /* SENDCRED */
#if defined SENDNOP
    socket_puts(p, "");
#endif
    /* get result */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    if (welcome[0] == 'O' && welcome[1] == 'K')
	return 1;
    if (welcome[0] != 'E')
	goto invalid;
    if (welcome[1] != 'P')
	goto invalid;
    errno = EPERM;
    return 0;
invalid:
    errno = EINVAL;
    return 0;
}

/* connect to a running server using TCP */

#ifdef THEY_HAVE_SSL
static int connect_tcp(const config_data_t * cfg, socket_t * p) {
    struct addrinfo * ai, hints, * ptr;
    int errcode;
    const char * host, * port;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;
    host = config_strval(cfg, cfg_server);
    port = host + 1 + strlen(host);
    errcode = getaddrinfo(host, port, &hints, &ai);
    if (errcode) {
	switch (errcode) {
#ifdef EAI_ADDRFAMILY
	    case EAI_ADDRFAMILY :
#endif
	    case EAI_FAIL :
#ifdef EAI_NODATA
	    case EAI_NODATA :
#endif
	    case EAI_NONAME :
	    case EAI_SERVICE :
		errno = ENOENT;
		break;
	    case EAI_AGAIN :
		errno = EAGAIN;
		break;
	    case EAI_SYSTEM :
		break;
	    case EAI_MEMORY :
		errno = ENOMEM;
		break;
	    default :
		errno = EINVAL;
		break;
	}
	return 0;
    }
    for (ptr = ai; ptr; ptr = ptr->ai_next) {
	p->w_fd = p->r_fd =
	    socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (p->r_fd < 0) {
	    errcode = errno;
	    continue;
	}
	if (connect(p->r_fd, ptr->ai_addr, ptr->ai_addrlen) < 0) {
	    errcode = errno;
	    close(p->r_fd);
	    p->w_fd = p->r_fd = -1;
	    continue;
	}
	memcpy(&p->addr, ptr->ai_addr, ptr->ai_addrlen);
	p->family = ptr->ai_family;
	break;
    }
    freeaddrinfo(ai);
    if (ptr) return 1;
    errno = errcode;
    return 0;
}
#endif

/* send credentials to a TCP socket */

#ifdef THEY_HAVE_SSL
static int send_credentials_tcp(const config_data_t * cfg, socket_t * p) {
    int count = checksum_count(), cname = cnamesize(count);
    int csmax = max_csize(count), wp, i, ctype, send_hashname, csize;
    unsigned char challenge[CHALLENGE_SIZE], hash[csmax];
    char welcome[2 * CHALLENGE_SIZE + 2 * csmax + 32 + AUXSIZE + cname];
    if (! get_user(p, cfg))
	return 0;
    /* receive welcome and extract challenge */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    if (strncmp(welcome, "SHOULD", 6) != 0)
	goto invalid;
    wp = 6;
    while (welcome[wp] && isspace((int)welcome[wp])) wp++;
    if (welcome[wp] != '[')
	goto invalid;
    wp++;
    for (i = 0; i < 2 * CHALLENGE_SIZE; i++) {
	if (! isxdigit((int)welcome[wp + i]))
	    goto invalid;
    }
    if (welcome[wp + 2 * CHALLENGE_SIZE] != ']')
	goto invalid;
    for (i = 0; i < CHALLENGE_SIZE; i++) {
	char val[3] = "00";
	val[0] = welcome[wp++];
	val[1] = welcome[wp++];
	challenge[i] = strtol(val, NULL, 16);
    }
    while (welcome[wp] && isspace((int)welcome[wp])) wp++;
    /* see if they provided a list of recognised methods, if so select one */
    if (welcome[wp]) {
	int known[count], nv;
	const int * dp;
	ctype = -1;
	for (i = 0; i < count; i++)
	    known[i] = 0;
	while (welcome[wp]) {
	    const char * mn = &welcome[wp];
	    int mi;
	    while (welcome[wp] && ! isspace((int)welcome[wp])) wp++;
	    if (welcome[wp]) welcome[wp++] = 0;
	    while (welcome[wp] && isspace((int)welcome[wp])) wp++;
	    mi = checksum_byname(mn);
	    if (mi >= 0 && mi < count) known[mi] = 1;
	}
	nv = config_intarr_len(cfg, cfg_checksums);
	dp = config_intarr_data(cfg, cfg_checksums);
	for (i = 0; i < nv && ctype < 0; i++) {
	    if (dp[i] >= 0 && dp[i] < count && known[dp[i]]) ctype = dp[i];
	}
	for (i = 0; i < count && ctype < 0; i++) {
	    if (known[i]) ctype = i;
	}
	send_hashname = 1;
    } else {
	ctype = checksum_byname("md5");
	send_hashname = 0;
    }
    if (ctype < 0)
	goto invalid;
    csize = checksum_size(ctype);
    if (csize < 0 || csize >= csmax)
	goto invalid;
    /* prepare hash and send identification string */
    config_hash_user(p->username, p->password, ctype, challenge, hash);
    strcpy(welcome, p->username);
    wp = strlen(welcome);
    welcome[wp++] = ' ';
    if (send_hashname) {
	const char * cn = checksum_name(ctype);
	if (! cn)
	    goto invalid;
	welcome[wp++] = '[';
	strcpy(welcome + wp, cn);
	wp = strlen(welcome);
	welcome[wp++] = ']';
	welcome[wp++] = ' ';
    }
    for (i = 0; i < csize; i++)
	wp += sprintf(welcome + wp, "%02X", (unsigned int)hash[i]);
    if (! socket_puts(p, welcome))
	return 0;
    /* get result */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    if (welcome[0] == 'O' && welcome[1] == 'K')
	return 1;
    if (welcome[0] != 'E')
	goto invalid;
    if (welcome[1] != 'P')
	goto invalid;
    errno = EPERM;
    return 0;
invalid:
    errno = EINVAL;
    return 0;
}
#endif

/* connect to a running server */

socket_t * socket_connect(void) {
    const config_data_t * cfg;
    socket_t * p = mymalloc(sizeof(socket_t));
    int ok;
    char * const * tptr;
    const char * server;
    if (! p) return NULL;
    p->w_fd = p->r_fd = -1;
    memset(&p->addr, 0, sizeof(p->addr));
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    p->pid = -1;
    p->username = p->password = NULL;
    p->user = NULL;
    p->recv = 0;
    p->sent = 0;
    cfg = config_get();
    tptr = config_strarr(cfg, cfg_strarr_tunnel);
    p->debug = config_intval(cfg, cfg_flags) & config_flag_debug_server;
    server = config_strval(cfg, cfg_server);
    if (tptr && tptr[0]) {
	ok = connect_tunnel(cfg, p);
    } else if (server[0] != '/') {
#ifdef THEY_HAVE_SSL
	ok = connect_tcp(cfg, p);
#else
	myfree(p);
	config_put(cfg);
	errno = ENOSYS;
	return NULL;
#endif
    } else {
	ok = connect_unix(cfg, p);
    }
    if (! ok) {
	int e = errno, ws;
	if (p->w_fd >= 0 && p->w_fd != p->r_fd) close(p->w_fd);
	if (p->pid >= 0) waitpid(p->pid, &ws, 0);
	if (p->r_fd >= 0) close(p->r_fd);
	myfree(p);
	config_put(cfg);
	errno = e;
	return NULL;
    }
#ifdef THEY_HAVE_SSL
    if (server[0] != '/' &&
	! (tptr && tptr[0]) &&
	! send_credentials_tcp(cfg, p))
    {
	int e = errno, ws;
	if (p->w_fd >= 0 && p->w_fd != p->r_fd) close(p->w_fd);
	if (p->pid >= 0) waitpid(p->pid, &ws, 0);
	if (p->r_fd >= 0) close(p->r_fd);
	myfree(p);
	config_put(cfg);
	errno = e;
	return NULL;
    }
#endif
    p->type = TYPE_CLIENT;
    p->count = 1;
    config_put(cfg);
    return p;
}

/* connection information */

struct sockaddr_storage * socket_addr(socket_t * p) {
    return &p->addr;
}

const char * socket_user(const socket_t * p) {
    if (p->type == TYPE_SERVER) {
	switch (p->family) {
	    case AF_INET :
	    case AF_INET6 :
		if (p->user)
		    return p->user;
		break;
	    case AF_UNIX :  {
		const char * A = ((struct sockaddr_un *)&p->addr)->sun_path;
		if (A) A += 1 + strlen(A);
		return A;
	    }
	}
	return "(unknown user)";
    }
    if (p->type == TYPE_CLIENT)
	return p->username;
    return NULL;
}

const char * socket_password(const socket_t * p) {
    if (p->type == TYPE_CLIENT)
	return p->password;
    return NULL;
}

config_userop_t socket_actions(const socket_t * p) {
    if (p->type == TYPE_SERVER)
	return p->actions;
    return 0;
}

void socket_stats(socket_t * p, long long * recv, long long * sent) {
    *recv = p->recv;
    *sent = p->sent;
}

/* closes connection */

void socket_disconnect(socket_t * p) {
    int i;
    for (i = 0; i < p->count; i++) {
	int ws;
	if (p[i].w_fd >= 0 && p[i].w_fd != p[i].r_fd) close(p[i].w_fd);
	if (p->pid >= 0) waitpid(p->pid, &ws, 0);
	if (p[i].r_fd >= 0) close(p[i].r_fd);
	if (p[i].family == PF_UNIX && p[i].type == TYPE_LISTEN) {
	    struct sockaddr_un * bindaddr;
	    bindaddr = (struct sockaddr_un *)&p[i].addr;
	    unlink(bindaddr[i].sun_path);
	}
	if (p[i].username) myfree(p[i].username);
	if (p[i].password) myfree(p[i].password);
	if (p[i].user) myfree(p[i].user);
    }
    myfree(p);
}

/* returns file descriptor for use in poll / select */

int socket_poll(socket_t * p) {
    return p->r_fd;
}

/* send data on the socket: socket_put sends binary data, socket_puts
 * sends a line of text, terminated by CRLF */

static int flushit(socket_t * p) {
    const char * s = p->p_out;
    int n = p->b_out;
    while (n > 0) {
	ssize_t nw = write(p->w_fd, s, n);
	if (nw < 0) return 0;
	if (nw == 0) {
	    errno = EBADF;
	    return 0;
	}
	p->sent += nw;
	n -= nw;
	s += nw;
    }
    p->b_out = 0;
    return 1;
}

static int putout(socket_t * p, const char * s, int l) {
    while (l > 0) {
	int d = PACKETSIZE - p->b_out;
	if (d == 0) {
	    if (! flushit(p)) return 0;
	    d = PACKETSIZE;
	}
	if (d > l) d = l;
	memcpy(p->p_out + p->b_out, s, d);
	s += d;
	l -= d;
	p->b_out += d;
    }
    return 1;
}

int socket_put(socket_t * p, const void * s, int l) {
    if (p->debug) {
	int ip = 1, pt;
	const char * d = s;
	for (pt = 0; pt < l && ip; pt++)
	    if (! isgraph((int)d[pt]) && d[pt] != ' ')
		ip = 0;
	if (ip)
	    fprintf(stderr, "  > %.*s\n", l, d);
	else
	    fprintf(stderr, "  > #%d\n", l);
    }
    if (! putout(p, s, l)) return 0;
    if (! p->autoflush) return 1;
    return flushit(p);
}

int socket_puts(socket_t * p, const char * s) {
    if (p->debug) fprintf(stderr, ">>> %s\n", s);
    if (! putout(p, s, strlen(s))) return 0;
    if (! putout(p, "\015\012", 2)) return 0;
    if (! p->autoflush) return 1;
    return flushit(p);
}

/* enable/disable autoflush by socket_put/socket_puts */

void socket_autoflush(socket_t * p, int af) {
    p->autoflush = af;
}

/* receive data from the socket: socket_get receives binary data,
 * socket_gets receives a line of text, up to a terminating CRLF
 * (which is not stored); socket_getc gets a single byte of binary data;
 * socket_getdata returns up to the required amount of data, but may
 * return less depending on what is available */

static int getin(socket_t * p) {
    ssize_t nr;
    struct pollfd pfd;
    int nfd;
    /* wait for data or a signal */
    while (main_running) {
	pfd.fd = p->r_fd;
	pfd.events = POLLIN | POLLHUP;
	nfd = poll(&pfd, 1, POLL_TIME);
	if (nfd < 1) {
	    if (errno != EINTR) continue;
	    p->b_in = p->r_in = 0;
	    return 0;
	}
	if (pfd.revents & POLLHUP) {
	    errno = EINTR;
	    p->b_in = p->r_in = 0;
	    return 0;
	}
	if (pfd.revents & POLLIN)
	    break;
    }
    if (! main_running) {
	errno = EINTR;
	p->b_in = p->r_in = 0;
	return 0;
    }
    nr = read(p->r_fd, p->p_in, PACKETSIZE);
    if (nr < 0) {
	p->b_in = p->r_in = 0;
	return 0;
    }
    p->recv += nr;
    p->b_in = nr;
    p->r_in = 0;
    if (nr == 0) {
	errno = ECONNABORTED;
	return 0;
    }
    return 1;
}

int socket_getc(socket_t * p) {
    int c;
    if (p->r_in >= p->b_in) {
	if (! getin(p)) return -1;
	if (p->r_in >= p->b_in)
	    return -1;
    }
    c = p->p_in[p->r_in];
    p->r_in++;
    return c;
}

int socket_get(socket_t * p, void * _d, int l) {
    char * d = _d;
    int origl = l;
    while (l > 0) {
	int avail = p->b_in - p->r_in;
	if (avail < 1) {
	    if (! getin(p))
		return 0;
	    avail = p->b_in - p->r_in;
	    if (avail == 0)
		return 0;
	}
	if (avail > l) avail = l;
	memcpy(d, p->p_in + p->r_in, avail);
	p->r_in += avail;
	l -= avail;
	d += avail;
    }
    if (p->debug) {
	int ip = 1, pt;
	d = _d;
	for (pt = 0; pt < origl && ip; pt++)
	    if (! isgraph((int)d[pt]) && d[pt] != ' ')
		ip = 0;
	if (ip)
	    fprintf(stderr, "  < %.*s\n", origl, (const char *)d);
	else
	    fprintf(stderr, "  < #%d\n", origl);
    }
    return 1;
}

int socket_gets(socket_t * p, char * d, int l) {
    int ok = 0;
    char * start = d;
    l--;
    while (l > 0) {
	int c = socket_getc(p);
	if (c < 0) {
	    if (! ok) return 0;
	    *d = 0;
	    if (p->debug) fprintf(stderr, "<<< %s\n", start);
	    return ok;
	}
	if (c == '\015') {
	    c = socket_getc(p);
	    if (c == '\012')
		break;
	    *d++ = '\015';
	    l--;
	    if (l < 1)
		break;
	}
	*d++ = c;
	l--;
	ok = 1;
    }
    *d = 0;
    if (p->debug) fprintf(stderr, "<<< %s\n", start);
    return 1;
}

int socket_getdata(socket_t * p, void * d, int l) {
    int avail = p->b_in - p->r_in;
    if (l < 1) return 0;
    if (avail < 1) {
	if (! getin(p))
	    return -1;
	avail = p->b_in - p->r_in;
	if (avail == 0)
	    return 0;
    }
    if (avail > l) avail = l;
    memcpy(d, p->p_in + p->r_in, avail);
    p->r_in += avail;
    return avail;
}

void socket_setdebug(socket_t * p, int d) {
    if (p) p->debug = d;
}

