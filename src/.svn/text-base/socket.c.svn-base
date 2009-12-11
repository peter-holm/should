/* communicate with a running server: either via a local UNIX domain socket,
 * or via a network connection
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
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/poll.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "socket.h"
#include "mymalloc.h"
#include "config.h"
#include "notify_thread.h"
#include "error.h"
#include "usermap.h"

#define CHALLENGE_SIZE 8
#define AUXSIZE 256
#define PACKETSIZE 8192

/* used to represent a running connection */

struct socket_s {
    int fd;
    int family;
    enum { TYPE_CLIENT, TYPE_SERVER, TYPE_LISTEN } type;
    struct sockaddr_storage addr;
    const config_t * cfg;
    int count;
    union {
	struct ucred ucred;   /* for UNIX domain */
	config_user_t * user; /* for TCP sockets */
    };
    int debug;
    int b_in;
    int r_in;
    int b_out;
    int autoflush;
    char p_in[PACKETSIZE];
    char p_out[PACKETSIZE];
};

/* prepare a socket suitable for listening on a UNIX path */

static int listen_unix(socket_t * p, const char * path) {
    struct sockaddr_un * bindaddr;
    bindaddr = (struct sockaddr_un *)&p->addr;
    p->fd = -1;
    memset(&p->addr, 0, sizeof(p->addr));
    if (strlen(path) >= sizeof(bindaddr->sun_path)) {
	errno = ENAMETOOLONG;
	return 0;
    }
    if (! *path) {
	errno = EINVAL;
	return 0;
    }
    p->fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (p->fd < 0)
	return 0;
    bindaddr->sun_family = AF_UNIX;
    strcpy(bindaddr->sun_path, path);
    if (bind(p->fd, (struct sockaddr *)bindaddr, sizeof(*bindaddr)) < 0)
	return 0;
    if (listen(p->fd, SOMAXCONN) < 0)
	return 0;
    p->family = PF_UNIX;
    p->debug = 0;
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    return 1;
}

/* prepare a socket suitable for listening on a TCP port */

static int listen_tcp(socket_t * p, const struct addrinfo * addr) {
    int one = 1;
    memset(&p->addr, 0, sizeof(p->addr));
    p->fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (p->fd < 0)
	return 0;
    setsockopt(p->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(p->fd, addr->ai_addr, addr->ai_addrlen) < 0)
	return 0;
    if (listen(p->fd, SOMAXCONN) < 0)
	return 0;
    memcpy(&p->addr, addr->ai_addr, addr->ai_addrlen);
    p->family = addr->ai_family;
    p->debug = 0;
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    return 1;
}

/* prepare a socket suitable for listening on a UNIX path or TCP port */

socket_t * socket_listen(const config_t * cfg) {
    int count, ok, acount;
    typedef struct ailist_s ailist_t;
    struct ailist_s {
	ailist_t * next;
	struct addrinfo * this;
    };
    ailist_t * ai_all = NULL;
    config_listen_t * L = cfg->listen;
    socket_t * r;
    count = 1;
    while (L) {
	int errcode;
	struct addrinfo hints, * ptr;
	ailist_t * ai = mymalloc(sizeof(ailist_t));
	if (! ai)
	    return NULL;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	errcode = getaddrinfo(L->host, L->port, &hints, &ai->this);
	if (errcode) {
	    int e = EINVAL;
	    switch (errcode) {
		case EAI_ADDRFAMILY :
		case EAI_FAIL :
		case EAI_NODATA :
		case EAI_NONAME :
		case EAI_SERVICE :
		    e = ENOENT;
		    break;
		case EAI_AGAIN :
		    e = EAGAIN;
		    break;
		case EAI_SYSTEM :
		    break;
		case EAI_MEMORY :
		    e = ENOMEM;
		    break;
		default :
		    e = EINVAL;
		    break;
	    }
	    myfree(ai);
	    errno = e;
	    return NULL;
	}
	for (ptr = ai->this; ptr; ptr = ptr->ai_next)
	    count++;
	ai->next = ai_all;
	ai_all = ai;
	L = L->next;
    }
    r = mymalloc(count * sizeof(socket_t));
    if (! r) return NULL;
    ok = listen_unix(r, cfg->control_socket);
    if (! ok) {
	int e = errno;
	if (r->fd >= 0) close(r->fd);
	myfree(r);
	while (ai_all) {
	    ailist_t * ai = ai_all;
	    ai_all = ai_all->next;
	    freeaddrinfo(ai->this);
	    myfree(ai);
	}
	errno = e;
	return NULL;
    }
    acount = 1;
    while (ai_all) {
	struct addrinfo * ptr;
	ailist_t * ai = ai_all;
	ai_all = ai_all->next;
	for (ptr = ai->this; ptr; ptr = ptr->ai_next, acount++) {
	    ok = listen_tcp(&r[acount], ptr);
	    if (! ok) {
		int e = errno;
		if (r[acount].fd) close(r[acount].fd);
		while (acount > 0) {
		    acount--;
		    if (r[acount].fd) close(r[acount].fd);
		}
		myfree(r);
		unlink(cfg->control_socket);
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
    r->count = count;
    r->type = TYPE_LISTEN;
    r->cfg = cfg;
    return r;
}

/* receive credentials from a UNIX domain socket */

static int receive_credentials_unix(socket_t * p) {
    int one = 1, ok = 0;
    struct msghdr auxdata;
    struct iovec buffers;
    char buffvec[AUXSIZE], buffmsg[AUXSIZE];
    struct cmsghdr * cmsg;
    if (setsockopt(p->fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(int)) < 0)
	return 0;
    buffers.iov_base = buffvec;
    buffers.iov_len = AUXSIZE;
    auxdata.msg_name = NULL;
    auxdata.msg_namelen = 0;
    auxdata.msg_iov = &buffers;
    auxdata.msg_iovlen = 1;
    auxdata.msg_control = buffmsg;
    auxdata.msg_controllen = AUXSIZE;
    auxdata.msg_flags = 0;
    if (recvmsg(p->fd, &auxdata, 0) < 0)
	return 0;
    for (cmsg = CMSG_FIRSTHDR(&auxdata);
	 cmsg != NULL;
	 cmsg = CMSG_NXTHDR(&auxdata, cmsg))
    {
	if (cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_CREDENTIALS)
	{
	    struct sockaddr_un * A = (struct sockaddr_un *)&p->addr;
	    int len = 0;
	    p->ucred = *(struct ucred *)CMSG_DATA(cmsg);
	    snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
		     "pid#%d", p->ucred.pid);
	    len += strlen(A->sun_path + len) + 1;
	    if (usermap_fromid(p->ucred.uid,
			       A->sun_path + len,
			       sizeof(A->sun_path) - len) > 0)
	    {
		if (p->cfg->users) {
		    config_user_t * allow = p->cfg->users;
		    int found = 0, required = 0;
		    while (allow) {
			if (! allow->pass) {
			    required = 1;
			    if (strcmp(allow->user, A->sun_path + len) == 0)
				found = 1;
			}
			allow = allow->next;
		    }
		    if (required && ! found) {
			errno = EPERM;
			return 0;
		    }
		}
		len += strlen(A->sun_path + len);
		A->sun_path[len++] = ':';
	    } else {
		snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
			 "uid#%d:", p->ucred.uid);
		if (p->cfg->users) {
		    config_user_t * allow = p->cfg->users;
		    while (allow) {
			if (! allow->pass) {
			    /* we have user checking, but no way to check */
			    errno = EPERM;
			    return 0;
			}
			allow = allow->next;
			break;
		    }
		}
		len += strlen(A->sun_path + len);
	    }
	    if (groupmap_fromid(p->ucred.gid,
			        A->sun_path + len,
			        sizeof(A->sun_path) - len) <= 0)
		snprintf(A->sun_path + len, sizeof(A->sun_path) - len,
			 "gid#%d", p->ucred.gid);
	    ok = 1;
	}
    }
    errno = EINVAL;
    return ok;
}

/* generates MD5 hash from user, password, challenge */

static void hash_user(const char * user, const char * pass,
		      const unsigned char * challenge, unsigned char * hash)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    if (user) MD5_Update(&ctx, user, strlen(user));
    MD5_Update(&ctx, challenge, CHALLENGE_SIZE);
    if (pass) MD5_Update(&ctx, pass, strlen(pass));
    MD5_Final(hash, &ctx);
}

/* receive credentials from a TCP socket */

static int receive_credentials_tcp(socket_t * p) {
    unsigned char challenge[CHALLENGE_SIZE], hash[MD5_DIGEST_LENGTH];
    char welcome[2 * CHALLENGE_SIZE + 2 * MD5_DIGEST_LENGTH + 32];
    int i, wp = 0, ulen;
    config_user_t * allow = p->cfg->users;
    RAND_bytes(challenge, CHALLENGE_SIZE);
    /* send welcome string and challenge */
    wp += sprintf(welcome + wp, "SHOULD [");
    for (i = 0; i < CHALLENGE_SIZE; i++)
	wp += sprintf(welcome + wp, "%02X", (unsigned int)challenge[i]);
    wp += sprintf(welcome + wp, "]");
    if (! socket_puts(p, welcome))
	return 0;
    /* receive username and hash */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    wp = 0;
    while (welcome[wp] && ! isspace(welcome[wp])) wp++;
    if (wp == 0)
	goto invalid;
    ulen = wp;
    while (welcome[wp] && isspace(welcome[wp])) wp++;
    for (i = 0; i < 2 * MD5_DIGEST_LENGTH; i++) {
	if (! welcome[wp + i] || ! isxdigit(welcome[wp + i]))
	    goto invalid;
    }
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
	char val[3] = "00";
	val[0] = welcome[wp++];
	val[1] = welcome[wp++];
	hash[i] = strtol(val, NULL, 16);
    }
    /* compare with stored userlist */
    while (allow) {
	if (allow->pass) {
	    if (strlen(allow->user) == ulen) {
		if (strncmp(allow->user, welcome, ulen) == 0) {
		    unsigned char hashcmp[MD5_DIGEST_LENGTH];
		    p->user = allow;
		    /* for testing only: empty password */
		    if (! *allow->pass)
			goto welcome;
		    hash_user(allow->user, allow->pass, challenge, hashcmp);
		    if (memcmp(hash, hashcmp, MD5_DIGEST_LENGTH) == 0)
			goto welcome;
		    goto noperm;
		}
	    }
	}
	allow = allow->next;
    }
    goto noperm;
welcome:
    if (! socket_puts(p, "OK welcome"))
	return 0;
    return 1;
noperm:
    socket_puts(p, "EPERM Invalid username or password");
    errno = EPERM;
    return 0;
invalid:
    socket_puts(p, "EINVAL Invalid reply");
    errno = EBADF;
    return 0;
}

/* accept next connection */

socket_t * socket_accept(socket_t * p, int timeout) {
    socket_t * c, * s;
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct pollfd pfd[p->count];
    if (p->type != TYPE_LISTEN) {
	errno = EINVAL;
	return NULL;
    }
    for (fd = 0; fd < p->count; fd++) {
	pfd[fd].fd = p[fd].fd;
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
    fd = accept(s->fd, (struct sockaddr *)&addr, &addrlen);
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
    c->fd = fd;
    c->family = s->family;
    c->type = TYPE_SERVER;
    c->count = 1;
    c->addr = addr;
    c->cfg = p->cfg;
    c->autoflush = 1;
    if (c->family == PF_UNIX) {
	if (! receive_credentials_unix(c)) {
	    int e = errno;
	    close(fd);
	    myfree(c);
	    errno = e;
	    return NULL;
	}
    }
    if (c->family == PF_INET || c->family == PF_INET6) {
	if (! receive_credentials_tcp(c)) {
	    int e = errno;
	    close(fd);
	    myfree(c);
	    errno = e;
	    return NULL;
	}
    }
    c->debug = 0;
    c->b_in = 0;
    c->r_in = 0;
    c->b_out = 0;
    return c;
}

/* connect to a running server using UNIX domain sockets */

static int connect_unix(socket_t * p) {
    struct sockaddr_un * addr = (struct sockaddr_un *)&p->addr;
    struct msghdr auxdata;
    struct iovec buffers;
    char buffvec[AUXSIZE], buffmsg[AUXSIZE];
    struct cmsghdr * cmsg;
    struct ucred * ucred;
    int one;
    if (strlen(p->cfg->control_socket) >= sizeof(addr->sun_path)) {
	errno = ENAMETOOLONG;
	return 0;
    }
    p->family = PF_UNIX;
    p->fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (p->fd < 0)
	return 0;
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, p->cfg->control_socket);
    if (connect(p->fd, (struct sockaddr *)addr, sizeof(*addr)) < 0)
	return 0;
    one = 1;
    if (setsockopt(p->fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(int)) < 0)
	return 0;
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
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    ucred = (struct ucred *)CMSG_DATA(cmsg);
    ucred->pid = getpid();
    ucred->uid = getuid();
    ucred->gid = getgid();
    auxdata.msg_controllen = cmsg->cmsg_len;
    if (sendmsg(p->fd, &auxdata, 0) < 0)
	return 0;
    return 1;
}

/* connect to a running server using TCP */

static int connect_tcp(socket_t * p) {
    struct addrinfo * ai, hints, * ptr;
    int errcode;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;
    errcode =
	getaddrinfo(p->cfg->server.host, p->cfg->server.port, &hints, &ai);
    if (errcode) {
	myfree(p);
	switch (errcode) {
	    case EAI_ADDRFAMILY :
	    case EAI_FAIL :
	    case EAI_NODATA :
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
	p->fd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (p->fd < 0) {
	    errcode = errno;
	    continue;
	}
	if (connect(p->fd, ptr->ai_addr, ptr->ai_addrlen) < 0) {
	    errcode = errno;
	    close(p->fd);
	    p->fd = -1;
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

/* send credentials to a TCP socket */

static int send_credentials_tcp(socket_t * p) {
    unsigned char challenge[CHALLENGE_SIZE], hash[MD5_DIGEST_LENGTH];
    char welcome[2 * CHALLENGE_SIZE + 2 * MD5_DIGEST_LENGTH + 32 + AUXSIZE];
    char ubuffer[AUXSIZE], pbuffer[AUXSIZE];
    const char * user, * pass;
    int wp, i;
    /* receive welcome and extract challenge */
    if (! socket_gets(p, welcome, sizeof(welcome)))
	return 0;
    if (strncmp(welcome, "SHOULD", 6) != 0)
	goto invalid;
    wp = 6;
    while (welcome[wp] && isspace(welcome[wp])) wp++;
    if (welcome[wp] != '[')
	goto invalid;
    wp++;
    for (i = 0; i < 2 * CHALLENGE_SIZE; i++) {
	if (! isxdigit(welcome[wp + i]))
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
    /* prepare hash and send identification string */
    if (p->cfg->user) {
	user = p->cfg->user;
    } else {
	printf("User: ");
	fflush(stdout);
	fgets(ubuffer, sizeof(ubuffer), stdin);
	i = strlen(ubuffer);
	if (i > 0 && ubuffer[i - 1] == '\n') ubuffer[i - 1] = 0;
	user = ubuffer;
    }
    if (p->cfg->password) {
	pass = p->cfg->password;
    } else {
	struct termios T;
	int ok;
	printf("Password for %s: ", user);
	fflush(stdout);
	ok = tcgetattr(fileno(stdin), &T) >= 0;
	if (ok) {
	    struct termios n = T;
	    n.c_lflag &= ~ECHO;
	    tcsetattr(fileno(stdin), TCSAFLUSH, &n);
	}
	fgets(pbuffer, sizeof(pbuffer), stdin);
	if (ok) {
	    printf("\n");
	    tcsetattr(fileno(stdin), TCSAFLUSH, &T);
	}
	i = strlen(pbuffer);
	if (i > 0 && pbuffer[i - 1] == '\n') pbuffer[i - 1] = 0;
	pass = pbuffer;
    }
    hash_user(user, pass, challenge, hash);
    strcpy(welcome, user);
    wp = strlen(welcome);
    welcome[wp++] = ' ';
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
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

/* connect to a running server */

socket_t * socket_connect(const config_t * cfg) {
    socket_t * p = mymalloc(sizeof(socket_t));
    int ok;
    if (! p) return NULL;
    p->fd = -1;
    memset(&p->addr, 0, sizeof(p->addr));
    p->cfg = cfg;
    p->b_in = 0;
    p->r_in = 0;
    p->b_out = 0;
    p->autoflush = 1;
    if (cfg->server.host)
	ok = connect_tcp(p);
    else
	ok = connect_unix(p);
    if (! ok) {
	int e = errno;
	if (p->fd >= 0) close(p->fd);
	myfree(p);
	errno = e;
	return NULL;
    }
    p->debug = cfg->flags & config_flag_debug_server;
    if (cfg->server.host && ! send_credentials_tcp(p)) {
	int e = errno;
	close(p->fd);
	myfree(p);
	errno = e;
	return NULL;
    }
    p->type = TYPE_CLIENT;
    p->count = 1;
    return p;
}

/* connection information */

struct sockaddr_storage * socket_addr(socket_t * p) {
    return &p->addr;
}

const char * socket_user(const socket_t * p) {
    switch (p->family) {
	case AF_INET :
	case AF_INET6 : return p->user->user;
	case AF_UNIX :  {
	    const char * A = ((struct sockaddr_un *)&p->addr)->sun_path;
	    if (A) A += 1 + strlen(A);
	    return A;
	}
    }
    return "(unknown user)";
}

/* closes connection */

void socket_disconnect(socket_t * p) {
    int i;
    for (i = 0; i < p->count; i++) {
	close(p[i].fd);
	if (p[i].family == PF_UNIX && p[i].type == TYPE_LISTEN) {
	    struct sockaddr_un * bindaddr;
	    bindaddr = (struct sockaddr_un *)&p[i].addr;
	    unlink(bindaddr[i].sun_path);
	}
    }
    myfree(p);
}

/* returns file descriptor for use in poll / select */

int socket_poll(socket_t * p) {
    return p->fd;
}

/* send data on the socket: socket_put sends binary data, socket_puts
 * sends a line of text, terminated by CRLF */

static int flushit(socket_t * p) {
    const char * s = p->p_out;
    int n = p->b_out;
    while (n > 0) {
	ssize_t nw = write(p->fd, s, n);
	if (nw < 0) return 0;
	if (nw == 0) {
	    errno = EBADF;
	    return 0;
	}
	n -= nw;
    }
    p->b_out = 0;
    return 1;
}

static int getout(socket_t * p, const char * s, int l) {
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
    if (p->debug) printf("  > %.*s\n", l, (const char *)s);
    if (! getout(p, s, l)) return 0;
    if (! p->autoflush) return 1;
    return flushit(p);
}

int socket_puts(socket_t * p, const char * s) {
    if (p->debug) printf(">>> %s\n", s);
    if (! getout(p, s, strlen(s))) return 0;
    if (! getout(p, "\015\012", 2)) return 0;
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
    ssize_t nr = read(p->fd, p->p_in, PACKETSIZE);
    if (nr < 0) return 0;
    if (nr == 0) {
	errno = EBADF;
	return 0;
    }
    p->b_in = nr;
    p->r_in = 0;
    return 1;
}

int socket_get(socket_t * p, void * _d, int l) {
    char * d = _d;
    int origl = l;
    while (l > 0) {
	int avail = p->b_in - p->r_in;
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
	l -= avail;
    }
    if (p->debug) printf("  < %d\n", origl);
    return 1;
}

int socket_gets(socket_t * p, char * d, int l) {
    int ok = 0;
    char * start = d;
    l--;
    while (l > 0) {
	int c = socket_getc(p);
	if (c < 0)
	    return ok;
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
    }
    *d = 0;
    if (p->debug) printf("<<< %s\n", start);
    return 1;
}

int socket_getc(socket_t * p) {
    int c;
    if (p->r_in >= p->b_in) {
	if (! getin(p)) return -1;
    }
    if (p->r_in >= p->b_in)
	return -1;
    c = p->p_in[p->r_in];
    p->r_in++;
    return c;
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

