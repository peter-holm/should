/* interface to malloc which remembers data useful in case of errors
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include "mymalloc.h"
#include "error.h"
#include "main_thread.h"

#define MAGIC 0x17b9f23c4a60d85cLL

uint64_t mymalloc_used;
static int free_error;

typedef struct preamble_s preamble_t;
struct preamble_s {
    int64_t magic;
    size_t size;
    preamble_t * prev, * next;
    const char * file;
    int line;
} __attribute__((aligned(32)));

static preamble_t * first;
static pthread_mutex_t preamble_lock;

const char * mymalloc_init(void) {
    int code;
    mymalloc_used = 0;
    free_error = 0;
    first = NULL;
    code = pthread_mutex_init(&preamble_lock, NULL);
    if (code)
	return error_sys_errno("mymalloc_init", "pthread_mutex_init", code);
    return NULL;
}

void * _mymalloc_internal(size_t s, const char * file, int line) {
    preamble_t * p;
    int errcode;
    s += sizeof(preamble_t);
    p = malloc(s);
    if (! p)
	return NULL;
    p->magic = MAGIC;
    p->size = s;
    p->file = file;
    p->line = line;
    p->prev = NULL;
    errcode = pthread_mutex_lock(&preamble_lock);
    if (errcode) {
	p->magic = 0;
	free(p);
	errno = errcode;
	return NULL;
    }
    mymalloc_used += s;
    p->next = first;
    if (first) first->prev = p;
    first = p;
    pthread_mutex_unlock(&preamble_lock);
    return &p[1];
}

void _myfree_internal(void * p, const char * file, int line) {
    preamble_t * pr;
    int errcode;
    if (! p) return;
    pr = p;
    pr--;
    if (pr->magic != MAGIC) {
	static int reported = 0;
	if (! reported)
	    error_report(error_allocation, file, line);
	reported = 1;
	return;
    }
    pr->magic = 0;
    errcode = pthread_mutex_lock(&preamble_lock);
    if (errcode) {
	free_error = errcode;
    } else {
	mymalloc_used -= pr->size;
	if (pr == first) {
	    first = pr->next;
	    if (first) first->prev = NULL;
	} else {
	    if (pr->next) pr->next->prev = pr->prev;
	    pr->prev->next = pr->next;
	}
	pthread_mutex_unlock(&preamble_lock);
    }
    free(pr);
}

char * _mystrdup_internal(const char * s, const char * file, int line) {
    if (s) {
	char * res = _mymalloc_internal(1 + strlen(s), file, line);
	if (res)
	    strcpy(res, s);
	return res;
    }
    return NULL;
}

void mymalloc_exit(void) {
#if USE_SHOULDBOX
    if (mymalloc_used)
	error_report(error_shouldbox_int, "mymalloc_exit",
		     "mymalloc_used", mymalloc_used);
#endif
    if (free_error) {
#if USE_SHOULDBOX
	errno = free_error;
	perror("myfree");
#endif
    } else {
#if USE_SHOULDBOX
	int title = 1;
#endif
	while (first) {
	    preamble_t * pr = first;
#if USE_SHOULDBOX
	    if (title) {
		fprintf(stderr, "** Memory leaks detected **\n");
		fprintf(stderr, "Block size    line    file\n");
		title = 0;
	    }
	    fprintf(stderr, "%10ld  %6d    %s\n",
		    (long)pr->size - sizeof(preamble_t),
		    pr->line, pr->file);
#endif
	    first = first->next;
	    free(pr);
	}
    }
    pthread_mutex_destroy(&preamble_lock);
}

