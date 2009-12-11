#ifndef __SHOULD_MYMALLOC_H__
#define __SHOULD_MYMALLOC_H__ 1

/* interface to malloc which remembers data useful in case of errors
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include <stdint.h>
#include <sys/types.h>

const char * mymalloc_init(void);

void * _mymalloc_internal(size_t, const char *, int);
#define mymalloc(s) _mymalloc_internal(s, __FILE__, __LINE__)

void _myfree_internal(void *, const char *, int);
#define myfree(p) _myfree_internal(p, __FILE__, __LINE__)

char * _mystrdup_internal(const char *, const char *, int);
#define mystrdup(s) _mystrdup_internal(s, __FILE__, __LINE__)

extern uint64_t mymalloc_used;

void mymalloc_exit(void);

#endif /* __SHOULD_MYMALLOC_H__ */
