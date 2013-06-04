/* interface to malloc which remembers data useful in case of errors
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
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

#ifndef __SHOULD_MYMALLOC_H__
#define __SHOULD_MYMALLOC_H__ 1

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
