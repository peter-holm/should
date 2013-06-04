/* pipe to/from a command
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
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

#ifndef __SHOULD_PIPE_H__
#define __SHOULD_PIPE_H__ 1

#include <sys/types.h>
#include "config.h"

/* data created by pipe_open* */

typedef struct {
    pid_t pid;
    int fromchild;
    int tochild;
} pipe_t;

/* opens a pipe from a command, returns 1 == OK, 0 == error */

int pipe_openfrom(char * const *, pipe_t *);

/* opens a pipe to a command, returns 1 == OK, 0 == error */

int pipe_opento(char * const *, pipe_t *);

/* opens a bidirectional pipe to/from command, returns 1 == OK, 0 == error */

int pipe_openfromto(char * const *, pipe_t *);

/* closes pipe and waits for command to exit; returns exit status */

int pipe_close(pipe_t *);

#endif /* __SHOULD_PIPE_H__ */
