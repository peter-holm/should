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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "config.h"
#include "pipe.h"

/* opens a pipe to a command, returns 1 == OK, 0 == error */

int pipe_opento(char * const * cmd, pipe_t * P) {
    int tochild[2];
    if (pipe(tochild) < 0)
	return 0;
    fflush(NULL);
    P->pid = fork();
    if (P->pid < 0) {
	int e = errno;
	close(tochild[0]);
	close(tochild[1]);
	errno = e;
	return 0;
    }
    if (P->pid == 0) {
	/* child process - run the command */
	close(tochild[1]);
	fclose(stdin);
	if (dup2(tochild[0], 0) < 0) {
	    perror("dup2");
	    close(tochild[0]);
	    exit(1);
	}
	execvp(cmd[0], cmd);
	perror(cmd[0]);
	exit(2);
    }
    /* parent process */
    close(tochild[0]);
    P->tochild = tochild[1];
    P->fromchild = -1;
    return 1;
}

/* opens a pipe from a command, returns 1 == OK, 0 == error */

int pipe_openfrom(char * const * cmd, pipe_t * P) {
    int fromchild[2];
    if (pipe(fromchild) < 0)
	return 0;
    fflush(NULL);
    P->pid = fork();
    if (P->pid < 0) {
	int e = errno;
	close(fromchild[0]);
	close(fromchild[1]);
	errno = e;
	return 0;
    }
    if (P->pid == 0) {
	/* child process - run the command */
	close(fromchild[0]);
	fclose(stdout);
	if (dup2(fromchild[1], 1) < 0) {
	    perror("dup2");
	    close(fromchild[1]);
	    exit(1);
	}
	execvp(cmd[0], cmd);
	perror(cmd[0]);
	exit(2);
    }
    /* parent process */
    close(fromchild[1]);
    P->fromchild = fromchild[0];
    P->tochild = -1;
    return 1;
}

/* opens a bidirectional pipe to/from command, returns 1 == OK, 0 == error */

int pipe_openfromto(char * const * cmd, pipe_t * P) {
    int fromchild[2], tochild[2];
    if (pipe(fromchild) < 0)
	return 0;
    if (pipe(tochild) < 0) {
	int e = errno;
	close(fromchild[0]);
	close(fromchild[1]);
	errno = e;
	return 0;
    }
    fflush(NULL);
    P->pid = fork();
    if (P->pid < 0) {
	int e = errno;
	close(fromchild[0]);
	close(fromchild[1]);
	close(tochild[0]);
	close(tochild[1]);
	errno = e;
	return 0;
    }
    if (P->pid == 0) {
	/* child process */
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
	execvp(cmd[0], cmd);
	perror(cmd[0]);
	exit(2);
    }
    /* parent */
    close(fromchild[1]);
    close(tochild[0]);
    P->fromchild = fromchild[0];
    P->tochild = tochild[1];
    return 1;
}

/* closes pipe and waits for command to exit; returns exit status */

int pipe_close(pipe_t * P) {
    int ws = 0;
    if (P->tochild >= 0) close(P->tochild);
    if (P->fromchild >= 0) close(P->fromchild);
    if (P->pid >= 0) waitpid(P->pid, &ws, 0);
    P->fromchild = P->tochild = -1;
    P->pid = -1;
    return ws;
}

