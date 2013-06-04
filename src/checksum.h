/* checksum calculations for should
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

#ifndef __SHOULD_CHECKSUM_H__
#define __SHOULD_CHECKSUM_H__ 1

/* number of checksum methods supported */

int checksum_count(void);

/* name of a checksum method: 0 <= n < checksum_count() */

const char * checksum_name(int n);

/* look up a method by name; returns -1 if the method is not known */

int checksum_byname(const char *);

/* size of checksum (in its binary form): 0 <= n < checksum_count() */

int checksum_size(int n);

/* checksums a block of data: the destination buffer must have
 * space for the checksum, as returned by checksum_size(n) */

int checksum_data(int n, const void * src, int size, unsigned char * dst);

#endif /* __SHOULD_CHECKSUM_H__ */
