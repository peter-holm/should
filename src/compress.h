/* data compression for should
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

#ifndef __SHOULD_COMPRESS_H__
#define __SHOULD_COMPRESS_H__ 1

/* number of compression methods supported; there is always at least
 * one, which returns uncompressed data */

int compress_count(void);

/* name of a compression method: 0 <= n < compress_count() */

const char * compress_name(int n);

/* look up a method by name; a NULL means the non compressing method;
 * returns -1 if the method is not known */

int compress_byname(const char *);

/* tries to compress a block of data: the destination buffer must have
 * at least the same size as the source. Returns the compressed data
 * size, if smaller than the source, or a negative number, in which case
 * the contents of the destination buffer are undefined */

int compress_data(int n, const void * src, int size, void * dst);

/* uncompresses a block of data. Returns NULL if OK, or an error message
 * if decompression fails; dstsize is modified to reflect the space used */

const char * uncompress_data(int n, const void * src, int srcsize,
			     void * dst, int * dstsize);

#endif /* __SHOULD_COMPRESS_H__ */
