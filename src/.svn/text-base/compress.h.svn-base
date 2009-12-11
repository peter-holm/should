#ifndef __SHOULD_COMPRESS_H__
#define __SHOULD_COMPRESS_H__ 1

/* data compression for should
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

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
