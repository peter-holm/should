/* data compression for should
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

#include "site.h"
#include <string.h>
#if THEY_HAVE_ZLIB
#include <zlib.h>
#endif
#if THEY_HAVE_BZLIB
#include <bzlib.h>
#endif
#include "mymalloc.h"
#include "compress.h"

typedef struct {
    const char * name;
    int (*compress)(const void *, int, void *);
    const char * (*uncompress)(const void *, int, void *, int *);
} compress_t;

static int c_null(const void * src, int size, void * dst) {
    return -1;
}

static const char * u_null(const void * src, int srcsize,
			   void * dst, int * dstsize)
{
    if (srcsize > *dstsize) return "Buffer too small to uncompress";
    memcpy(dst, src, srcsize);
    *dstsize = srcsize;
    return NULL;
}

#if THEY_HAVE_ZLIB
static voidpf z_mymalloc(voidpf opaque, uInt items, uInt size) {
    return mymalloc(items * size);
}

static void z_myfree(voidpf opaque, voidpf address) {
    myfree(address);
}

static int c_gzip(const void * src, int size, void * dst) {
    z_stream zs;
    int rv;
    if (size < 1) return -1;
    zs.zalloc     = z_mymalloc;
    zs.zfree      = z_myfree;
    zs.opaque     = NULL;
    if (deflateInit(&zs, 9) != Z_OK)
	return -1;
    zs.next_in    = (void *)src;
    zs.avail_in   = size;
    zs.total_in   = 0,
    zs.next_out   = dst;
    zs.avail_out  = size;
    zs.total_out  = 0;
    if (deflate(&zs, Z_FINISH) == Z_STREAM_END)
	rv = size - zs.avail_out;
    else
	rv = -1;
    deflateEnd(&zs);
    return rv;
}

static const char * u_gzip(const void * src, int srcsize,
			   void * dst, int * dstsize)
{
    z_stream zs;
    const char * rv;
    zs.zalloc     = z_mymalloc;
    zs.zfree      = z_myfree;
    zs.opaque     = NULL;
    if (inflateInit(&zs) != Z_OK)
	return "Could not initialise zlib";
    zs.next_in    = (void *)src;
    zs.avail_in   = srcsize;
    zs.total_in   = 0;
    zs.next_out   = dst;
    zs.avail_out  = *dstsize;
    zs.total_out  = 0;
    if (inflate(&zs, Z_FINISH) == Z_STREAM_END) {
	*dstsize -= zs.avail_out;
	rv = NULL;
    } else {
	rv = "zlib returned decompression error";
    }
    inflateEnd(&zs);
    return rv;
}
#endif

#if THEY_HAVE_BZLIB
static void * bz2_mymalloc(void * opaque, int items, int size) {
    return mymalloc(items * size);
}

static void bz2_myfree(void * opaque, void * address) {
    myfree(address);
}

static int c_bzip2(const void * src, int size, void * dst) {
    bz_stream bz2s;
    int rv;
    if (size < 1) return -1;
    bz2s.bzalloc    = bz2_mymalloc;
    bz2s.bzfree     = bz2_myfree;
    bz2s.opaque     = NULL;
    if (BZ2_bzCompressInit(&bz2s, 9, 0, 0) != BZ_OK)
	return -1;
    bz2s.next_in    = (void *)src;
    bz2s.avail_in   = size;
    bz2s.next_out   = dst;
    bz2s.avail_out  = size;
    if (BZ2_bzCompress(&bz2s, BZ_FINISH) == BZ_STREAM_END)
	rv = size - bz2s.avail_out;
    else
	rv = -1;
    BZ2_bzCompressEnd(&bz2s);
    return rv;
}

static const char * u_bzip2(const void * src, int srcsize,
			    void * dst, int * dstsize)
{
    bz_stream bz2s;
    const char * rv;
    bz2s.bzalloc    = bz2_mymalloc;
    bz2s.bzfree     = bz2_myfree;
    bz2s.opaque     = NULL;
    if (BZ2_bzDecompressInit(&bz2s, 0, 0) != BZ_OK)
	return "Could not initialise bzlib";
    bz2s.next_in    = (void *)src;
    bz2s.avail_in   = srcsize;
    bz2s.next_out   = dst;
    bz2s.avail_out  = *dstsize;
    if (BZ2_bzDecompress(&bz2s) == BZ_STREAM_END) {
	*dstsize -= bz2s.avail_out;
	rv = NULL;
    } else {
	rv = "bzlib returned decompression error";
    }
    BZ2_bzDecompressEnd(&bz2s);
    return rv;
}
#endif

static compress_t methods[] = {
#if THEY_HAVE_ZLIB
    { "gzip",     c_gzip,     u_gzip },
#endif
#if THEY_HAVE_BZLIB
    { "bzip2",    c_bzip2,    u_bzip2 },
#endif
    { "null",     c_null,     u_null }
};
#define N_METHODS (sizeof(methods) / sizeof(compress_t))

/* number of compression methods supported; there is always at least
 * one, which returns uncompressed data */

int compress_count(void) {
    return N_METHODS;
}

/* name of a compression method: 0 <= n < compress_count() */

const char * compress_name(int n) {
    if (n < 0 || n >= N_METHODS) return NULL;
    return methods[n].name;
}

/* look up a method by name; a NULL means the non compressing method;
 * returns -1 if the method is not known */

int compress_byname(const char * name) {
    int n;
    if (! name) name = "null";
    for (n = 0; n < N_METHODS; n++)
	if (strcmp(name, methods[n].name) == 0)
	    return n;
    return -1;
}

/* tries to compress a block of data: the destination buffer must have
 * at least the same size as the source. Returns the compressed data
 * size, if smaller than the source, or a negative number, in which case
 * the contents of the destination buffer are undefined */

int compress_data(int n, const void * src, int size, void * dst) {
    if (n < 0 || n >= N_METHODS) return -1;
    return methods[n].compress(src, size, dst);
}

/* uncompresses a block of data. Returns NULL if OK, or an error message
 * if decompression fails; dstsize is modified to reflect the space used */

const char * uncompress_data(int n, const void * src, int srcsize,
			     void * dst, int * dstsize)
{
    if (n < 0 || n >= N_METHODS) return "Unknown compression method";
    if (srcsize < 0 || dstsize < 0) return "Invalid buffer sizes";
    return methods[n].uncompress(src, srcsize, dst, dstsize);
}

