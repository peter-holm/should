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

#include "site.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#if THEY_HAVE_MD5
#include <openssl/md5.h>
#endif
#if THEY_HAVE_SHA1 || THEY_HAVE_SHA224 || THEY_HAVE_SHA256 || \
    THEY_HAVE_SHA384 || THEY_HAVE_SHA512
#include <openssl/sha.h>
#endif
#if THEY_HAVE_RIPEMD160
#include <openssl/ripemd.h>
#endif
#include "checksum.h"

typedef struct {
    const char * name;
    int size;
    int (*checksum)(const void *, int, unsigned char *);
} checksum_t;

#if THEY_HAVE_MD5
static int md5_checksum(const void * data, int length, unsigned char * hash) {
    MD5_CTX ctx;
    int ok;
    if (! MD5_Init(&ctx)) return 0;
    ok = MD5_Update(&ctx, data, length);
    MD5_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_SHA1
static int sha1_checksum(const void * data, int length, unsigned char * hash) {
    SHA_CTX ctx;
    int ok;
    if (! SHA1_Init(&ctx)) return 0;
    ok = SHA1_Update(&ctx, data, length);
    SHA1_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_SHA224
static int sha224_checksum(const void * data, int length, unsigned char * hash)
{
    SHA256_CTX ctx;
    int ok;
    if (! SHA224_Init(&ctx)) return 0;
    ok = SHA224_Update(&ctx, data, length);
    SHA224_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_SHA256
static int sha256_checksum(const void * data, int length, unsigned char * hash)
{
    SHA256_CTX ctx;
    int ok;
    if (! SHA256_Init(&ctx)) return 0;
    ok = SHA256_Update(&ctx, data, length);
    SHA256_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_SHA384
static int sha384_checksum(const void * data, int length, unsigned char * hash)
{
    SHA512_CTX ctx;
    int ok;
    if (! SHA384_Init(&ctx)) return 0;
    ok = SHA384_Update(&ctx, data, length);
    SHA384_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_SHA512
static int sha512_checksum(const void * data, int length, unsigned char * hash)
{
    SHA512_CTX ctx;
    int ok;
    if (! SHA512_Init(&ctx)) return 0;
    ok = SHA512_Update(&ctx, data, length);
    SHA512_Final(hash, &ctx);
    return ok;
}
#endif

#if THEY_HAVE_RIPEMD160
static int ripemd160_checksum(const void * data, int length,
			      unsigned char * hash)
{
    RIPEMD160_CTX ctx;
    int ok;
    if (! RIPEMD160_Init(&ctx)) return 0;
    ok = RIPEMD160_Update(&ctx, data, length);
    RIPEMD160_Final(hash, &ctx);
    return ok;
}
#endif

static checksum_t methods[] = {
#if THEY_HAVE_SHA1
    { "sha1",         SHA_DIGEST_LENGTH,          sha1_checksum },
#endif
#if THEY_HAVE_MD5
    { "md5",          MD5_DIGEST_LENGTH,          md5_checksum },
#endif
#if THEY_HAVE_SHA224
    { "sha224",       SHA224_DIGEST_LENGTH,       sha224_checksum },
#endif
#if THEY_HAVE_SHA256
    { "sha256",       SHA256_DIGEST_LENGTH,       sha256_checksum },
#endif
#if THEY_HAVE_SHA384
    { "sha384",       SHA384_DIGEST_LENGTH,       sha384_checksum },
#endif
#if THEY_HAVE_SHA512
    { "sha512",       SHA512_DIGEST_LENGTH,       sha512_checksum },
#endif
#if THEY_HAVE_RIPEMD160
    { "ripemd160",    RIPEMD160_DIGEST_LENGTH,    ripemd160_checksum },
#endif
};
#define N_METHODS (sizeof(methods) / sizeof(checksum_t))

/* number of checksum methods supported */

int checksum_count(void) {
    return N_METHODS;
}

/* name of a checksum method: 0 <= n < checksum_count() */

const char * checksum_name(int n) {
    if (n < 0 || n >= N_METHODS) return NULL;
    return methods[n].name;
}

/* look up a method by name; returns -1 if the method is not known */

int checksum_byname(const char * name) {
    int n;
    for (n = 0; n < N_METHODS; n++)
	if (strcmp(name, methods[n].name) == 0)
	    return n;
    return -1;
}

/* size of checksum (in its binary form): 0 <= n < checksum_count() */

int checksum_size(int n) {
    if (n < 0 || n >= N_METHODS) return 0;
    return methods[n].size;
}

/* checksums a block of data: the destination buffer must have
 * space for the checksum, as returned by checksum_size(n) */

int checksum_data(int n, const void * src, int size, unsigned char * dst) {
    if (n < 0 || n >= N_METHODS) return 0;
    return methods[n].checksum(src, size, dst);
}

