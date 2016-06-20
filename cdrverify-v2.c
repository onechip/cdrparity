
/* Copyright 2016 Chris Studholme.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cdrverify.h"
#include "siphash24.h"


/* Marker format (block zero):
 *   uint32_t signature;       // 0x972fae43
 *   uint16_t log2_blocksize;  // min 6
 *   uint16_t index;           // 0
 *   uint64_t date_time;
 *
 *   uint32_t num_stripes;
 *   uint32_t first_blocks;
 *   uint32_t stripe_blocks;
 *   uint32_t image_blocks;
 *
 *   uint64_t parity_hash;
 *   uint64_t stripe_hashes[];
 *   uint64_t checksum;    
 *
 * Block one and later (i):
 *   uint32_t signature;       // 0x972fae43
 *   uint16_t log2_blocksize;
 *   uint16_t index;           // i
 *
 *   uint64_t stripe_hashes[];
 *   uint64_t checksum;    
 */

#define SIG  0x972fae43u
#define SIGR 0x43ae2f97u

// dest/src must be aligned on some machines
static void memxor(void* dest, const void* src, size_t n) {
    while (n >= sizeof(unsigned long)) {
        *(unsigned long*)dest ^= *(unsigned long*)src;
        dest = 1 + (unsigned long*)dest;
        src = 1 + (unsigned long*)src;
        n -= sizeof(unsigned long);
    }
    while (n > 0) {
        *(unsigned char*)dest ^= *(unsigned char*)src;
        dest = 1 + (unsigned char*)dest;
        src = 1 + (unsigned char*)src;
        --n;
    }
}

static int verify_stripe_hash(const void* stripe, size_t stripe_bytes,
                              void* marker, unsigned index,
                              const void* expected_hash) {
    const int need_bswap = *(uint32_t*)marker == SIGR;
    ((uint16_t*)marker)[3] = need_bswap ? bswap_16(index) : index;
    uint8_t hash[SIPHASH_DIGEST_LENGTH];
    siphash(hash, stripe, stripe_bytes, marker);
    return memcmp(hash, expected_hash, SIPHASH_DIGEST_LENGTH) == 0;
}

static int verify_marker_block_hash(const void* src, size_t block_bytes) {
    static const uint8_t zero_key[SIPHASH_KEY_LENGTH] = {0};
    uint8_t hash[SIPHASH_DIGEST_LENGTH];
    siphash(hash, src, block_bytes - 8, zero_key);
    const void* expected_hash = ((char*)src) + block_bytes - 8;
    return memcmp(hash, expected_hash, SIPHASH_DIGEST_LENGTH) == 0;
}

static int verify_marker_hash(const void* src, size_t block_bytes,
                              unsigned marker_blocks) {
    while (marker_blocks > 0) {
        if (!verify_marker_block_hash(src, block_bytes))
            return 0;
        src = ((char*)src) + block_bytes;
        --marker_blocks;
    }
    return 1;
}
    
// -1 if not found, offset otherwise
ssize_t find_marker_v2(const void* src, size_t len) {
    size_t i = len & ~(size_t)63;
    const uint32_t* p = src;
    p += i / 4;
    while (i > 0) {
        i -= 64;
        p -= 16;
        if (*p == SIG && ((const uint16_t*)p)[3] == 0) {
            const int block_log2 = ((const uint16_t*)p)[2];
            if (block_log2 < 30) {
                const size_t block_bytes = 1 << block_log2;
                if (i + block_bytes <= len &&
                    verify_marker_block_hash(p, block_bytes))
                    return i;
            }
        }
        else if (*p == SIGR && ((const uint16_t*)p)[3] == 0) {
            const int block_log2 = bswap_16(((const uint16_t*)p)[2]);
            if (block_log2 < 30) {
                const size_t block_bytes = 1 << block_log2;
                if (i + block_bytes <= len &&
                    verify_marker_block_hash(p, block_bytes))
                    return i;
            }
        }
    }
    return -1;
}

// returns 0 if successful
int verify_v2(int in, void* _marker) {
    uint16_t* m16 = (uint16_t*)_marker;
    uint32_t* m32 = (uint32_t*)_marker;
    uint64_t* m64 = (uint64_t*)_marker;

    const int need_bswap = m32[0] == SIGR;
    if (need_bswap)
        printf("marker needs to be byte-swapped\n");

    const int block_log2 = need_bswap ? bswap_16(m16[2]) : m16[2];
    const uint64_t block_bytes = 1 << block_log2;

    if (block_bytes < 64 || (block_bytes & (block_bytes-1))) {
        printf("INVALID BLOCK SIZE (%ld)\n",block_bytes);
        return 1;
    }

    const uint64_t date_time = need_bswap ? bswap_64(m64[1]) : m64[1];
    const time_t dt = date_time / (1000*1000*1000);
    printf("created:     %s", ctime(&dt));

    printf("block size:  %ld bytes\n", block_bytes);
    
    const unsigned num_stripes   = need_bswap ? bswap_32(m32[4]) : m32[4];
    const unsigned first_blocks  = need_bswap ? bswap_32(m32[5]) : m32[5];
    const unsigned stripe_blocks = need_bswap ? bswap_32(m32[6]) : m32[6];
    const unsigned image_blocks  = need_bswap ? bswap_32(m32[7]) : m32[7];

    const uint64_t image_bytes = image_blocks * block_bytes;
    const int64_t first_bytes  = first_blocks * block_bytes;
    const int64_t stripe_bytes = stripe_blocks * block_bytes;
    
    printf("num stripes: %d\n", num_stripes);
    printf("stripe size: %d blocks (%ld kiB)\n",
           stripe_blocks, stripe_bytes/1024);
    printf("image size:  %d blocks (%ld kiB)\n",
           image_blocks, image_bytes/1024);

    if (first_blocks > stripe_blocks) {
        printf("INVALID FIRST STRIPE (%d)\n",first_blocks);
        return 1;
    }
    if (stripe_blocks > image_blocks) {
        printf("INVALID STRIPE SIZE (%d)\n",stripe_blocks);
        return 1;
    }
    if (image_blocks != first_blocks + stripe_blocks*(num_stripes-1)) {
        printf("INVALID NUMBER OF STRIPES (%d)\n",num_stripes);
        return 1;
    }

    // stripe hashes per marker block
    const unsigned m0_lim = block_bytes / sizeof(uint64_t) - 6;
    const unsigned mi_lim = block_bytes / sizeof(uint64_t) - 2;

    unsigned marker_blocks = 0;
    while (num_stripes > m0_lim + marker_blocks * mi_lim)
        ++marker_blocks;
    ++marker_blocks;
    printf("marker size: %d blocks\n", marker_blocks);
    const int64_t marker_bytes  = marker_blocks * block_bytes;
    void* marker = malloc(marker_bytes);

    unsigned hash_lim = m0_lim;
    const uint64_t* stripe_hash = ((uint64_t*)marker) + 5;

    // verify markers
    printf("checking marker #1...");
    if (lseek(in,(image_blocks+marker_blocks+stripe_blocks)*block_bytes,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(in,marker,marker_bytes) != marker_bytes) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (memcmp(marker,m32,block_bytes) != 0 ||
        !verify_marker_hash(marker,block_bytes,marker_blocks)) {
        printf(" CORRUPT.\n");
        return 1;
    }
    printf(" good.\n");

    uint8_t* stripe =
        malloc(stripe_bytes > marker_bytes ? stripe_bytes : marker_bytes);

    printf("checking marker #2...");
    if (lseek(in,image_blocks*block_bytes,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(in,stripe,marker_bytes) != marker_bytes) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (memcmp(stripe,marker,marker_bytes) != 0) {
        printf(" CORRUPT.\n");
        return 1;
    }
    printf(" good.\n");

    uint8_t* parity = malloc(stripe_bytes);

    // read parity
    printf("reading parity...");
    fflush(stdout);
    if (lseek(in,(image_blocks+marker_blocks)*block_bytes,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(in,parity,stripe_bytes) != stripe_bytes) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (!verify_stripe_hash(parity,stripe_bytes,m16,num_stripes,m64+4)) {
        printf(" CORRUPT.\n");
        return 1;
    }
    printf(" done.\n");

    // read stripes
    if (lseek(in,0,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    printf("reading first stripe... \r");
    fflush(stdout);
    if (read(in,stripe,first_bytes) != first_bytes) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (!verify_stripe_hash(stripe,first_bytes,m16,0,stripe_hash++)) {
        printf("first stripe CORRUPT.   \n");
        return 1;
    }
    memxor(parity+stripe_bytes-first_bytes,stripe,first_bytes);
    --hash_lim;

    unsigned i;
    for (i = 1; i < num_stripes; ++i) {
        printf("reading stripe #%d...    \r",i+1);
        fflush(stdout);
        if (read(in,stripe,stripe_bytes) != stripe_bytes) {
            fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
            return 1;
        }
        if (!verify_stripe_hash(stripe,stripe_bytes,m16,i,stripe_hash++)) {
            printf("stripe #%d CORRUPT.   \n",i+1);
            return 1;
        }
        if (--hash_lim == 0) {
            hash_lim = mi_lim;
            stripe_hash += 2;
        }
        memxor(parity,stripe,stripe_bytes);
    }
    printf("reading done.             \n");
    free(marker);
    free(stripe);

    // parity should be all zero
    size_t parity_errors = 0;
    for (i = 0; i < stripe_bytes; ++i)
        if (parity[i])
            ++parity_errors;
    if (!parity_errors)
        printf("valid parity.\n");
    else
        printf("INVALID PARITY (%ld errors)\n",parity_errors);
    free(parity);

    return parity_errors > 0;
}

