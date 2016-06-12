
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
    
// -1 if not found, offset otherwise
static ssize_t find_marker_v2(const void* src, size_t len) {
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

static int repair_stripe(int fd, off_t ofs, uint8_t* buf,
                         const uint8_t* diff, int64_t stripe_bytes,
                         void* marker, unsigned index,
                         const void* expected_hash) {

    if (lseek(fd,ofs,SEEK_SET) != ofs) {
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 0;
    }

    printf("re-reading corrupt stripe #%d...", index+1);
    fflush(stdout);
    memset(buf, 0, stripe_bytes);
    if (read(fd,buf,stripe_bytes) < 0) {
        printf(" failed!\n");
        fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
        return 0;
    }
    printf(" done.\n");

    printf("applying correction...");
    memxor(buf, diff, stripe_bytes);
    if (!verify_stripe_hash(buf, stripe_bytes, marker, index, expected_hash)) {
        printf(" repair failed!\n");
        return 0;
    }
    printf(" success.\n");

    if (lseek(fd,ofs,SEEK_SET) != ofs) {
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 0;
    }

    printf("writing stripe #%d...", index+1);
    if (write(fd,buf,stripe_bytes) != stripe_bytes) {
        printf(" failed!\n");
        fprintf(stderr,"cdrrepair: write() failed (%s)\n",strerror(errno));
        return 0;
    }
    printf(" done.\n");

    return 1;
}

// returns 0 if successful
static int repair_v2(int fd, void* _marker) {
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
    const int64_t offset_bytes = stripe_bytes - first_bytes;
    
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
    uint8_t* marker = malloc(marker_bytes);

    unsigned hash_lim = m0_lim;
    const uint64_t* stripe_hash = ((uint64_t*)marker) + 5;

    uint8_t* stripe =
        malloc(stripe_bytes > marker_bytes ? stripe_bytes : marker_bytes);

    // read markers
    printf("reading markers...");
    const off_t marker1_offset = image_blocks*block_bytes;
    if (lseek(fd,marker1_offset,SEEK_SET) != marker1_offset) {
        printf(" failed!\n");
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(fd,marker,marker_bytes) != marker_bytes) {
        printf(" failed!\n");
        fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    const off_t marker2_offset =
        (image_blocks+marker_blocks+stripe_blocks)*block_bytes;
    memset(stripe, 0, marker_bytes);
    if (lseek(fd,marker2_offset,SEEK_SET) != marker2_offset)
        printf(" missing!\n");
    else if (read(fd,stripe,marker_bytes) != marker_bytes)
        printf(" truncated!\n");
    else
        printf(" done.\n");

    unsigned i;
    int* marker_good = malloc(marker_blocks * sizeof(int));
    for (i = 0; i < marker_blocks; ++i) {
        ssize_t ofs = i*block_bytes;
        marker_good[i] =
            verify_marker_block_hash(marker+ofs, block_bytes);
        marker_good[i] |=
            verify_marker_block_hash(stripe+ofs, block_bytes) << 1;

        switch (marker_good[i]) {
        case 0:
            fprintf(stderr,"marker block %d CORRUPT! repair failed!\n", i);
            return 1;
            
        case 1:
            printf("marker #2 block %d CORRUPT!\n", i);
            break;

        case 2:
            printf("marker #1 block %d CORRUPT!\n", i);
            memcpy(marker+ofs, stripe+ofs, block_bytes);
            break;

        case 3:
            if (memcmp(marker+ofs, stripe+ofs, block_bytes) != 0) {
                fprintf(stderr,"marker block %d mismatch! repair failed!\n", i);
                return 1;
            }
        }
    }
    if (memcmp(m16, marker, block_bytes) != 0) {
        fprintf(stderr,"marker block 0 mismatch! repair failed!\n");
        return 1;
    }

    uint8_t* parity = malloc(stripe_bytes);

    const off_t parity_offset = (image_blocks+marker_blocks)*block_bytes;
    if (lseek(fd,parity_offset,SEEK_SET) != parity_offset) {
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }

    // read parity
    printf("reading parity...");
    fflush(stdout);
    memset(parity, 0, stripe_bytes);
    if (read(fd,parity,stripe_bytes) < 0) {
        printf(" failed!\n");
        fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    const int parity_good =
        verify_stripe_hash(parity,stripe_bytes,m16,num_stripes,m64+4);
    if (parity_good)
        printf(" done.\n");
    else
        printf(" CORRUPT!\n");

    int* stripe_good = malloc(num_stripes * sizeof(int));
    int bad_count = !parity_good;

    if (lseek(fd,0,SEEK_SET) != 0) {
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }

    // read stripes
    printf("reading first stripe... \r");
    if (read(fd,stripe,first_bytes) != first_bytes) {
        fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    stripe_good[0] =
        verify_stripe_hash(stripe,first_bytes,m16,0,stripe_hash++);
    --hash_lim;
    if (!stripe_good[0]) {
        printf("stripe #1 CORRUPT!       \n");
        ++bad_count;
    }
    memxor(parity+offset_bytes,stripe,first_bytes);

    for (i = 1; i < num_stripes; ++i) {
        printf("reading stripe #%d...    \r",i+1);
        fflush(stdout);
        if (read(fd,stripe,stripe_bytes) != stripe_bytes) {
            fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
            return 1;
        }
        stripe_good[i] =
            verify_stripe_hash(stripe,stripe_bytes,m16,i,stripe_hash++);
        if (--hash_lim == 0) {
            hash_lim = mi_lim;
            stripe_hash += 2;
        }
        if (!stripe_good[i]) {
            printf("stripe #%d CORRUPT!   \n",i+1);
            ++bad_count;
        }
        memxor(parity,stripe,stripe_bytes);
    }
    printf("reading stripes done.       \n");

    int changes_made = 0;
    
    if (bad_count == 0) {
        // parity should be all zero
        ssize_t j;
        for (j = 0; j < stripe_bytes; ++j)
            if (parity[j]) {
                fprintf(stderr,"cannot determine location of error! repair failed!");
                return 1;
            }
    }

    else if (bad_count == 1) {
        // parity must not be all zero
        ssize_t j;
        for (j = 0; j < stripe_bytes; ++j)
            if (parity[j]) break;
        if (j >= stripe_bytes) {
            fprintf(stderr,"cannot determine location of error! repair failed!");
            return 1;
        }

        if (!parity_good) {
            if (!repair_stripe(fd, parity_offset,
                               stripe, parity, stripe_bytes,
                               m16, num_stripes, m64+4))
                return 1;
        }

        else if (!stripe_good[0]) {
            if (j < offset_bytes) {
                fprintf(stderr,"cannot determine location of error! repair failed!");
                return 1;
            }
            if (!repair_stripe(fd, 0, stripe,
                               parity+offset_bytes, first_bytes,
                               m16, 0, m64+5))
                return 1;
        }

        else {
            for (i = 1; i < num_stripes; ++i)
                if (!stripe_good[i]) {
                    stripe_hash = ((uint64_t*)marker) + 5 + i;
                    for (hash_lim = m0_lim; i >= hash_lim; hash_lim += mi_lim)
                        stripe_hash += 2;
                    if (!repair_stripe(fd, first_bytes + (i-1)*stripe_bytes,
                                       stripe, parity, stripe_bytes,
                                       m16, i, stripe_hash))
                        return 1;
                    else
                        break;
                }
            if (i >= num_stripes) {
                fprintf(stderr,"UNKNOWN FAILURE!\n");
                return 1;
            }
        }
        changes_made = 1;
    }

    else {
        fprintf(stderr,"too many errors! repair failed!\n");
        return 1;
    }

    // fix marker
    for (i = 0; i < marker_blocks; ++i) {
        if (marker_good[i] != 3) {
            off_t ofs;
            switch (marker_good[i]) {
            case 1:
                printf("writing marker #2 block %d...", i);
                ofs = marker2_offset;
                break;
            case 2:
                printf("writing marker #1 block %d...", i);
                ofs = marker1_offset;
                break;
            default:
                fprintf(stderr,"UNKNOWN FAILURE!\n");
                return 1;
            }
            ofs += i * block_bytes;

            if (lseek(fd,ofs,SEEK_SET) != ofs) {
                printf(" failed!\n");
                fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
                return 1;
            }
            
            if (write(fd,marker+i*block_bytes,block_bytes) != (ssize_t)block_bytes) {
                printf(" failed!\n");
                fprintf(stderr,"cdrrepair: write() failed (%s)\n",strerror(errno));
                return 1;
            }
            printf(" done.\n");
            changes_made = 1;
        }
    }

    if (!changes_made)
        fprintf(stdout,"no changes made.\n");
    
    free(parity);
    free(stripe);
    free(stripe_good);
    free(marker);
    free(marker_good);
        
    return 0;
}



int main(int argc, char*argv[]) {

    if (argc <= 1) {
        printf("Usage:\n  cdrrepair file\n");
        return 1;
    }

    // open cdrom device
    const int fd = open(argv[1],O_RDWR);
    if (fd == -1) {
        fprintf(stderr,"cdrrepair: failed to open file %s\n",argv[1]);
        return 1;
    }

    // figure out size of image on media
    const off_t file_size = lseek(fd,0,SEEK_END);
    if (file_size == (off_t)-1) {
        fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }

    static const ssize_t buf_size = 1024*1024;
    off_t nio = (file_size+buf_size-1) / buf_size;
    uint8_t* buf = malloc(buf_size);
    
    ssize_t ofs = -1;

    // scan for marker
    printf("scanning for marker...");
    fflush(stdout);
    while (nio > 0) {
        --nio;
        if (lseek(fd,nio*buf_size,SEEK_SET) == (off_t)-1) {
            fprintf(stderr,"cdrrepair: lseek() failed (%s)\n",strerror(errno));
            return 1;
        }
        ssize_t len;
        if ((len = read(fd,buf,buf_size)) <= 0) {
            fprintf(stderr,"cdrrepair: read() failed (%s)\n",strerror(errno));
            return 1;
        }
        assert(len <= buf_size);
        ofs = find_marker_v2(buf,len);
        if (ofs >= 0)
            break;
    }

    int r = 1;
    if (ofs >= 0) {
        printf(" found.\n");
        r = repair_v2(fd, buf + ofs);
    }
    else
        printf(" not found\n");

    free(buf);
    return r;
}

