
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cdrverify.h"

#define BUF_SIZE (1024*1024)

#define MARKER_INTS (8)
#define MARKER_BYTES (MARKER_INTS*(int)sizeof(uint64_t))

#define SIG1 0xc56a5d888149eee7ULL
#define SIG2 0x4139ef05dda34f80ULL
#define SIG1R 0xe7ee4981885d6ac5ULL
#define SIG2R 0x804fa3dd05ef3941ULL

/* Marker format:
 *   uint64_t signature1;
 *   uint64_t signature2;
 *   uint64_t blocksize;    // bytes
 *   uint64_t imagesize;    // blocks
 *   uint64_t stripesize;   // blocks
 *   uint64_t nstripes;
 *   uint64_t stripeoffset; // blocks
 *   uint64_t checksum;
 */

static inline uint64_t checksum_marker(const uint64_t* src) {
    return src[0] ^ src[1] ^ src[2] ^ src[3] ^ src[4] ^ src[5] ^ src[6];
}

static inline uint64_t bswap_marker(uint64_t x, uint64_t sig1) {
    if (sig1 == SIG1R) 
        return bswap_64(x);
    else {
        assert(sig1 == SIG1);
        return x;
    }
}

static void fill_marker(void* dest, const void* src, size_t n) {
    assert(n >= MARKER_BYTES && ((n&(n-1))==0));
    while (n > 0) {
        memcpy(dest,src,MARKER_BYTES);
        dest = MARKER_BYTES + (unsigned char*)dest;
        n -= MARKER_BYTES;
    }
}

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

static int read_and_xor(void* dest, int in, ssize_t n) {
    unsigned char* buf = malloc(BUF_SIZE);
    while (n > 0) {
        ssize_t n_buf;
        if (n < BUF_SIZE)
            n_buf = n;
        else
            n_buf = BUF_SIZE;
        if (read(in,buf,n_buf) != n_buf) {
            fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
            free(buf);
            return 1;
        }
        memxor(dest,buf,n_buf);
        dest = n_buf + (unsigned char*)dest;
        n -= n_buf;
    }
    free(buf);
    return 0;
}

// -1 if not found, offset otherwise
ssize_t find_marker_v1(const void* src, size_t len) {
    size_t i = len & ~(size_t)(MARKER_BYTES-1);
    const uint64_t* p = src;
    p += i / sizeof(uint64_t);
    while (i > 0) {
        i -= MARKER_BYTES;
        p -= MARKER_INTS;
        if (((p[0] == SIG1  && p[1] == SIG2) ||
             (p[0] == SIG1R && p[1] == SIG2R)) &&
            p[7] == checksum_marker(p))
            return i;
    }
    return -1;
}

int verify_v1(int in, size_t ofs, void* buf_small, size_t buf_size) {

    size_t i;
    size_t parity_errors;
    uint64_t* marker;

    marker = (uint64_t*)(((char*)buf_small) + ofs);
    if (marker[0] == SIG1R)
        printf("marker needs to be byte-swapped\n");

    const int64_t blocksize = bswap_marker(marker[2],marker[0]);     // bytes
    const uint64_t imagesize = bswap_marker(marker[3],marker[0]);    // blocks
    const uint64_t stripesize = bswap_marker(marker[4],marker[0]);   // blocks
    const uint64_t nstripes = bswap_marker(marker[5],marker[0]);
    const uint64_t stripeoffset = bswap_marker(marker[6],marker[0]); // blocks

    const uint64_t imagebytes = imagesize * blocksize;
    const uint64_t stripebytes = stripesize * blocksize;
    const int64_t mainbytes = (stripesize - stripeoffset) * blocksize;
    const int64_t offsetbytes = stripeoffset * blocksize;

    if (blocksize < MARKER_BYTES || (blocksize & (blocksize-1))) {
        printf("INVALID BLOCK SIZE (%ld)\n",blocksize);
        return 1;
    }
    printf("block size:  %ld bytes\n", blocksize);
    printf("image size:  %ld blocks (%ld kiB)\n", imagesize, imagebytes/1024);
    if (stripesize > imagesize) {
        printf("INVALID STRIPE SIZE (%ld)\n",stripesize);
        return 1;
    }
    printf("stripe size: %ld blocks (%ld kiB)\n", stripesize, stripebytes/1024);
    if (nstripes != (imagesize + stripesize - 1) / stripesize) {
        printf("INVALID NUMBER OF STRIPES (%ld)\n",nstripes);
        return 1;
    }
    printf("num stripes: %ld\n", nstripes);
    if (stripeoffset >= stripesize) {
        printf("INVALID STRIPE OFFSET (%ld)\n",stripeoffset);
        return 1;
    }

    // construct full marker block to verify both markers on disc
    uint64_t* full_marker = malloc(blocksize);
    fill_marker(full_marker,marker,blocksize);
    marker = 0;

    unsigned char* buf_large = malloc(stripebytes);

    // verify markers
    printf("checking marker #1...");
    if (lseek(in,(imagesize+1+stripesize)*blocksize,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(in,buf_large,blocksize) != blocksize) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (memcmp(full_marker,buf_large,blocksize) != 0) {
        printf(" CORRUPT.\n");
        return 1;
    }
    printf(" good.\n");
    printf("checking marker #2...");
    if (lseek(in,imagesize*blocksize,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (read(in,buf_large,blocksize) != blocksize) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (memcmp(full_marker,buf_large,blocksize) != 0) {
        printf(" CORRUPT.\n");
        return 1;
    }
    printf(" good.\n");
    free(full_marker);

    // read parity
    printf("reading parity...");
    fflush(stdout);
    if (lseek(in,(imagesize+1)*blocksize,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    if (stripeoffset > 0) {
        if (read(in,buf_large+mainbytes,offsetbytes) != offsetbytes) {
            fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
            return 1;
        }
    }
    if (read(in,buf_large,mainbytes) != mainbytes) {
        fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
        return 1;
    }
    printf(" done.\n");

    // read stripes
    if (lseek(in,0,SEEK_SET) == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }
    for (i = 1; i < nstripes; ++i) {
        printf("reading stripe #%ld...\r",i);
        fflush(stdout);
        if (read_and_xor(buf_large,in,stripebytes) != 0)
            return 1;
    }
    printf("reading last stripe...    \r");
    fflush(stdout);
    if (read_and_xor(buf_large,in,imagebytes - (nstripes-1)*stripebytes) != 0)
        return 1;
    printf("reading done.             \n");

    // parity should be all zero
    parity_errors = 0;
    for (i = 0; i < stripebytes; ++i)
        if (buf_large[i])
            ++parity_errors;
    if (!parity_errors)
        printf("valid parity.\n");
    else
        printf("INVALID PARITY (%ld errors)\n",parity_errors);
    
    free(buf_large);
    return parity_errors > 0;
}

