
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cdrverify.h"

#define BUF_SIZE (1024*1024)
#define MAX_SCAN (16*1024*1024)

int main(int argc, char*argv[]) {

    int in;
    off_t device_size, nio, total_read;
    struct stat sbuf;
    unsigned char* buf_small;
    ssize_t marker_ofs;
    int marker_ver;

    if (argc <= 1) {
        printf("Usage:\n  cdrverify device\n");
        return 1;
    }

    // open cdrom device
    in = open(argv[1],O_RDONLY);
    if (in == -1) {
        fprintf(stderr,"cdrverify: failed to open device %s\n",argv[1]);
        return 1;
    }

    // figure out size of image on media
    device_size = lseek(in,0,SEEK_END);
    if (device_size == (off_t)-1) {
        fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
        return 1;
    }

    // stat for io size
    if (fstat(in,&sbuf) != 0) {
        fprintf(stderr,"cdrverify: fstat() failed (%s)\n",strerror(errno));
        return 1;
    }
    buf_small = malloc(sbuf.st_blksize);

    //printf("blksize = %ld\n",sbuf.st_blksize);
    //printf("device_size = %ld\n",device_size);

    // scan for marker (need to get at least 5380kiB back from end of device)
    nio = device_size / sbuf.st_blksize;
    marker_ver = 0;
    marker_ofs = 0;
    total_read = 0;
    printf("scanning for marker...");
    fflush(stdout);
    while (nio > 0 && total_read < MAX_SCAN) {
        --nio;
        if (lseek(in,nio*sbuf.st_blksize,SEEK_SET) == (off_t)-1) {
            fprintf(stderr,"cdrverify: lseek() failed (%s)\n",strerror(errno));
            return 1;
        }
        if (read(in,buf_small,sbuf.st_blksize) != sbuf.st_blksize) {
            fprintf(stderr,"cdrverify: read() failed (%s)\n",strerror(errno));
            return 1;
        }
        total_read += sbuf.st_blksize;
        marker_ofs = find_marker_v2(buf_small, sbuf.st_blksize);
        if (marker_ofs != -1) {
            marker_ver = 2;
            break;
        }
        marker_ofs = find_marker_v1(buf_small, sbuf.st_blksize);
        if (marker_ofs != -1) {
            marker_ver = 1;
            break;
        }
    }

    int r = 1;
    switch (marker_ver) {
    case 1:
        printf(" found v1.\n");
         r = verify_v1(in, marker_ofs, buf_small, sbuf.st_blksize);
        break;
    case 2:
        printf(" found v2.\n");
        r = verify_v2(in, marker_ofs, buf_small, sbuf.st_blksize);
        break;
    default:
        printf(" not found\n");
    }

    free(buf_small);
    return r;
}

