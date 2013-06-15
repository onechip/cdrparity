
/* Copyright 2013 Chris Studholme.

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

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "Marker.h"


#define MB (1024*1024)


struct auto_file_descriptor {
    const int fd;
    explicit auto_file_descriptor(int fd) : fd(fd) {}
    ~auto_file_descriptor() {
        if (fd != -1) close(fd);
    }
    inline operator int() const {
        return fd;
    }
};

template <typename T>
struct unique_array {
    typedef T value_type;
    value_type* arr;
    explicit unique_array(value_type* arr) : arr(arr) {}
    ~unique_array() { delete[] arr; }
    value_type* get() { return arr; }
    const value_type* get() const { return arr; }
    value_type& operator[](unsigned i) { return arr[i]; }
    const value_type& operator[](unsigned i) const { return arr[i]; }

private:
    unique_array(const unique_array&);
    unique_array& operator=(const unique_array&);
};

static bool read_and_xor(void* _stripe, 
                         size_t stripesize, ssize_t block_size, 
                         int fd) {
    unsigned long* stripe = (unsigned long*)_stripe;
    const size_t long_per_block = block_size / sizeof(unsigned long);
    unsigned long buf[long_per_block];
    while (stripesize > 0) {
        // read block
        if (read(fd,buf,block_size) != block_size)
            return false;
        // xor with stripe
        for (size_t j = 0; j < long_per_block; ++j)
            *stripe++ ^= buf[j];
        --stripesize;
    }
    return true;
}

static off64_t parse_size(const char* s) {
    char* end;
    off64_t result = strtol(s,&end,10);
    if (strcasecmp(end,"k") == 0) {
        result *= 1024;
    }
    else if (strcasecmp(end,"m") == 0) {
        result *= 1024*1024;
    }
    else if (end[0]) {
        // invalid suffix, should do something?
    }
    return result;
}

static bool check_for_marker(Marker& m, ssize_t block_size, int fd) {
    // check for existing parity
    if (lseek64(fd,-block_size,SEEK_END) < 0) {
        std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    char buf[block_size];
    if (read(fd,buf,block_size) != block_size) {
        std::cerr << "cdrparity: read failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    bool found = false;
    for (size_t i = 0; i <= block_size - sizeof(Marker); ++i) {
        if (memcmp(buf+i,&Marker::SIG1,sizeof(Marker::SIG1)) == 0 ||
            memcmp(buf+i,&Marker::SIG1R,sizeof(Marker::SIG1R)) == 0) {
            memcpy(&m,buf+i,sizeof(Marker));
            if (m.is_valid()) {
                m.fix_endian();
                found = true;
                break;
            }
        }
    }
    if (lseek(fd,0,SEEK_SET) != 0)
        std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                  << std::endl;
    return found;
}

static bool process_file(const char* isofile,
                         off64_t cdr_size,
                         off_t block_size,
                         off_t buffer_size,
                         bool force,
                         bool strip,
                         bool pad) {

    // stat image file
    struct stat64 s;
    if (stat64(isofile,&s) != 0) {
        std::cerr << "cdrparity: stat failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    
    // open image file
    const auto_file_descriptor fd(open(isofile,O_RDWR|O_LARGEFILE));
    if (fd == -1) {
        std::cerr << "cdrparity: open failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    
    // compute image size (in blocks) and pad if necessary
    off_t imagesize = s.st_size / block_size;
    if (s.st_size != imagesize * block_size) {
        if (!pad) {
            std::cerr << "cdrparity: image is not a multiple of block size"
                      << std::endl;
            return false;
        }
        if (lseek(fd,0,SEEK_END) < 0) {
            std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        const ssize_t pad_needed = ++imagesize * block_size - s.st_size;
        const std::vector<unsigned char> zero_buf(pad_needed,0);
        std::cout << "note: padding image file" << std::endl;
        if (write(fd,zero_buf.data(),zero_buf.size()) != pad_needed) {
            std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        if (lseek(fd,0,SEEK_SET) != 0) {
            std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
    }
    if (imagesize < 1) {
        std::cerr << "cdrparity: file is empty" << std::endl;
        return false;
    }
    std::cout << "note: image file has " << imagesize << " blocks" << std::endl;

    // check for existing parity
    Marker old;
    if (check_for_marker(old,block_size,fd)) {
        std::cout << "note: parity data found in file" << std::endl;
        if (strip) {
            std::cerr << "cdrparity: strip not implemented" << std::endl;
            return false;
        }
        else if (!force) {
            std::cerr << "cdrparity: not adding additional parity data"
                      << std::endl;
            return false;
        }
        else
            std::cout << "note: forcing additional parity data" << std::endl;
    }
    
    // guess disk size if unknown
    off_t disksize = cdr_size / block_size;
    if (disksize == 0) {
        // guess disksize
        if (imagesize <= 649*MB/block_size)
            disksize = 650*MB/block_size;
        else if (imagesize <= 699*MB/block_size)
            disksize = 700*MB/block_size;
        else {
            std::cerr << "cdrparity: large image, must specify final size"
                      << std::endl;
            return false;
        }
        std::cout << "note: final size is assumed to be "
                  << (disksize*block_size/MB) << " MB ("
                  << disksize << " blocks)" << std::endl;
    }

    // compute stripe size
    ssize_t stripesize = disksize - imagesize - 2;
    if (stripesize < 1) {
        std::cerr << "cdrparity: final size is too small for image"
                  << std::endl;
        return false;
    }
    if (stripesize > imagesize)
        stripesize = imagesize;
    const int nstripes = (imagesize+stripesize-1) / stripesize;
    const ssize_t laststripesize = imagesize - stripesize*(nstripes-1);
    const ssize_t stripeoffset = stripesize - laststripesize;
    
    if (nstripes > 1)
        std::cout << "note: dividing image into " << nstripes << " stripes of "
                  << stripesize << " blocks each" << std::endl
                  << "\tlast stripe has " << laststripesize << " blocks"
                  << std::endl
                  << "\tparity offset by " << stripeoffset << " blocks"
                  << std::endl;
    else
        std::cout << "note: image is 1 stripe of "
                  << stripesize << " blocks" << std::endl;
    
    // allocate stripe
    unique_array<unsigned char> stripe(
        new unsigned char[stripesize*block_size]);
    if (stripe.get() == NULL) {
        std::cerr << "cdrparity: failed to allocate needed memory"
                  << std::endl;
        return false;
    }

    // read first stripe
    std::cout << "reading stripe #1...\r" << std::flush;
    if (read(fd,stripe.get(),stripesize*block_size) != stripesize*block_size) {
        std::cerr << std::endl
                  << "cdrparity: read failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }

    // read each additional stripe and xor with stripe
    for (int i = 1; i < nstripes-1; ++i) {
        std::cout << "reading stripe #" << (i+1) << "... \r" << std::flush;
        if (!read_and_xor(stripe.get(),stripesize,block_size,fd)) {
            std::cerr << std::endl
                      << "cdrparity: read failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
    }

    // read last stripe (it may be short)
    if (nstripes > 1) {
        std::cout << "reading last stripe...     \r" << std::flush;
        if (!read_and_xor(stripe.get(),laststripesize,block_size,fd)) {
            std::cerr << std::endl
                      << "cdrparity: read failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
    }
    std::cout << "image successfully read and parity calculated"
              << std::endl;
    
    // prepare marker
    Marker marker;
    marker.blocksize = block_size;
    marker.imagesize = imagesize;
    marker.stripesize = stripesize;
    marker.nstripes = nstripes;
    marker.stripeoffset = stripeoffset;
    marker.set_checksum();

    // prepare marker block
    assert(block_size % sizeof(marker) == 0);
    const std::vector<Marker> marker_block(block_size/sizeof(marker),marker);

    // write marker
    std::cout << "writing marker..." << std::endl;
    if (write(fd,marker_block.data(),block_size) != block_size) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }

    // write stripe
    std::cout << "writing parity data..." << std::endl;
    const ssize_t main_size = (stripesize-stripeoffset)*block_size;
    if (stripeoffset > 0) {
        // write tail of stripe first
        if (write(fd,
                  &stripe[main_size],
                  stripeoffset*block_size) != stripeoffset*block_size) {
            std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
    }
    if (write(fd,stripe.get(),main_size) != main_size) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
  
    // write marker
    std::cout << "writing marker..." << std::endl;
    if (write(fd,marker_block.data(),block_size) != block_size) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
  
    std::cout << "done." << std::endl;
    return true;
}

static void usage(std::ostream& out) {
    out << "Usage:" << std::endl
        << "  cdrparity [OPTIONS] iso_image ..." << std::endl
        << "    -s size\tset final size (default: 650M or 700M)" << std::endl
        << "    -b size\tset block size (default: 2k)" << std::endl
        << "    -B size\tmemory use (default: 16M)" << std::endl
        << "    -p  \tpad to block size" << std::endl
        << "    -f  \tforce adding extra parity" << std::endl
        << "    -S  \tstrip existing parity before starting" << std::endl;
}


int main(int argc, char*argv[]) {
    ++argv; --argc;
    if (argc < 1) {
        usage(std::cout);
        return -1;
    }

    off64_t cdr_size = 0;
    off_t block_size = 2048;
    off_t buffer_size = 16*MB;
    bool force = false;
    bool strip = false;
    bool pad = false;
  
    // parse options
    while (argc > 0 && argv[0][0] == '-') {
        if (!argv[0][1] || argv[0][2]) {
            std::cerr << "cdrparity: invalid argument: " << argv[0]
                      << std::endl;
            return -1;
        }
        switch (argv[0][1]) {
        case '-':
            --argc; ++argv;
            break;

        case 's':
            if (argc < 2) {
                std::cerr << "cdrparity: argument missing value: " << argv[0]
                          << std::endl;
                return -1;
            }
            cdr_size = parse_size(argv[1]);
            --argc; ++argv;
            break;

        case 'b':
            if (argc < 2) {
                std::cerr << "cdrparity: argument missing value: " << argv[0]
                          << std::endl;
                return -1;
            }
            block_size = parse_size(argv[1]);
            --argc; ++argv;
            break;

        case 'B':
            if (argc < 2) {
                std::cerr << "cdrparity: argument missing value: " << argv[0]
                          << std::endl;
                return -1;
            }
            buffer_size = parse_size(argv[1]);
            --argc; ++argv;
            std::cout << "note: custom buffer size ignored (not implemented)"
                      << std::endl;
            break;

        case 'f':
            force = true;
            break;

        case 'p':
            pad = true;
            break;

        case 'S':
            strip = true;
            break;

        default:
            std::cerr << "cdrparity: invalid argument: " << argv[0]
                      << std::endl;
            return -1;
        }
        --argc; ++argv;
    }

    if (argc <= 0) {
        std::cerr << "cdrparity: no files to process" << std::endl;
        return -1;
    }

    // check block_size
    if (block_size < (int)sizeof(Marker)) {
        std::cerr << "cdrparity: block size too small: " << block_size
                  << std::endl;
        return -1;
    }
    if (block_size & (block_size-1)) {
        std::cerr << "cdrparity: block size must be a power of two: "
                  << block_size << std::endl;
        return -1;
    }

    // check buffer_size
    if (buffer_size < block_size) {
        std::cerr << "cdrparity: buffer size too small: " << buffer_size
                  << std::endl;
        return -1;
    }
    buffer_size = (buffer_size/block_size) * block_size;

    // check cdr_size
    if (cdr_size < 0) {
        std::cerr << "cdrparity: final size must be positive: " << cdr_size
                  << std::endl;
        return -1;
    }
    if (cdr_size % block_size) {
        std::cerr << "cdrparity: final size must be a multiple of the block size: "
                  << cdr_size << std::endl;
        return -1;
    }
  
    while (argc >= 1) {
        std::cout << std::endl
                  << "processing file: " << argv[0] << std::endl;
        if (!process_file(argv[0],
                          cdr_size, block_size, buffer_size,
                          force, strip, pad))
            return 1;
        --argc; ++argv;
    }
    
    return 0;
}
