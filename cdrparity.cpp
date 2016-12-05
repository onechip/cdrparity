
/* Copyright 2016 Chris Studholme

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
#include <memory>
#include <vector>
#include <iostream>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "siphash24.h"


static constexpr auto MB = 1024*1024;

namespace {
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

    struct marker_zero {
        uint32_t signature;
        uint16_t block_log2;
        uint16_t index;

        uint64_t datetime;

        uint32_t num_stripes;
        uint32_t first_blocks;
        uint32_t stripe_blocks;
        uint32_t image_blocks;

        uint64_t parity_hash;
        uint64_t stripe_hashes[];
        //uint64_t checksum;
    };

    struct marker_one {
        uint32_t signature;
        uint16_t block_log2;
        uint16_t index;
        uint64_t stripe_hashes[];
        //uint64_t checksum;
    };

    static constexpr uint32_t SIG  = 0x972fae43u;
    static constexpr uint32_t SIGR = 0x43ae2f97u;
}

static unsigned ilog2(unsigned x) {
    unsigned r = 0;
    while (x >>= 1) ++r;
    return r;
}

template <typename T>
static void byteswap_in_place(T& x) {
    auto p = reinterpret_cast<unsigned char*>(&x);
    for (unsigned i = 0; i < sizeof(T)/2; ++i)
        std::swap(p[i],p[sizeof(T)-1-i]);
}

static bool check_for_marker(marker_zero& m, ssize_t block_size, int fd) {
    for (int i = 1; ; ) {
        if (lseek64(fd,-i*block_size,SEEK_END) < 0) {
            std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        if (read(fd,&m,block_size) != block_size) {
            std::cerr << "cdrparity: read failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        if (m.signature == SIGR) {
            byteswap_in_place(m.signature);
            byteswap_in_place(m.block_log2);
            byteswap_in_place(m.index);
            assert(m.signature == SIG);
        }
        if (m.signature == SIG) {
            if (block_size != (1<<m.block_log2))
                break;
            const int j = 1 + m.index;
            if (j == 1)
                return true;
            else if (i < j) {
                i = j;
                continue;
            }
        }
        break;
    }
    return false;
}

static bool read_and_xor(siphash_ctx& ctx,
                         void* _stripe, size_t stripe_blocks,
                         void* _block, ssize_t block_bytes, 
                         int fd) {
    assert(block_bytes > 0 &&
           size_t(block_bytes) >= sizeof(unsigned long) &&
           ((block_bytes-1)&block_bytes) == 0);
    auto buf = static_cast<unsigned long*>(_block);
    auto stripe = static_cast<unsigned long*>(_stripe);
    const auto long_per_block = block_bytes / sizeof(unsigned long);
    for ( ; stripe_blocks > 0; --stripe_blocks) {
        // read block
        if (read(fd,buf,block_bytes) != block_bytes)
            return false;
        siphash_update(&ctx, buf, block_bytes);
        // xor with stripe
        for (size_t j = 0; j < long_per_block; ++j, ++stripe)
            *stripe ^= buf[j];
    }
    return true;
}

static ssize_t write_large(int fd, const void *buf, size_t count) {
    ssize_t result = 0;
    while (count > 1024*1024*1024) {
        ssize_t r = write(fd, buf, 1024*1024*1024);
        if (r < 0) return r;
        result += r;
        if (r != 1024*1024*1024) return result;
        buf = ((const char*)buf) + 1024*1024*1024;
        count -= 1024*1024*1024;
    }
    ssize_t r = write(fd, buf, count);
    if (r < 0) return r;
    return result += r;
}

static bool process_file(const char* isofile,
                         int64_t cdr_bytes,
                         int block_bytes,
                         size_t,  //  buffer_bytes
                         bool force,
                         bool strip,
                         bool pad) {

    // buffer for single block
    assert(block_bytes >= 64 && ((block_bytes-1)&block_bytes) == 0);
    auto block =
        std::unique_ptr<unsigned char[]>(new unsigned char[block_bytes]);

    // stat image file
    struct stat64 s;
    static_assert(sizeof(s.st_size) > 4, "need 64-bit file size");
    if (stat64(isofile,&s) != 0) {
        std::cerr << "cdrparity: stat failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    
    // open image file
    const auto fd = auto_file_descriptor(open(isofile,O_RDWR|O_LARGEFILE));
    if (fd == -1) {
        std::cerr << "cdrparity: open failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    
    // compute image size (in blocks) and pad if necessary
    auto image_blocks = s.st_size / block_bytes;
    if (image_blocks < 0 || (image_blocks>>30) != 0) {
        std::cerr << "cdrparity: block size too small / too many blocks"
                  << std::endl;
        return false;
    }
    if (s.st_size != image_blocks * block_bytes) {
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
        const auto pad_bytes = ++image_blocks * block_bytes - s.st_size;
        assert(pad_bytes <= block_bytes);
        memset(block.get(),0,pad_bytes);
        std::cout << "note: padding image file" << std::endl;
        if (write(fd,block.get(),pad_bytes) != pad_bytes) {
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
    if (image_blocks <= 0) {
        std::cerr << "cdrparity: file is empty" << std::endl;
        return false;
    }
    std::cout << "note: image file has " << image_blocks << " blocks"
              << std::endl;
    
    // guess disk size if unknown
    int cdr_blocks = cdr_bytes / block_bytes;
    if (cdr_blocks == 0) {
        // guess cdr_blocks
        if (image_blocks <= 649*MB/block_bytes)
            cdr_blocks = 650*MB/block_bytes;
        else if (image_blocks <= 699*MB/block_bytes)
            cdr_blocks = 700*MB/block_bytes;
        else if (image_blocks <= int64_t(4481)*MB/block_bytes)
            cdr_blocks = int64_t(4482)*MB/block_bytes;
        else if (image_blocks <= int64_t(23599)*MB/block_bytes)
            cdr_blocks = int64_t(23600)*MB/block_bytes;
        else {
            std::cerr << "cdrparity: large image, must specify final size"
                      << std::endl;
            return false;
        }
        std::cout << "note: final size is assumed to be "
                  << (int64_t(cdr_blocks)*block_bytes/MB) << " MB ("
                  << cdr_blocks << " blocks)" << std::endl;
    }

    // check for existing parity
    marker_zero& old = *reinterpret_cast<marker_zero*>(block.get());
    if (check_for_marker(old,block_bytes,fd)) {
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
    if (lseek(fd,0,SEEK_SET) != 0) {
        std::cerr << "cdrparity: seek failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }

    // stripes per marker block
    const auto m0_lim = block_bytes / sizeof(uint64_t) - 6;
    const auto mi_lim = block_bytes / sizeof(uint64_t) - 2;
    
    // compute stripe and marker size
    int stripe_blocks;
    int num_stripes;
    int marker_blocks = 1;
    for (int lim = m0_lim; ; lim += mi_lim, ++marker_blocks) {
        stripe_blocks = cdr_blocks - image_blocks - 2*marker_blocks;
        if (stripe_blocks < 1) {
            std::cerr << "cdrparity: final size is too small for image"
                      << std::endl;
            return false;
        }
        if (stripe_blocks > image_blocks)
            stripe_blocks = image_blocks;
        num_stripes = (image_blocks+stripe_blocks-1) / stripe_blocks;
        if (num_stripes <= lim)
            break;
    }
    const ssize_t first_blocks = image_blocks - stripe_blocks*(num_stripes-1);
    const ssize_t first_offset = stripe_blocks - first_blocks;
        
    if (num_stripes > 1)
        std::cout << "note: dividing image into " << num_stripes
                  << " stripes of " << stripe_blocks
                  << " blocks each" << std::endl
                  << "\tfirst stripe has " << first_blocks
                  << " blocks (offset by " << first_offset << ")"
                  << std::endl
                  << "\tmarker has " << marker_blocks << " blocks"
                  << std::endl;
    else
        std::cout << "note: image is 1 stripe of "
                  << stripe_blocks << " blocks" << std::endl;

    // marker
    const ssize_t marker_bytes = marker_blocks * block_bytes;
    std::vector<uint64_t> marker(marker_bytes / sizeof(uint64_t));
    auto& m0 = *reinterpret_cast<marker_zero*>(marker.data());
    m0.signature = SIG;
    m0.block_log2 = ilog2(block_bytes);
    m0.index = 0;
    struct timeval tv;
    if (gettimeofday(&tv, nullptr) != 0) {
        std::cerr << std::endl
                  << "cdrparity: gettimeofday (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    m0.datetime = tv.tv_sec;
    m0.datetime = (m0.datetime*(1000*1000) + tv.tv_usec)*1000;

    m0.num_stripes = num_stripes;
    m0.first_blocks = first_blocks;
    m0.stripe_blocks = stripe_blocks;
    m0.image_blocks = image_blocks;

    auto hash_dest = marker.begin() + sizeof(marker_zero) / sizeof(uint64_t);
    auto hash_lim = m0_lim;

    // parity
    const auto stripe_bytes = ssize_t(stripe_blocks) * block_bytes;
    std::vector<unsigned char> parity(stripe_bytes, 0);

    // read first stripe (it may be short)
    {
        std::cout << "reading first stripe... \r" << std::flush;
        siphash_ctx ctx;
        siphash_init(&ctx,&m0);
        ++m0.index;
        if (!read_and_xor(ctx,
                          parity.data()+first_offset*block_bytes,first_blocks,
                          block.get(),block_bytes,fd)) {
            std::cerr << std::endl
                      << "cdrparity: read failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        siphash_final(&ctx,&*hash_dest++);
        --hash_lim;
    }

    // read remaining stripes, hash and xor
    for (int i = 1; i < num_stripes; ++i) {
        std::cout << "reading stripe #" << (i+1) << "...   \r" << std::flush;
        siphash_ctx ctx;
        siphash_init(&ctx,&m0);
        ++m0.index;
        if (!read_and_xor(ctx,parity.data(),stripe_blocks,
                          block.get(),block_bytes,fd)) {
            std::cerr << std::endl
                      << "cdrparity: read failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        siphash_final(&ctx,&*hash_dest++);
        if (--hash_lim == 0) {
            hash_lim = mi_lim;
            hash_dest += 2;
        }
    }
    std::cout << "image successfully read and parity calculated"
              << std::endl;

    // hash parity
    {
        siphash_ctx ctx;
        siphash_init(&ctx,&m0);
        siphash_update(&ctx,parity.data(),stripe_bytes);
        siphash_final(&ctx,&m0.parity_hash);
    }

    // hash marker
    m0.index = 0;
    for (int i = 1; i < marker_blocks; ++i) {
        auto& mi = *reinterpret_cast<marker_one*>(
            marker.data() + i * block_bytes / sizeof(uint64_t));
        mi.signature = m0.signature;
        mi.block_log2 = m0.block_log2;
        mi.index = i;
    }
    static const uint8_t zero_key[SIPHASH_KEY_LENGTH] = {0};
    for (int i = 0; i < marker_blocks; ++i) {
        auto begin = marker.data() + i * block_bytes / sizeof(uint64_t);
        siphash_ctx ctx;
        siphash_init(&ctx,zero_key);
        siphash_update(&ctx,begin,block_bytes-sizeof(uint64_t));
        auto end = begin + (block_bytes / sizeof(uint64_t) - 1);
        siphash_final(&ctx,end);
    }
    
    // write marker
    std::cout << "writing marker..." << std::endl;
    if (write(fd,&m0,marker_bytes) != marker_bytes) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }

    // write parity
    std::cout << "writing parity data..." << std::endl;
    if (write_large(fd,parity.data(),stripe_bytes) != stripe_bytes) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
  
    // write marker
    std::cout << "writing marker..." << std::endl;
    if (write(fd,&m0,marker_bytes) != marker_bytes) {
        std::cerr << "cdrparity: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
  
    std::cout << "done." << std::endl;
    return true;
}

static off64_t parse_size(const char* s) {
    char* end;
    off64_t result = strtol(s,&end,10);
    if (strcasecmp(end,"k") == 0)
        result *= 1024;
    else if (strcasecmp(end,"m") == 0)
        result *= 1024*1024;
    else if (end[0]) {
        // invalid suffix, should do something?
    }
    return result;
}

static void usage(std::ostream& out) {
    out << "Usage:" << std::endl
        << "  cdrparity [OPTIONS] iso_image ..." << std::endl
        << "    -s size\tset final size (default: 650M, 700M, 4482M or 23600M)" << std::endl
        << "    -b size\tset block size (default: 2k)" << std::endl
        << "    -B size\tmemory use (default: 64M)" << std::endl
        << "    -p  \tpad to block size" << std::endl
        << "    -f  \tforce adding extra parity" << std::endl
        << "    -S  \tstrip existing parity before starting" << std::endl;
}


/*** main ***/

int main(int argc, char*argv[]) {
    ++argv; --argc;
    if (argc < 1) {
        usage(std::cout);
        return -1;
    }

    off64_t cdr_size = 0;
    off_t block_size = 2048;
    off_t buffer_size = 64*MB;
    auto force = false;
    auto strip = false;
    auto pad = false;
  
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
    if (block_size < 64) {
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
    buffer_size = ((buffer_size+block_size-1)/block_size) * block_size;

    // check cdr_size
    if (cdr_size < 0) {
        std::cerr << "cdrparity: final size must be positive: " << cdr_size
                  << std::endl;
        return -1;
    }
    if (cdr_size % block_size) {
        std::cerr << "cdrparity: final size must be a multiple of block size: "
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
