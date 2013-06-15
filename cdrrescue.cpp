
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

class BitMap2d {
public:
    static const unsigned BITS_PER_LONG = sizeof(unsigned long)*8;

    const unsigned nrows;
    const unsigned ncols;
  
    BitMap2d(unsigned rows, unsigned cols) 
        : nrows(rows), 
          ncols(cols),
          per_row((ncols+BITS_PER_LONG-1) / BITS_PER_LONG),
          bits(nrows*per_row,0) {
    }

    bool test(unsigned int row, unsigned int col) const {
        return (bucket(row,col)>>(col%BITS_PER_LONG))&1;
    }
    
    void set(unsigned int row, unsigned int col) {
        bucket(row,col) |= 1ul<<(col%BITS_PER_LONG);
    }
    void reset(unsigned int row, unsigned int col) {
        bucket(row,col) &= ~(1ul<<(col%BITS_PER_LONG));
    }
    void flip(unsigned int row, unsigned int col) {
        bucket(row,col) ^= 1ul<<(col%BITS_PER_LONG);
    }
  
private:
    const unsigned per_row;
    std::vector<unsigned long> bits;

    inline unsigned long& bucket(unsigned row, unsigned col) {
        return bits[row*per_row + col/BITS_PER_LONG];
    }
    inline const unsigned long& bucket(unsigned row, unsigned col) const {
        return bits[row*per_row + col/BITS_PER_LONG];
    }
};


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


static bool seek_and_read(void* dest, int fd, off64_t pos, size_t n) {
    if (lseek64(fd,pos,SEEK_SET) != pos) {
        std::cerr << "cdrrescue: seek failed" << std::endl;
        return false;
    }
    if (read(fd,dest,n) != (ssize_t)n) {
        std::cerr << "cdrrescue: read failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    return true;
}

static bool seek_and_write(int fd, const void* src, off64_t pos, size_t n) {
    if (lseek64(fd,pos,SEEK_SET) != pos) {
        std::cerr << "cdrrescue: seek on output file failed" << std::endl;
        return false;
    }
    if (write(fd,src,n) != (ssize_t)n) {
        std::cerr << "cdrrescue: write failed (" << strerror(errno) << ")"
                  << std::endl;
        return false;
    }
    return true;
}


static bool find_marker(Marker& m, int fd) {
    static const int block_size = 2048;
    static const int look_back = 1024;
    char buf[block_size];

    bool found = false;
    for (int j = 1; j <= look_back && !found; ++j) {
        off64_t o = lseek64(fd,-j*block_size,SEEK_END);
        if (o == (off64_t)-1) {
            std::cerr << "cdrrescue: seek failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        //std::cerr << "cdrrescue: o=" << o << std::endl;
        if (read(fd,buf,block_size) != block_size) {
            std::cerr << "cdrrescue: read failed (" << strerror(errno) << ")"
                      << std::endl;
            continue;
        }
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
    }
    if (lseek(fd,0,SEEK_SET) != 0)
        std::cerr << "cdrrescue: seek failed (" << strerror(errno) << ")"
                  << std::endl;
    return found;
}

static bool recover_image(const char* destfile, const char* srcfile) {
    // open src file
    const auto_file_descriptor fin(open(srcfile,O_RDONLY|O_LARGEFILE));
    if (fin == -1) {
        std::cerr << "cdrrescue: " << strerror(errno)
                  << " '" << srcfile << "'"
                  << std::endl;
        return false;
    }
  
    // find existing parity marker
    Marker m;
    if (!find_marker(m,fin)) {
        std::cerr << "cdrrescue: marker not found" << std::endl;
        return false;
    }
    const size_t laststripesize = m.imagesize - m.stripesize*(m.nstripes-1);
    const size_t totalsize = m.imagesize + m.stripesize + 1; // not including last marker

    std::cout << "note: image file has " << m.imagesize << " blocks"
              << std::endl;
    std::cout << "note: divided into " << m.nstripes << " stripes of "
              << m.stripesize << " blocks each" << std::endl;
    std::cout << "\tlast stripe has " << laststripesize << " blocks"
              << std::endl;
    std::cout << "\tparity offset by " << m.stripeoffset << " blocks"
              << std::endl;

    // allocate all-zero block
    const std::vector<char> zeroblock(m.blocksize, 0);
  
    // allocate stripe
    std::vector<char> stripe(m.stripesize * m.blocksize, 0);

    // allocate read buffer
    size_t bufsize = MB;
    if (bufsize < m.blocksize)
        bufsize = m.blocksize;
    size_t blocks_per_buf = bufsize / m.blocksize;
    while (blocks_per_buf > m.stripesize) {
        blocks_per_buf /= 2;
        bufsize /= 2;
    }
    unique_array<char> buf(new char[bufsize]);
    if (buf.get() == NULL) {
        std::cerr << "cdrrescue: failed to allocate needed memory" << std::endl;
        return false;
    }
  
    // open dest file
    const auto_file_descriptor fout(
        open(destfile,O_CREAT|O_TRUNC|O_WRONLY|O_LARGEFILE,0666));
    if (fout == -1) {
        std::cerr << "cdrrescue: " << strerror(errno)
                  << " '" << destfile << "'"
                  << std::endl;
        return false;
    }
 
    // bitmap to track successfully read blocks
    BitMap2d bm(m.nstripes+1,m.stripesize);

    // mark tail blocks in last stripe as successfully read
    for (unsigned int i = laststripesize; i < m.stripesize; ++i)
        bm.set(m.nstripes-1,i);

    // read large buffer
    unsigned int blocks_found = 0;
    unsigned int blocks_written = 0;
    unsigned int nfullbufs = totalsize/blocks_per_buf;
    for (unsigned int buf_num = 0; buf_num < nfullbufs; ++buf_num) {
        std::cout << "cdrrescue: " << blocks_found << '/' << m.imagesize
                  << "     \r" << std::flush;

        off64_t buf_start = bufsize;
        buf_start *= buf_num;
        if (!seek_and_read(buf.get(),fin,buf_start,bufsize))
            continue;

        // write out zero blocks if necessary
        if (buf_num*blocks_per_buf <= m.imagesize)
            while(blocks_written < buf_num*blocks_per_buf) {
                if (write(fout,&zeroblock[0],m.blocksize) != (ssize_t)m.blocksize) {
                    std::cerr << "cdrrescue: write failed (" << strerror(errno)
                              << ")" << std::endl;
                    return false;
                }
                ++blocks_written;
            }
    
        for (unsigned int i = 0; i < blocks_per_buf; ++i) {
            unsigned int block_num = buf_num*blocks_per_buf+i;
            if (block_num < m.imagesize) {
                // main image
                int stripe_num = block_num/m.stripesize;
                int col = block_num%m.stripesize;
                if (write(fout,&buf[i*m.blocksize],m.blocksize) != (ssize_t)m.blocksize) {
                    std::cerr << "cdrrescue: write failed (" << strerror(errno)
                              << ")" << std::endl;
                    return false;
                }
                ++blocks_written;
                memxor(&stripe[col*m.blocksize],
                       &buf[i*m.blocksize],
                       m.blocksize);
                bm.set(stripe_num,col);
                ++blocks_found;
            }
            // note: block_num==m.imagesize is a marker block (ignore)
            else if (block_num > m.imagesize) {
                // parity data
                int col = (block_num-m.imagesize-1+
                           m.stripesize-m.stripeoffset) % m.stripesize;
                bm.set(m.nstripes,col);
                memxor(&stripe[col*m.blocksize],
                       &buf[i*m.blocksize],
                       m.blocksize);
            }
        }
    }

    // write out zero blocks if necessary
    while(blocks_written < m.imagesize) {
        if (write(fout,&zeroblock[0],m.blocksize) != (ssize_t)m.blocksize) {
            std::cerr << "cdrrescue: write failed (" << strerror(errno) << ")"
                      << std::endl;
            return false;
        }
        ++blocks_written;
    }
    assert(blocks_written == m.imagesize);
  
    // attempt to read remainder of parity data
    for (unsigned int block_num = 
             nfullbufs*blocks_per_buf; block_num < totalsize; ++block_num) {
        off64_t block_start = m.blocksize;
        block_start *= block_num;
        if (!seek_and_read(buf.get(),fin,block_start,m.blocksize))
            continue;
        // parity data
        int col = (block_num-m.imagesize-1+
                   m.stripesize-m.stripeoffset)%m.stripesize;
        bm.set(m.nstripes,col);
        memxor(&stripe[col*m.blocksize],buf.get(),m.blocksize);
    }

    // attempt to read or reconstruct all missing blocks
    unsigned int last_blocks_found = 0;
    while (blocks_found<m.imagesize) {
        for (unsigned int block_num = 0; block_num < totalsize; ++block_num) {
            if (last_blocks_found != blocks_found) {
                last_blocks_found = blocks_found;
                std::cout << "cdrrescue: " << blocks_found
                          << '/' << m.imagesize << "     \r" << std::flush;
            }

            off64_t block_start = m.blocksize;
            block_start *= block_num;

            // check if block is known or can be reconstructed
            if (block_num < m.imagesize) {
                // main image
                const unsigned int stripe_num = block_num / m.stripesize;
                const unsigned int col = block_num % m.stripesize;
                if (bm.test(stripe_num,col))
                    continue;

                // can we reconstruct?
                bool data_known = true;
                for (unsigned int i = 0; i <= m.nstripes; ++i) {
                    if (i != stripe_num && !bm.test(i,col)) {
                        data_known = false;
                        break;
                    }
                }

                if (data_known) {
                    // parity array contains reconstructed data
                    if (!seek_and_write(fout,
                                        &stripe[col*m.blocksize],
                                        block_start,
                                        m.blocksize)) {
                        return false;
                    }
                    memset(&stripe[col*m.blocksize],0,m.blocksize);
                    bm.set(stripe_num,col);
                    ++blocks_found;
                    continue;
                }
            }

            else if (block_num > m.imagesize) {
                // parity data
                int col = (block_num-m.imagesize-1+
                           m.stripesize-m.stripeoffset)%m.stripesize;
                if (bm.test(m.nstripes,col))
                    continue;
                // do we need it?
                bool data_known = true;
                for (unsigned int i = 0; i < m.nstripes; ++i) {
                    if (!bm.test(i,col)) {
                        data_known = false;
                        break;
                    }
                }
                if (data_known) {
                    memset(&stripe[col*m.blocksize],0,m.blocksize);
                    bm.set(m.nstripes,col);
                    continue;
                }
            }

            else // block_num==m.imagesize is a marker block (skip)
                continue;

            // attempt to read block
            if (!seek_and_read(buf.get(),fin,block_start,m.blocksize))
                continue;
      
            if (block_num < m.imagesize) {
                // main image
                const int stripe_num = block_num / m.stripesize;
                const int col = block_num % m.stripesize;
                if (!seek_and_write(fout,buf.get(),block_start,m.blocksize))
                    return false;
                memxor(&stripe[col*m.blocksize],buf.get(),m.blocksize);
                bm.set(stripe_num,col);
                ++blocks_found;
            }
            // note: block_num==m.imagesize is a marker block (ignore)
            else if (block_num > m.imagesize) {
                // parity data
                int col = (block_num-m.imagesize-1+
                           m.stripesize-m.stripeoffset)%m.stripesize;
                bm.set(m.nstripes,col);
                memxor(&stripe[col*m.blocksize],buf.get(),m.blocksize);
            }
        }
    }
  
    std::cout << std::endl << "done." << std::endl;
  
    for (unsigned int i = 0; i < m.stripesize*m.blocksize; ++i)
        if (stripe[i]) {
            std::cerr << "cdrrescue: parity data not zero (image corrupt)"
                      << std::endl;
            break;
        }
  
    return true;
}

static void usage(std::ostream& out) {
    out << "Usage:" << std::endl
        << "  cdrrescue src_device output_file" << std::endl;
}


int main(int argc, char*argv[]) {
    ++argv; --argc;
    if (argc < 1) {
        usage(std::cout);
        return -1;
    }

    // parse options
    while (argc > 0 && argv[0][0] == '-') {
        if (!argv[0][1] || argv[0][2]) {
            std::cerr << "cdrrescue: invalid argument: " << argv[0]
                      << std::endl;
            return -1;
        }
        switch (argv[0][1]) {
        case '-':
            --argc; ++argv;
            break;
        default:
            std::cerr << "cdrrescue: invalid argument: " << argv[0]
                      << std::endl;
            return -1;
        }
        --argc; ++argv;
    }

    if (argc < 2) {
        usage(std::cout);
        return -1;
    }

    if (!recover_image(argv[1],argv[0]))
        return 1;
 
    return 0;
}
