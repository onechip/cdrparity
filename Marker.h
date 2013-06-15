#ifndef __Marker_H
#define __Marker_H

#include <stdint.h>


class Marker {
  public:
    /* magic signature values */
    static const uint64_t SIG1;
    static const uint64_t SIG2;

    /* magic signature values (wrong endian) */
    static const uint64_t SIG1R;
    static const uint64_t SIG2R;

    /* default block size */
    static const uint64_t DEFAULT_BLOCKSIZE;

    uint64_t signature1;
    uint64_t signature2;
    uint64_t blocksize;    /* bytes */
    uint64_t imagesize;    /* blocks */
    uint64_t stripesize;   /* blocks */
    uint64_t nstripes;
    uint64_t stripeoffset; /* blocks */
    uint64_t checksum;


  public:
    Marker()
        : signature1(SIG1),
          signature2(SIG2),
          blocksize(DEFAULT_BLOCKSIZE),
          imagesize(0),
          stripesize(0),
          nstripes(0),
          stripeoffset(0),
          checksum(0) {
    }

    inline void set_checksum() {
        checksum = signature1 ^ signature2 
            ^ blocksize ^ imagesize
            ^ stripesize ^ nstripes
            ^ stripeoffset;
    }

    inline bool check_checksum() const {
        return (signature1 ^ signature2 
                ^ blocksize ^ imagesize
                ^ stripesize ^ nstripes
                ^ stripeoffset ^ checksum) == 0;
    }

    inline bool check_signature() const {
        return ((signature1==SIG1 && signature2==SIG2) ||
                (signature1==SIG1R && signature2==SIG2R));
    }

    inline bool is_valid() const {
        return check_signature() && check_checksum();
    }
  
    inline bool wrong_endian() const {
        return signature1 == SIG1R;
    }

    void fix_endian();

    static uint64_t change_endian(uint64_t i);
};


#endif
