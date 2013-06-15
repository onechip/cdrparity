#include "Marker.h"


const uint64_t Marker::DEFAULT_BLOCKSIZE = 2048;
const uint64_t Marker::SIG1 = 0xc56a5d888149eee7ULL;
const uint64_t Marker::SIG2 = 0x4139ef05dda34f80ULL;
const uint64_t Marker::SIG1R = 0xe7ee4981885d6ac5ULL;
const uint64_t Marker::SIG2R = 0x804fa3dd05ef3941ULL;


uint64_t Marker::change_endian(uint64_t i) {
    uint64_t result;
    ((unsigned char*)&result)[0] = ((unsigned char*)&i)[7];
    ((unsigned char*)&result)[1] = ((unsigned char*)&i)[6];
    ((unsigned char*)&result)[2] = ((unsigned char*)&i)[5];
    ((unsigned char*)&result)[3] = ((unsigned char*)&i)[4];
    ((unsigned char*)&result)[4] = ((unsigned char*)&i)[3];
    ((unsigned char*)&result)[5] = ((unsigned char*)&i)[2];
    ((unsigned char*)&result)[6] = ((unsigned char*)&i)[1];
    ((unsigned char*)&result)[7] = ((unsigned char*)&i)[0];
    return result;
}

void Marker::fix_endian() {
    if (wrong_endian()) {
        signature1   = change_endian(signature1);
        signature2   = change_endian(signature2);
        blocksize    = change_endian(blocksize);
        imagesize    = change_endian(imagesize);
        stripesize   = change_endian(stripesize);
        nstripes     = change_endian(nstripes);
        stripeoffset = change_endian(stripeoffset);
        checksum     = change_endian(checksum);
    }
}
