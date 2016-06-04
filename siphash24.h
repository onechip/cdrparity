#ifndef __SIPHASH24_H
#define __SIPHASH24_H

#include <stddef.h>
#include <stdint.h>

#define SIPHASH_KEY_LENGTH (16)
#define SIPHASH_DIGEST_LENGTH (8)

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint64_t v0, v1, v2, v3;
        uint64_t b;
        unsigned len, extra;
    } siphash_ctx;

    int siphash_init(siphash_ctx* ctx, const void* k);
    int siphash_update(siphash_ctx* ctx, const void* in, size_t inlen);
    int siphash_final(siphash_ctx* ctx, void* out);

    int siphash(uint8_t* out,
                const uint8_t* in, uint64_t inlen,
                const uint8_t* k);

#ifdef __cplusplus
}
#endif

#endif
