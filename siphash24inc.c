/*
   SipHash reference C implementation

   Copyright (c) 2012-2014 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.

   Modified by Chris Studholme 2016 to support incremental hashing.
*/

#include "siphash24.h"
#include <stdio.h>
#include <string.h>

/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                         \
    (p)[0] = (uint8_t)((v));                    \
    (p)[1] = (uint8_t)((v) >> 8);               \
    (p)[2] = (uint8_t)((v) >> 16);              \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                         \
    U32TO8_LE((p), (uint32_t)((v)));            \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                            \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |         \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |  \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |  \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                        \
    do {                                                                \
        ctx->v0 += ctx->v1;                                             \
        ctx->v1 = ROTL(ctx->v1, 13);                                    \
        ctx->v1 ^= ctx->v0;                                             \
        ctx->v0 = ROTL(ctx->v0, 32);                                    \
        ctx->v2 += ctx->v3;                                             \
        ctx->v3 = ROTL(ctx->v3, 16);                                    \
        ctx->v3 ^= ctx->v2;                                             \
        ctx->v0 += ctx->v3;                                             \
        ctx->v3 = ROTL(ctx->v3, 21);                                    \
        ctx->v3 ^= ctx->v0;                                             \
        ctx->v2 += ctx->v1;                                             \
        ctx->v1 = ROTL(ctx->v1, 17);                                    \
        ctx->v1 ^= ctx->v2;                                             \
        ctx->v2 = ROTL(ctx->v2, 32);                                    \
    } while (0)

#ifdef DEBUG
#define TRACE                                                           \
    do {                                                                \
        printf("(%3d) v0 %08x %08x\n", (int)ctx->len,                   \
               (uint32_t)(ctx->v0 >> 32),                               \
               (uint32_t)ctx->v0);                                      \
        printf("(%3d) v1 %08x %08x\n", (int)ctx->len,                   \
               (uint32_t)(ctx->v1 >> 32),                               \
               (uint32_t)ctx->v1);                                      \
        printf("(%3d) v2 %08x %08x\n", (int)ctx->len,                   \
               (uint32_t)(ctx->v2 >> 32),                               \
               (uint32_t)ctx->v2);                                      \
        printf("(%3d) v3 %08x %08x\n", (int)ctx->len,                   \
               (uint32_t)(ctx->v3 >> 32),                               \
               (uint32_t)ctx->v3);                                      \
    } while (0)
#else
#define TRACE
#endif

int siphash_init(siphash_ctx* ctx, const void* _k) {
    /* "somepseudorandomlygeneratedbytes" */
    ctx->v0 = 0x736f6d6570736575ULL;
    ctx->v1 = 0x646f72616e646f6dULL;
    ctx->v2 = 0x6c7967656e657261ULL;
    ctx->v3 = 0x7465646279746573ULL;

    const uint8_t* k = (const uint8_t*)_k;
    uint64_t k0 = U8TO64_LE(k);
    uint64_t k1 = U8TO64_LE(k + 8);
    ctx->v3 ^= k1;
    ctx->v2 ^= k0;
    ctx->v1 ^= k1;
    ctx->v0 ^= k0;

#ifdef DOUBLE
    ctx->v1 ^= 0xee;
#endif

    ctx->b = 0;
    ctx->len = 0;
    ctx->extra = 0;
    
    return 0;
}

int siphash_update(siphash_ctx* ctx, const void* _in, size_t inlen) {
    unsigned i;

    ctx->len += inlen;  /* don't care if this overflows */
    const uint8_t* in = (const uint8_t*)_in;

    if (ctx->extra > 0) {
        while (inlen > 0) {
            ctx->b |= ((uint64_t)*in) << (8*ctx->extra);
            ++in;
            --inlen;
            if (++ctx->extra >= 8) {
                ctx->v3 ^= ctx->b;
                TRACE;
                for (i = 0; i < cROUNDS; ++i)
                    SIPROUND;
                ctx->v0 ^= ctx->b;
                ctx->extra = 0;
                ctx->b = 0;
                break;
            }
        }
    }

    for ( ; inlen >= 8; inlen -= 8, in += 8) {
        uint64_t m = U8TO64_LE(in);
        ctx->v3 ^= m;
        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;
        ctx->v0 ^= m;
    }

    if (inlen > 0) {
        switch (ctx->extra = inlen) {
        case 7:
            ctx->b |= ((uint64_t)in[6]) << 48;
        case 6:
            ctx->b |= ((uint64_t)in[5]) << 40;
        case 5:
            ctx->b |= ((uint64_t)in[4]) << 32;
        case 4:
            ctx->b |= ((uint64_t)in[3]) << 24;
        case 3:
            ctx->b |= ((uint64_t)in[2]) << 16;
        case 2:
            ctx->b |= ((uint64_t)in[1]) << 8;
        case 1:
            ctx->b |= ((uint64_t)in[0]);
        }
    }

    return 0;
}

int siphash_final(siphash_ctx* ctx, void* _out) {
    unsigned i;

    ctx->b |= ((uint64_t)ctx->len) << 56;
    ctx->v3 ^= ctx->b;
    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;
    ctx->v0 ^= ctx->b;

#ifndef DOUBLE
    ctx->v2 ^= 0xff;
#else
    ctx->v2 ^= 0xee;
#endif

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    uint64_t b = ctx->v0 ^ ctx->v1 ^ ctx->v2 ^ ctx->v3;
    uint8_t* out = (uint8_t*)_out;
    U64TO8_LE(out, b);

#ifdef DOUBLE
    ctx->v1 ^= 0xdd;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = ctx->v0 ^ ctx->v1 ^ ctx->v2 ^ ctx->v3;
    U64TO8_LE(out + 8, b);
#endif

    return 0;
}


