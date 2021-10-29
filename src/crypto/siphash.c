/*
   SipHash reference C implementation

   Copyright (c) 2012-2021 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "siphash.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

/* default: SipHash-2-4 */
#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif

#define ROTL_64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define ROTL_32(x, b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (uint8_t)((v));                                                   \
    (p)[1] = (uint8_t)((v) >> 8);                                              \
    (p)[2] = (uint8_t)((v) >> 16);                                             \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (uint32_t)((v)));                                           \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define U8TO32_LE(p)                                                           \
    (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) |                        \
     ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

#define SIPROUND_SH                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL_64(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL_64(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL_64(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL_64(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL_64(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL_64(v2, 32);                                                     \
    } while (0)

#define SIPROUND_HSH                                                           \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL_32(v1, 5);                                                   \
        v1 ^= v0;                                                              \
        v0 = ROTL_32(v0, 16);                                                  \
        v2 += v3;                                                              \
        v3 = ROTL_32(v3, 8);                                                   \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL_32(v3, 7);                                                   \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL_32(v1, 13);                                                  \
        v1 ^= v2;                                                              \
        v2 = ROTL_32(v2, 16);                                                  \
    } while (0)

#ifdef DEBUG
#define TRACE                                                                  \
    do {                                                                       \
        printf("(%3zu) v0 %016" PRIx64 "\n", inlen, v0);                       \
        printf("(%3zu) v1 %016" PRIx64 "\n", inlen, v1);                       \
        printf("(%3zu) v2 %016" PRIx64 "\n", inlen, v2);                       \
        printf("(%3zu) v3 %016" PRIx64 "\n", inlen, v3);                       \
    } while (0)
#else
#define TRACE
#endif

#ifdef DEBUG
#define TRACE_HSH                                                              \
    do {                                                                       \
        printf("(%3zu) v0 %08" PRIx32 "\n", inlen, v0);                        \
        printf("(%3zu) v1 %08" PRIx32 "\n", inlen, v1);                        \
        printf("(%3zu) v2 %08" PRIx32 "\n", inlen, v2);                        \
        printf("(%3zu) v3 %08" PRIx32 "\n", inlen, v3);                        \
    } while (0)
#else
#define TRACE_HSH
#endif


int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out,
            const size_t outlen) {

    const unsigned char *ni = (const unsigned char *)in;
    const unsigned char *kk = (const unsigned char *)k;

    assert((outlen == 8) || (outlen == 16));
    uint64_t v0 = UINT64_C(0x736f6d6570736575);
    uint64_t v1 = UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = UINT64_C(0x6c7967656e657261);
    uint64_t v3 = UINT64_C(0x7465646279746573);
    uint64_t k0 = U8TO64_LE(kk);
    uint64_t k1 = U8TO64_LE(kk + 8);
    uint64_t m;
    int i;
    const unsigned char *end = ni + inlen - (inlen % sizeof(uint64_t));
    const int left = inlen & 7;
    uint64_t b = ((uint64_t)inlen) << 56;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    if (outlen == 16)
        v1 ^= 0xee;

    for (; ni != end; ni += 8) {
        m = U8TO64_LE(ni);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND_SH;

        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)ni[6]) << 48;
    case 6:
        b |= ((uint64_t)ni[5]) << 40;
    case 5:
        b |= ((uint64_t)ni[4]) << 32;
    case 4:
        b |= ((uint64_t)ni[3]) << 24;
    case 3:
        b |= ((uint64_t)ni[2]) << 16;
    case 2:
        b |= ((uint64_t)ni[1]) << 8;
    case 1:
        b |= ((uint64_t)ni[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND_SH;

    v0 ^= b;

    if (outlen == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND_SH;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);

    if (outlen == 8)
        return 0;

    v1 ^= 0xdd;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND_SH;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out + 8, b);

    return 0;
}

int halfsiphash(const void *in, const size_t inlen, const void *k, uint8_t *out,
                const size_t outlen) {

    const unsigned char *ni = (const unsigned char *)in;
    const unsigned char *kk = (const unsigned char *)k;

    assert((outlen == 4) || (outlen == 8));
    uint32_t v0 = 0;
    uint32_t v1 = 0;
    uint32_t v2 = UINT32_C(0x6c796765);
    uint32_t v3 = UINT32_C(0x74656462);
    uint32_t k0 = U8TO32_LE(kk);
    uint32_t k1 = U8TO32_LE(kk + 4);
    uint32_t m;
    int i;
    const unsigned char *end = ni + inlen - (inlen % sizeof(uint32_t));
    const int left = inlen & 3;
    uint32_t b = ((uint32_t)inlen) << 24;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    if (outlen == 8)
        v1 ^= 0xee;

    for (; ni != end; ni += 4) {
        m = U8TO32_LE(ni);
        v3 ^= m;

        TRACE_HSH;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND_HSH;

        v0 ^= m;
    }

    switch (left) {
    case 3:
        b |= ((uint32_t)ni[2]) << 16;
    case 2:
        b |= ((uint32_t)ni[1]) << 8;
    case 1:
        b |= ((uint32_t)ni[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE_HSH;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND_HSH;

    v0 ^= b;

    if (outlen == 8)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE_HSH;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND_HSH;

    b = v1 ^ v3;
    U32TO8_LE(out, b);

    if (outlen == 4)
        return 0;

    v1 ^= 0xdd;

    TRACE_HSH;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND_HSH;

    b = v1 ^ v3;
    U32TO8_LE(out + 4, b);

    return 0;
}
