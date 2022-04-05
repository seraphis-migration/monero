// Copyright (c) 2014-2020, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#include "generators.h"

#include "crypto.h"
extern "C"
{
#include "crypto-ops.h"
}
#include "cryptonote_config.h"
#include "hash.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>


namespace crypto
{

struct uint_point
{
    unsigned char bytes[32];
};

// generators
//standard ed25519 generator G: {x, 4/5} (positive x when decompressing y = 4/5)
static const ec_point G = { {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66} };
//pedersen commitment generator H: toPoint(cn_fast_hash(G))
static const uint_point H_uint = { {0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94} };
static ec_point H;
//seraphis generator U: keccak_to_pt(keccak("seraphis_U"))
static const uint_point U_uint = { {0x12, 0x65, 0x82, 0xdf, 0xc3, 0x57, 0xb1, 0x0e, 0xcb, 0x0c, 0xe0, 0xf1, 0x2c, 0x26, 0x35, 0x9f, 0x53, 0xc6, 0x4d, 0x49, 0x00, 0xb7, 0x69, 0x6c, 0x2c, 0x4b, 0x3f, 0x7d, 0xca, 0xb7, 0xf7, 0x30} };
static ec_point U;
//seraphis generator X: keccak_to_pt(keccak("seraphis_X"))
static const uint_point X_uint = { {0x40, 0x17, 0xa1, 0x26, 0x18, 0x1c, 0x34, 0xb0, 0x77, 0x4d, 0x59, 0x05, 0x23, 0xa0, 0x83, 0x46, 0xbe, 0x4f, 0x42, 0x34, 0x8e, 0xdd, 0xd5, 0x0e, 0xb7, 0xa4, 0x41, 0xb5, 0x71, 0xb2, 0xb6, 0x13} };
static ec_point X;
static ge_p3 G_p3;
static ge_p3 H_p3;
static ge_p3 U_p3;
static ge_p3 X_p3;

// misc
static std::once_flag init_gens_once_flag;

//-------------------------------------------------------------------------------------------------------------------
// hash-to-point: H_p(x) = 8*point_from_bytes(keccak(x))
//-------------------------------------------------------------------------------------------------------------------
static void hash_to_point(const hash &x, crypto::ec_point &res)
{
    ge_p3 temp_p3;

    hash h;
    ge_p2 temp_p2;
    ge_p1p1 temp_p1p1;
    cn_fast_hash(reinterpret_cast<unsigned char*>(&x), sizeof(hash), h);
    ge_fromfe_frombytes_vartime(&temp_p2, reinterpret_cast<unsigned char*>(&h));
    ge_mul8(&temp_p1p1, &temp_p2);
    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);
    ge_p3_tobytes(to_bytes(res), &temp_p3);
}
//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_gens()
{
    std::call_once(init_gens_once_flag,
        [&](){

        // copy uint generator representations to standard 'ec_point' representations (char arrays)
        memcpy(H.data, H_uint.bytes, 32);
        memcpy(U.data, U_uint.bytes, 32);
        memcpy(X.data, X_uint.bytes, 32);

        // build ge_p3 representations of generators
        ge_frombytes_vartime(&G_p3, to_bytes(G));
        ge_frombytes_vartime(&H_p3, to_bytes(H));
        ge_frombytes_vartime(&U_p3, to_bytes(U));
        ge_frombytes_vartime(&X_p3, to_bytes(X));

#if !defined(NDEBUG)
{
    // check that G is reproducible
    // G = {x, 4/5 mod q}
    fe four, five, inv_five, y;
    fe_0(four);
    fe_0(five);
    four[0] = 4;
    five[0] = 5;
    fe_invert(inv_five, five);
    fe_mul(y, four, inv_five);
    ec_point reproduced_G;
    fe_tobytes(to_bytes(reproduced_G), y);

    assert(reproduced_G == G);

    // check that H is reproducible
    // H = 8*to_point(keccak(G))
    // note: this does not use the point_from_bytes() function found in H_p(), instead directly interpreting the
    //       input bytes as a compressed point (this can fail, so should not be used generically)
    ge_p3 temp_p3;
    ge_p2 temp_p2;
    ge_p1p1 temp_p1p1;
    hash H_temp_hash{cn_fast_hash(to_bytes(G), sizeof(ec_point))};
    assert(ge_frombytes_vartime(&temp_p3, reinterpret_cast<unsigned char*>(&H_temp_hash)));  // this is known to pass for canonical value of G
    ge_p3_to_p2(&temp_p2, &temp_p3);
    ge_mul8(&temp_p1p1, &temp_p2);
    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);
    ec_point reproduced_H;
    ge_p3_tobytes(to_bytes(reproduced_H), &temp_p3);

    assert(reproduced_H == H);

    // check that U is reproducible
    // U = H_p(keccak("seraphis_U"))
    const std::string U_salt{config::HASH_KEY_SERAPHIS_U};
    hash U_temp_hash{cn_fast_hash(U_salt.data(), U_salt.size())};
    hash_to_point(U_temp_hash, reproduced_U);

    assert(reproduced_U == U);

    // check that X is reproducible
    // X = H_p(keccak("seraphis_X"))
    const std::string X_salt{config::HASH_KEY_SERAPHIS_X};
    hash X_temp_hash{cn_fast_hash(X_salt.data(), X_salt.size())};
    hash_to_point(X_temp_hash, reproduced_X);

    assert(reproduced_X == X);
}
#endif //debug

    });
}
//-------------------------------------------------------------------------------------------------------------------
const ec_point get_G_gen()
{
    init_gens();
    return G;
}
//-------------------------------------------------------------------------------------------------------------------
const ec_point get_H_gen()
{
    init_gens();
    return H;
}
//-------------------------------------------------------------------------------------------------------------------
const ec_point get_U_gen()
{
    init_gens();
    return U;
}
//-------------------------------------------------------------------------------------------------------------------
const ec_point get_X_gen()
{
    init_gens();
    return X;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3 get_G_p3_gen()
{
    init_gens();
    return G_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3 get_H_p3_gen()
{
    init_gens();
    return H_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3 get_U_p3_gen()
{
    init_gens();
    return U_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3 get_X_p3_gen()
{
    init_gens();
    return X_p3;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace crypto
