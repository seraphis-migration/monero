// Copyright (c) 2022, The Monero Project
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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
#include "mx25519.h"
}
#include "crypto/generators.h"
#include "crypto/x25519.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <std::size_t Sz>
static void bitshift_array_right(const std::size_t bits, unsigned char (&arr)[Sz])
{
    ASSERT_TRUE(bits <= 8);
    static_assert(Sz > 0, "");

    unsigned char bits_for_next{0};
    unsigned char saved_bits{0};
    for (int i{Sz - 1}; i >= 0; --i)
    {
        bits_for_next = arr[i] & ((unsigned char)255 >> (8 - bits));
        arr[i] >>= bits;
        arr[i] |= saved_bits << (8 - bits);
        saved_bits = bits_for_next;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <std::size_t Sz>
static void bitshift_array_left(const std::size_t bits, unsigned char (&arr)[Sz])
{
    ASSERT_TRUE(bits <= 8);
    static_assert(Sz > 0, "");

    unsigned char bits_for_next{0};
    unsigned char saved_bits{0};
    for (std::size_t i{0}; i <= Sz - 1; ++i)
    {
        bits_for_next = arr[i] & ((unsigned char)255 << (8 - bits));
        arr[i] <<= bits;
        arr[i] |= saved_bits >> (8 - bits);
        saved_bits = bits_for_next;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(x25519, x25519_sample_tests)
{
    // 1. x25519 private keys are byte buffers like rct::key
    crypto::x25519_scalar test1;
    const rct::key testrct{rct::skGen()};
    memcpy(test1.data, testrct.bytes, 32);
    ASSERT_TRUE(memcmp(test1.data, testrct.bytes, 32) == 0);

    // 2. x * G == x * G
    crypto::x25519_scalar test2_privkey;
    crypto::rand(32, test2_privkey.data);

    crypto::x25519_pubkey test2_key_1;
    crypto::x25519_pubkey test2_key_2;

    const crypto::x25519_pubkey generator_G{crypto::get_x25519_G()};
    crypto::x25519_scmul_key(test2_privkey, generator_G, test2_key_1);
    crypto::x25519_scmul_base(test2_privkey, test2_key_2);
    ASSERT_TRUE(memcmp(&test2_key_2, &test2_key_1, 32) == 0);

    // 3. derived x25519 scalars are canonical: H_n_x25519[k](x)
    for (int i{0}; i < 1000; ++i)
    {
        crypto::x25519_scalar test3_scalar;
        const rct::key test3_derivation_key{rct::skGen()};
        std::string test3_data{};

        sp::sp_derive_x25519_key(test3_derivation_key.bytes, test3_data.data(), test3_data.size(), test3_scalar.data);
        ASSERT_TRUE(crypto::x25519_scalar_is_canonical(test3_scalar));
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(x25519, x25519_invmul_key_test)
{
    rct::key temp{};
    temp.bytes[0] = 255;
    temp.bytes[1] = 255;
    temp.bytes[2] = 255;
    rct::key temp2{temp};
    bitshift_array_left(3, temp2.bytes);
    bitshift_array_right(3, temp2.bytes);
    ASSERT_TRUE(temp == temp2);

    // 1. make a non-canonical scalar x >= 2^255 and x % 64 == 0
    // note: need the scalar to be a multiple of 8*8 so bitshifting right 3 bits is equivalent to div8 and won't
    //       produce a non-canonical result
    crypto::x25519_scalar x{};
    x.data[0] = 255 - 63;
    x.data[31] = 128;

    // 2. 1/x
    // note: x25519 scalars are stored mul8 via bit shift, so we do (1/(8*reduce_32(x)) << 3)
    rct::key x_inv;
    memcpy(x_inv.bytes, x.data, 32);
    sc_reduce32(x_inv.bytes);  //mod l
    sc_mul(x_inv.bytes, rct::EIGHT.bytes, x_inv.bytes);  //8*x
    x_inv = sp::invert(x_inv);  //1/(8*x)
    bitshift_array_left(3, x_inv.bytes);  //1/(8*x) << 3

    rct::key x_recovered;
    memcpy(x_recovered.bytes, x_inv.bytes, 32);
    sc_reduce32(x_recovered.bytes);  //mod l
    sc_mul(x_recovered.bytes, rct::EIGHT.bytes, x_recovered.bytes);  //8*(1/x)
    x_recovered = sp::invert(x_recovered);  //1/(8*(1/x))
    bitshift_array_left(3, x_recovered.bytes);  //1/(8*(1/x)) << 3

    ASSERT_TRUE(memcmp(x.data, x_recovered.bytes, 32) == 0);  //can recover x by reversing the inversion

    crypto::x25519_scalar x_inv_copy;
    memcpy(x_inv_copy.data, x_inv.bytes, 32);
    ASSERT_TRUE(crypto::x25519_scalar_is_canonical(x_inv_copy));  //make sure result is canonical 

    // 3. P = 1/(1/x) * G
    // note: 1/(1/x) = x, but x is non-canonical and should cause mx25519_invkey() to return an error, but then
    //       x25519_invkey_mul() handles that case
    crypto::x25519_secret_key x_inv_attempt;
    ASSERT_FALSE(mx25519_invkey(&x_inv_attempt, &x_inv_copy, 1) == 0);

    crypto::x25519_pubkey P;
    crypto::x25519_invmul_key({x_inv_copy}, crypto::get_x25519_G(), P);

    // 4. expect: P == 8 * [(x >> 3) * G]  (the last bit of any scalar is ignored, so we first make x smaller by 8
    //    then mul8 [can't do div2, mul2 because the first 3 bits of any scalar are ignored so mul2 isn't possible])
    crypto::x25519_scalar x_shifted{x};
    bitshift_array_right(3, x_shifted.data);  //x >> 3

    crypto::x25519_pubkey P_reproduced;
    crypto::x25519_scmul_base(x_shifted, P_reproduced);  //(x >> 3) * G

    const crypto::x25519_scalar eight{crypto::x25519_eight()};
    crypto::x25519_scmul_key(eight, P_reproduced, P_reproduced);  //8 * [(x >> 3) * G]

    ASSERT_TRUE(P == P_reproduced);  //P == 8 * [(x >> 3) * G] == x * G
}
//-------------------------------------------------------------------------------------------------------------------
