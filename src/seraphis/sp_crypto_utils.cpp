// Copyright (c) 2021, The Monero Project
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

// NOT FOR PRODUCTION

//paired header
#include "sp_crypto_utils.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "concise_grootle.h"
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <array>
#include <cmath>
#include <mutex>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

#define CHECK_AND_ASSERT_THROW_MES_L1(expr, message) {if(!(expr)) {MWARNING(message); throw std::runtime_error(message);}}

namespace sp
{
/// File-scope data

// generators
static ge_p3 G_p3;
static ge_p3 H_p3;
static ge_p3 U_p3;
static ge_p3 X_p3;
static rct::key U;
static rct::key X;

// Useful scalar and group constants
static const rct::key ZERO = rct::zero();
static const rct::key ONE = rct::identity();
static const rct::key IDENTITY = rct::identity();

// misc
static std::once_flag init_gens_once_flag;


//-------------------------------------------------------------------------------------------------------------------
// Helper function for scalar inversion
// return: x*(y^2^n)
//-------------------------------------------------------------------------------------------------------------------
static rct::key sm(rct::key y, int n, const rct::key &x)
{
    while (n--)
        sc_mul(y.bytes, y.bytes, y.bytes);
    sc_mul(y.bytes, y.bytes, x.bytes);
    return y;
}
//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_sp_gens()
{
    std::call_once(init_gens_once_flag,
        [&](){

        // Build G
        ge_frombytes_vartime(&G_p3, rct::G.bytes);

        // Build H
        ge_frombytes_vartime(&H_p3, rct::H.bytes);

        // Build U
        // U = keccak_to_pt("seraphis U")
        const std::string U_salt(config::HASH_KEY_SERAPHIS_U);
        hash_to_p3(U_p3, rct::hash2rct(crypto::cn_fast_hash(U_salt.data(), U_salt.size())));
        ge_p3_tobytes(U.bytes, &U_p3);

        // Build X
        // X = keccak_to_pt("seraphis X")
        const std::string X_salt(config::HASH_KEY_SERAPHIS_X);
        hash_to_p3(X_p3, rct::hash2rct(crypto::cn_fast_hash(X_salt.data(), X_salt.size())));
        ge_p3_tobytes(X.bytes, &X_p3);

/*
printf("U: ");
for (const unsigned char byte : U.bytes)
    printf("0x%x, ", byte);
printf("\n");

printf("X: ");
for (const unsigned char byte : X.bytes)
    printf("0x%x, ", byte);
printf("\n");
*/
CHECK_AND_ASSERT_THROW_MES(rct::rct2pk(rct::G) == crypto::get_G_gen(), "invalid G");
CHECK_AND_ASSERT_THROW_MES(rct::rct2pk(rct::H) == crypto::get_H_gen(), "invalid H");
CHECK_AND_ASSERT_THROW_MES(rct::rct2pk(U) == crypto::get_U_gen(), "invalid U");
CHECK_AND_ASSERT_THROW_MES(rct::rct2pk(X) == crypto::get_X_gen(), "invalid X");

rct::key temp_minus_one;
sc_sub(temp_minus_one.bytes, ZERO.bytes, ONE.bytes);
CHECK_AND_ASSERT_THROW_MES(temp_minus_one == MINUS_ONE, "invalid MINUS_ONE");
    });
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3& get_G_p3_gen()
{
    init_sp_gens();
    return G_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3& get_H_p3_gen()
{
    init_sp_gens();
    return H_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3& get_U_p3_gen()
{
    init_sp_gens();
    return U_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const ge_p3& get_X_p3_gen()
{
    init_sp_gens();
    return X_p3;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& get_U_gen()
{
    init_sp_gens();
    return U;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& get_X_gen()
{
    init_sp_gens();
    return X;
}
//-------------------------------------------------------------------------------------------------------------------
rct::key invert(const rct::key &x)
{
    CHECK_AND_ASSERT_THROW_MES(!(x == ZERO), "Cannot invert zero!");

    rct::key _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

    _1 = x;
    sc_mul(_10.bytes, _1.bytes, _1.bytes);
    sc_mul(_100.bytes, _10.bytes, _10.bytes);
    sc_mul(_11.bytes, _10.bytes, _1.bytes);
    sc_mul(_101.bytes, _10.bytes, _11.bytes);
    sc_mul(_111.bytes, _10.bytes, _101.bytes);
    sc_mul(_1001.bytes, _10.bytes, _111.bytes);
    sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
    sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

    rct::key inv;
    sc_mul(inv.bytes, _1111.bytes, _1.bytes);

    inv = sm(inv, 123 + 3, _101);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 4, _1001);
    inv = sm(inv, 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 3, _101);
    inv = sm(inv, 3 + 3, _101);
    inv = sm(inv, 3, _111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 2 + 3, _111);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 2 + 4, _1011);
    inv = sm(inv, 6 + 4, _1001);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 1 + 4, _1001);
    inv = sm(inv, 1 + 3, _111);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 1 + 2, _11);

    // Confirm inversion
    rct::key temp;
    sc_mul(temp.bytes, x.bytes, inv.bytes);
    CHECK_AND_ASSERT_THROW_MES(temp == ONE, "Scalar inversion failed!");

    return inv;
}
//-------------------------------------------------------------------------------------------------------------------
void decompose(const std::size_t val, const std::size_t base, const std::size_t size, std::vector<std::size_t> &r_out)
{
    CHECK_AND_ASSERT_THROW_MES(base > 1, "Bad decomposition parameters!");
    CHECK_AND_ASSERT_THROW_MES(size > 0, "Bad decomposition parameters!");
    CHECK_AND_ASSERT_THROW_MES(r_out.size() >= size, "Bad decomposition result vector size!");

    std::size_t temp = val;

    for (std::size_t i = 0; i < size; ++i)
    {
        std::size_t slot = std::pow(base, size - i - 1);
        r_out[size - i - 1] = temp/slot;
        temp -= slot*r_out[size - i - 1];
    }
}
//-------------------------------------------------------------------------------------------------------------------
rct::key kronecker_delta(const std::size_t x, const std::size_t y)
{
    if (x == y)
        return ONE;
    else
        return ZERO;
}
//-------------------------------------------------------------------------------------------------------------------
rct::keyV convolve(const rct::keyV &x, const rct::keyV &y, const std::size_t m)
{
    CHECK_AND_ASSERT_THROW_MES(x.size() >= m, "Bad convolution parameters!");
    CHECK_AND_ASSERT_THROW_MES(y.size() == 2, "Bad convolution parameters!");

    rct::key temp;
    rct::keyV result;
    result.resize(m + 1, ZERO);

    for (std::size_t i = 0; i < m; ++i)
    {
        for (std::size_t j = 0; j < 2; ++j)
        {
            sc_mul(temp.bytes, x[i].bytes, y[j].bytes);
            sc_add(result[i + j].bytes, result[i + j].bytes, temp.bytes);
        }
    }

    return result;
}
//-------------------------------------------------------------------------------------------------------------------
rct::keyV powers_of_scalar(const rct::key &scalar, const std::size_t num_pows, const bool negate_all)
{
    if (num_pows == 0)
        return rct::keyV{};

    rct::keyV pows;
    pows.resize(num_pows);

    if (negate_all)
        pows[0] = MINUS_ONE;
    else
        pows[0] = ONE;

    for (std::size_t i = 1; i < num_pows; ++i)
    {
        sc_mul(pows[i].bytes, pows[i - 1].bytes, scalar.bytes);
    }

    return pows;
}
//-------------------------------------------------------------------------------------------------------------------
void generate_proof_nonce(const rct::key &base, crypto::secret_key &nonce_out, rct::key &nonce_pub_out)
{
    // make proof nonce as crypto::secret_key
    CHECK_AND_ASSERT_THROW_MES(!(base == rct::identity()), "Bad base for generating proof nonce!");

    nonce_out = rct::rct2sk(ZERO);

    while (nonce_out == rct::rct2sk(ZERO) || nonce_pub_out == rct::identity())
    {
        nonce_out = rct::rct2sk(rct::skGen());
        rct::scalarmultKey(nonce_pub_out, base, rct::sk2rct(nonce_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void generate_proof_nonce(const rct::key &base, rct::key &nonce_out, rct::key &nonce_pub_out)
{
    // make proof nonce as rct::key
    crypto::secret_key temp;
    generate_proof_nonce(base, temp, nonce_pub_out);
    nonce_out = rct::sk2rct(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void subtract_secret_key_vectors(const std::vector<crypto::secret_key> &keys_A,
    const std::vector<crypto::secret_key> &keys_B,
    crypto::secret_key &result_out)
{
    result_out = rct::rct2sk(rct::zero());

    // add keys_A
    for (const crypto::secret_key &key_A : keys_A)
        sc_add(to_bytes(result_out), to_bytes(result_out), to_bytes(key_A));

    // subtract keys_B
    for (const crypto::secret_key &key_B : keys_B)
        sc_sub(to_bytes(result_out), to_bytes(result_out), to_bytes(key_B));
}
//-------------------------------------------------------------------------------------------------------------------
void mask_key(const crypto::secret_key &mask, const rct::key &key, rct::key &masked_key_out)
{
    // K" = mask G + K
    rct::addKeys1(masked_key_out, rct::sk2rct(mask), key);
}
//-------------------------------------------------------------------------------------------------------------------
bool key_domain_is_prime_subgroup(const rct::key &check_key)
{
    // l*K ?= identity
    ge_p3 check_key_p3;
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&check_key_p3, check_key.bytes) == 0, "ge_frombytes_vartime failed");
    ge_scalarmult_p3(&check_key_p3, rct::curveOrder().bytes, &check_key_p3);

    return (ge_p3_is_point_at_infinity_vartime(&check_key_p3) != 0);
}
//-------------------------------------------------------------------------------------------------------------------
bool multiexp_is_identity(const std::vector<rct::pippenger_prep_data> &multiexp_data_sets)
{
    // verify the multiexponentiation resolves to the identity element
    ge_p3 result = rct::pippenger_p3(multiexp_data_sets);
    if (ge_p3_is_point_at_infinity_vartime(&result) == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool multiexp_is_identity(rct::pippenger_prep_data multiexp_data_set)
{
    std::vector<rct::pippenger_prep_data> multiexp_data_sets;
    multiexp_data_sets.emplace_back(std::move(multiexp_data_set));

    return multiexp_is_identity(multiexp_data_sets);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
