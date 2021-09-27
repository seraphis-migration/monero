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

//paired header
#include "seraphis_crypto_utils.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "grootle.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/lexical_cast.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

//standard headers
#include <cmath>


#define CHECK_AND_ASSERT_THROW_MES_L1(expr, message) {if(!(expr)) {MWARNING(message); throw std::runtime_error(message);}}

namespace sp
{

/// File-scope data

// generators
static ge_p3 grootle_Hi_p3[GROOTLE_MAX_MN];
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
static const rct::key MINUS_ONE = { {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
    0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10} };

// misc
static boost::mutex init_mutex;


////
// Helper function for scalar inversion
// return: x*(y^2^n)
///
static rct::key sm(rct::key y, int n, const rct::key &x)
{
    while (n--)
        sc_mul(y.bytes, y.bytes, y.bytes);
    sc_mul(y.bytes, y.bytes, x.bytes);
    return y;
}

////
// Invert a nonzero scalar
// return: (1/x) mod l
///
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

/// Make generators, but only once
void init_sp_gens()
{
    boost::lock_guard<boost::mutex> lock(init_mutex);

    static bool init_done = false;
    if (init_done) return;

    // Build Hi generators
    // H_i = keccak_to_pt("grootle Hi", i)
    static const std::string Hi_salt(config::HASH_KEY_GROOTLE_Hi);
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        std::string hash = Hi_salt + tools::get_varint_data(i);
        hash_to_p3(grootle_Hi_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
    }

    // Build U
    // U = keccak_to_pt("seraphis U")
    static const std::string U_salt(config::HASH_KEY_SERAPHIS_U);
    hash_to_p3(U_p3, rct::hash2rct(crypto::cn_fast_hash(U_salt.data(), U_salt.size())));
    ge_p3_tobytes(U.bytes, &U_p3);

    // Build X
    // X = keccak_to_pt("seraphis X")
    static const std::string X_salt(config::HASH_KEY_SERAPHIS_X);
    hash_to_p3(X_p3, rct::hash2rct(crypto::cn_fast_hash(X_salt.data(), X_salt.size())));
    ge_p3_tobytes(X.bytes, &X_p3);

    // Build H
    ge_frombytes_vartime(&H_p3, rct::H.bytes);

    // Build G
    ge_frombytes_vartime(&G_p3, rct::G.bytes);

    init_done = true;
}

ge_p3 get_grootle_Hi_p3_gen(const std::size_t i)
{
    init_sp_gens();

    return grootle_Hi_p3[i];
}
ge_p3 get_G_p3_gen()
{
    init_sp_gens();

    return G_p3;
}
ge_p3 get_H_p3_gen()
{
    init_sp_gens();

    return H_p3;
}
ge_p3 get_U_p3_gen()
{
    init_sp_gens();

    return U_p3;
}
ge_p3 get_X_p3_gen()
{
    init_sp_gens();

    return X_p3;
}
rct::key get_U_gen()
{
    init_sp_gens();

    return U;
}
rct::key get_X_gen()
{
    init_sp_gens();

    return X;
}

std::shared_ptr<rct::pippenger_cached_data> get_grootle_Hi_pippinger_cache_init()
{
    init_sp_gens();

    std::vector<rct::MultiexpData> data;
    data.reserve(GROOTLE_MAX_MN);
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        data.push_back({ZERO, grootle_Hi_p3[i]});
    }
    CHECK_AND_ASSERT_THROW_MES(data.size() == GROOTLE_MAX_MN, "Bad generator vector size!");

    // initialize multiexponentiation cache
    return rct::pippenger_init_cache(data, 0, 0);
}

////
// Decompose an integer with a fixed base and size
// val -> [_, _, ... ,_]
// - num slots = 'size'
// - numeric base = 'base'
// e.g. if base = 2 then convert val to binary, if base = 10 then put its decimal digits into the return vector
// r = decomposed val (little endian)
///
void decompose(std::vector<std::size_t> &r, const std::size_t val, const std::size_t base, const std::size_t size)
{
    CHECK_AND_ASSERT_THROW_MES(base > 1, "Bad decomposition parameters!");
    CHECK_AND_ASSERT_THROW_MES(size > 0, "Bad decomposition parameters!");
    CHECK_AND_ASSERT_THROW_MES(r.size() >= size, "Bad decomposition result vector size!");

    std::size_t temp = val;

    for (std::size_t i = 0; i < size; ++i)
    {
        std::size_t slot = std::pow(base, size - i - 1);
        r[size - i - 1] = temp/slot;
        temp -= slot*r[size - i - 1];
    }
}

////
// Commit to a scalar matrix
// vector commitment for values a_{1,1}, ..., a_{1,n} ..., a_{m,n} and blinding factor x
// C = x G + a_{1,1} H_{1,1} + a_{1,2} H_{1,2} + ... + a_{m,n} H_{m,n}
///
void com_matrix(std::vector<rct::MultiexpData> &data, const rct::keyM &M, const rct::key &x)
{
    const std::size_t m = M.size();
    CHECK_AND_ASSERT_THROW_MES(m > 0, "Bad matrix size!");
    const std::size_t n = M[0].size();
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Bad matrix commitment parameters!");
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Bad matrix commitment result vector size!");

    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            data[j*n + i] = {M[j][i], grootle_Hi_p3[j*n + i]};
        }
    }
    data[m*n] = {x, G_p3}; // mask
}

/// Kronecker delta
rct::key delta(const std::size_t x, const std::size_t y)
{
    if (x == y)
        return ONE;
    else
        return ZERO;
}

////
// Compute a convolution with a degree-one polynomial
// x: x_1, x_2, ..., x_m
// y: a, b
// return: [a*x_1], [b*x_1 + a*x_2], ..., [b*x_{m - 2} + a*x_{m - 1}], [b*x_m]
///
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

////
// return: (negate ? -1 : 1)*([key^0], [key^1], ..., [key^{num_pows - 1}])
///
rct::keyV powers_of_key(const rct::key &key, const std::size_t num_pows, const bool negate_all)
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
        sc_mul(pows[i].bytes, pows[i - 1].bytes, key.bytes);
    }

    return pows;
}

////
// Generate a curve scalar of arbitrary size (in bytes).
//
// WARNING: NOT FOR USE WITH CRYPTOGRAPHIC SECRETS
///
rct::key small_scalar_gen(const std::size_t size_bytes)
{
    if (size_bytes == 0)
        return rct::zero();

    rct::key result{rct::skGen()};

    // clear all bytes above size desired
    for (std::size_t byte_index = size_bytes; byte_index < 32; ++byte_index)
    {
        result.bytes[byte_index] = 0x00;
    }

    return result;
}

////
// multiExp_p3
// computes aA + bB + ... + pP
///
void multiExp_p3(ge_p3 &result, const rct::keyV &pubkeys, const rct::keyV &privkeys)
{
    ge_p3 temp_pP, temp_ge_p3;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;

    CHECK_AND_ASSERT_THROW_MES_L1(pubkeys.size() == privkeys.size(), "Input vectors don't match!");
    if (pubkeys.empty())
    {
        result = ge_p3_identity;
        return;
    }

    for (std::size_t i = 0; i < pubkeys.size(); ++i)
    {
        // p*P
        CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&temp_ge_p3, pubkeys[i].bytes) == 0,
            "ge_frombytes_vartime failed at " + boost::lexical_cast<std::string>(__LINE__));

        if (privkeys[i].bytes[0] == 1 && privkeys[i] == rct::identity())  // short-circuit if first byte != 1
            temp_pP = temp_ge_p3;  // 1*P
        else
            ge_scalarmult_p3(&temp_pP, privkeys[i].bytes, &temp_ge_p3);  // p*P

        if (i > 0)
        {
            // P[i-1] + P[i]
            ge_p3_to_cached(&temp_cache, &temp_pP);
            ge_add(&temp_p1p1, &result, &temp_cache);   // P[i-1] + P[i]
            ge_p1p1_to_p3(&result, &temp_p1p1);
        }
        else
        {
            result = temp_pP;
        }
    }
}

} //namespace sp
