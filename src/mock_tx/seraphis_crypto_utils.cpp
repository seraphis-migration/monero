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
#include "seraphis_crypto_utils.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "grootle.h"
#include "misc_log_ex.h"
#include "mock_tx_utils.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "wipeable_string.h"

//third party headers
#include <boost/lexical_cast.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

//standard headers
#include <array>
#include <cmath>
#include <vector>


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

// misc
static boost::mutex init_mutex;


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
    boost::lock_guard<boost::mutex> lock(init_mutex);

    static bool init_done = false;
    if (init_done) return;

    // Build Hi generators
    // H_i = keccak_to_pt("grootle Hi", i)
    const std::string Hi_salt(config::HASH_KEY_GROOTLE_Hi);
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        std::string hash = Hi_salt + tools::get_varint_data(i);
        hash_to_p3(grootle_Hi_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
    }

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

    // Build H
    ge_frombytes_vartime(&H_p3, rct::H.bytes);

    // Build G
    ge_frombytes_vartime(&G_p3, rct::G.bytes);

    init_done = true;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_grootle_Hi_p3_gen(const std::size_t i)
{
    init_sp_gens();

    return grootle_Hi_p3[i];
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_G_p3_gen()
{
    init_sp_gens();

    return G_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_H_p3_gen()
{
    init_sp_gens();

    return H_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_U_p3_gen()
{
    init_sp_gens();

    return U_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_X_p3_gen()
{
    init_sp_gens();

    return X_p3;
}
//-------------------------------------------------------------------------------------------------------------------
rct::key get_U_gen()
{
    init_sp_gens();

    return U;
}
//-------------------------------------------------------------------------------------------------------------------
rct::key get_X_gen()
{
    init_sp_gens();

    return X;
}
//-------------------------------------------------------------------------------------------------------------------
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
void com_matrix(const rct::keyM &M_priv, const rct::key &x, std::vector<rct::MultiexpData> &data_out)
{
    const std::size_t m = M_priv.size();
    CHECK_AND_ASSERT_THROW_MES(m > 0, "Bad matrix size!");
    const std::size_t n = M_priv[0].size();
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Bad matrix commitment parameters!");
    CHECK_AND_ASSERT_THROW_MES(data_out.size() == m*n + 1, "Bad matrix commitment result vector size!");

    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            data_out[j*n + i] = {M_priv[j][i], grootle_Hi_p3[j*n + i]};
        }
    }
    data_out[m*n] = {x, G_p3}; // mask
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
// WARNING: NOT FOR USE WITH CRYPTOGRAPHIC SECRETS
//-------------------------------------------------------------------------------------------------------------------
rct::key small_scalar_gen(const std::size_t size_bytes)
{
    if (size_bytes == 0)
        return rct::zero();

    rct::key result{ZERO};

    while (result == ZERO)
    {
        result = rct::skGen();

        // clear all bytes above size desired
        for (std::size_t byte_index = size_bytes; byte_index < 32; ++byte_index)
        {
            result.bytes[byte_index] = 0x00;
        }
    }

    return result;
}
//-------------------------------------------------------------------------------------------------------------------
void generate_proof_alpha(const rct::key &base, rct::key &alpha_out, rct::key &alpha_pub_out)
{
    CHECK_AND_ASSERT_THROW_MES(!(base == rct::identity()), "Bad base for generating proof alpha!");

    alpha_out = ZERO;

    while (alpha_out == ZERO || alpha_pub_out == rct::identity())
    {
        alpha_out = rct::skGen();
        rct::scalarmultKey(alpha_pub_out, base, alpha_out);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp(const rct::keyV &privkeys, const rct::keyV &pubkeys, rct::key &result_out)
{
    ge_p3 result_p3;
    multi_exp_p3(privkeys, pubkeys, result_p3);
    ge_p3_tobytes(result_out.bytes, &result_p3);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp(const rct::keyV &privkeys, const std::vector<ge_p3> &pubkeys, rct::key &result_out)
{
    ge_p3 result_p3;
    multi_exp_p3(privkeys, pubkeys, result_p3);
    ge_p3_tobytes(result_out.bytes, &result_p3);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_p3(const rct::keyV &privkeys, const rct::keyV &pubkeys, ge_p3 &result_out)
{
    std::vector<ge_p3> pubkeys_p3;
    pubkeys_p3.resize(pubkeys.size());

    for (std::size_t i = 0; i < pubkeys.size(); ++i)
    {
        /// convert key P to ge_p3
        CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&pubkeys_p3[i], pubkeys[i].bytes) == 0,
            "ge_frombytes_vartime failed at " + boost::lexical_cast<std::string>(__LINE__));
    }

    multi_exp_p3(privkeys, pubkeys_p3, result_out);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_p3(const rct::keyV &privkeys, const std::vector<ge_p3> &pubkeys, ge_p3 &result_out)
{
    ge_p3 temp_pP;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;
    rct::key temp_rct;

    CHECK_AND_ASSERT_THROW_MES_L1(pubkeys.size() <= privkeys.size(), "Too many input pubkeys!");
    if (privkeys.empty())
    {
        result_out = ge_p3_identity;
        return;
    }

    // first keys are p*P
    for (std::size_t i = 0; i < pubkeys.size(); ++i)
    {
        /// p*P

        // optimize for 1*P
        if (privkeys[i] == IDENTITY)
        {
            temp_pP = pubkeys[i];  // 1*P
        }
        else
        {
            ge_scalarmult_p3(&temp_pP, privkeys[i].bytes, &pubkeys[i]);  // p*P
        }


        /// add p*P into result

        // P[i-1] + P[i]
        if (i > 0)
        {
            ge_p3_to_cached(&temp_cache, &temp_pP);
            ge_add(&temp_p1p1, &result_out, &temp_cache);   // P[i-1] + P[i]
            ge_p1p1_to_p3(&result_out, &temp_p1p1);
        }
        else
        {
            result_out = temp_pP;
        }
    }

    // last keys are p*G
    rct::key base_privkey{ZERO};

    for (std::size_t i = pubkeys.size(); i < privkeys.size(); ++i)
    {
        sc_add(base_privkey.bytes, base_privkey.bytes, privkeys[i].bytes);
    }
    
    if (pubkeys.size() < privkeys.size())
    {
        /// p_sum*G

        // optimize for 1*G
        if (base_privkey == IDENTITY)
        {
            temp_pP = G_p3;  // 1*G
        }
        // optimize for P == G
        else
        {
            sc_reduce32copy(temp_rct.bytes, base_privkey.bytes); //do this beforehand
            ge_scalarmult_base(&temp_pP, temp_rct.bytes);
        }


        /// add p_sum*G into result

        // P[i-1] + P[i]
        if (pubkeys.size() > 0)
        {
            ge_p3_to_cached(&temp_cache, &temp_pP);
            ge_add(&temp_p1p1, &result_out, &temp_cache);   // P[i-1] + P[i]
            ge_p1p1_to_p3(&result_out, &temp_p1p1);
        }
        else
        {
            result_out = temp_pP;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_vartime(const rct::keyV &privkeys, const rct::keyV &pubkeys, rct::key &result_out)
{
    ge_p3 result_p3;
    multi_exp_vartime_p3(privkeys, pubkeys, result_p3);
    ge_p3_tobytes(result_out.bytes, &result_p3);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_vartime(const rct::keyV &privkeys, const std::vector<ge_p3> &pubkeys, rct::key &result_out)
{
    ge_p3 result_p3;
    multi_exp_vartime_p3(privkeys, pubkeys, result_p3);
    ge_p3_tobytes(result_out.bytes, &result_p3);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_vartime_p3(const rct::keyV &privkeys, const rct::keyV &pubkeys, ge_p3 &result_out)
{
    std::vector<ge_p3> pubkeys_p3;
    pubkeys_p3.resize(pubkeys.size());

    for (std::size_t i = 0; i < pubkeys.size(); ++i)
    {
        /// convert key P to ge_p3
        CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&pubkeys_p3[i], pubkeys[i].bytes) == 0,
            "ge_frombytes_vartime failed at " + boost::lexical_cast<std::string>(__LINE__));
    }

    multi_exp_vartime_p3(privkeys, pubkeys_p3, result_out);
}
//-------------------------------------------------------------------------------------------------------------------
void multi_exp_vartime_p3(const rct::keyV &privkeys, const std::vector<ge_p3> &pubkeys, ge_p3 &result_out)
{
    // initialize
    std::vector<std::array<signed char, 256>> scalar_slides;
    std::vector<std::array<ge_cached, 8>> precomps;
    ge_p1p1 t;
    ge_p3 u;
    ge_p2 r;
    int i;
    std::size_t unary_scalar_count{0};

    // check
    CHECK_AND_ASSERT_THROW_MES_L1(pubkeys.size() <= privkeys.size(), "Too many input pubkeys!");
    if (privkeys.empty())
    {
        result_out = ge_p3_identity;
        return;
    }

    // set 'p' (in pG)
    rct::key base_privkey{ZERO};

    for (std::size_t privkey_index{pubkeys.size()}; privkey_index < privkeys.size(); ++privkey_index)
    {
        if (privkey_index == pubkeys.size())
            base_privkey = privkeys[privkey_index];
        else
            sc_add(base_privkey.bytes, base_privkey.bytes, privkeys[privkey_index].bytes);
    }

    // find how many elements have scalar = 1
    if (base_privkey == IDENTITY)
        ++unary_scalar_count;

    for (std::size_t pubkey_index{0}; pubkey_index < pubkeys.size(); ++pubkey_index)
    {
        if (privkeys[pubkey_index] == IDENTITY)
            ++unary_scalar_count;
    }

    rct::keyV unaries;
    unaries.resize(unary_scalar_count, IDENTITY);

    if (base_privkey == IDENTITY)
        --unary_scalar_count;

    // separate elements with scalar = 1, and prepare for vartime multi exp for other elements
    std::vector<ge_p3> unary_pubkeys;
    unary_pubkeys.reserve(unary_scalar_count);

    precomps.resize(pubkeys.size() - unary_scalar_count);

    if (unaries.size() > unary_scalar_count)
        scalar_slides.resize(precomps.size());  // in p*G, p = 1
    else if (privkeys.size() > pubkeys.size() && !(base_privkey == ZERO))
        scalar_slides.resize(precomps.size() + 1);  // an extra scalar for p*G, with p > 1
    else
        scalar_slides.resize(precomps.size());  // p = 0

    std::size_t precomp_index{0};
    std::size_t slides_index{0};

    for (std::size_t pubkey_index{0}; pubkey_index < pubkeys.size(); ++pubkey_index)
    {
        if (privkeys[pubkey_index] == IDENTITY)
            unary_pubkeys.push_back(pubkeys[pubkey_index]);
        else
        {
            ge_dsm_precomp(precomps[precomp_index].data(), &pubkeys[pubkey_index]);
            slide(scalar_slides[slides_index].data(), privkeys[pubkey_index].bytes);
            ++precomp_index;
            ++slides_index;
        }
    }

    if (scalar_slides.size() > precomps.size())
    {
        slide(scalar_slides.back().data(), base_privkey.bytes); // for p*G, p > 1
    }

    // add all elements with scalar = 1
    if (unaries.size() > 0)
        multi_exp_p3(unaries, unary_pubkeys, result_out);

    // leave early if we are done
    if (scalar_slides.size() == 0)
        return;

    // perform multi exp for elements with scalar > 0
    ge_p2_0(&r);
    int max_i{0};
    bool found_nonzero_scalar{false};

    for (std::size_t slides_index{0}; slides_index < scalar_slides.size(); ++slides_index)
    {
        if (max_i < 0)
            max_i = 0;

        for (i = 255; i >= max_i; --i)
        {
            if (scalar_slides[slides_index][i])
            {
                max_i = i;
                found_nonzero_scalar = true;
                break;
            }
        }
    }

    if (!found_nonzero_scalar)
    {
        // return identity if no scalars > 0 mod l
        if (unaries.size() == 0)
            result_out = ge_p3_identity;

        return;
    }

    for (i = max_i; i >= 0; --i)
    {
        ge_p2_dbl(&t, &r);

        // add all non-G components if they exist
        for (std::size_t precomp_index{0}; precomp_index < precomps.size(); ++precomp_index)
        {
            if (scalar_slides[precomp_index][i] > 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_add(&t, &u, &precomps[precomp_index][scalar_slides[precomp_index][i]/2]);
            }
            else if (scalar_slides[precomp_index][i] < 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_sub(&t, &u, &precomps[precomp_index][(-scalar_slides[precomp_index][i])/2]);
            }
        }

        // add base point 'G' component if it exists
        if (scalar_slides.size() > precomps.size())
        {
            if (scalar_slides.back()[i] > 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_madd(&t, &u, &ge_Bi[scalar_slides.back()[i]/2]);
            }
            else if (scalar_slides.back()[i] < 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_msub(&t, &u, &ge_Bi[(-scalar_slides.back()[i])/2]);
            }
        }

        // prep for next step
        if (i == 0)
        {
            // we are done, set final result
            if (unaries.size() > 0)
            {
                // combine scalar = 1 and scalar > 1 parts
                ge_cached temp_cache;
                ge_p1p1 temp_p1p1;

                ge_p1p1_to_p3(&u, &t);
                ge_p3_to_cached(&temp_cache, &u);
                ge_add(&temp_p1p1, &result_out, &temp_cache);
                ge_p1p1_to_p3(&result_out, &temp_p1p1);
            }
            else
            {
                // no scalar = 1 part, get result directly
                ge_p1p1_to_p3(&result_out, &t);
            }
        }
        else
            ge_p1p1_to_p2(&r, &t);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void mask_key(const crypto::secret_key &mask, const rct::key &key, rct::key &masked_key_out)
{
    // K' = mask G + K
    rct::addKeys1(masked_key_out, rct::sk2rct(mask), key);
}
//-------------------------------------------------------------------------------------------------------------------
void domain_separate_rct_hash(const std::string &domain_separator, const rct::key &rct_key, crypto::secret_key &hash_result_out)
{
    // H("domain-sep", rct_key)
    epee::wipeable_string hash{};
    hash.reserve(domain_separator.size() + sizeof(rct::key));
    hash += domain_separator;
    hash.append((const char*) rct_key.bytes, sizeof(rct_key));

    //TODO: is this inefficient use of hash_to_scalar? e.g. ringct has various seemingly optimized calls into keccak()
    crypto::hash_to_scalar(hash.data(), hash.size(), hash_result_out);

    // clear the string in case the key is a secret
    hash.wipe();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
