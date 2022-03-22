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
#include "dual_base_vector_proof.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

namespace config  //todo: move to config file
{
    const char HASH_KEY_CRYPTO_DUAL_BASE_VECTOR_PROOF[] = "dual_base_vector_proof";
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "crypto"

namespace crypto
{
//-------------------------------------------------------------------------------------------------------------------
// return: [scalar^0], [scalar^1], ..., [scalar^{num_pows - 1}]
//-------------------------------------------------------------------------------------------------------------------
rct::keyV powers_of_scalar(const rct::key &scalar, const std::size_t num_pows)
{
    if (num_pows == 0)
        return rct::keyV{};

    rct::keyV pows;
    pows.resize(num_pows);
    pows[0] = rct::identity();

    for (std::size_t i = 1; i < num_pows; ++i)
        sc_mul(pows[i].bytes, pows[i - 1].bytes, scalar.bytes);

    return pows;
}
//-------------------------------------------------------------------------------------------------------------------
// Initialize transcript
//-------------------------------------------------------------------------------------------------------------------
static void transcript_init(rct::key &transcript)
{
    std::string salt(config::HASH_KEY_CRYPTO_DUAL_BASE_VECTOR_PROOF);
    rct::hash_to_scalar(transcript, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Aggregation coefficient 'mu' for concise structure
//
// mu = H(H("domain-sep"), message, {V_1}, {V_2})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient(const rct::key &message,
    const rct::keyV &V_1,
    const rct::keyV &V_2)
{
    CHECK_AND_ASSERT_THROW_MES(V_1.size() == V_2.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;
    hash.reserve((2 + 2*(V_1.size()))*sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(challenge.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    for (const auto &V : V_1)
        hash.append(reinterpret_cast<const char*>(V.bytes), sizeof(rct::key));
    for (const auto &V : V_2)
        hash.append(reinterpret_cast<const char*>(V.bytes), sizeof(rct::key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
// challenge_message = H(message)
//
// note: in practice, this extends the aggregation coefficient (i.e. message = mu)
// challenge_message = H(H(H("domain-sep"), message, {V_1}, {V_2}))
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message)
{
    rct::key challenge;
    std::string hash;
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H(challenge_message, [V_1 proof key], [V_2 proof key])
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::key &V_1_proofkey,
    const rct::key &V_2_proofkey)
{
    rct::key challenge;
    std::string hash;
    hash.reserve(3*sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(V_1_proofkey.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(V_2_proofkey.bytes), sizeof(rct::key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Proof response
// r = alpha - c * sum_i(mu^i * k_i)
//-------------------------------------------------------------------------------------------------------------------
static void compute_response(const std::vector<crypto::secret_key> &k,
    const rct::keyV &mu_pows,
    const rct::key &alpha,
    const rct::key &challenge,
    rct::key &r_out)
{
    CHECK_AND_ASSERT_THROW_MES(k.size() == mu_pows.size(), "Not enough keys!");

    // compute response
    // r = alpha - c * sum_i(mu^i * k_i)
    rct::key r_temp;
    rct::key r_sum_temp{rct::zero()};
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        // cleanup: clear secret prover data at the end
        memwipe(&r_temp, sizeof(rct::key));
        memwipe(&r_sum_temp, sizeof(rct::key));
    });

    for (std::size_t i{0}; i < k.size(); ++i)
    {
        sc_mul(r_temp.bytes, mu_pows[i].bytes, reinterpret_cast<const unsigned char*>(&k[i]));  // mu^i * k_i
        sc_add(r_sum_temp.bytes, r_sum_temp.bytes, r_temp.bytes);  // sum_i(...)
    }
    sc_mulsub(r_out.bytes, challenge.bytes, r_sum_temp.bytes, alpha.bytes);  // alpha - c * sum_i(...)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
DualBaseVectorProof dual_base_vector_prove(const rct::key &G_1,
    const rct::key &G_2,
    const std::vector<crypto::secret_key> &k,
    const rct::key &message)
{
    /// input checks and initialization
    const std::size_t num_keys{k.size()};
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Not enough keys to make a proof!");

    DualBaseVectorProof proof;
    proof.m = message;

    proof.V_1.reserve(num_keys);
    proof.V_2.reserve(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(reinterpret_cast<const unsigned char*>(&k[i])), "Bad private key (k[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(reinterpret_cast<const unsigned char*>(&k[i])) == 0, "Bad private key (k[i])!");

        // verify the input keys matche the input private keys
        proof.V_1.emplace_back(rct::scalarmultKey(G_1, rct::sk2rct(k[i])));
        proof.V_2.emplace_back(rct::scalarmultKey(G_2, rct::sk2rct(k[i])));

        CHECK_AND_ASSERT_THROW_MES(!(proof.V_1.back() == rct::identity()), "Bad proof key (V_1[i] identity)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.V_2.back() == rct::identity()), "Bad proof key (V_2[i] identity)!");
    }


    /// signature openers: alpha * G_1, alpha * G_2
    crypto::secret_key alpha{rct::rct2sk(rct::skGen())};
    rct::key alpha_1_pub{rct::scalarmultKey(G_1, rct::sk2rct(alpha))};
    rct::key alpha_2_pub{rct::scalarmultKey(G_2, rct::sk2rct(alpha))};


    /// challenge message and aggregation coefficient
    rct::key mu = compute_base_aggregation_coefficient(proof.m, proof.V_1, proof.V_2);
    rct::keyV mu_pows = powers_of_scalar(mu, num_keys);

    rct::key m = compute_challenge_message(mu);


    /// compute proof challenge
    proof.c = compute_challenge(m, alpha_1_pub, alpha_2_pub);


    /// responses
    compute_response(k,
        mu_pows,
        rct::sk2rct(alpha),
        proof.c,
        proof.r);


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool dual_base_vector_verify(const DualBaseVectorProof &proof,
    const rct::key &G_1,
    const rct::key &G_2)
{
    /// input checks and initialization
    const std::size_t num_keys{proof.V_1.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Proof has no keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proof.V_1.size(), "Input key sets not the same size (V_2)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r.bytes), "Bad response (r zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r.bytes) == 0, "Bad resonse (r)!");


    /// challenge message and aggregation coefficient
    rct::key mu = compute_base_aggregation_coefficient(proof.m, proof.V_1, proof.V_2);
    rct::keyV mu_pows = powers_of_scalar(mu, num_keys);

    rct::key m = compute_challenge_message(mu);


    /// challenge pieces

    // V_1 part: [r G_1 + c * sum_i(mu^i * V_1[i])]
    // V_2 part: [r G_2 + c * sum_i(mu^i * V_2[i])]
    ge_p3 V_1_part_p3;
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&V_1_part_p3, rct::identity().bytes) == 0, "ge_frombytes_vartime failed!");
    ge_p3 V_2_part_p3{V_1_part_p3};

    ge_p3 temp_p3;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;
    rct::key coeff_temp;

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // c * mu^i
        coeff_temp = proof.c;
        sc_mul(coeff_temp.bytes, coeff_temp.bytes, mu_pows[i].bytes);

        // V_1_part: + c * mu^i * V_1[i]
        CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, proof.V_1[i].bytes) == 0, "ge_frombytes_vartime failed!");
        ge_scalarmult_p3(&temp_p3, coeff_temp.bytes, &temp_p3);  //c * mu^i * V_1[i]
        ge_p3_to_cached(&temp_cache, &temp_p3);
        ge_add(&temp_p1p1, &V_1_part_p3, &temp_cache);  //+ c * mu^i * V_1[i]
        ge_p1p1_to_p3(&V_1_part_p3, &temp_p1p1);

        // V_2_part: + c * mu^i * V_2[i]
        CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, proof.V_2[i].bytes) == 0, "ge_frombytes_vartime failed!");
        ge_scalarmult_p3(&temp_p3, coeff_temp.bytes, &temp_p3);  //c * mu^i * V_2[i]
        ge_p3_to_cached(&temp_cache, &temp_p3);
        ge_add(&temp_p1p1, &V_2_part_p3, &temp_cache);  //+ c * mu^i * V_2[i]
        ge_p1p1_to_p3(&V_2_part_p3, &temp_p1p1);
    }

    // r G_1 + V_1_part
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, G_1.bytes) == 0, "ge_frombytes_vartime failed!");
    ge_scalarmult_p3(&temp_p3, proof.r.bytes, &temp_p3);  //r G_1
    ge_p3_to_cached(&temp_cache, &temp_p3);
    ge_add(&temp_p1p1, &V_1_part_p3, &temp_cache);  //r G_1 + V_1_part
    ge_p1p1_to_p3(&V_1_part_p3, &temp_p1p1);

    // r G_1 + V_2_part
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, G_2.bytes) == 0, "ge_frombytes_vartime failed!");
    ge_scalarmult_p3(&temp_p3, proof.r.bytes, &temp_p3);  //r G_2
    ge_p3_to_cached(&temp_cache, &temp_p3);
    ge_add(&temp_p1p1, &V_2_part_p3, &temp_cache);  //r G_2 + V_2_part
    ge_p1p1_to_p3(&V_2_part_p3, &temp_p1p1);


    /// compute nominal challenge and validate proof
    rct::key V_1_part;
    rct::key V_2_part;
    ge_p3_tobytes(V_1_part.bytes, &V_1_part_p3);
    ge_p3_tobytes(V_2_part.bytes, &V_2_part_p3);

    return compute_challenge(m, V_1_part, V_2_part) == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace crypto
