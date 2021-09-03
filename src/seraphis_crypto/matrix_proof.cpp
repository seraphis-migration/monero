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
#include "matrix_proof.h"

//local headers
#include "common/container_helpers.h"
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
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// compute: A_inout += k * P
//-------------------------------------------------------------------------------------------------------------------
static void mul_add(const rct::key &k, const crypto::public_key &P, ge_p3 &A_inout)
{
    ge_p3 temp_p3;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;

    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, to_bytes(P)) == 0, "ge_frombytes_vartime failed!");
    ge_scalarmult_p3(&temp_p3, k.bytes, &temp_p3);  //k * P
    ge_p3_to_cached(&temp_cache, &temp_p3);
    ge_add(&temp_p1p1, &A_inout, &temp_cache);  //+ k * P
    ge_p1p1_to_p3(&A_inout, &temp_p1p1);
}
//-------------------------------------------------------------------------------------------------------------------
// aggregation coefficient 'mu' for concise structure
//
// mu = H_n(message, {B}, {{V}})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient(const rct::key &message,
    const std::vector<crypto::public_key> &B,
    const std::vector<std::vector<crypto::public_key>> &M)
{
    // collect aggregation coefficient hash data
    SpFSTranscript transcript{
            config::HASH_KEY_MATRIX_PROOF_AGGREGATION_COEFF,
            (1 + B.size() + (M.size() ? M[0].size() * M.size() : 0))*sizeof(crypto::public_key)
        };
    transcript.append("message", message);
    transcript.append("B", B);
    transcript.append("M", M);

    // mu
    rct::key aggregation_coefficient;
    sp_hash_to_scalar(transcript.data(), transcript.size(), aggregation_coefficient.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(aggregation_coefficient.bytes),
        "matrix proof aggregation coefficient: aggregation coefficient must be nonzero!");

    return aggregation_coefficient;
}
//-------------------------------------------------------------------------------------------------------------------
// challenge message
// challenge_message = H_32(message)
//
// note: in practice, this extends the aggregation coefficient (i.e. message = mu)
// challenge_message = H_32(mu) = H_32(H_n(message, {B}, {{V}}))
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message)
{
    // collect challenge message hash data
    SpFSTranscript transcript{config::HASH_KEY_MATRIX_PROOF_CHALLENGE_MSG, sizeof(rct::key)};
    transcript.append("message", message);

    // m
    rct::key challenge_message;
    sp_hash_to_32(transcript.data(), transcript.size(), challenge_message.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge_message.bytes),
        "matrix proof challenge message: challenge_message must be nonzero!");

    return challenge_message;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H_n(challenge_message, [V_1 proof key], [V_2 proof key], ...)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message, const rct::keyV &V_proofkeys)
{
    // collect challenge hash data
    SpFSTranscript transcript{config::HASH_KEY_MATRIX_PROOF_CHALLENGE, (1 + V_proofkeys.size())*sizeof(rct::key)};
    transcript.append("message", message);
    transcript.append("V_proofkeys", V_proofkeys);

    // c
    rct::key challenge;
    sp_hash_to_scalar(transcript.data(), transcript.size(), challenge.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes),
        "matrix proof challenge: challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// proof response
// r = alpha - c * sum_i(mu^i * k_i)
//-------------------------------------------------------------------------------------------------------------------
static void compute_response(const std::vector<crypto::secret_key> &k,
    const rct::keyV &mu_pows,
    const crypto::secret_key &alpha,
    const rct::key &challenge,
    rct::key &r_out)
{
    CHECK_AND_ASSERT_THROW_MES(k.size() == mu_pows.size(), "matrix proof response: not enough keys!");

    // compute response
    // r = alpha - c * sum_i(mu^i * k_i)
    crypto::secret_key r_temp;
    crypto::secret_key r_sum_temp{rct::rct2sk(rct::zero())};

    for (std::size_t i{0}; i < k.size(); ++i)
    {
        sc_mul(to_bytes(r_temp), mu_pows[i].bytes, to_bytes(k[i]));    //mu^i * k_i
        sc_add(to_bytes(r_sum_temp), to_bytes(r_sum_temp), to_bytes(r_temp));  //sum_i(...)
    }
    sc_mulsub(r_out.bytes, challenge.bytes, to_bytes(r_sum_temp), to_bytes(alpha));  //alpha - c * sum_i(...)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const MatrixProof &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("m", container.m);
    transcript_inout.append("c", container.c);
    transcript_inout.append("r", container.r);
    transcript_inout.append("M", container.M);
}
//-------------------------------------------------------------------------------------------------------------------
void make_matrix_proof(const rct::key &message,
    const std::vector<crypto::public_key> &B,
    const std::vector<crypto::secret_key> &privkeys,
    MatrixProof &proof_out)
{
    /// input checks and initialization
    const std::size_t num_basekeys{B.size()};
    const std::size_t num_keys{privkeys.size()};
    CHECK_AND_ASSERT_THROW_MES(num_basekeys > 0, "matrix proof: not enough base keys to make a proof!");
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "matrix proof: not enough keys to make a proof!");

    // 1. proof message
    proof_out.m = message;

    // 2. prepare (1/8)*{k}
    std::vector<crypto::secret_key> k_i_inv8_temp;

    for (const crypto::secret_key &k_i : privkeys)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k_i)), "matrix proof: bad private key (k_i zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k_i)) == 0, "matrix proof: bad private key (k_i)!");

        // k_i * (1/8)
        sc_mul(to_bytes(tools::add_element(k_i_inv8_temp)), to_bytes(k_i), rct::INV_EIGHT.bytes);
    }

    // 3. prepare (1/8)*{{V}}
    proof_out.M.clear();
    proof_out.M.reserve(num_basekeys);
    std::vector<std::vector<crypto::public_key>> V_mul8;
    V_mul8.reserve(num_basekeys);

    for (const crypto::public_key &basekey : B)
    {
        proof_out.M.emplace_back();
        proof_out.M.back().reserve(num_keys);
        V_mul8.emplace_back();
        V_mul8.back().reserve(num_keys);

        for (const crypto::secret_key &k_i_inv8 : k_i_inv8_temp)
        {
            proof_out.M.back().emplace_back(rct::rct2pk(rct::scalarmultKey(rct::pk2rct(basekey), rct::sk2rct(k_i_inv8))));
            V_mul8.back().emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof_out.M.back().back()))));
        }
    }


    /// signature openers: alpha * {B}
    const crypto::secret_key alpha{rct::rct2sk(rct::skGen())};
    rct::keyV alpha_pubs;
    alpha_pubs.reserve(num_basekeys);

    for (const crypto::public_key &basekey : B)
        alpha_pubs.emplace_back(rct::scalarmultKey(rct::pk2rct(basekey), rct::sk2rct(alpha)));


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof_out.m, B, V_mul8)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// compute proof challenge
    proof_out.c = compute_challenge(m, alpha_pubs);


    /// response
    compute_response(privkeys, mu_pows, alpha, proof_out.c, proof_out.r);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_matrix_proof(const MatrixProof &proof, const std::vector<crypto::public_key> &B)
{
    /// input checks and initialization
    const std::size_t num_basekeys{B.size()};
    CHECK_AND_ASSERT_THROW_MES(num_basekeys > 0, "matrix proof (verify): there are no base keys!");
    CHECK_AND_ASSERT_THROW_MES(num_basekeys == proof.M.size(), "matrix proof (verify): proof has invalid pubkey sets!");

    const std::size_t num_keys{proof.M[0].size()};
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "matrix proof (verify): proof has no pubkeys!");

    for (const std::vector<crypto::public_key> &V : proof.M)
    {
        CHECK_AND_ASSERT_THROW_MES(V.size() == num_keys, "matrix proof (verify): inconsistent pubkey set sizes!");
    }

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r.bytes), "matrix proof (verify): bad response (r zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r.bytes) == 0, "matrix proof (verify): bad response (r)!");

    // recover the proof keys
    std::vector<std::vector<crypto::public_key>> M_recovered;
    M_recovered.reserve(num_basekeys);

    for (std::size_t j{0}; j < num_basekeys; ++j)
    {
        M_recovered.emplace_back();
        M_recovered.reserve(num_keys);

        for (std::size_t i{0}; i < num_keys; ++i)
            M_recovered.back().emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.M[j][i]))));
    }


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof.m, B, M_recovered)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// challenge pieces
    rct::keyV V_proofkeys;
    V_proofkeys.reserve(num_basekeys);

    rct::key coeff_temp;
    ge_p3 V_j_part_p3;

    for (std::size_t j{0}; j < num_basekeys; ++j)
    {
        // V_j part: [r B_j + c * sum_i(mu^i * V_j[i])]
        V_j_part_p3 = ge_p3_identity;

        for (std::size_t i{0}; i < num_keys; ++i)
        {
            // c * mu^i
            sc_mul(coeff_temp.bytes, proof.c.bytes, mu_pows[i].bytes);

            // V_j_part: + c * mu^i * V_j[i]
            mul_add(coeff_temp, M_recovered[j][i], V_j_part_p3);
        }

        // r B_j + V_j_part
        mul_add(proof.r, B[j], V_j_part_p3);

        // convert to pubkey
        ge_p3_tobytes(tools::add_element(V_proofkeys).bytes, &V_j_part_p3);
    }


    /// compute nominal challenge and validate proof
    return compute_challenge(m, V_proofkeys) == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
