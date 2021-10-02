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
#include "seraphis_composition_proof.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto_utils.h"

//third party headers
#include <boost/lexical_cast.hpp>

//standard headers
#include <vector>


namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// Initialize transcript
//-------------------------------------------------------------------------------------------------------------------
static void transcript_init(rct::key &transcript)
{
    std::string salt(config::HASH_KEY_SP_COMPOSITION_PROOF_TRANSCRIPT);
    rct::hash_to_scalar(transcript, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Aggregation coefficient 'a' for concise structure
// - K_t2 = K_t1 - X - KI
//   - X is a generator
//   - embedding {K_t1}, {KI} in the coefficient implicitly embeds K_t2
//
// mu_a = H(H("domain-sep"), message, {K_t1}, {KI})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient_a(const rct::key &message,
    const rct::keyV &K_t1,
    const rct::keyV &KI)
{
    CHECK_AND_ASSERT_THROW_MES(K_t1.size() == KI.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;
    hash.reserve((2*(K_t1.size()) + 2)*sizeof(rct::key));
    hash = std::string((const char*) challenge.bytes, sizeof(challenge));
    hash += std::string((const char*) message.bytes, sizeof(message));
    for (const auto &Kt1 : K_t1)
    {
        hash += std::string((const char*) Kt1.bytes, sizeof(Kt1));
    }
    for (const auto &Ki : KI)
    {
        hash += std::string((const char*) Ki.bytes, sizeof(Ki));
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Aggregation coefficient 'b' for concise structure
// - {KI} is embedded in mu_a, so it is sufficient to separate mu_a and mu_b with a single hash
//
// mu_b = H(mu_a)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient_b(const rct::key &mu_a)
{
    rct::key challenge;
    std::string hash;
    hash.reserve(1*sizeof(rct::key));
    hash = std::string((const char*) mu_a.bytes, sizeof(mu_a));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
// m = H(message, {K})
//
// note: in practice, this extends the aggregation coefficients (i.e. message = mu_b)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message, const rct::keyV &K)
{
    rct::key challenge;
    std::string hash;
    hash.reserve((K.size() + 1)*sizeof(rct::key));
    hash = std::string((const char*) message.bytes, sizeof(message));
    for (std::size_t i = 0; i < K.size(); ++i)
    {
        hash += std::string((const char*) K[i].bytes, sizeof(K[i]));
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H(message, [K_t2 proof key], [KI proof key], {[K_t1 proof key]})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::key &K_t2_proofkey,
    const rct::key &KI_proofkey,
    const rct::keyV &K_t1_proofkeys)
{
    rct::key challenge;
    std::string hash;
    hash.reserve((K_t1_proofkeys.size() + 3)*sizeof(rct::key));
    hash = std::string((const char*) message.bytes, sizeof(message));
    hash += std::string((const char*) K_t2_proofkey.bytes, sizeof(K_t2_proofkey));
    hash += std::string((const char*) KI_proofkey.bytes, sizeof(KI_proofkey));
    for (std::size_t i = 0; i < K_t1_proofkeys.size(); ++i)
    {
        hash += std::string((const char*) K_t1_proofkeys[i].bytes, sizeof(K_t1_proofkeys[i]));
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove(const rct::keyV &K,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z,
    const rct::key &message)
{
    /// input checks and initialization
    const std::size_t num_keys{K.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Not enough keys to make a proof!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == x.size(), "Input key sets not the same size (K ?= x)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == y.size(), "Input key sets not the same size (K ?= y)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == z.size(), "Input key sets not the same size (K ?= z)!");

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(!(K[i] == rct::identity()), "Bad proof key (K[i] identity)!");

        // x == 0 is allowed
        CHECK_AND_ASSERT_THROW_MES(sc_check(x[i].bytes) == 0, "Bad private key (x[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(y[i].bytes), "Bad private key (y[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(y[i].bytes) == 0, "Bad private key (y[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(z[i].bytes), "Bad private key (z[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(z[i].bytes) == 0, "Bad private key (z[i])!");
    }

    rct::key U_gen{get_U_gen()};

    SpCompositionProof proof;

    // make K_t1 and KI
    rct::keyV KI;
    rct::key privkey_temp;
    proof.K_t1.resize(num_keys);
    KI.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // K_t1_i = (1/y_i) * K_i
        privkey_temp = invert(y[i]);
        rct::scalarmultKey(proof.K_t1[i], K[i], privkey_temp);

        // KI = (z_i / y_i) * U
        sc_mul(privkey_temp.bytes, privkey_temp.bytes, z[i].bytes);
        rct::scalarmultKey(KI[i], U_gen, privkey_temp);
    }


    /// signature openers

    // alpha_a * G
    rct::key alpha_a;
    rct::key alpha_a_pub;

    generate_proof_alpha(rct::G, alpha_a, alpha_a_pub);

    // alpha_b * U
    rct::key alpha_b;
    rct::key alpha_b_pub;

    generate_proof_alpha(U_gen, alpha_b, alpha_b_pub);

    // alpha_i[i] * K_i
    rct::keyV alpha_i;
    rct::keyV alpha_i_pub;
    alpha_i.resize(num_keys);
    alpha_i_pub.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        generate_proof_alpha(K[i], alpha_i[i], alpha_i_pub[i]);
    }


    /// challenge message and aggregation coefficients
    rct::key mu_a = compute_base_aggregation_coefficient_a(message, proof.K_t1, KI);
    rct::keyV mu_a_pows = powers_of_scalar(mu_a, num_keys);

    rct::key mu_b = compute_base_aggregation_coefficient_b(mu_a);
    rct::keyV mu_b_pows = powers_of_scalar(mu_b, num_keys);

    rct::key m = compute_challenge_message(mu_b, K);


    /// compute proof challenge
    proof.c = compute_challenge(m, alpha_a_pub, alpha_b_pub, alpha_i_pub);


    /// responses
    rct::key r_temp;
    rct::key r_sum_temp;

    // r_a = alpha_a - c * sum_i(mu_a^i * (x_i / y_i))
    r_sum_temp = rct::zero();
    for (std::size_t i{0}; i < num_keys; ++i)
    {
        r_temp = invert(y[i]);  // 1 / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, x[i].bytes);  // x_i / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, mu_a_pows[i].bytes);  // mu_a^i * x_i / y_i
        sc_add(r_sum_temp.bytes, r_sum_temp.bytes, r_temp.bytes);  // sum_i(...)
    }
    sc_mulsub(proof.r_a.bytes, proof.c.bytes, r_sum_temp.bytes, alpha_a.bytes);  // alpha_a - c * sum_i(...)

    // r_b = alpha_b - c * sum_i(mu_b^i * (z_i / y_i))
    r_sum_temp = rct::zero();
    for (std::size_t i{0}; i < num_keys; ++i)
    {
        r_temp = invert(y[i]);  // 1 / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, z[i].bytes);  // z_i / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, mu_b_pows[i].bytes);  // mu_b^i * z_i / y_i
        sc_add(r_sum_temp.bytes, r_sum_temp.bytes, r_temp.bytes);  // sum_i(...)
    }
    sc_mulsub(proof.r_b.bytes, proof.c.bytes, r_sum_temp.bytes, alpha_b.bytes);  // alpha_b - c * sum_i(...)

    // r_i = alpha_i - c * (1 / y_i)
    proof.r_i.resize(num_keys);
    for (std::size_t i{0}; i < num_keys; ++i)
    {
        r_temp = invert(y[i]);  // 1 / y_i
        sc_mulsub(proof.r_i[i].bytes, proof.c.bytes, r_temp.bytes, alpha_i[i].bytes);  // alpha_i - c * (1 / y_i)
    }


    /// cleanup: clear secret prover data
    memwipe(&alpha_a, sizeof(rct::key));
    memwipe(&alpha_b, sizeof(rct::key));
    memwipe(alpha_i.data(), alpha_i.size()*sizeof(rct::key));


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::keyV &K,
    const rct::keyV &KI,
    const rct::key &message)
{
    /// input checks and initialization
    const std::size_t num_keys{K.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Proof has no keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == KI.size(), "Input key sets not the same size (KI)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proof.K_t1.size(), "Input key sets not the same size (K_t1)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proof.r_i.size(), "Insufficient proof responses!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r_a.bytes), "Bad response (r_a zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_a.bytes) == 0, "Bad resonse (r_a)!");

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r_i[i].bytes), "Bad response (r[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_i[i].bytes) == 0, "Bad resonse (r[i])!");

        CHECK_AND_ASSERT_THROW_MES(!(KI[i] == rct::identity()), "Invalid key image!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.K_t1[i] == rct::identity()), "Invalid proof element K_t1!");
    }

    /// challenge message and aggregation coefficients
    rct::key mu_a = compute_base_aggregation_coefficient_a(message, proof.K_t1, KI);
    rct::keyV mu_a_pows = powers_of_scalar(mu_a, num_keys);

    rct::key mu_b = compute_base_aggregation_coefficient_b(mu_a);
    rct::keyV mu_b_pows = powers_of_scalar(mu_b, num_keys);

    rct::key m = compute_challenge_message(mu_b, K);


    /// challenge pieces

    // K_t2 part: [r_a * G + c * sum_i(mu_a^i * K_t2[i])]
    // KI part:   [r_b * U + c * sum_i(mu_b^i * KI[i]  )]
    // K_t1[i] parts: [r[i] * K[i] + c * K_t1[i]]
    rct::keyV K_t2_privkeys;
    rct::keyV KI_privkeys;
    rct::keyV K_t1_privkeys;
    std::vector<ge_p3> K_t2_p3;
    std::vector<ge_p3> KI_part_p3;
    std::vector<ge_p3> K_t1_p3;
    rct::keyV challenge_parts_i;
    ge_p3 temp_p3;
    ge_cached temp_cache;
    ge_cached X_cache;
    ge_p1p1 temp_p1p1;
    K_t2_privkeys.reserve(num_keys + 1);
    KI_privkeys.reserve(num_keys + 1);
    K_t1_privkeys.resize(2);
    K_t2_p3.resize(num_keys);   // note: no '+ 1' because G is implied
    KI_part_p3.resize(num_keys + 1);
    K_t1_p3.resize(2);
    challenge_parts_i.resize(num_keys);

    temp_p3 = get_X_p3_gen();
    ge_p3_to_cached(&X_cache, &temp_p3); // cache X for use below
    K_t1_privkeys[1] = proof.c; // prep outside loop

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // c * mu_a^i
        K_t2_privkeys.push_back(mu_a_pows[i]);
        sc_mul(K_t2_privkeys.back().bytes, K_t2_privkeys.back().bytes, proof.c.bytes);

        // c * mu_b^i
        KI_privkeys.push_back(mu_b_pows[i]);
        sc_mul(KI_privkeys.back().bytes, KI_privkeys.back().bytes, proof.c.bytes);

        // get K_t1
        CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&K_t1_p3[1], proof.K_t1[i].bytes) == 0,
            "ge_frombytes_vartime failed!");

        // get KI
        CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&KI_part_p3[i], KI[i].bytes) == 0,
            "ge_frombytes_vartime failed!");

        // get K
        CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&K_t1_p3[0], K[i].bytes) == 0,
            "ge_frombytes_vartime failed!");

        // temp: K_t1 - KI
        ge_p3_to_cached(&temp_cache, &KI_part_p3[i]);
        ge_sub(&temp_p1p1, &K_t1_p3[1], &temp_cache);
        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        // K_t2 = (K_t1 - KI) - X
        ge_sub(&temp_p1p1, &temp_p3, &X_cache);
        ge_p1p1_to_p3(&K_t2_p3[i], &temp_p1p1);

        // privkey for K_t1 part
        K_t1_privkeys[0] = proof.r_i[i];

        // compute 'K_t1[i]' piece
        multi_exp(K_t1_p3, K_t1_privkeys, challenge_parts_i[i]);
    }

    // K_t2: r_a * G + ...
    K_t2_privkeys.push_back(proof.r_a);
    //G implied, not stored in 'K_t2_p3'

    // KI: r_b * U + ...
    KI_privkeys.push_back(proof.r_b);
    KI_part_p3[num_keys] = get_U_p3_gen();

    // compute 'a' piece
    rct::key challenge_part_a;
    multi_exp(K_t2_p3, K_t2_privkeys, challenge_part_a);

    // compute 'b' piece
    rct::key challenge_part_b;
    multi_exp(KI_part_p3, KI_privkeys, challenge_part_b);


    /// compute nominal challenge
    rct::key challenge_nom{compute_challenge(m, challenge_part_a, challenge_part_b, challenge_parts_i)};


    /// validate proof
    return challenge_nom == proof.c;
}
/*
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::keyV &KI,
    const rct::keyV &K,
    const rct::key &message)
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPrep sp_composition_multisig_init()
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPartial sp_composition_multisig_response(const SpCompositionProofMultisigProposal &proposal,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z_e,
    const rct::keyV &signer_openings,
    const rct::key &local_opening_priv,
    const rct::key &message)
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs)
{

}
//-------------------------------------------------------------------------------------------------------------------
*/
} //namespace sp
