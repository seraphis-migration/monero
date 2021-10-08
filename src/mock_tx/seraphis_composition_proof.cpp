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
// Aggregation coefficient 'mu_a' for concise structure
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
// Aggregation coefficient 'mu_b' for concise structure
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
// Proof responses
// r_a = alpha_a - c * sum_i(mu_a^i * (x_i / y_i))
// r_b = alpha_b - c * sum_i(mu_b^i * (z_i / y_i))
// r_i = alpha_i - c * (1 / y_i)
//-------------------------------------------------------------------------------------------------------------------
static void compute_responses(const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z,
    const rct::keyV &mu_a_pows,
    const rct::keyV &mu_b_pows,
    const rct::key &alpha_a,
    const rct::key &alpha_b,
    const rct::keyV &alpha_i,
    const rct::key &challenge,
    rct::key &r_a_out,
    rct::key &r_b_out,
    rct::keyV &r_i_out)
{
    /// input checks
    const std::size_t num_keys{x.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys == y.size(), "Not enough keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == z.size(), "Not enough keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == mu_a_pows.size(), "Not enough keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == mu_b_pows.size(), "Not enough keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == alpha_i.size(), "Not enough keys!");


    /// compute responses
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
    sc_mulsub(r_a_out.bytes, challenge.bytes, r_sum_temp.bytes, alpha_a.bytes);  // alpha_a - c * sum_i(...)

    // r_b = alpha_b - c * sum_i(mu_b^i * (z_i / y_i))
    r_sum_temp = rct::zero();
    for (std::size_t i{0}; i < num_keys; ++i)
    {
        r_temp = invert(y[i]);  // 1 / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, z[i].bytes);  // z_i / y_i
        sc_mul(r_temp.bytes, r_temp.bytes, mu_b_pows[i].bytes);  // mu_b^i * z_i / y_i
        sc_add(r_sum_temp.bytes, r_sum_temp.bytes, r_temp.bytes);  // sum_i(...)
    }
    sc_mulsub(r_b_out.bytes, challenge.bytes, r_sum_temp.bytes, alpha_b.bytes);  // alpha_b - c * sum_i(...)

    // r_i = alpha_i - c * (1 / y_i)
    r_i_out.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        r_temp = invert(y[i]);  // 1 / y_i
        sc_mulsub(r_i_out[i].bytes, challenge.bytes, r_temp.bytes, alpha_i[i].bytes);  // alpha_i - c * (1 / y_i)
    }


    /// cleanup: clear secret prover data
    memwipe(&r_temp, sizeof(rct::key));
    memwipe(&r_sum_temp, sizeof(rct::key));
}
//-------------------------------------------------------------------------------------------------------------------
// Element 'K_t1[i]' for a proof
//   - multiplied by (1/8) for storage (and use in byte-aware contexts)
// K_t1_i = (1/y_i) * K_i
// return: (1/8)*K_t1_i
//-------------------------------------------------------------------------------------------------------------------
static void compute_K_t1_for_proof(const rct::key &y_i,
    const rct::key &K_i,
    rct::key &K_t1_out)
{
    K_t1_out = invert(y_i);  // borrow the variable
    sc_mul(K_t1_out.bytes, K_t1_out.bytes, rct::INV_EIGHT.bytes);
    rct::scalarmultKey(K_t1_out, K_i, K_t1_out);
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

    const rct::key U_gen{get_U_gen()};

    SpCompositionProof proof;

    // make K_t1 and KI
    rct::keyV KI;
    proof.K_t1.resize(num_keys);
    KI.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // K_t1_i = (1/8) * (1/y_i) * K_i
        compute_K_t1_for_proof(y[i], K[i], proof.K_t1[i]);

        // KI = (z_i / y_i) * U
        // note: plain KI is used in all byte-aware contexts
        seraphis_key_image_from_privkeys(z[i], y[i], KI[i]);
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
    compute_responses(x, y, z, mu_a_pows, mu_b_pows, alpha_a, alpha_b, alpha_i, proof.c, proof.r_a, proof.r_b, proof.r_i);


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
    rct::keyV K_t2_coeff;
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
    K_t2_coeff.reserve(num_keys + 1);
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
        K_t2_coeff.push_back(mu_a_pows[i]);
        sc_mul(K_t2_coeff.back().bytes, K_t2_coeff.back().bytes, proof.c.bytes);

        // c * mu_b^i
        KI_privkeys.push_back(mu_b_pows[i]);
        sc_mul(KI_privkeys.back().bytes, KI_privkeys.back().bytes, proof.c.bytes);

        // get K_t1, convert to the prime subgroup, and check it is non-identity
        rct::scalarmult8(K_t1_p3[1], proof.K_t1[i]);
        CHECK_AND_ASSERT_THROW_MES(!(ge_p3_is_point_at_infinity(&K_t1_p3[1])), "Invalid proof element K_t1!");

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
        multi_exp_vartime(K_t1_privkeys, K_t1_p3, challenge_parts_i[i]);
    }

    // K_t2: r_a * G + ...
    K_t2_coeff.push_back(proof.r_a);
    //G implied, not stored in 'K_t2_p3'

    // KI: r_b * U + ...
    KI_privkeys.push_back(proof.r_b);
    KI_part_p3[num_keys] = get_U_p3_gen();

    // compute 'a' piece
    rct::key challenge_part_a;
    multi_exp_vartime(K_t2_coeff, K_t2_p3, challenge_part_a);

    // compute 'b' piece
    rct::key challenge_part_b;
    multi_exp_vartime(KI_privkeys, KI_part_p3, challenge_part_b);


    /// compute nominal challenge
    rct::key challenge_nom{compute_challenge(m, challenge_part_a, challenge_part_b, challenge_parts_i)};


    /// validate proof
    return challenge_nom == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::keyV &KI,
    const rct::keyV &K,
    const rct::key &message)
{
    /// input checks and initialization
    const std::size_t num_keys{K.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Proof has no keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == KI.size(), "Input key sets not the same size (KI)!");

    SpCompositionProofMultisigProposal proposal;


    /// assemble proposal
    proposal.KI = KI;
    proposal.K = K;
    proposal.message = message;

    rct::key dummy;
    generate_proof_alpha(rct::G, proposal.signature_opening_K_t2, dummy);

    proposal.signature_openings_K_t1.resize(num_keys);
    for (std::size_t i{0}; i < num_keys; ++i)
    {
        generate_proof_alpha(K[i], proposal.signature_openings_K_t1[i], dummy);
    }

    return proposal;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPrep sp_composition_multisig_init()
{
    SpCompositionProofMultisigPrep prep;

    // alpha_{e,b}*U
    rct::key U{get_U_gen()};
    generate_proof_alpha(U, prep.signature_opening_KI_priv, prep.signature_opening_KI_pub);

    return prep;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z_e,
    const rct::keyV &signer_openings,
    const rct::key &local_opening_priv)
{
    /// input checks and initialization
    const std::size_t num_keys{proposal.K.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Not enough keys to make a proof!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proposal.KI.size(), "Input key sets not the same size (K ?= KI)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proposal.signature_openings_K_t1.size(), "Input key sets not the same size (K ?= KI)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == x.size(), "Input key sets not the same size (K ?= x)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == y.size(), "Input key sets not the same size (K ?= y)!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == z_e.size(), "Input key sets not the same size (K ?= z)!");

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(!(proposal.K[i] == rct::identity()), "Bad proof key (K[i] identity)!");
        CHECK_AND_ASSERT_THROW_MES(!(proposal.KI[i] == rct::identity()), "Bad proof key (KI[i] identity)!");

        // x == 0 is allowed
        CHECK_AND_ASSERT_THROW_MES(sc_check(x[i].bytes) == 0, "Bad private key (x[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(y[i].bytes), "Bad private key (y[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(y[i].bytes) == 0, "Bad private key (y[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(z_e[i].bytes), "Bad private key (z[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(z_e[i].bytes) == 0, "Bad private key (z[i])!");
    }

    const rct::key U_gen{get_U_gen()};

    // check that the local signer's signature opening is in the input set of opening pubkeys
    rct::key local_opening_pub;
    bool found_local_opening{false};
    rct::scalarmultKey(local_opening_pub, U_gen, local_opening_priv);

    for (const auto &opening : signer_openings)
    {
        if (local_opening_pub == opening)
        {
            found_local_opening = true;
            break;
        }
    }
    CHECK_AND_ASSERT_THROW_MES(found_local_opening, "Local signer's opening key not in input set!");


    /// prepare partial signature
    SpCompositionProofMultisigPartial partial_sig;

    // make K_t1
    partial_sig.K_t1.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // K_t1_i = (1/8) * (1/y_i) * K_i
        compute_K_t1_for_proof(y[i], proposal.K[i], partial_sig.K_t1[i]);
    }

    // set partial sig pieces
    partial_sig.KI = proposal.KI;
    partial_sig.K = proposal.K;
    partial_sig.message = proposal.message;


    /// signature openers

    // alpha_a * G
    rct::key alpha_a_pub;
    rct::scalarmultKey(alpha_a_pub, rct::G, proposal.signature_opening_K_t2);

    // alpha_b * U
    // - sum of components from all multisig participants
    rct::key alpha_b_pub{rct::identity()};

    for (const auto &opening : signer_openings)
    {
        rct::addKeys(alpha_b_pub, alpha_b_pub, opening);
    }

    // alpha_i[i] * K_i
    rct::keyV alpha_i_pub;
    alpha_i_pub.resize(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        rct::scalarmultKey(alpha_i_pub[i], partial_sig.K[i], proposal.signature_openings_K_t1[i]);
    }


    /// challenge message and aggregation coefficients
    rct::key mu_a = compute_base_aggregation_coefficient_a(partial_sig.message, partial_sig.K_t1, partial_sig.KI);
    rct::keyV mu_a_pows = powers_of_scalar(mu_a, num_keys);

    rct::key mu_b = compute_base_aggregation_coefficient_b(mu_a);
    rct::keyV mu_b_pows = powers_of_scalar(mu_b, num_keys);

    rct::key m = compute_challenge_message(mu_b, partial_sig.K);


    /// compute proof challenge
    partial_sig.c = compute_challenge(m, alpha_a_pub, alpha_b_pub, alpha_i_pub);


    /// responses
    compute_responses(x,
            y,
            z_e,  // for partial signature
            mu_a_pows,
            mu_b_pows,
            proposal.signature_opening_K_t2,
            local_opening_priv,  // for partial signature
            proposal.signature_openings_K_t1,
            partial_sig.c,
            partial_sig.r_a,
            partial_sig.r_b_partial,  // partial response
            partial_sig.r_i
        );


    /// done
    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0, "No partial signatures to make proof out of!");

    const std::size_t num_keys{partial_sigs[0].K.size()};

    // common parts between partial signatures should match
    for (std::size_t sig_index{0}; sig_index < partial_sigs.size(); ++sig_index)
    {
        CHECK_AND_ASSERT_THROW_MES(num_keys == partial_sigs[sig_index].K.size(), "Input key sets not the same size!");
        CHECK_AND_ASSERT_THROW_MES(num_keys == partial_sigs[sig_index].KI.size(), "Input key sets not the same size!");
        CHECK_AND_ASSERT_THROW_MES(num_keys == partial_sigs[sig_index].K_t1.size(), "Input key sets not the same size!");
        CHECK_AND_ASSERT_THROW_MES(num_keys == partial_sigs[sig_index].r_i.size(), "Input key sets not the same size!");

        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].c == partial_sigs[sig_index].c, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_a == partial_sigs[sig_index].r_a, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].message == partial_sigs[sig_index].message, "Input key sets don't match!");

        for (std::size_t i{0}; i < num_keys; ++i)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K[i] == partial_sigs[sig_index].K[i], "Input key sets don't match!");
            CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].KI[i] == partial_sigs[sig_index].KI[i], "Input key sets don't match!");
            CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K_t1[i] == partial_sigs[sig_index].K_t1[i], "Input key sets don't match!");
            CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_i[i] == partial_sigs[sig_index].r_i[i], "Input key sets don't match!");
        }
    }


    /// assemble the final proof
    SpCompositionProof proof;

    proof.c = partial_sigs[0].c;
    proof.r_a = partial_sigs[0].r_a;

    proof.r_b = rct::zero();
    for (std::size_t sig_index{0}; sig_index < partial_sigs.size(); ++sig_index)
    {
        // sum of responses from each multisig participant
        sc_add(proof.r_b.bytes, proof.r_b.bytes, partial_sigs[sig_index].r_b_partial.bytes);
    }

    proof.r_i = partial_sigs[0].r_i;
    proof.K_t1 = partial_sigs[0].K_t1;


    /// verify that proof assembly succeeded
    CHECK_AND_ASSERT_THROW_MES(sp_composition_verify(proof,
            partial_sigs[0].K,
            partial_sigs[0].KI,
            partial_sigs[0].message),
        "Multisig composition proof failed to verify on assembly!");


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
