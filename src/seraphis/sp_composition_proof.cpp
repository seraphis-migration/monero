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
#include "sp_composition_proof.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_misc_utils.h"  //for equals_from_less (todo: remove this dependency?)

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
struct sp_multisig_binonce_factors
{
    rct::key nonce_1;
    rct::key nonce_2;

    /// overload operator< for sorting: compare nonce_1 then nonce_2
    bool operator<(const sp_multisig_binonce_factors &other) const
    {
        const int nonce_1_comparison{memcmp(nonce_1.bytes, &other.nonce_1.bytes, sizeof(rct::key))};
    
        if (nonce_1_comparison < 0)
            return true;
        else if (nonce_1_comparison == 0 && memcmp(nonce_2.bytes, &other.nonce_2.bytes, sizeof(rct::key)) < 0)
            return true;
        else
            return false;
    }
    bool operator==(const sp_multisig_binonce_factors &other) const { return equals_from_less{}(*this, other); }
};
inline const std::string get_container_name(const sp_multisig_binonce_factors&) { return "sp_multisig_binonce_factors"; }
void append_to_transcript(const sp_multisig_binonce_factors &container, SpTranscript &transcript_inout)
{
    transcript_inout.append("nonce1", container.nonce_1);
    transcript_inout.append("nonce2", container.nonce_2);
}

//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
//
// challenge_message = H_32(X, U, m, K, KI, K_t1)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    const rct::key &K_t1)
{
    // collect challenge message hash data
    SpTranscript transcript{config::HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE_MESSAGE, 6*sizeof(rct::key)};
    transcript.append("X", get_X_gen());
    transcript.append("U", get_U_gen());
    transcript.append("message", message);
    transcript.append("K", K);
    transcript.append("KI", KI);
    transcript.append("K_t1", K_t1);

    // challenge_message
    rct::key challenge_message;
    sp_hash_to_32(transcript, challenge_message.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge_message.bytes), "Transcript challenge_message must be nonzero!");

    return challenge_message;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge: extend the challenge message
// c = H_n(challenge_message, [K_t1 proof key], [K_t2 proof key], [KI proof key])
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &challenge_message,
    const rct::key &K_t1_proofkey,
    const rct::key &K_t2_proofkey,
    const rct::key &KI_proofkey)
{
    // collect challenge hash data
    SpTranscript transcript{config::HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE, 4*sizeof(rct::key)};
    transcript.append("challenge_message", challenge_message);
    transcript.append("K_t1_proofkey", K_t1_proofkey);
    transcript.append("K_t2_proofkey", K_t2_proofkey);
    transcript.append("KI_proofkey", KI_proofkey);

    rct::key challenge;
    sp_hash_to_scalar(transcript, challenge.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Proof responses
// r_t1 = alpha_t1 - c * (1 / y)
// r_t2 = alpha_t2 - c * (x / y)
// r_ki = alpha_ki - c * (z / y)
//-------------------------------------------------------------------------------------------------------------------
static void compute_responses(const rct::key &challenge,
    const rct::key &alpha_t1,
    const rct::key &alpha_t2,
    const rct::key &alpha_ki,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    rct::key &r_t1_out,
    rct::key &r_t2_out,
    rct::key &r_ki_out)
{
    // r_t1 = alpha_t1 - c * (1 / y)
    r_t1_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mulsub(r_t1_out.bytes, challenge.bytes, r_t1_out.bytes, alpha_t1.bytes);  // alpha_t1 - c * (1 / y)

    // r_t2 = alpha_t2 - c * (x / y)
    r_t2_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_t2_out.bytes, r_t2_out.bytes, to_bytes(x));  // x / y
    sc_mulsub(r_t2_out.bytes, challenge.bytes, r_t2_out.bytes, alpha_t2.bytes);  // alpha_t2 - c * (x / y)

    // r_ki = alpha_ki - c * (z / y)
    r_ki_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_ki_out.bytes, r_ki_out.bytes, to_bytes(z));  // z / y
    sc_mulsub(r_ki_out.bytes, challenge.bytes, r_ki_out.bytes, alpha_ki.bytes);  // alpha_ki - c * (z / y)
}
//-------------------------------------------------------------------------------------------------------------------
// Element 'K_t1' for a proof
//   - multiplied by (1/8) for storage (and for use in byte-aware contexts)
// K_t1 = (1/y) * K
// return: (1/8)*K_t1
//-------------------------------------------------------------------------------------------------------------------
static void compute_K_t1_for_proof(const crypto::secret_key &y,
    const rct::key &K,
    rct::key &K_t1_out)
{
    rct::key inv_y{invert(rct::sk2rct(y))};
    sc_mul(inv_y.bytes, inv_y.bytes, rct::INV_EIGHT.bytes);
    rct::scalarmultKey(K_t1_out, K, inv_y);
}
//-------------------------------------------------------------------------------------------------------------------
// MuSig2--style bi-nonce signing merge factor
// rho_e = H_n(m, alpha_1_1, alpha_2_1, ..., alpha_1_N, alpha_2_N)
//-------------------------------------------------------------------------------------------------------------------
static rct::key multisig_binonce_merge_factor(const rct::key &message,
    const std::vector<sp_multisig_binonce_factors> &nonces)
{
    // build hash
    SpTranscript transcript{config::HASH_KEY_MULTISIG_BINONCE_MERGE_FACTOR, (1 + 2 * nonces.size()) * sizeof(rct::key)};
    transcript.append("message", message);
    transcript.append("nonces", nonces);

    rct::key merge_factor;
    sp_hash_to_scalar(transcript, merge_factor.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(merge_factor.bytes), "Binonce merge factor must be nonzero!");

    return merge_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCompositionProof &container, SpTranscript &transcript_inout)
{
    transcript_inout.append("c", container.c);
    transcript_inout.append("r_t1", container.r_t1);
    transcript_inout.append("r_t2", container.r_t2);
    transcript_inout.append("r_ki", container.r_ki);
    transcript_inout.append("K_t1", container.K_t1);
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(!(K == rct::identity()), "Bad proof key (K identity)!");

    // x == 0 is allowed
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(x)) == 0, "Bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)), "Bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(y)) == 0, "Bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z)), "Bad private key (z zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(z)) == 0, "Bad private key (z)!");

    // verify the input key matches the input private keys
    rct::key temp_K;
    make_seraphis_spendbase(z, temp_K);
    extend_seraphis_spendkey(y, temp_K);
    mask_key(x, temp_K, temp_K);

    CHECK_AND_ASSERT_THROW_MES(K == temp_K, "Bad proof key (K doesn't match privkeys)!");

    const rct::key &U_gen{get_U_gen()};

    SpCompositionProof proof;


    /// make K_t1 and KI

    // K_t1 = (1/8) * (1/y) * K
    compute_K_t1_for_proof(y, K, proof.K_t1);

    // KI = (z / y) * U
    // note: plain KI is used in all byte-aware contexts
    crypto::key_image KI;
    make_seraphis_key_image(y, z, KI);


    /// signature openers

    // alpha_t1 * K
    crypto::secret_key alpha_t1;
    rct::key alpha_t1_pub;
    generate_proof_nonce(K, alpha_t1, alpha_t1_pub);

    // alpha_t2 * G
    crypto::secret_key alpha_t2;
    rct::key alpha_t2_pub;
    generate_proof_nonce(rct::G, alpha_t2, alpha_t2_pub);

    // alpha_ki * U
    crypto::secret_key alpha_ki;
    rct::key alpha_ki_pub;
    generate_proof_nonce(U_gen, alpha_ki, alpha_ki_pub);


    /// compute proof challenge
    const rct::key m{compute_challenge_message(message, K, KI, proof.K_t1)};
    proof.c = compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    compute_responses(proof.c,
        rct::sk2rct(alpha_t1),
        rct::sk2rct(alpha_t2),
        rct::sk2rct(alpha_ki),
        x,
        y,
        z,
        proof.r_t1,
        proof.r_t2,
        proof.r_ki);


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t1.bytes) == 0, "Bad response (r_t1)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t2.bytes) == 0, "Bad response (r_t2)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_ki.bytes) == 0, "Bad response (r_ki)!");

    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(KI) == rct::identity()), "Invalid key image!");


    /// challenge message
    const rct::key m{compute_challenge_message(message, K, KI, proof.K_t1)};


    /// challenge pieces

    rct::key part_t1, part_t2, part_ki;
    ge_p3 K_p3, K_t1_p3, K_t2_p3, KI_p3;

    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;
    ge_p2 temp_p2;
    ge_dsmp temp_dsmp;

    // get K
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&K_p3, K.bytes) == 0, "ge_frombytes_vartime failed!");

    // get K_t1
    rct::scalarmult8(K_t1_p3, proof.K_t1);
    CHECK_AND_ASSERT_THROW_MES(!(ge_p3_is_point_at_infinity_vartime(&K_t1_p3)), "Invalid proof element K_t1!");

    // get KI
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&KI_p3, rct::ki2rct(KI).bytes) == 0, "ge_frombytes_vartime failed!");

    // K_t2 = K_t1 - X - KI
    ge_p3_to_cached(&temp_cache, &get_X_p3_gen());
    ge_sub(&temp_p1p1, &K_t1_p3, &temp_cache);  //K_t1 - X
    ge_p1p1_to_p3(&K_t2_p3, &temp_p1p1);
    ge_p3_to_cached(&temp_cache, &KI_p3);
    ge_sub(&temp_p1p1, &K_t2_p3, &temp_cache);  //(K_t1 - X) - KI
    ge_p1p1_to_p3(&K_t2_p3, &temp_p1p1);

    // K_t1 part: [r_t1 * K + c * K_t1]
    ge_dsm_precomp(temp_dsmp, &K_t1_p3);
    ge_double_scalarmult_precomp_vartime(&temp_p2, proof.r_t1.bytes, &K_p3, proof.c.bytes, temp_dsmp);
    ge_tobytes(part_t1.bytes, &temp_p2);

    // K_t2 part: [r_t2 * G + c * K_t2]
    ge_double_scalarmult_base_vartime(&temp_p2, proof.c.bytes, &K_t2_p3, proof.r_t2.bytes);
    ge_tobytes(part_t2.bytes, &temp_p2);

    // KI part:   [r_ki * U + c * KI  ]
    ge_dsm_precomp(temp_dsmp, &KI_p3);
    ge_double_scalarmult_precomp_vartime(&temp_p2, proof.r_ki.bytes, &(get_U_p3_gen()), proof.c.bytes, temp_dsmp);
    ge_tobytes(part_ki.bytes, &temp_p2);


    /// compute nominal challenge
    const rct::key challenge_nom{compute_challenge(m, part_t1, part_t2, part_ki)};


    /// validate proof
    return challenge_nom == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// multisig
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool SpCompositionProofMultisigNonceRecord::has_record(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter) const
{
    return m_record.find(message) != m_record.end() &&
        m_record.at(message).find(proof_key) != m_record.at(message).end() &&
        m_record.at(message).at(proof_key).find(filter) != m_record.at(message).at(proof_key).end();
}
//-------------------------------------------------------------------------------------------------------------------
bool SpCompositionProofMultisigNonceRecord::try_add_nonces(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter,
    const SpCompositionProofMultisigPrep &prep)
{
    if (has_record(message, proof_key, filter))
        return false;

    // add record
    m_record[message][proof_key][filter] = prep;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpCompositionProofMultisigNonceRecord::try_get_recorded_nonce_privkeys(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter,
    crypto::secret_key &nonce_privkey_1_out,
    crypto::secret_key &nonce_privkey_2_out) const
{
    if (!has_record(message, proof_key, filter))
        return false;

    // privkeys
    nonce_privkey_1_out = m_record.at(message).at(proof_key).at(filter).signature_nonce_1_KI_priv;
    nonce_privkey_2_out = m_record.at(message).at(proof_key).at(filter).signature_nonce_2_KI_priv;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpCompositionProofMultisigNonceRecord::try_get_recorded_nonce_pubkeys(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter,
    SpCompositionProofMultisigPubNonces &nonce_pubkeys_out) const
{
    if (!has_record(message, proof_key, filter))
        return false;

    // pubkeys
    nonce_pubkeys_out = m_record.at(message).at(proof_key).at(filter).signature_nonces_KI_pub;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpCompositionProofMultisigNonceRecord::try_remove_record(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter)
{
    if (!has_record(message, proof_key, filter))
        return false;

    // cleanup
    m_record[message][proof_key].erase(filter);
    if (m_record[message][proof_key].empty())
        m_record[message].erase(proof_key);
    if (m_record[message].empty())
        m_record.erase(message);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI)
{
    /// assemble proposal
    SpCompositionProofMultisigProposal proposal;

    proposal.message = message;
    proposal.K = K;
    proposal.KI = KI;

    rct::key dummy;
    generate_proof_nonce(K, proposal.signature_nonce_K_t1, dummy);
    generate_proof_nonce(rct::G, proposal.signature_nonce_K_t2, dummy);

    return proposal;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPrep sp_composition_multisig_init()
{
    SpCompositionProofMultisigPrep prep;

    // alpha_{ki,1,e}*U
    // store with (1/8)
    const rct::key &U{get_U_gen()};
    generate_proof_nonce(U, prep.signature_nonce_1_KI_priv, prep.signature_nonces_KI_pub.signature_nonce_1_KI_pub);
    rct::scalarmultKey(prep.signature_nonces_KI_pub.signature_nonce_1_KI_pub,
        prep.signature_nonces_KI_pub.signature_nonce_1_KI_pub,
        rct::INV_EIGHT);

    // alpha_{ki,2,e}*U
    // store with (1/8)
    generate_proof_nonce(U, prep.signature_nonce_2_KI_priv, prep.signature_nonces_KI_pub.signature_nonce_2_KI_pub);
    rct::scalarmultKey(prep.signature_nonces_KI_pub.signature_nonce_2_KI_pub,
        prep.signature_nonces_KI_pub.signature_nonce_2_KI_pub,
        rct::INV_EIGHT);

    return prep;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<SpCompositionProofMultisigPubNonces> &signer_pub_nonces,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv)
{
    /// input checks and initialization
    const std::size_t num_signers{signer_pub_nonces.size()};

    CHECK_AND_ASSERT_THROW_MES(!(proposal.K == rct::identity()), "Bad proof key (K identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(proposal.KI) == rct::identity()), "Bad proof key (KI identity)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.signature_nonce_K_t1)),
        "Bad private key (proposal nonce K_t1 zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.signature_nonce_K_t1)) == 0,
        "Bad private key (proposal nonce K_t1)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.signature_nonce_K_t2)),
        "Bad private key (proposal nonce K_t2 zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.signature_nonce_K_t2)) == 0,
        "Bad private key (proposal nonce K_t2)!");

    // x == 0 is allowed
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(x)) == 0, "Bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)), "Bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(y)) == 0, "Bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z_e)), "Bad private key (z_e zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(z_e)) == 0, "Bad private key (z)!");

    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_1_priv)) == 0, "Bad private key (local_nonce_1_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_1_priv)), "Bad private key (local_nonce_1_priv zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_2_priv)) == 0, "Bad private key (local_nonce_2_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_2_priv)), "Bad private key (local_nonce_2_priv zero)!");

    // prepare participant nonces
    std::vector<sp_multisig_binonce_factors> signer_nonces_pub_mul8;
    signer_nonces_pub_mul8.reserve(num_signers);

    for (const SpCompositionProofMultisigPubNonces &signer_pub_nonce_pair : signer_pub_nonces)
    {
        signer_nonces_pub_mul8.emplace_back();
        signer_nonces_pub_mul8.back().nonce_1 = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_1_KI_pub);
        signer_nonces_pub_mul8.back().nonce_2 = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_2_KI_pub);

        CHECK_AND_ASSERT_THROW_MES(!(signer_nonces_pub_mul8.back().nonce_1 == rct::identity()),
            "Bad signer nonce (alpha_1 identity)!");
        CHECK_AND_ASSERT_THROW_MES(!(signer_nonces_pub_mul8.back().nonce_2 == rct::identity()),
            "Bad signer nonce (alpha_2 identity)!");
    }

    // sort participant nonces so binonce merge factor is deterministic
    std::sort(signer_nonces_pub_mul8.begin(), signer_nonces_pub_mul8.end());

    // check that the local signer's signature opening is in the input set of opening nonces
    const rct::key U_gen{get_U_gen()};
    sp_multisig_binonce_factors local_nonce_pubs;
    rct::scalarmultKey(local_nonce_pubs.nonce_1, U_gen, rct::sk2rct(local_nonce_1_priv));
    rct::scalarmultKey(local_nonce_pubs.nonce_2, U_gen, rct::sk2rct(local_nonce_2_priv));

    CHECK_AND_ASSERT_THROW_MES(std::find(signer_nonces_pub_mul8.begin(),
            signer_nonces_pub_mul8.end(),
            local_nonce_pubs) != signer_nonces_pub_mul8.end(),
        "Local signer's opening nonces not in input set!");


    /// prepare partial signature
    SpCompositionProofMultisigPartial partial_sig;

    // set partial sig pieces
    partial_sig.message = proposal.message;
    partial_sig.K = proposal.K;
    partial_sig.KI = proposal.KI;

    // make K_t1 = (1/8) * (1/y) * K
    compute_K_t1_for_proof(y, proposal.K, partial_sig.K_t1);


    /// challenge message and binonce merge factor
    const rct::key m{compute_challenge_message(partial_sig.message, partial_sig.K, partial_sig.KI, partial_sig.K_t1)};

    const rct::key binonce_merge_factor{multisig_binonce_merge_factor(m, signer_nonces_pub_mul8)};


    /// signature openers

    // alpha_t1 * K
    rct::key alpha_t1_pub;
    rct::scalarmultKey(alpha_t1_pub, partial_sig.K, rct::sk2rct(proposal.signature_nonce_K_t1));

    // alpha_t2 * G
    rct::key alpha_t2_pub;
    rct::scalarmultKey(alpha_t2_pub, rct::G, rct::sk2rct(proposal.signature_nonce_K_t2));

    // alpha_ki * U
    // - MuSig2-style merged nonces from all multisig participants

    // alpha_ki_1 = sum(alpha_ki_1_e * U)
    rct::key alpha_ki_pub{rct::identity()};

    // alpha_ki_2 * U = rho * sum(alpha_ki_2_e * U)
    // rho = H_n(m, {alpha_ki_1_e * U}, {alpha_ki_2_e * U})   (binonce merge factor)
    rct::key alpha_ki_2_pub{rct::identity()};

    for (const sp_multisig_binonce_factors &nonce_pair : signer_nonces_pub_mul8)
    {
        rct::addKeys(alpha_ki_pub, alpha_ki_pub, nonce_pair.nonce_1);
        rct::addKeys(alpha_ki_2_pub, alpha_ki_2_pub, nonce_pair.nonce_2);
    }

    rct::scalarmultKey(alpha_ki_2_pub, alpha_ki_2_pub, binonce_merge_factor);

    // alpha_ki * U = alpha_ki_1 + alpha_ki_2
    rct::addKeys(alpha_ki_pub, alpha_ki_pub, alpha_ki_2_pub);


    /// compute proof challenge
    partial_sig.c = compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    crypto::secret_key merged_nonce_KI_priv;  // alpha_1_local + rho * alpha_2_local
    sc_muladd(to_bytes(merged_nonce_KI_priv),
        to_bytes(local_nonce_2_priv),
        binonce_merge_factor.bytes,
        to_bytes(local_nonce_1_priv));

    compute_responses(partial_sig.c,
            rct::sk2rct(proposal.signature_nonce_K_t1),
            rct::sk2rct(proposal.signature_nonce_K_t2),
            rct::sk2rct(merged_nonce_KI_priv),  // for partial signature
            x,
            y,
            z_e,  // for partial signature
            partial_sig.r_t1,
            partial_sig.r_t2,
            partial_sig.r_ki_partial  // partial response
        );


    /// done
    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_sp_composition_multisig_partial_sig(
    const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<SpCompositionProofMultisigPubNonces> &signer_pub_nonces,
    const multisig::signer_set_filter filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpCompositionProofMultisigPartial &partial_sig_out)
{
    // get the nonce privkeys to sign with
    crypto::secret_key nonce_privkey_1;
    crypto::secret_key nonce_privkey_2;
    if (!nonce_record_inout.try_get_recorded_nonce_privkeys(proposal.message,
        proposal.K,
        filter,
        nonce_privkey_1,
        nonce_privkey_2))
    {
        return false;
    }

    // make the partial signature
    SpCompositionProofMultisigPartial partial_sig_temp{
            sp_composition_multisig_partial_sig(
                proposal,
                x,
                y,
                z_e,
                signer_pub_nonces,
                nonce_privkey_1,
                nonce_privkey_2)
        };

    // clear the used nonces
    CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_remove_record(proposal.message, proposal.K, filter),
        "Sp composition proof: failed to clear nonces from nonce record (aborting partial signature)!");

    // set the output partial sig AFTER used nonces are cleared, in case of exception
    partial_sig_out = std::move(partial_sig_temp);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0, "No partial signatures to make proof out of!");

    // common parts between partial signatures should match
    for (const SpCompositionProofMultisigPartial &partial_sig : partial_sigs)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].c == partial_sig.c, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t1 == partial_sig.r_t1, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t2 == partial_sig.r_t2, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K_t1 == partial_sig.K_t1, "Input key sets don't match!");

        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K == partial_sig.K, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].KI == partial_sig.KI, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].message == partial_sig.message, "Input key sets don't match!");
    }


    /// assemble the final proof
    SpCompositionProof proof;

    proof.c = partial_sigs[0].c;
    proof.r_t1 = partial_sigs[0].r_t1;
    proof.r_t2 = partial_sigs[0].r_t2;

    proof.r_ki = rct::zero();
    for (const SpCompositionProofMultisigPartial &partial_sig : partial_sigs)
    {
        // sum of responses from each multisig participant
        sc_add(proof.r_ki.bytes, proof.r_ki.bytes, partial_sig.r_ki_partial.bytes);
    }

    proof.K_t1 = partial_sigs[0].K_t1;


    /// verify that proof assembly succeeded
    CHECK_AND_ASSERT_THROW_MES(sp_composition_verify(proof,
            partial_sigs[0].message,
            partial_sigs[0].K,
            partial_sigs[0].KI),
        "Multisig composition proof failed to verify on assembly!");


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
