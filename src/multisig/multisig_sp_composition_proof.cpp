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

//paired header
#include "multisig_sp_composition_proof.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig_nonce_cache.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//-------------------------------------------------------------------------------------------------------------------
// MuSig2-style bi-nonce signing merge factor
// rho_e = H_n(m, alpha_1_1*U, alpha_2_1*U, ..., alpha_1_N*U, alpha_2_N*U)
//-------------------------------------------------------------------------------------------------------------------
static rct::key multisig_binonce_merge_factor(const rct::key &message, const std::vector<MultisigPubNonces> &nonces)
{
    // build hash
    sp::SpKDFTranscript transcript{
            config::HASH_KEY_MULTISIG_BINONCE_MERGE_FACTOR,
            sizeof(rct::key) + nonces.size() * multisig_pub_nonces_size_bytes()
        };
    transcript.append("message", message);
    transcript.append("nonces", nonces);

    rct::key merge_factor;
    sp::sp_hash_to_scalar(transcript.data(), transcript.size(), merge_factor.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(merge_factor.bytes),
        "multisig sp composition proof: binonce merge factor must be nonzero!");

    return merge_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void signer_nonces_mul8(const MultisigPubNonces &signer_pub_nonce_pair, MultisigPubNonces &nonce_pair_mul8_out)
{
    nonce_pair_mul8_out.signature_nonce_1_pub = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_1_pub);
    nonce_pair_mul8_out.signature_nonce_2_pub = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_2_pub);

    CHECK_AND_ASSERT_THROW_MES(!(nonce_pair_mul8_out.signature_nonce_1_pub == rct::identity()),
        "multisig sp composition proof: bad signer nonce (alpha_1 identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(nonce_pair_mul8_out.signature_nonce_2_pub == rct::identity()),
        "multisig sp composition proof: bad signer nonce (alpha_2 identity)!");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    SpCompositionProofMultisigProposal &proposal_out)
{
    /// assemble proposal
    proposal_out.message = message;
    proposal_out.K       = K;
    proposal_out.KI      = KI;

    rct::key dummy;
    sp::generate_proof_nonce(K,      proposal_out.signature_nonce_K_t1, dummy);
    sp::generate_proof_nonce(rct::G, proposal_out.signature_nonce_K_t2, dummy);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    SpCompositionProofMultisigPartial &partial_sig_out)
{
    /// input checks and initialization
    const std::size_t num_signers{signer_pub_nonces.size()};

    CHECK_AND_ASSERT_THROW_MES(!(proposal.K == rct::identity()),
        "make sp composition multisig partial sig: bad proof key (K identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(proposal.KI) == rct::identity()),
        "make sp composition multisig partial sig: bad proof key (KI identity)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.signature_nonce_K_t1)),
        "make sp composition multisig partial sig: bad private key (proposal nonce K_t1 zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.signature_nonce_K_t1)) == 0,
        "make sp composition multisig partial sig: bad private key (proposal nonce K_t1)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.signature_nonce_K_t2)),
        "make sp composition multisig partial sig: bad private key (proposal nonce K_t2 zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.signature_nonce_K_t2)) == 0,
        "make sp composition multisig partial sig: bad private key (proposal nonce K_t2)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(x)),
        "make sp composition multisig partial sig: bad private key (x zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(x)) == 0,
        "make sp composition multisig partial sig: bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)),
        "make sp composition multisig partial sig: bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(y)) == 0,
        "make sp composition multisig partial sig: bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z_e)),
        "make sp composition multisig partial sig: bad private key (z_e zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(z_e)) == 0,
        "make sp composition multisig partial sig: bad private key (z)!");

    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_1_priv)) == 0,
        "make sp composition multisig partial sig: bad private key (local_nonce_1_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_1_priv)),
        "make sp composition multisig partial sig: bad private key (local_nonce_1_priv zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_2_priv)) == 0,
        "make sp composition multisig partial sig: bad private key (local_nonce_2_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_2_priv)),
        "make sp composition multisig partial sig: bad private key (local_nonce_2_priv zero)!");

    // prepare participant nonces
    std::vector<MultisigPubNonces> signer_pub_nonces_mul8;
    signer_pub_nonces_mul8.reserve(num_signers);

    for (const MultisigPubNonces &signer_pub_nonce_pair : signer_pub_nonces)
        signer_nonces_mul8(signer_pub_nonce_pair, tools::add_element(signer_pub_nonces_mul8));

    // sort participant nonces so binonce merge factor is deterministic
    std::sort(signer_pub_nonces_mul8.begin(), signer_pub_nonces_mul8.end());

    // check that the local signer's signature opening is in the input set of opening nonces
    MultisigPubNonces local_nonce_pubs;
    const rct::key U_gen{rct::pk2rct(crypto::get_U())};
    rct::scalarmultKey(local_nonce_pubs.signature_nonce_1_pub, U_gen, rct::sk2rct(local_nonce_1_priv));
    rct::scalarmultKey(local_nonce_pubs.signature_nonce_2_pub, U_gen, rct::sk2rct(local_nonce_2_priv));

    CHECK_AND_ASSERT_THROW_MES(
        std::find(signer_pub_nonces_mul8.begin(), signer_pub_nonces_mul8.end(), local_nonce_pubs) !=
            signer_pub_nonces_mul8.end(),
        "make sp composition multisig partial sig: local signer's opening nonces not in input set!");


    /// prepare partial signature

    // set partial sig pieces
    partial_sig_out.message = proposal.message;
    partial_sig_out.K       = proposal.K;
    partial_sig_out.KI      = proposal.KI;

    // make K_t1 = (1/8) * (1/y) * K
    sp::composition_proof_detail::compute_K_t1_for_proof(y, proposal.K, partial_sig_out.K_t1);


    /// challenge message and binonce merge factor
    // rho = H_n(m, {alpha_ki_1_e * U}, {alpha_ki_2_e * U})   (binonce merge factor)
    const rct::key m{
            sp::composition_proof_detail::compute_challenge_message(partial_sig_out.message,
                partial_sig_out.K,
                partial_sig_out.KI,
                partial_sig_out.K_t1)
        };

    const rct::key binonce_merge_factor{multisig_binonce_merge_factor(m, signer_pub_nonces_mul8)};


    /// signature openers

    // alpha_t1 * K
    rct::key alpha_t1_pub;
    rct::scalarmultKey(alpha_t1_pub, partial_sig_out.K, rct::sk2rct(proposal.signature_nonce_K_t1));

    // alpha_t2 * G
    rct::key alpha_t2_pub;
    rct::scalarmultKey(alpha_t2_pub, rct::G, rct::sk2rct(proposal.signature_nonce_K_t2));

    // alpha_ki * U
    // - MuSig2-style merged nonces from all multisig participants

    // alpha_ki_1 * U = sum_e(alpha_ki_1_e * U)
    // alpha_ki_2 * U = rho * sum_e(alpha_ki_2_e * U)
    rct::key alpha_ki_1_pub{rct::identity()};
    rct::key alpha_ki_2_pub{rct::identity()};

    for (const MultisigPubNonces &nonce_pair : signer_pub_nonces_mul8)
    {
        rct::addKeys(alpha_ki_1_pub, alpha_ki_1_pub, nonce_pair.signature_nonce_1_pub);
        rct::addKeys(alpha_ki_2_pub, alpha_ki_2_pub, nonce_pair.signature_nonce_2_pub);
    }

    rct::scalarmultKey(alpha_ki_2_pub, alpha_ki_2_pub, binonce_merge_factor);  //rho * sum_e(alpha_ki_2_e * U)

    // alpha_ki * U = alpha_ki_1 * U + alpha_ki_2 * U
    const rct::key alpha_ki_pub{rct::addKeys(alpha_ki_1_pub, alpha_ki_2_pub)};


    /// compute proof challenge
    partial_sig_out.c = sp::composition_proof_detail::compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    crypto::secret_key merged_nonce_KI_priv;  //alpha_1_local + rho * alpha_2_local
    sc_muladd(to_bytes(merged_nonce_KI_priv),
        to_bytes(local_nonce_2_priv),
        binonce_merge_factor.bytes,
        to_bytes(local_nonce_1_priv));

    sp::composition_proof_detail::compute_responses(partial_sig_out.c,
            rct::sk2rct(proposal.signature_nonce_K_t1),
            rct::sk2rct(proposal.signature_nonce_K_t2),
            rct::sk2rct(merged_nonce_KI_priv),  //for partial signature
            x,
            y,
            z_e,  //for partial signature
            partial_sig_out.r_t1,
            partial_sig_out.r_t2,
            partial_sig_out.r_ki_partial  //partial response
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout,
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
        return false;

    // make the partial signature
    SpCompositionProofMultisigPartial partial_sig_temp;
    make_sp_composition_multisig_partial_sig(proposal,
        x,
        y,
        z_e,
        signer_pub_nonces,
        nonce_privkey_1,
        nonce_privkey_2,
        partial_sig_temp);

    // clear the used nonces
    CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_remove_record(proposal.message, proposal.K, filter),
        "try make sp composition proof multisig partial sig: failed to clear nonces from nonce record (aborting partial "
        "signature)!");

    // set the output partial sig AFTER used nonces are cleared, in case of exception
    partial_sig_out = std::move(partial_sig_temp);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_sp_composition_multisig_proof(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs,
    sp::SpCompositionProof &proof_out)
{
    /// input checks
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0,
        "finalize sp composition multisig proof: no partial signatures to make a proof out of!");

    // common parts between partial signatures should match
    for (const SpCompositionProofMultisigPartial &partial_sig : partial_sigs)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].message == partial_sig.message,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K == partial_sig.K,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].KI == partial_sig.KI,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].c == partial_sig.c,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t1 == partial_sig.r_t1,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t2 == partial_sig.r_t2,
            "finalize sp composition multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K_t1 == partial_sig.K_t1,
            "finalize sp composition multisig proof: input partial sigs don't match!");
    }


    /// assemble the final proof
    proof_out.c    = partial_sigs[0].c;
    proof_out.r_t1 = partial_sigs[0].r_t1;
    proof_out.r_t2 = partial_sigs[0].r_t2;

    proof_out.r_ki = rct::zero();  //sum of responses from each multisig participant
    for (const SpCompositionProofMultisigPartial &partial_sig : partial_sigs)
        sc_add(proof_out.r_ki.bytes, proof_out.r_ki.bytes, partial_sig.r_ki_partial.bytes);

    proof_out.K_t1 = partial_sigs[0].K_t1;


    /// verify that proof assembly succeeded
    CHECK_AND_ASSERT_THROW_MES(sp::verify_sp_composition_proof(proof_out,
            partial_sigs[0].message,
            partial_sigs[0].K,
            partial_sigs[0].KI),
        "finalize sp composition multisig proof: proof failed to verify on assembly!");
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
