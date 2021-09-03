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
#include "multisig_partial_sig_makers.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_log_ex.h"
#include "multisig_clsag.h"
#include "multisig_nonce_cache.h"
#include "multisig_signing_helper_types.h"
#include "multisig_signer_set_filter.h"
#include "multisig_sp_composition_proof.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//-------------------------------------------------------------------------------------------------------------------
// for local signer's partial proof key K_e = (k_offset + k_e)*G
// and secondary proof key C_z = z*G
//-------------------------------------------------------------------------------------------------------------------
static CLSAGMultisigPartial attempt_make_clsag_multisig_partial_sig(const rct::key &one_div_threshold,
    const crypto::secret_key &k_e,
    const crypto::secret_key &k_offset,
    const crypto::secret_key &z,
    const CLSAGMultisigProposal &proof_proposal,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const multisig::signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout)
{
    // prepare the main signing privkey: (1/threshold)*k_offset + k_e
    // note: k_offset is assumed to be a value known by all signers, so each signer adds (1/threshold)*k_offset to ensure
    //       the sum of partial signatures works out
    crypto::secret_key k_e_signing;
    sc_mul(to_bytes(k_e_signing), one_div_threshold.bytes, to_bytes(k_offset));  //(1/threshold)*k_offset
    sc_add(to_bytes(k_e_signing), to_bytes(k_e_signing), to_bytes(k_e));  //+ k_e

    // prepare the auxilliary signing key: (1/threshold)*z
    crypto::secret_key z_e_signing;
    sc_mul(to_bytes(z_e_signing), one_div_threshold.bytes, to_bytes(z));

    // local signer's partial sig for this proof key
    CLSAGMultisigPartial partial_sig;

    if (!try_make_clsag_multisig_partial_sig(proof_proposal,
            k_e_signing,
            z_e_signing,
            signer_pub_nonces_G,
            signer_pub_nonces_Hp,
            filter,
            nonce_record_inout,
            partial_sig))
        throw;

    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
// for local signer's partial proof key K_e = x*G + y*X + z_multiplier*( (1/threshold) * z_offset + z_e )*U
//-------------------------------------------------------------------------------------------------------------------
static SpCompositionProofMultisigPartial attempt_make_sp_composition_multisig_partial_sig(
    const rct::key &one_div_threshold,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_offset,
    const crypto::secret_key &z_multiplier,
    const crypto::secret_key &z_e,
    const SpCompositionProofMultisigProposal &proof_proposal,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const multisig::signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout)
{
    // prepare the signing privkey: z_multiplier*((1/threshold)*z_offset + z_e)
    // note: z_offset is assumed to be a value known by all signers, so each signer adds (1/threshold)*z_offset to ensure
    //       the sum of partial signatures works out
    crypto::secret_key z_e_signing;
    sc_mul(to_bytes(z_e_signing), one_div_threshold.bytes, to_bytes(z_offset));    //(1/threshold)*z_offset 
    sc_add(to_bytes(z_e_signing), to_bytes(z_e_signing), to_bytes(z_e));           //... + z_e
    sc_mul(to_bytes(z_e_signing), to_bytes(z_multiplier), to_bytes(z_e_signing));  //z_multiplier*(...)

    // local signer's partial sig for this proof key
    SpCompositionProofMultisigPartial partial_sig;

    if (!try_make_sp_composition_multisig_partial_sig(proof_proposal,
            x,
            y,
            z_e_signing,
            signer_pub_nonces,
            filter,
            nonce_record_inout,
            partial_sig))
        throw;

    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
MultisigPartialSigMakerCLSAG::MultisigPartialSigMakerCLSAG(const std::uint32_t threshold,
    const std::vector<CLSAGMultisigProposal> &proof_proposals,
    const std::vector<crypto::secret_key> &proof_privkeys_k_offset,
    const std::vector<crypto::secret_key> &proof_privkeys_z) :
        m_inv_threshold{threshold ? sp::invert(rct::d2h(threshold)) : rct::zero()},  //avoid throwing in call to invert()
        m_proof_proposals{proof_proposals},
        m_proof_privkeys_k_offset{proof_privkeys_k_offset},
        m_proof_privkeys_z{proof_privkeys_z}
{
    const std::size_t num_proposals{m_proof_proposals.size()};

    CHECK_AND_ASSERT_THROW_MES(threshold > 0,
        "MultisigPartialSigMakerCLSAG: multisig threshold is zero.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_k_offset.size() == num_proposals,
        "MultisigPartialSigMakerCLSAG: proof k offset privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_z.size() == num_proposals,
        "MultisigPartialSigMakerCLSAG: proof z privkeys don't line up with proof proposals.");

    // cache the proof keys mapped to indices in the referenced signature context data
    for (std::size_t signature_proposal_index{0}; signature_proposal_index < num_proposals; ++signature_proposal_index)
        m_cached_proof_keys[main_proof_key_ref(m_proof_proposals[signature_proposal_index])] = signature_proposal_index;
}
//-------------------------------------------------------------------------------------------------------------------
void MultisigPartialSigMakerCLSAG::attempt_make_partial_sig(const rct::key &proof_message,
    const rct::key &proof_key,
    const multisig::signer_set_filter signer_group_filter,
    const std::vector<std::vector<MultisigPubNonces>> &signer_group_pub_nonces,
    const crypto::secret_key &local_multisig_signing_key,
    MultisigNonceCache &nonce_record_inout,
    MultisigPartialSigVariant &partial_sig_out) const
{
    CHECK_AND_ASSERT_THROW_MES(m_cached_proof_keys.find(proof_key) != m_cached_proof_keys.end(),
        "MultisigPartialSigMakerCLSAG (attempt make partial sig): requested signature proposal's proof key is unknown.");
    CHECK_AND_ASSERT_THROW_MES(signer_group_pub_nonces.size() == 2,
        "MultisigPartialSigMakerCLSAG (attempt make partial sig): signer group's pub nonces don't line up with signature "
        "requirements (must be two sets for base keys G and Hp(proof key)).");

    const std::size_t signature_proposal_index{m_cached_proof_keys.at(proof_key)};

    CHECK_AND_ASSERT_THROW_MES(m_proof_proposals.at(signature_proposal_index).message == proof_message,
        "MultisigPartialSigMakerCLSAG (attempt make partial sig): proof message doesn't match with the requested "
        "proof proposal.");

    partial_sig_out = attempt_make_clsag_multisig_partial_sig(m_inv_threshold,
        local_multisig_signing_key,
        m_proof_privkeys_k_offset.at(signature_proposal_index),
        m_proof_privkeys_z.at(signature_proposal_index),
        m_proof_proposals.at(signature_proposal_index),
        signer_group_pub_nonces.at(0),  //G
        signer_group_pub_nonces.at(1),  //Hp(proof key)
        signer_group_filter,
        nonce_record_inout);
}
//-------------------------------------------------------------------------------------------------------------------
MultisigPartialSigMakerSpCompositionProof::MultisigPartialSigMakerSpCompositionProof(const std::uint32_t threshold,
    const std::vector<SpCompositionProofMultisigProposal> &proof_proposals,
    const std::vector<crypto::secret_key> &proof_privkeys_x,
    const std::vector<crypto::secret_key> &proof_privkeys_y,
    const std::vector<crypto::secret_key> &proof_privkeys_z_offset,
    const std::vector<crypto::secret_key> &proof_privkeys_z_multiplier) :
        m_inv_threshold{threshold ? sp::invert(rct::d2h(threshold)) : rct::zero()},  //avoid throwing in call to invert()
        m_proof_proposals{proof_proposals},
        m_proof_privkeys_x{proof_privkeys_x},
        m_proof_privkeys_y{proof_privkeys_y},
        m_proof_privkeys_z_offset{proof_privkeys_z_offset},
        m_proof_privkeys_z_multiplier{proof_privkeys_z_multiplier}
{
    const std::size_t num_proposals{m_proof_proposals.size()};

    CHECK_AND_ASSERT_THROW_MES(threshold > 0,
        "MultisigPartialSigMakerSpCompositionProof: multisig threshold is zero.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_x.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof x privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_y.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof y privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_z_offset.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof z_offset privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_z_multiplier.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof z_multiplier privkeys don't line up with proof proposals.");

    // cache the proof keys mapped to indices in the referenced signature context data
    for (std::size_t signature_proposal_index{0}; signature_proposal_index < num_proposals; ++signature_proposal_index)
        m_cached_proof_keys[m_proof_proposals[signature_proposal_index].K] = signature_proposal_index;
}
//-------------------------------------------------------------------------------------------------------------------
void MultisigPartialSigMakerSpCompositionProof::attempt_make_partial_sig(const rct::key &proof_message,
    const rct::key &proof_key,
    const multisig::signer_set_filter signer_group_filter,
    const std::vector<std::vector<MultisigPubNonces>> &signer_group_pub_nonces,
    const crypto::secret_key &local_multisig_signing_key,
    MultisigNonceCache &nonce_record_inout,
    MultisigPartialSigVariant &partial_sig_out) const
{
    CHECK_AND_ASSERT_THROW_MES(m_cached_proof_keys.find(proof_key) != m_cached_proof_keys.end(),
        "MultisigPartialSigMakerSpCompositionProof (attempt make partial sig): requested signature proposal's proof key "
        "is unknown.");
    CHECK_AND_ASSERT_THROW_MES(signer_group_pub_nonces.size() == 1,
        "MultisigPartialSigMakerSpCompositionProof (attempt make partial sig): signer group's pub nonces don't line up with "
        "signature requirements (must be one set for base key U).");

    const std::size_t signature_proposal_index{m_cached_proof_keys.at(proof_key)};

    CHECK_AND_ASSERT_THROW_MES(m_proof_proposals.at(signature_proposal_index).message == proof_message,
        "MultisigPartialSigMakerCLSAG (attempt make partial sig): proof message doesn't match with the requested "
        "proof proposal.");

    partial_sig_out = attempt_make_sp_composition_multisig_partial_sig(m_inv_threshold,
        m_proof_privkeys_x.at(signature_proposal_index),
        m_proof_privkeys_y.at(signature_proposal_index),
        m_proof_privkeys_z_offset.at(signature_proposal_index),
        m_proof_privkeys_z_multiplier.at(signature_proposal_index),
        local_multisig_signing_key,
        m_proof_proposals.at(signature_proposal_index),
        signer_group_pub_nonces.at(0),
        signer_group_filter,
        nonce_record_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
