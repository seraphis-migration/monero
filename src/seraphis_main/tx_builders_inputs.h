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

// Seraphis tx-builder/component-builder implementations (tx inputs).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "enote_record_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: make_input_images_prefix_v1 - hash of enote images (for tx hashes)
*   - H_32({C", KI}((legacy)), {K", C", KI})
* param: legacy_enote_images -
* param: sp_enote_images -
* outparam: input_images_prefix_out -
*/
void make_input_images_prefix_v1(const std::vector<LegacyEnoteImageV2> &legacy_enote_images,
    const std::vector<SpEnoteImageV1> &sp_enote_images,
    rct::key &input_images_prefix_out);
/**
* brief: check_v1_input_proposal_semantics_v1 - check the semantics of a seraphis v1 input proposal
*   - throws on failure
* param: input_proposal -
* param: sp_core_spend_pubkey -
* param: k_view_balance -
*/
void check_v1_input_proposal_semantics_v1(const SpInputProposalCore &input_proposal,
    const rct::key &sp_core_spend_pubkey,
    const crypto::secret_key &k_view_balance);
void check_v1_input_proposal_semantics_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &sp_core_spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: make_input_proposal - make the core of a seraphis input proposal
* param: enote_core -
* param: key_image -
* param: enote_view_extension_g -
* param: enote_view_extension_x -
* param: enote_view_extension_u -
* param: input_amount_blinding_factor -
* param: input_amount -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_input_proposal(const SpEnoteCore &enote_core,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_extension_g,
    const crypto::secret_key &enote_view_extension_x,
    const crypto::secret_key &enote_view_extension_u,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalCore &proposal_out);
/**
* brief: make_v1_input_proposal_v1 - make a seraphis v1 input proposal
* param: enote_record -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out);
/**
* brief: try_make_v1_input_proposal_v1 - try to make a seraphis v1 input proposal from an enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: input_context -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
bool try_make_v1_input_proposal_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out);
/**
* brief: make_standard_input_context_v1 - compute an input context for non-coinbase transactions
* param: legacy_input_proposals -
* param: sp_input_proposals -
* outparam: input_context_out -
*/
void make_standard_input_context_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    rct::key &input_context_out);
void make_standard_input_context_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    rct::key &input_context_out);
/**
* brief: make_v1_image_proof_v1 - make a seraphis composition proof for an enote image in the squashed enote model
* param: input_proposal -
* param: message -
* param: sp_spend_privkey -
* param: k_view_balance -
* outparam: image_proof_out -
*/
void make_v1_image_proof_v1(const SpInputProposalCore &input_proposal,
    const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    SpImageProofV1 &image_proof_out);
/**
* brief: make_v1_image_proofs_v1 - make a set of seraphis composition proofs for enote images in the squashed enote model
* param: input_proposals -
* param: message -
* param: sp_spend_privkey -
* param: k_view_balance -
* outparam: image_proofs_out -
*/
void make_v1_image_proofs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpImageProofV1> &image_proofs_out);
/**
* brief: check_v1_partial_input_semantics_v1 - check the semantics of a v1 partial seraphis input
*   - throws on failure
* param: partial_input -
*/
void check_v1_partial_input_semantics_v1(const SpPartialInputV1 &partial_input);
/**
* brief: make_v1_partial_input_v1 - make a v1 partial seraphis input
* param: input_proposal -
* param: tx_proposal_prefix -
* param: sp_image_proof -
* param: sp_core_spend_pubkey -
* param: k_view_balance -
* outparam: partial_input_out -
*/
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &tx_proposal_prefix,
    SpImageProofV1 sp_image_proof,
    const rct::key &sp_core_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialInputV1 &partial_input_out);
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &tx_proposal_prefix,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    SpPartialInputV1 &partial_input_out);
/**
* brief: make_v1_partial_inputs_v1 - make a full set of v1 partial inputs
* param: input_proposals -
* param: tx_proposal_prefix -
* param: sp_spend_privkey -
* param: k_view_balance -
* outparam: partial_inputs_out -
*/
void make_v1_partial_inputs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &tx_proposal_prefix,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpPartialInputV1> &partial_inputs_out);
/**
* brief: get_input_commitment_factors_v1 - collect input amounts and input image amount commitment blinding factors
* param: input_proposals -
* outparam: input_amounts_out -
* outparam: blinding_factors_out -
*/
void get_input_commitment_factors_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
void get_input_commitment_factors_v1(const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
/**
* brief: make_binned_ref_set_generator_seed_v1 - compute a generator seed for making a binned reference set
*   seed = H_32(K", C")
*   note: depending on the enote image ensures the seed is a function of some 'random' information that is always
*         available to both tx authors and validators (i.e. the masks, which are embedded in the image); seraphis
*         membership proofs can be constructed in isolation, in which case only the real reference and the masks are
*         available (so there are no other options for entropy without passing additional bytes around)
* param: masked_address -
* param: masked_commitment -
* outparam: generator_seed_out -
*/
void make_binned_ref_set_generator_seed_v1(const rct::key &masked_address,
    const rct::key &masked_commitment,
    rct::key &generator_seed_out);
void make_binned_ref_set_generator_seed_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &generator_seed_out);
/**
* brief: make_tx_membership_proof_message_v1 - message to sign in seraphis membership proofs used in a transaction
*   - H_32({binned reference set})
* param: binned_reference_set -
* outparam: message_out - the message to sign in a membership proof
*/
void make_tx_membership_proof_message_v1(const SpBinnedReferenceSetV1 &binned_reference_set, rct::key &message_out);
/**
* brief: make_v1_membership_proof_v1 - make a grootle membership proof in the squashed enote model
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* param: binned_reference_set -
* param: referenced_enotes_squashed -
* param: real_spend_index_in_set -
* param: real_reference_enote -
* param: image_address_mask -
* param: image_commitment_mask -
* outparam: membership_proof_out -
*/
void make_v1_membership_proof_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpBinnedReferenceSetV1 binned_reference_set,
    const std::vector<rct::key> &referenced_enotes_squashed,
    const std::size_t real_spend_index_in_set,
    const SpEnoteCoreVariant &real_reference_enote,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_commitment_mask,
    SpMembershipProofV1 &membership_proof_out);
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep, SpMembershipProofV1 &membership_proof_out);
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpMembershipProofV1> &membership_proofs_out);
/**
* brief: make_v1_alignable_membership_proof_v1 - make an alignable membership proof (alignable means it can be aligned
*   with the corresponding enote image at a later time)
* param: membership_proof_prep -
* outparam: alignable_membership_proof_out -
*/
void make_v1_alignable_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep,
    SpAlignableMembershipProofV1 &alignable_membership_proof_out);
void make_v1_alignable_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proof_out);
/**
* brief: align_v1_membership_proofs_v1 - rearrange seraphis membership proofs so they line up with a set of input images
* param: input_images -
* param: membership_proofs_alignable -
* outparam: membership_proofs_out -
*/
void align_v1_membership_proofs_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpAlignableMembershipProofV1> membership_proofs_alignable,
    std::vector<SpMembershipProofV1> &membership_proofs_out);

} //namespace sp
