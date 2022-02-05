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

// Seraphis tx-builder/component-builder implementations
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: align_v1_tx_membership_proofs_sp_v1 - rearrange membership proofs so they line up with a set of input images
*   sort order: key images ascending with byte-wise comparisons
* param: input_images -
* inparam: tx_membership_proofs_sortable_in -
* outparam: tx_membership_proofs_out -
*/
void align_v1_tx_membership_proofs_sp_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_sortable_in,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out);
/**
* brief: get_tx_membership_proof_message_sp_v1 - message for membership proofs
*   - H(crypto project name, enote ledger references)
* TODO: use a real reference system instead of plain indices
* param - enote_ledger_indices
* return: empty message for a membership proof
*/
rct::key get_tx_membership_proof_message_sp_v1(const std::vector<std::size_t> &enote_ledger_indices);
/**
* brief: prepare_input_commitment_factors_for_balance_proof_v1 - collect input amounts and input image amount
*   commitment blinding factors
* param: input_proposals -
* param: image_address_masks -
* outparam: blinding_factors_out -
* outparam: input_amounts_out -
*/
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_address_masks,
    std::vector<crypto::secret_key> &blinding_factors_out,
    std::vector<rct::xmr_amount> &input_amounts_out);
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<crypto::secret_key> &blinding_factors_out,
    std::vector<rct::xmr_amount> &input_amounts_out);
/**
* brief: make_v1_tx_image_proof_sp_v1 - make a v1 tx input image proof (seraphis composition proof) (squashed enote model)
* param: input_proposal -
* param: masked_address -
* param: message -
* outparam: tx_image_proof_out -
*/
void make_v1_tx_image_proof_sp_v1(const SpInputProposal &input_proposal,
    const rct::key &masked_address,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_out);
/**
* brief: make_v1_tx_image_proofs_sp_v1 - make v1 tx input image proofs (seraphis composition proofs: 1 per input)
*   (squashed enote model)
* param: input_proposals -
* param: input_images -
* param: message -
* outparam: tx_image_proofs_out -
*/
void make_v1_tx_image_proofs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpEnoteImageV1> &input_images,
    const rct::key &message,
    std::vector<SpImageProofV1> &tx_image_proofs_out);
/**
* brief: make_v1_tx_membership_proof_sp_v1 - make a v1 membership proof (concise grootle) (squashed enote model)
* param: membership_ref_set -
* param: image_address_mask -
* param: image_amount_mask -
* outparam: tx_membership_proof_out -
*/
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &tx_membership_proof_out);
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofSortableV1 &tx_membership_proof_out);
/**
* brief: make_v1_tx_membership_proofs_sp_v1 - make v1 membership proofs (concise grootle: 1 per input)
*   (squashed enote model)
* param: membership_ref_sets -
* param: image_address_masks -
* param: image_amount_masks -
* outparam: tx_membership_proofs_out -
*/
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out);
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out);
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SpTxPartialV1 &partial_tx,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out);
/**
* brief: make_v1_tx_partial_inputs_sp_v1 - make a full set of v1 partial inputs
* param: input_proposals -
* param: proposal_prefix -
* outparam: partial_inputs_out -
*/
void make_v1_tx_partial_inputs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    std::vector<SpTxPartialInputV1> &partial_inputs_out);
/**
* brief: gen_mock_sp_input_proposals_v1 - create random mock inputs
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts);
/**
* brief: gen_mock_sp_membership_ref_sets_v1 - create random reference sets for tx inputs, with real spend at a random index,
*   and update mock ledger to include all members of the reference set (including squashed enotes)
* param: input_proposals -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: set of membership proof reference sets
*/
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpEnoteV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);

} //namespace sp
