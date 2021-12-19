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
#include "sp_base_types.h"
#include "sp_tx_builder_types.h"
#include "sp_tx_component_types.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: get_tx_membership_proof_message_sp_v1 - message for membership proofs
*   - H(crypto project name, enote ledger references)
* TODO: use a real reference system instead of plain indices
* param - enote_ledger_indices
* return: empty message for a membership proof
*/
rct::key get_tx_membership_proof_message_sp_v1(const std::vector<std::size_t> &enote_ledger_indices);
/**
* brief: get_tx_image_proof_message_sp_v1 - message for tx image proofs
*   - H(crypto project name, version string, output enotes, enote pubkeys)
* param: version_string -
* param: output_enotes -
* param: tx_supplement -
* return: message to insert in a tx image proof
*/
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<SpENoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement);
/**
* brief: get_tx_input_sort_order_v1 - get mapping new_index:old_index for sorting of inputs
*    - sort order: key images ascending with byte-wise comparisons
* param: partial_inputs/input_images/input_key_images - key image sorces
* return: vector of indices into the input vector; at new position 'i' place old element in_vec[out_vec[i]]
*/
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<SpTxPartialInputV1> &partial_inputs);
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<SpENoteImageV1> &input_images);
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<crypto::key_image> &input_key_images);
/**
* brief: sort_tx_inputs_sp_v1 - sort tx inputs
*   sort order: key images ascending with byte-wise comparisons
* param: tx_membership_proofs_sortable -
* outparam: tx_membership_proofs_out -
* inoutparam: input_images_inout -
* inoutparam: tx_image_proofs_inout -
*/
void sort_tx_inputs_sp_v1(const std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_sortable,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out,
    std::vector<SpENoteImageV1> &input_images_inout,
    std::vector<SpImageProofV1> &tx_image_proofs_inout);
/**
* brief: sort_tx_inputs_sp_v2 - sort tx inputs BEFORE making any input proofs
*   - designed for SpTxTypeMerge, where all input image proofs are merged into one structure (so sort order must be known)
*   sort order: key images ascending with byte-wise comparisons
* inoutparam: input_images_inout -
* inoutparam: image_address_masks_inout -
* inoutparam: image_amount_masks_inout -
* inoutparam: membership_ref_sets_inout -
* inoutparam: input_proposals_inout -
*/
void sort_tx_inputs_sp_v2(std::vector<SpENoteImageV1> &input_images_inout,
    std::vector<crypto::secret_key> &image_address_masks_inout,
    std::vector<crypto::secret_key> &image_amount_masks_inout,
    std::vector<SpMembershipReferenceSetV1> &membership_ref_sets_inout,
    std::vector<SpInputProposalV1> &input_proposals_inout);
/**
* brief: align_v1_tx_membership_proofs_sp_v1 - rearrange membership proofs so they line up with a set of input images
*   sort order: key images ascending with byte-wise comparisons
* param: input_images -
* inparam: tx_membership_proofs_sortable_in -
* outparam: tx_membership_proofs_out -
*/
void align_v1_tx_membership_proofs_sp_v1(const std::vector<SpENoteImageV1> &input_images,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_sortable_in,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out);
/**
* brief: prepare_input_commitment_factors_for_balance_proof_v1 - collect input amounts and input image amount
*   commitment blinding factors
* param: input_proposals -
* param: image_address_masks -
* outparam: input_amounts_out -
* outparam: input_image_amount_commitment_blinding_factors_out -
*/
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_address_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out);
/**
* brief: prepare_input_commitment_factors_for_balance_proof_v2 - collect input image amount commitment blinding
*   factors from partial inputs
* param: partial_inputs -
* outparam: input_image_amount_commitment_blinding_factors_out -
*/
void prepare_input_commitment_factors_for_balance_proof_v2(
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out);
/**
* brief: make_v1_tx_outputs_sp_v1 - make v1 tx outputs
*   TODO: special treatment of change dest for 2-out tx (expect both outputs to have same enote pub key, only store 1)
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* inoutparam: tx_supplement_inout -
*/
void make_v1_tx_outputs_sp_v1(const std::vector<SpDestinationV1> &destinations,
    std::vector<SpENoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    SpTxSupplementV1 &tx_supplement_inout);
/**
* brief: make_v1_tx_image_sp_v1 - make all v1 input images for a tx EXCEPT LAST
* param: input_proposal -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_sp_v1(const SpInputProposalV1 &input_proposal,
    SpENoteImageV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_image_sp_v2 - make all v1 input images for a tx EXCEPT LAST (squashed enote model)
* param: input_proposal -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_sp_v2(const SpInputProposalV1 &input_proposal,
    SpENoteImageV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_image_last_sp_v1 - make LAST v1 input image for a tx
*   - last amount commitment total blinding factor (v_c) equals sum of output amount blinding factors (y_t)
*      minus sum input blinding factors (v_c_except_last)
* param: input_proposal -
* param: output_amount_commitment_blinding_factors -
* param: input_amount_blinding_factors -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_last_sp_v1(const SpInputProposalV1 &input_proposal,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &input_amount_blinding_factors,
    SpENoteImageV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_image_last_sp_v2 - make LAST v1 input image for a tx (squashed enote model)
*   - last amount commitment total blinding factor (v_c) equals sum of output amount blinding factors (y_t)
*      minus sum input blinding factors (v_c_except_last)
* param: input_proposal -
* param: output_amount_commitment_blinding_factors -
* param: input_amount_blinding_factors -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_last_sp_v2(const SpInputProposalV1 &input_proposal,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &input_amount_blinding_factors,
    SpENoteImageV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_images_sp_v1 - make all v1 input images for a tx
* param: input_proposals -
* outparam: input_images_out -
* outparam: image_address_masks_out -
* outparam: image_amount_masks_out -
*/
void make_v1_tx_images_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpENoteImageV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out);
/**
* brief: make_v1_tx_images_sp_v2 - make all v1 input images for a tx (squashed enote model)
* param: input_proposals -
* outparam: input_images_out -
* outparam: image_address_masks_out -
* outparam: image_amount_masks_out -
*/
void make_v1_tx_images_sp_v2(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpENoteImageV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out);
/**
* brief: make_v1_tx_images_sp_v3 - make all v1 input images for a tx
*   - last input image's amount mask is set so input image commitments sum to equal output commitments
* param: input_proposals -
* param: output_amount_commitment_blinding_factors -
* outparam: input_images_out -
* outparam: image_address_masks_out -
* outparam: image_amount_masks_out -
*/
void make_v1_tx_images_sp_v3(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    std::vector<SpENoteImageV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out);
/**
* brief: make_v1_tx_image_proof_sp_v1 - make a v1 tx input image proof (seraphis composition proof)
* param: input_proposal -
* param: input_image -
* param: image_address_mask -
* param: message -
* outparam: tx_image_proof_out -
*/
void make_v1_tx_image_proof_sp_v1(const SpInputProposalV1 &input_proposal,
    const SpENoteImageV1 &input_image,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_out);
/**
* brief: make_v1_tx_image_proof_sp_v2 - make a v1 tx input image proof (seraphis composition proof) (squashed enote model)
* param: input_proposal -
* param: input_image -
* param: image_address_mask -
* param: message -
* outparam: tx_image_proof_out -
*/
void make_v1_tx_image_proof_sp_v2(const SpInputProposalV1 &input_proposal,
    const SpENoteImageV1 &input_image,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_out);
/**
* brief: make_v1_tx_image_proofs_sp_v1 - make v1 tx input image proofs (seraphis composition proofs: 1 per input)
* param: input_proposals -
* param: input_images -
* param: image_address_masks -
* param: message -
* outparam: tx_image_proofs_out -
*/
void make_v1_tx_image_proofs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpENoteImageV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<SpImageProofV1> &tx_image_proofs_out);
/**
* brief: make_v1_tx_image_proofs_sp_v2 - make v1 tx input image proof with merged seraphis composition proof for all inputs
*   note: all inputs must be 'owned' by same signer, since all input image proof privkeys must be known to make a proof
* param: input_proposals -
* param: input_images -
* param: image_address_masks -
* param: message -
* outparam: tx_image_proof_merged_out -
*/
void make_v1_tx_image_proofs_sp_v2(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpENoteImageV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_merged_out);
/**
* brief: make_v1_tx_image_proofs_sp_v3 - make v1 tx input image proofs (seraphis composition proofs: 1 per input)
*   (squashed enote model)
* param: input_proposals -
* param: input_images -
* param: image_address_masks -
* param: message -
* outparam: tx_image_proofs_out -
*/
void make_v1_tx_image_proofs_sp_v3(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpENoteImageV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<SpImageProofV1> &tx_image_proofs_out);
/**
* brief: make_v1_tx_balance_proof_sp_v1 - make v1 tx balance proof (BP+ for range proofs; balance is implicit)
* param: output_amounts -
* param: input_image_amount_commitment_blinding_factors -
* param: output_amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: balance_proof_out -
*/
void make_v1_tx_balance_proof_sp_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<SpBalanceProofV1> &balance_proof_out);
/**
* brief: make_v1_tx_balance_proof_sp_v2 - make v1 tx balance proof (BP+ for range proofs; balance is implicit)
*   - range proofs for input image amount commitments and output commitments (squashed enote model)
* param: input_amounts -
* param: output_amounts -
* param: input_image_amount_commitment_blinding_factors -
* param: output_amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: balance_proof_out -
*/
void make_v1_tx_balance_proof_sp_v2(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<SpBalanceProofV1> &balance_proof_out);
/**
* brief: make_v2_tx_balance_proof_sp_v1 - make v2 tx balance proof (BP+ for range proofs; balance is implicit)
* param: output_amounts -
* param: output_amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: balance_proof_out -
*/
void make_v2_tx_balance_proof_sp_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<SpBalanceProofV2> &balance_proof_out);
/**
* brief: make_v1_tx_membership_proof_sp_v1 - make a v1 membership proof (concise grootle)
* param: membership_ref_set -
* param: image_address_mask -
* param: image_amount_mask -
* outparam: tx_membership_proof_out -
*/
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofSortableV1 &tx_membership_proof_out);
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &tx_membership_proof_out);
/**
* brief: make_v1_tx_membership_proof_sp_v2 - make a v1 membership proof (concise grootle) (squashed enote model)
* param: membership_ref_set -
* param: image_address_mask -
* param: image_amount_mask -
* outparam: tx_membership_proof_out -
*/
void make_v1_tx_membership_proof_sp_v2(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofSortableV1 &tx_membership_proof_out);
void make_v1_tx_membership_proof_sp_v2(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &tx_membership_proof_out);
/**
* brief: make_v1_tx_membership_proofs_sp_v1 - make v1 membership proofs (concise grootle: 1 per input)
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
* brief: make_v1_tx_membership_proofs_sp_v2 - make v1 membership proofs (concise grootle: 1 per input)
*   (squashed enote model)
* param: membership_ref_sets -
* param: image_address_masks -
* param: image_amount_masks -
* outparam: tx_membership_proofs_out -
*/
void make_v1_tx_membership_proofs_sp_v2(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out);
/**
* brief: make_v1_tx_partial_inputs_sp_v1 - make a full set of v1 partial inputs
* param: input_proposals -
* param: proposal_prefix -
* param: tx_proposal -
* outparam: partial_inputs_out -
*/
void make_v1_tx_partial_inputs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const SpTxProposalV1 &tx_proposal,
    std::vector<SpTxPartialInputV1> &partial_inputs_out);
/**
* brief: balance_check_in_out_amnts_sp_v1 - wrapper on balance_check_in_out_amnts()
* param: input_proposals -
* param: destinations -
* param: transaction_fee -
* return: true if amounts balance between inputs and outputs
*/
bool balance_check_in_out_amnts_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpDestinationV1> &destinations,
    const rct::xmr_amount transaction_fee = 0);
/**
* brief: gen_mock_sp_input_proposals_v1 - create random mock inputs
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts);
/**
* brief: gen_mock_sp_membership_ref_sets_v1 - create random reference sets for tx inputs, with real spend at a random index,
*   and update mock ledger to include all members of the reference set
* param: input_proposals -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: set of membership proof reference sets
*/
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpENoteV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
/**
* brief: gen_mock_sp_membership_ref_sets_v2 - create random reference sets for tx inputs, with real spend at a random index,
*   and update mock ledger to include all members of the reference set (including squashed enotes)
* param: input_proposals -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: set of membership proof reference sets
*/
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v2(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v2(
    const std::vector<SpENoteV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
/**
* brief: gen_mock_sp_destinations_v1 - create random mock destinations
* param: out_amounts -
* return: set of generated destinations
*/
std::vector<SpDestinationV1> gen_mock_sp_destinations_v1(const std::vector<rct::xmr_amount> &out_amounts);

} //namespace sp
