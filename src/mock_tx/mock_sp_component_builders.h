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

// Mock tx: Seraphis component implementations
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "mock_sp_base.h"
#include "mock_sp_component_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace mock_tx
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
*   - H(crypto project name, version string, output enotes, range proofs, enote pubkeys)
* param: version_string -
* param: output_enotes -
* param: balance_proof -
* param: tx_supplement -
* return: message to insert in a tx image proof
*/
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<MockENoteSpV1> &output_enotes,
    const std::shared_ptr<const MockBalanceProofSpV1> &balance_proof,
    const MockSupplementSpV1 &tx_supplement);
/**
* brief: gen_mock_sp_inputs_v1 - create random mock inputs
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<MockInputSpV1> gen_mock_sp_inputs_v1(const std::vector<rct::xmr_amount> in_amounts);
/**
* brief: gen_mock_sp_membership_ref_sets_v1 - create random reference sets for tx inputs, with real spend at a random index,
*   and update mock ledger to include all members of the reference set
* param: inputs -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: set of membership proof reference sets
*/
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(const std::vector<MockInputSpV1> &inputs,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
/**
* brief: gen_mock_sp_dests_v1 - create random mock destinations
* param: out_amounts -
* return: set of generated destinations
*/
std::vector<MockDestSpV1> gen_mock_sp_dests_v1(const std::vector<rct::xmr_amount> &out_amounts);
/**
* brief: make_v1_tx_outputs_sp_v1 - make v1 tx outputs
*   TODO: special treatment of change dest for 2-out tx (expect both outputs to have same enote pub key, only store 1)
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* inoutparam: tx_supplement_inout -
*/
void make_v1_tx_outputs_sp_v1(const std::vector<MockDestSpV1> &destinations,
    std::vector<MockENoteSpV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    MockSupplementSpV1 &tx_supplement_inout);
/**
* brief: make_v1_tx_image_sp_v1 - make all v1 input images for a tx EXCEPT LAST
* param: input_to_spend -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_sp_v1(const MockInputSpV1 &input_to_spend,
    MockENoteImageSpV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_image_last_sp_v1 - make LAST v1 input image for a tx
*   - last amount commitment total blinding factor (v_c) equals sum of output amount blinding factors (y_t)
*      minus sum input blinding factors (v_c_except_last)
* param: input_to_spend -
* param: output_amount_commitment_blinding_factors -
* param: input_amount_blinding_factors -
* outparam: input_image_out -
* outparam: image_address_mask_out -
* outparam: image_amount_mask_out -
*/
void make_v1_tx_image_last_sp_v1(const MockInputSpV1 &input_to_spend,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &input_amount_blinding_factors,
    MockENoteImageSpV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out);
/**
* brief: make_v1_tx_images_sp_v1 - make all v1 input images for a tx
* param: inputs_to_spend -
* param: output_amount_commitment_blinding_factors -
* outparam: input_images_out -
* outparam: image_address_masks_out -
* outparam: image_amount_masks_out -
*/
void make_v1_tx_images_sp_v1(const std::vector<MockInputSpV1> &inputs_to_spend,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageSpV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out);
/**
* brief: make_v1_tx_image_proof_sp_v1 - make a v1 tx input image proof (seraphis composition proof)
* param: input_to_spend -
* param: input_image -
* param: image_address_mask -
* param: message -
* outparam: tx_image_proof_out -
*/
void make_v1_tx_image_proof_sp_v1(const MockInputSpV1 &input_to_spend,
    const MockENoteImageSpV1 &input_image,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    MockImageProofSpV1 &tx_image_proof_out);
/**
* brief: make_v1_tx_image_proofs_sp_v1 - make v1 tx input image proofs (seraphis composition proofs: 1 per input)
* param: inputs_to_spend -
* param: input_images -
* param: image_address_masks -
* param: message -
* outparam: tx_image_proofs_out -
*/
void make_v1_tx_image_proofs_sp_v1(const std::vector<MockInputSpV1> &inputs_to_spend,
    const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<MockImageProofSpV1> &tx_image_proofs_out);
/**
* brief: make_v1_tx_balance_proof_rct_v1 - make v1 tx balance proof (BP+ for range proofs; balance is implicit)
* param: output_amounts -
* param: output_amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: balance_proof_out -
*/
void make_v1_tx_balance_proof_rct_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<MockBalanceProofSpV1> &balance_proof_out);
/**
* brief: make_v1_tx_membership_proof_sp_v1 - make a v1 membership proof (concise grootle)
* param: membership_ref_set -
* param: image_address_mask -
* param: image_amount_mask -
* outparam: tx_membership_proof_out -
*/
void make_v1_tx_membership_proof_sp_v1(const MockMembershipReferenceSetSpV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    MockMembershipProofSpV1 &tx_membership_proof_out);
/**
* brief: make_v1_tx_membership_proofs_sp_v1 - make v1 membership proofs (concise grootle: 1 per input)
* param: membership_ref_sets -
* param: image_address_masks -
* param: image_amount_masks -
* outparam: tx_membership_proofs_out -
*/
void make_v1_tx_membership_proofs_sp_v1(const std::vector<MockMembershipReferenceSetSpV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_out);
/**
* brief: sort_tx_inputs_sp_v1 - sort tx inputs
*   sort order: key images ascending with byte-wise comparisons
* inoutparam: input_images_inout -
* inoutparam: tx_image_proofs_inout -
* inoutparam: tx_membership_proofs_inout -
*/
void sort_tx_inputs_sp_v1(std::vector<MockENoteImageSpV1> &input_images_inout,
    std::vector<MockImageProofSpV1> &tx_image_proofs_inout,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_inout);

} //namespace mock_tx
