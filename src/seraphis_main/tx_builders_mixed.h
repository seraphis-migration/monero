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

// Seraphis tx-builder/component-builder implementations (those related to both inputs and outputs).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_input_selection.h"
#include "txtype_base.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: make_tx_proposal_prefix_v1 - hash representing a tx proposal
*   - H_32(tx version, legacy input key images, seraphis input key images, output enotes, fee, tx supplement)
* param: tx_version -
* param: legacy_input_key_images -
* param: sp_input_key_images -
* param: output_enotes -
* param: transaction_fee -
* param: tx_supplement -
* outparam: tx_proposal_prefix_out - hash representing a tx proposal
*/
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const rct::xmr_amount transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const DiscretizedFee transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyEnoteImageV2> &input_legacy_enote_images,
    const std::vector<SpEnoteImageV1> &input_sp_enote_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const DiscretizedFee transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyInputV1> &legacy_inputs,
    const std::vector<SpPartialInputV1> &sp_partial_inputs,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out);
void make_tx_proposal_prefix_v1(const SpTxSquashedV1 &tx, rct::key &tx_proposal_prefix_out);
/**
* brief: make_tx_proofs_prefix_v1 - hash of all proofs in a tx (e.g. for use in making a tx id)
*   - H_32(balance proof, legacy ring signatures, seraphis image proofs, seraphis membership proofs)
* param: balance_proof -
* param: legacy_ring_signatures -
* param: sp_image_proofs -
* param: sp_membership_proofs -
* outparam: tx_proofs_prefix_out -
*/
void make_tx_proofs_prefix_v1(const SpBalanceProofV1 &balance_proof,
    const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<SpImageProofV1> &sp_image_proofs,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs,
    rct::key &tx_proofs_prefix_out);
/**
* brief: make_tx_artifacts_merkle_root_v1 - merkle root of transaction artifacts (input images and proofs)
*   - H_32(input images prefix, tx proofs prefix)
* param: input_images_prefix -
* param: tx_proofs_prefix -
* outparam: tx_artifacts_merkle_root_out -
*/
void make_tx_artifacts_merkle_root_v1(const rct::key &input_images_prefix,
    const rct::key &tx_proofs_prefix,
    rct::key &tx_artifacts_merkle_root_out);
/**
* brief: check_v1_coinbase_tx_proposal_semantics_v1 - check semantics of a coinbase tx proposal
*   - throws if a check fails
*   - NOTE: it is permitted for there to be no output coinbase enotes (i.e. for unit testing/mockups)
* param: tx_proposal -
*/
void check_v1_coinbase_tx_proposal_semantics_v1(const SpCoinbaseTxProposalV1 &tx_proposal);
/**
* brief: check_v1_tx_proposal_semantics_v1 - check semantics of a tx proposal
*   - throws if a check fails
* param: tx_proposal -
* param: legacy_spend_pubkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
*/
void check_v1_tx_proposal_semantics_v1(const SpTxProposalV1 &tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: make_v1_coinbase_tx_proposal_v1 - make v1 coinbase tx proposal
* param: block_height -
* param: block_reward -
* param: normal_payment_proposals -
* param: additional_memo_elements -
* outparam: tx_proposal_out -
*/
void make_v1_coinbase_tx_proposal_v1(const std::uint64_t block_height,
    const rct::xmr_amount block_reward,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpCoinbaseTxProposalV1 &tx_proposal_out);
/**
* brief: make_v1_tx_proposal_v1 - make v1 tx proposal
* param: legacy_input_proposals -
* param: sp_input_proposals -
* param: normal_payment_proposals -
* param: selfsend_payment_proposals -
* param: discretized_transaction_fee -
* param: additional_memo_elements -
* outparam: tx_proposal_out -
*/
void make_v1_tx_proposal_v1(std::vector<LegacyInputProposalV1> legacy_input_proposals,
    std::vector<SpInputProposalV1> sp_input_proposals,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &tx_proposal_out);
void make_v1_tx_proposal_v1(const std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs,
    const std::vector<SpContextualEnoteRecordV1> &sp_contextual_inputs,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    const TxExtra &partial_memo_for_tx,
    SpTxProposalV1 &tx_proposal_out);
/**
* brief: balance_check_in_out_amnts_v1 - verify that the block reward equals output amounts (coinbase txs)
* param: block_reward -
* param: output_proposals -
* return: true if amounts balance between block reward and outputs
*/
bool balance_check_in_out_amnts_v1(const rct::xmr_amount block_reward,
    const std::vector<SpCoinbaseOutputProposalV1> &output_proposals);
/**
* brief: balance_check_in_out_amnts_v2 - verify that input amounts equal output amounts + fee (normal txs)
* param: legacy_input_proposals -
* param: sp_input_proposals -
* param: output_proposals -
* param: discretized_transaction_fee -
* return: true if amounts balance between inputs and outputs (plus fee)
*/
bool balance_check_in_out_amnts_v2(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee discretized_transaction_fee);
/**
* brief: make_v1_balance_proof_v1 - make v1 tx balance proof (BP+ for range proofs; balance check is sum-to-zero)
*   - range proofs: for seraphis input image amount commitments and output commitments (squashed enote model)
* param: legacy_input_amounts -
* param: sp_input_amounts -
* param: output_amounts -
* param: transaction_fee -
* param: legacy_input_image_amount_commitment_blinding_factors -
* param: sp_input_image_amount_commitment_blinding_factors -
* param: output_amount_commitment_blinding_factors -
* outparam: balance_proof_out -
*/
void make_v1_balance_proof_v1(const std::vector<rct::xmr_amount> &legacy_input_amounts,
    const std::vector<rct::xmr_amount> &sp_input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee,
    const std::vector<crypto::secret_key> &legacy_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &sp_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out);
/**
* brief: check_v1_partial_tx_semantics_v1 - check the semantics of a partial tx against SpTxSquashedV1 validation rules
*   - throws if a check fails
*   - makes a mock tx and validates it using the specified SpTxSquashedV1 semantics rules version
* param: partial_tx -
* param: semantic_rules_version -
*/
void check_v1_partial_tx_semantics_v1(const SpPartialTxV1 &partial_tx,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version);
/**
* brief: make_v1_partial_tx_v1 - make v1 partial transaction (everything ready for a full tx except seraphis membership
*   proofs)
* param: legacy_inputs -
* param: sp_partial_inputs -
* param: output_proposals -
* param: discretized_transaction_fee -
* param: partial_memo -
* param: tx_version -
* outparam: partial_tx_out -
*/
void make_v1_partial_tx_v1(std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    std::vector<SpOutputProposalV1> output_proposals,
    const DiscretizedFee discretized_transaction_fee,
    const TxExtra &partial_memo,
    const tx_version_t &tx_version,
    SpPartialTxV1 &partial_tx_out);
void make_v1_partial_tx_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialTxV1 &partial_tx_out);

} //namespace sp
