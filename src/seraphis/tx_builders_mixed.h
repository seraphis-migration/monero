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

// Seraphis tx-builder/component-builder implementations (those related to both inputs and outputs).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis/tx_base.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_discretized_fee.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: make_tx_image_proof_message_v1 - message for tx image proofs
*   - H(crypto project name, version string, input key images, output enotes, enote ephemeral pubkeys, memos, fee)
* param: version_string -
* param: input_key_images -
* param: output_enotes -
* param: tx_supplement -
* param: transaction_fee -
* outparam: proof_message_out - message to insert in a tx image proof
*/
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const rct::xmr_amount transaction_fee,
    rct::key &proof_message_out);
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const DiscretizedFee &transaction_fee,
    rct::key &proof_message_out);
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<SpEnoteImageV1> &input_enote_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    const DiscretizedFee &transaction_fee,
    rct::key &proof_message_out);
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<crypto::key_image> &input_key_images,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proof_message_out);
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<SpPartialInputV1> &partial_inputs,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proof_message_out);
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &transaction_fee,
    rct::key &proof_message_out);
/**
* brief: check_v1_tx_proposal_semantics_v1 - check semantics of a tx proposal
*   - throws if a check fails
*   - outputs should have unique and canonical onetime addresses
*   - self-send payment proposals should have destinations owned by the user
*   - amount commitments are consistent with masks/amounts recorded in the proposal
*   - the tx supplement should have valid semantics
* param: tx_proposal -
* param: wallet_spend_pubkey -
* param: k_view_balance -
*/
void check_v1_tx_proposal_semantics_v1(const SpTxProposalV1 &tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: make_v1_tx_proposal_v1 - make v1 tx proposal
* param: normal_payment_proposals -
* param: selfsend_payment_proposals -
* param: tx_fee -
* param: input_proposals -
* param: additional_memo_elements -
* outparam: proposal_out -
*/
void make_v1_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee &tx_fee,
    std::vector<SpInputProposalV1> input_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &proposal_out);
/**
* brief: make_v1_balance_proof_v1 - make v1 tx balance proof (BP+ for range proofs; balance check is sum-to-zero)
*   - range proofs: for input image amount commitments and output commitments (squashed enote model)
* param: input_amounts -
* param: output_amounts -
* param: transaction_fee -
* param: input_image_amount_commitment_blinding_factors -
* param: output_amount_commitment_blinding_factors -
* outparam: balance_proof_out -
*/
void make_v1_balance_proof_v1(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out);
/**
* brief: balance_check_in_out_amnts_v1 - verify that input amounts equal output amounts + fee
* param: input_proposals -
* param: output_proposals -
* param: discretized_transaction_fee -
* return: true if amounts balance between inputs and outputs (plus fee)
*/
bool balance_check_in_out_amnts_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee &discretized_transaction_fee);
/**
* brief: check_v1_partial_tx_semantics_v1 - check the semantics of a partial tx
*   - throws if a check fails
*   - should be able to make a mock tx and validate it using the specified semantics rules version
* param: partial_tx -
* param: semantic_rules_version -
*/
void check_v1_partial_tx_semantics_v1(const SpPartialTxV1 &partial_tx,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version);
/**
* brief: make_v1_partial_tx_v1 - make v1 partial transaction (everything ready for a full tx except membership proofs)
* param: tx_proposal -
* param: partial_inputs -
* param: version_string -
* param: k_view_balance -
* outparam: partial_tx_out -
*/
void make_v1_partial_tx_v1(std::vector<SpPartialInputV1> partial_inputs,
    std::vector<SpOutputProposalV1> output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &tx_fee,
    const std::string &version_string,
    SpPartialTxV1 &partial_tx_out);
void make_v1_partial_tx_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<SpPartialInputV1> partial_inputs,
    const std::string &version_string,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialTxV1 &partial_tx_out);

} //namespace sp
