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

// Seraphis tx-builder/component-builder implementations

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: get_tx_image_proof_message_sp_v1 - message for tx image proofs
*   - H(crypto project name, version string, output enotes, enote ephemeral pubkeys)
* param: version_string -
* param: output_enotes -
* param: tx_supplement -
* return: message to insert in a tx image proof
*/
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement);
/**
* brief: make_v1_tx_balance_proof_sp_v1 - make v1 tx balance proof (BP+ for range proofs; balance check is sum-to-zero)
*   - range proofs: for input image amount commitments and output commitments (squashed enote model)
* param: input_amounts -
* param: output_amounts -
* param: input_image_amount_commitment_blinding_factors -
* param: output_amount_commitment_blinding_factors -
* outparam: balance_proof_out -
*/
void make_v1_tx_balance_proof_sp_v1(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out);
/**
* brief: balance_check_in_out_amnts_sp_v1 - verify that input amounts equal output amounts + fee
* param: input_proposals -
* param: output_proposals -
* param: transaction_fee -
* return: true if amounts balance between inputs and outputs (plus fee)
*/
bool balance_check_in_out_amnts_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::xmr_amount transaction_fee);
/**
* brief: make_v1_tx_partial_v1 - make v1 partial transaction (everything ready for a full tx except membership proofs)
* param: proposal -
* param: partial_inputs -
* param: version_string -
* outparam: partial_tx_out -
*/
void make_v1_tx_partial_v1(const SpTxProposalV1 &proposal,
    std::vector<SpTxPartialInputV1> partial_inputs,
    const std::string &version_string,
    SpTxPartialV1 &partial_tx_out);

} //namespace sp
