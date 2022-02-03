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
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: get_tx_image_proof_message_sp_v1 - message for tx image proofs
*   - H(crypto project name, version string, output enotes, enote pubkeys)
* param: version_string -
* param: output_enotes -
* param: tx_supplement -
* return: message to insert in a tx image proof
*/
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement);
/**
* brief: make_v1_tx_balance_proof_sp_v1 - make v1 tx balance proof (BP+ for range proofs; balance is implicit)
*   - range proofs for input image amount commitments and output commitments (squashed enote model)
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
    std::shared_ptr<SpBalanceProofV1> &balance_proof_out);
/**
* brief: balance_check_in_out_amnts_sp_v1 - wrapper on balance_check_in_out_amnts()
* param: input_proposals -
* param: destinations -
* param: transaction_fee -
* return: true if amounts balance between inputs and outputs
*/
bool balance_check_in_out_amnts_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::xmr_amount transaction_fee);

} //namespace sp
