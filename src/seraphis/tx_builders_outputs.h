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
#include <string>
#include <vector>

//forward declarations


namespace sp
{

//todo
void finalize_v1_output_proposal_set_sp_v1();
/**
* brief: get_tx_membership_proof_message_sp_v1 - message for membership proofs
*   - H(crypto project name, enote ledger references)
* TODO: use a real reference system instead of plain indices
* param - enote_ledger_indices
* return: empty message for a membership proof
*/
void check_v1_output_proposals_semantics_sp_v1(const std::vector<SpOutputProposalV1> &output_proposals);
/**
* brief: get_tx_membership_proof_message_sp_v1 - message for membership proofs
*   - H(crypto project name, enote ledger references)
* TODO: use a real reference system instead of plain indices
* param - enote_ledger_indices
* return: empty message for a membership proof
*/
void check_v1_tx_supplement_semantics_sp_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs);
/**
* brief: make_v1_tx_outputs_sp_v1 - make v1 tx outputs
*   TODO: special treatment of change dest for 2-out tx (expect both outputs to have same enote pub key, only store 1)
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* inoutparam: tx_supplement_inout -
*/
void make_v1_tx_outputs_sp_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    SpTxSupplementV1 &tx_supplement_inout);
/**
* brief: gen_mock_sp_destinations_v1 - create random mock destinations
* param: out_amounts -
* return: set of generated destinations
*/
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts);

} //namespace sp
