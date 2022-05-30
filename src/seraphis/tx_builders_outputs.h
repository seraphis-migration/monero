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

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_destination.h"
#include "jamtis_payment_proposal.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

enum class OutputProposalSetExtraTypesV1
{
    // a plain dummy output (random recipient, random enote ephemeral pubkey)
    NORMAL_DUMMY,
    // a self-send dummy output (specified recipient, normal enote ephemeral pubkey)
    NORMAL_SELF_SEND_DUMMY,
    // a normal change output (specified recipient, normal enote ephemeral pubkey)
    NORMAL_CHANGE,
    // a special dummy output (random recipient, shared enote ephemeral pubkey)
    SPECIAL_DUMMY,
    // a special self-send dummy output (specified recipient, shared enote ephemeral pubkey)
    SPECIAL_SELF_SEND_DUMMY,
    // a special change output (specified recipient, shared enote ephemeral pubkey)
    SPECIAL_CHANGE
};

/**
* brief: check_v1_output_proposal_semantics_v1 - check semantics of an output proposal
*   - throws if a check fails
*   - partial memo should be valid
* param: output_proposal -
*/
void check_v1_output_proposal_semantics_v1(const SpOutputProposalV1 &output_proposal);
/**
* brief: check_v1_output_proposal_set_semantics_v1 - check semantics of a set of output proposals
*   - throws if a check fails
*   - if 2 proposals, should be 1 unique enote ephemeral pubkey
*   - if >2 proposals, should be 1 unique enote ephemeral pubkey per output
*   - proposals should be sorted
*   - proposals should have unique and canonical onetime addresses
* param: output_proposals -
*/
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals);
/**
* brief: check_v1_tx_supplement_semantics_v1 - check semantics of a tx supplement
*   - throws if a check fails
*   - if num_outputs == 2, should be 1 enote ephemeral pubkey
*   - if num_outputs > 2, should be 'num_outputs' enote ephemeral pubkeys
*   - all enote ephemeral pubkeys should be unique
* param: tx_supplement -
* param: num_outputs -
*/
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs);
/**
* brief: make_v1_outputs_v1 - make v1 tx outputs
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* outparam: output_enote_ephemeral_pubkeys_out -
*/
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<rct::key> &output_enote_ephemeral_pubkeys_out);
//todo
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out);
/**
* brief: finalize_v1_output_proposal_set_v1 - finalize a set of output proposals (new proposals are appended)
*   - add a change output if necessary
*   - add a dummy output if appropriate
*   - All output sets will contain at least 1 self-send, either from the original set passed in, a change, or a dummy.
*     - Only very rare txs should acquire an extra output due to this invariant. Most txs will contain a change output
*       or have a 'natural' dummy output (a dummy that would be there anyway, so it can be made a self-send trivially).
*     - A self-send dummy will only be made if there are no other self-sends; otherwise dummies will be purely random.
*     - The goal of this is for all txs made from output sets produced by this function to be identifiable by view
*       tag checks. If the local signer is scanning for enotes, then they only need key images from txs that are flagged
*       by a view tag check in order to identify all of their self-send enotes spent in txs that use output sets from this
*       function. This optimizes third-party view-tag scanning services, which only need to transmit key images from txs
*       with view tag matches to the local client. Only txs that don't use this function to define the output set _might_
*       cause failures to identify spent enotes in that workflow. At the time of writing this, it is assumed there are no
*       workflows where skipping this function would be valuable.
* param: total_input_amount -
* param: transaction_fee -
* param: change_destination -
* param: dummy_destination -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* inoutparam: normal_payment_proposals_inout -
* inoutparam: selfsend_payment_proposals_inout -
*/
void get_additional_output_types_for_output_set_v1(const std::size_t num_outputs,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const bool output_ephemeral_pubkeys_are_unique,
    const rct::xmr_amount change_amount,
    std::vector<OutputProposalSetExtraTypesV1> &additional_outputs_out);
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout);
/**
* brief: gen_mock_sp_output_proposals_v1 - create random output proposals
* param: out_amounts -
* param: num_random_memo_elements -
* return: set of generated output proposals
*/
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts,
    const std::size_t num_random_memo_elements);

} //namespace sp
