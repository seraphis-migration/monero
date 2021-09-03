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

// Utiltities to support seraphis transaction building.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builder_types_legacy.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/tx_fee_calculator.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: try_prepare_inputs_and_outputs_for_transfer_v1 - try to select inputs then finalize outputs for a tx
* param: change_address -
* param: dummy_address -
* param: local_user_input_selector -
* param: tx_fee_calculator -
* param: fee_per_tx_weight -
* param: max_inputs -
* param: normal_payment_proposals -
* param: selfsend_payment_proposals -
* param: k_view_balance -
* outparam: legacy_contextual_inputs_out -
* outparam: sp_contextual_inputs_out -
* outparam: final_normal_payment_proposals_out -
* outparam: final_selfsend_payment_proposals_out -
* outparam: discretized_transaction_fee_out -
*/
bool try_prepare_inputs_and_outputs_for_transfer_v1(const jamtis::JamtisDestinationV1 &change_address,
    const jamtis::JamtisDestinationV1 &dummy_address,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const crypto::secret_key &k_view_balance,
    std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs_out,
    std::vector<SpContextualEnoteRecordV1> &sp_contextual_inputs_out,
    std::vector<jamtis::JamtisPaymentProposalV1> &final_normal_payment_proposals_out,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &final_selfsend_payment_proposals_out,
    DiscretizedFee &discretized_transaction_fee_out);

} //namespace sp
