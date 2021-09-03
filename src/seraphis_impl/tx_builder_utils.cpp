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

//paired header
#include "tx_builder_utils.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_impl/tx_input_selection_output_context_v1.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
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
    DiscretizedFee &discretized_transaction_fee_out)
{
    legacy_contextual_inputs_out.clear();
    sp_contextual_inputs_out.clear();
    final_normal_payment_proposals_out.clear();
    final_selfsend_payment_proposals_out.clear();

    // 1. try to select inputs for the tx
    const OutputSetContextForInputSelectionV1 output_set_context{
            normal_payment_proposals,
            selfsend_payment_proposals
        };

    rct::xmr_amount reported_final_fee;
    input_set_tracker_t selected_input_set;

    if (!try_get_input_set_v1(output_set_context,
            max_inputs,
            local_user_input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            reported_final_fee,
            selected_input_set))
        return false;

    // 2. separate into legacy and seraphis inputs
    split_selected_input_set(selected_input_set, legacy_contextual_inputs_out, sp_contextual_inputs_out);

    // 3. get total input amount
    const boost::multiprecision::uint128_t total_input_amount{
            total_amount(legacy_contextual_inputs_out) +
            total_amount(sp_contextual_inputs_out)
        };

    // 4. finalize output set
    finalize_v1_output_proposal_set_v1(total_input_amount,
        reported_final_fee,
        change_address,
        dummy_address,
        k_view_balance,
        normal_payment_proposals,
        selfsend_payment_proposals);

    CHECK_AND_ASSERT_THROW_MES(tx_fee_calculator.compute_fee(fee_per_tx_weight,
                legacy_contextual_inputs_out.size(), sp_contextual_inputs_out.size(),
                normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
            reported_final_fee,
        "prepare inputs and outputs for transfer (v1): final fee is not consistent with input selector fee (bug).");

    final_normal_payment_proposals_out   = std::move(normal_payment_proposals);
    final_selfsend_payment_proposals_out = std::move(selfsend_payment_proposals);

    // 5. set transaction fee
    discretized_transaction_fee_out = discretize_fee(reported_final_fee);
    CHECK_AND_ASSERT_THROW_MES(discretized_transaction_fee_out == reported_final_fee,
        "prepare inputs and outputs for transfer (v1): the input selector fee was not properly discretized (bug).");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
