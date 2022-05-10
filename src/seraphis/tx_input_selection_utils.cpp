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

//paired header
#include "tx_input_selection_utils.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_builders_outputs.h"
#include "tx_discretized_fee.h"
#include "tx_enote_record_types.h"
#include "txtype_squashed_v1.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <list>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t compute_num_additional_outputs(const rct::key &wallet_spend_pubkey
    const crypto::secret_key &k_view_balance,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::xmr_amount change_amount)
{
    OutputProposalSetExtraTypesContextV1 dummy;
    std::vector<OutputProposalSetExtraTypesV1> additional_outputs_from_change;

    get_additional_output_types_for_output_set_v1(wallet_spend_pubkey,
        k_view_balance,
        output_proposals,
        change_amount,
        dummy,
        additional_outputs_from_change);

    return additional_outputs_from_change.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t compute_total_amount(
    const std::list<SpContextualEnoteRecordV1> &contextual_enote_records)
{
    boost::multiprecision::uint128_t amount_sum{0};

    for (const SpContextualEnoteRecordV1 &contextual_enote_record : contextual_enote_records)
        amount_sum += contextual_enote_record.get_amount();

    return amount_sum;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void sort_contextual_enote_records(std::list<SpContextualEnoteRecordV1> &contextual_enote_records_inout)
{
    std::sort(contextual_enote_records_inout.begin(), contextual_enote_records_inout.end(),
            [](const auto &record1, const auto &record1) -> bool
            {
                return record1.get_amount() < record2.get_amount();
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_v1(const boost::multiprecision::uint128_t output_amount,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    SpTxSquashedV1::WeightParams &tx_weight_parameters_inout,
    std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // make sure the inputs are sorted
    sort_contextual_enote_records(added_inputs_inout);
    sort_contextual_enote_records(excluded_inputs_inout);

    // current tx fee
    tx_weight_parameters_inout.m_num_inputs = added_inputs_inout.size();

    const DiscretizedFee current_fee_discretized{
            fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters_inout)
        };

    rct::xmr_amount current_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(current_fee_discretized, current_fee),
        "updating an input set: could not extract discretized fee for current case (bug).");

    SpContextualEnoteRecordV1 requested_input;

    // inputs are not full
    if (added_inputs_inout.size() < max_inputs_allowed)
    {
        // next tx fee (from adding one input)
        ++tx_weight_parameters_inout.m_num_inputs;

        const DiscretizedFee next_fee_discretized{
                fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters_inout)
            };

        rct::xmr_amount next_fee;
        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(next_fee_discretized, next_fee),
            "updating an input set: could not extract discretized fee for next input case (bug).");

        // try to use the highest excluded input to cover and exceed the differential fee from adding it
        CHECK_AND_ASSERT_THROW_MES(next_fee >= current_fee,
            "updating an input set: next fee is less than current fee (bug).");

        if (excluded_inputs_inout.size() > 0 &&
            excluded_inputs_inout.back().get_amount() > next_fee - current_fee)
        {
            auto exclude_last = excluded_inputs_inout.rbegin();
            added_inputs_inout.splice(added_inputs_inout.begin(), excluded_inputs_inout, exclude_last);

            return true;
        }

        // try to request a new input from the selector 
        while (input_selector.try_select_input_v1(output_amount + next_fee,
            added_inputs_inout,
            excluded_inputs_inout,
            requested_input))
        {
            // if requested input can cover its differential fee, add it to the inputs list
            if (requested_input.get_amount() > next_fee - current_fee)
            {
                added_inputs_inout.emplace_front(std::move(requested_input));

                return true;
            }
            // otherwise, add it to the excluded list
            else
            {
                excluded_inputs_inout.emplace_front(requested_input);  //don't move - requested_input may be used again
            }
        }

        // if no more inputs to select, fall back to trying to add a range of excluded inputs
        if (excluded_inputs_inout.size() > 0)
        {
            sort_contextual_enote_records(excluded_inputs_inout);

            boost::multiprecision::uint128_t range_sum{0};
            std::size_t range_size{0};
            for (auto exclude_it = excluded_inputs_inout.rbegin(); exclude_it != excluded_inputs_inout.rend(); ++exclude_it)
            {
                range_sum += exclude_it->get_amount();
                ++range_size;

                // we have failed if our range exceeds the input limit
                if (added_inputs_inout.size() + range_size > max_inputs_allowed)
                    return false;

                // total fee including this range of inputs
                tx_weight_parameters_inout.m_num_inputs = added_inputs_inout.size() + range_size;

                const DiscretizedFee range_fee_discretized{
                        fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters_inout)
                    };

                rct::xmr_amount range_fee;
                CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(range_fee_discretized, range_fee),
                    "updating an input set: could not extract discretized fee for range input case (bug).");

                // if range of excluded inputs can cover the differential fee from those inputs, insert them
                CHECK_AND_ASSERT_THROW_MES(range_fee >= current_fee,
                    "updating an input set: range fee is less than current fee (bug).");

                if (range_sum > range_fee - current_fee)
                {
                    added_inputs_inout.splice(added_inputs_inout.begin(),
                        excluded_inputs_inout,
                        exclude_it,
                        excluded_inputs_inout.end());

                    return true;
                }
            }
        }
    }
    // inputs are full
    else
    {
        CHECK_AND_ASSERT_THROW_MES(max_inputs_allowed > 0 && added_inputs_inout.size() > 0,
            "updating an input set: unexpectedly there are no inputs in max inputs case (max ins should be > 0).");

        // try to use the highest excluded input to replace the lowest amount in the added inputs
        if (excluded_inputs_inout.size() > 0 &&
            excluded_inputs_inout.back().get_amount() > added_inputs_inout.front().get_amount())
        {
            auto exclude_last = excluded_inputs_inout.rbegin();
            added_inputs_inout.pop_front();
            added_inputs_inout.splice(added_inputs_inout.begin(), excluded_inputs_inout, exclude_last);

            return true;
        }

        // try to request a new input from the selector to replace the lowest amount in the added inputs
        while (input_selector.try_select_input_v1(output_amount + current_fee,
            added_inputs_inout,
            excluded_inputs_inout,
            requested_input))
        {
            // if requested input can cover the lowest added amount, replace it in the inputs list
            if (requested_input.get_amount() > added_inputs_inout.front.get_amount())
            {
                added_inputs_inout.pop_front();
                added_inputs_inout.emplace_front(std::move(requested_input));

                return true;
            }
            // otherwise, add it to the excluded list
            else
            {
                excluded_inputs_inout.emplace_front(requested_input);  //don't move - requested_input may be used again
            }
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_select_inputs_v1(const boost::multiprecision::uint128_t output_amount,
    const rct::xmr_amount fee_per_tx_weight,
    SpTxSquashedV1::WeightParams tx_weight_parameters,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    std::list<SpContextualEnoteRecordV1> &contextual_enote_records_out)
{
    CHECK_AND_ASSERT_THROW_MES(max_inputs_allowed > 0, "selecting an input set: zero inputs were allowed.");

    // update the input set until the output amount + fee is satisfied (or updating fails)
    std::list<SpContextualEnoteRecordV1> added_inputs;
    std::list<SpContextualEnoteRecordV1> excluded_inputs;

    while (try_update_added_inputs_v1(output_amount,
        fee_per_tx_weight,
        input_selector,
        tx_weight_parameters,
        added_inputs,
        excluded_inputs))
    {
        CHECK_AND_ASSERT_THROW_MES(added_inputs.size() <= max_inputs_allowed,
            "selecting an input set: there are more inputs than the number allowed (bug).");

        // compute current fee
        tx_weight_parameters.m_num_inputs = added_inputs.size();

        const DiscretizedFee fee_discretized{fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)};

        rct::xmr_amount fee;
        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(fee_discretized, fee),
            "selecting an input set: could not extract discretized fee for zero inputs case (bug).");

        // check if we have covered the required amount
        if (compute_total_amount(added_inputs) >= output_amount + fee)
        {
            contextual_enote_records_out = std::move(added_inputs);
            return true;
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
/*
    - for multisig, must prepare the output set before selecting inputs
    - note: this algorithm will fail to find a possible solution if there are combinations that lead to 0-change successes,
      but the combination that was found has non-zero change that doesn't cover the differential fee of adding a change
      output (and there are no solutions that can cover that additional change output differential fee)
        - only a brute force search can find the success solution(s) to this problem (e.g. if step (4) fails, you could
          fall-back to brute force search on the 0-change case; however, such cases will be extremely rare if they ever
          actually occur, so it probably isn't worthwhile to implement)
*/
//-------------------------------------------------------------------------------------------------------------------
bool try_get_input_set_v1(const boost::multiprecision::uint128_t output_amount,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::xmr_amount fee_per_tx_weight,
    SpTxSquashedV1::WeightParams tx_weight_parameters,
    const std::size_t max_inputs_allowed,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const InputSelectorV1 &input_selector,
    std::list<SpContextualEnoteRecordV1> &contextual_enote_records_out)
{
    /// try to get an input set
    contextual_enote_records_out.clear();

    // 1. select inputs to cover requested output amount (assume 0 change)

    // a. get number of additional outputs assuming zero change amount
    const std::size_t num_additional_outputs_no_change{
            compute_num_additional_outputs(wallet_spend_pubkey, k_view_balance, output_proposals, 0)
        };

    tx_weight_parameters.m_num_outputs = output_proposals.size() + num_additional_outputs_no_change;

    // b. select inputs
    if (!try_select_inputs_v1(output_amount,
            fee_per_tx_weight,
            tx_weight_parameters,
            max_inputs_allowed,
            input_selector,
            contextual_enote_records_out))
        return false;

    // 2. compute fee for selected inputs
    tx_weight_parameters.m_num_inputs = contextual_enote_records_out.size();

    const DiscretizedFee zero_change_fee_discretized{fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)};

    rct::xmr_amount zero_change_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(zero_change_fee_discretized, zero_change_fee),
        "getting an input set: could not extract discretized fee for zero change case (bug).");

    // 3. return if we are done (zero change is covered by input amounts) (very rare case)
    if (compute_total_amount(contextual_enote_records_out) == output_amount + zero_change_fee)
        return true;

    // 4. if non-zero change with computed fee, assume change must be non-zero (typical case)

    // a. update fee assuming non-zero change
    const std::size_t num_additional_outputs_with_change{
            compute_num_additional_outputs(wallet_spend_pubkey, k_view_balance, output_proposals, 1)
        };

    tx_weight_parameters.m_num_outputs = output_proposals.size() + num_additional_outputs_with_change;

    DiscretizedFee nonzero_change_fee_discretized{fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)};

    rct::xmr_amount nonzero_change_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(nonzero_change_fee_discretized, nonzero_change_fee),
        "getting an input set: could not extract discretized fee for nonzero change case (bug).");

    CHECK_AND_ASSERT_THROW_MES(zero_change_fee <= nonzero_change_fee,
        "getting an input set: adding a change output reduced the tx fee (bug).");

    // b. if previously selected inputs are insufficient for non-zero change, select inputs again (very rare case)
    if (compute_total_amount(contextual_enote_records_out) <= output_amount + nonzero_change_fee)
    {
        if (!try_select_inputs_v1(output_amount + 1,  //+1 to force a non-zero change
                fee_per_tx_weight,
                tx_weight_parameters,
                max_inputs_allowed,
                input_selector,
                contextual_enote_records_out))
            return false;

        tx_weight_parameters.m_num_inputs = contextual_enote_records_out.size();
        nonzero_change_fee_discretized = DiscretizedFee{
                fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
            };

        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(nonzero_change_fee_discretized, nonzero_change_fee),
            "getting an input set: could not extract discretized fee for nonzero change + updated inputs case (bug).");
    }

    // c. we are done (non-zero change is covered by input amounts)
    CHECK_AND_ASSERT_THROW_MES(compute_total_amount(contextual_enote_records_out) > output_amount + nonzero_change_fee,
        "getting an input set: selecting inputs for the non-zero change amount case failed (bug).");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
