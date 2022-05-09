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
#include "tx_builders_outputs.h"
#include "tx_discretized_fee.h"
#include "tx_enote_record_types.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers
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

    return additional_outputs_from_change;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
/*
    - note: call get_additional_output_types_for_output_set_v1() to figure out how many total outputs there will be
    - for multisig, must prepare the output set before selecting inputs
- try_select_inputs(total amount needed, fee/byte ratio, tx weight parameters, max inputs, input_selector, enote_set_out) -> bool
    - PROBLEM: what if the average amount in a collection of inputs can cover the average differential fee of adding them?
    - old_fee = fee from input parameters assuming num inputs equals zero
    - incrementally select inputs to cover/exceed requested amount + fee
        - record inputs map (sorted by incremental fee cost): {incremental fee cost, enote}
        - if total amount in inputs map doesn't meet requested amount + old_fee, try to add another input
            - new_fee = fee from existing parameters with +1 input
                - differential fee = new_fee - old_fee
            - try to select an enote to be an input: input_selector.try_select_additional_input(inputs_selected, ineligible_enotes)
                - if there are no eligible enotes, put entire ineligible set back into availability
                    - some enotes may have too low amount to cover early inputs' differential fee, but can cover later inputs' differential fee
                - if number of inputs has not changed since last emptying the ineligible set, return false (i.e. we recycled the inelgible set but couldn't use any of them)
                - try again: try_select_additional_input(inputs_selected, ineligible_enotes)
                    - if fail again, return false
            - if the inputs map is full and the new enote's amount exceeds the lowest amount in the inputs map, then replace that lowest amount position with the new enote
                - label the removed enote as temporarily ineligible
                - note: can pre-filter enote selection by ignoring those with amount <= the highest amount that has been previously removed from the inputs map due to the input cap, then return false if no enote satisfying that condition can be found
            - if the enote amount is <= the incremental fee cost of adding it, see if it can be swapped with any of the enotes in the existing enote map (i.e. the new enote exceeds the other enote's paired incremental cost, and the other enote's amount exceeds the new input's incremental fee cost)
                - if not, then label this enote temporarily ineligible and look for a new one
                - note: balancing inputs like this maximizes the solution success of this sub-algorithm
            - old_fee = new_fee
    - return false if unable to reach requested amount
- try_get_inputs(requested output amount, fee/byte, tx weight parameters, max inputs, input_selector, input_set_out) -> bool
    - input_selector is an injected dependency (it has read access to an enote store, and can have internal heuristics for selecting inputs, such as avoid picking inputs too close together, or don't select unconfirmed enotes, etc.)
    1) select inputs to cover requested output amount: try_select_inputs(output amnt, ...)
        - note: the output count in initial tx weight parameters should start in the '0 change' scenario
    2) compute fee as if there were 0 change
    3) if non-zero change with computed fee, update fee for scenario where there is a change output
    4) if new change <= 0, call try_select_inputs(output amnt + incremental fee from change + 1, ...)
        - first update output count in tx weight parameters to include change output
        - note: + 1 because we now assume that change is required (this avoids an oscillation problem where there is a solution with 0 change amount when assuming there is a change output, and a solution with non-zero change amount when assuming there are no change outputs)
    - output: [fee/byte, real fee, {inputs}] (if possible with available inputs)
        - return false if unable to make any input sets
    - note: this algorithm will fail to find a possible solution if there are combinations that lead to 0-change successes, but the combination that was found has non-zero change that doesn't cover the differential fee of adding a change output (and there are no solutions that can cover that additional change output differential fee)
        - only a brute force search can find the success solution(s) to this problem (e.g. if step (4) fails, you could fall-back to brute force search on the 0-change case; however, such cases will be extremely rare if they ever actually occur, so it probably isn't worthwhile to implement)
*/
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_v1(const rct::xmr_amount output_amount,
    const rct::xmr_amount fee_per_tx_weight,
    SpTxSquashedV1WeightParams tx_weight_parameters,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // make sure the inputs are sorted
    added_inputs_inout.sort();
    excluded_inputs_inout.sort();

    // current tx fee
    tx_weight_parameters.m_num_inputs = added_inputs_inout.size();

    const DiscretizedFee current_fee_discretized{
            fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
        };

    rct::xmr_amount current_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(current_fee_discretized, current_fee),
        "updating an input set: could not extract discretized fee for current case (bug).");

    SpContextualEnoteRecordV1 requested_input;

    // inputs are not full
    if (added_inputs_inout.size() < max_inputs_allowed)
    {
        // next tx fee
        ++tx_weight_parameters.m_num_inputs;

        const DiscretizedFee next_fee_discretized{
                fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
            };

        rct::xmr_amount next_fee;
        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(next_fee_discretized, next_fee),
            "updating an input set: could not extract discretized fee for next input case (bug).");

        // try to use the highest excluded input to cover and exceed the differential fee from adding it
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
                excluded_inputs_inout.emplace_front(requested_input);
            }
        }

        // if no more inputs to select, fall back to trying to add a range of excluded inputs
        if (excluded_inputs_inout.size() > 0)
        {
            excluded_inputs_inout.sort();

            rct::xmr_amount range_sum{0};
            std::size_t range_size{0};
            for (auto exclude_it = excluded_inputs_inout.rbegin(); exclude_it != excluded_inputs_inout.rend(); ++exclude_it)
            {
                range_sum += exclude_it->get_amount();
                ++range_size;

                // total fee including this range of inputs
                tx_weight_parameters.m_num_inputs = added_inputs_inout.size() + range_size;

                const DiscretizedFee range_fee_discretized{
                        fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
                    };

                rct::xmr_amount range_fee;
                CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(range_fee_discretized, range_fee),
                    "updating an input set: could not extract discretized fee for range input case (bug).");

                // if range of excluded inputs can cover the differential fee from those inputs, insert them
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
                excluded_inputs_inout.emplace_front(requested_input);
            }
        }
    }

    return false;

    // step 1: incrementally add inputs that can cover their own differential fee
    // - sorted list of added inputs (sorted by amount)
    // - sorted list of excluded inputs (sorted by amount)
    // - for new input to add, first see if highest amount in excluded input list can cover its differential fee
    //   - if so, pop that one into the added inputs list
    //   - otherwise, request a new input
    //     - if new input can't cover new differential fee, insert to excluded input list and request a new one (loop)
    // step 2: handle inputs is full
    // - if added inputs is full, try to replace the lowest amount with each requested new input
    // step 3: ran out of inputs to request
    // - if no more inputs to request (and highest amount in excluded input list can't cover the next input's differential
    //   fee OR inputs list is full), then iteratively replace the lowest amount in the added inputs list with the highest
    //   amount in the excluded inputs list until no more replacements are possible
    // step 4: handle inputs is full (again)
    // - if inputs list is full, return false
    // step 5: see if excluded inputs can be grouped to cover differential input fees
    // - try to find a group of excluded inputs that can cover a range of differential input fees (i.e. the average
    //   input amount exceeds the average differential fee) (loop)
    // - return false
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_select_inputs_v1(const rct::xmr_amount output_amount,
    const rct::xmr_amount fee_per_tx_weight,
    SpTxSquashedV1WeightParams tx_weight_parameters,
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
        tx_weight_parameters,
        input_selector,
        added_inputs,
        excluded_inputs))
    {
        CHECK_AND_ASSERT_THROW_MES(added_inputs.size() <= max_inputs_allowed,
            "selecting an input set: there are more inputs than the number allowed (bug).");

        // compute current fee
        tx_weight_parameters.m_num_inputs = added_inputs.size();

        const DiscretizedFee fee_discretized{
                fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
            };

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
//-------------------------------------------------------------------------------------------------------------------
bool try_get_input_set_v1(const rct::xmr_amount output_amount,
    const rct::xmr_amount fee_per_tx_weight,
    SpTxSquashedV1WeightParams tx_weight_parameters,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    SpInputSetV1 &input_set_out)
{
    /// try to get an input set

    // 1. select inputs to cover requested output amount (assume 0 change)
    std::list<SpContextualEnoteRecordV1> contextual_enote_records;

    // a. add additional outputs assuming zero change amount
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
            contextual_enote_records))
        return false;

    // 2. compute fee for selected inputs
    tx_weight_parameters.m_num_inputs = contextual_enote_records.size();

    const DiscretizedFee zero_change_fee_discretized{
            fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
        };

    rct::xmr_amount zero_change_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(zero_change_fee_discretized, zero_change_fee),
        "getting an input set: could not extract discretized fee for zero change case (bug).");

    // 3. return if we are done (zero change is covered by input amounts) (very rare case)
    if (compute_total_amount(contextual_enote_records) == output_amount + zero_change_fee)
    {
        input_set_out.m_fee_per_tx_weight = fee_per_tx_weight;
        input_set_out.m_tx_fee = zero_change_fee_discretized;
        input_set_out.m_contextual_enote_records = std::move(contextual_enote_records);

        return true;
    }

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
    if (compute_total_amount(contextual_enote_records) <= output_amount + nonzero_change_fee)
    {
        if (!try_select_inputs_v1(output_amount + 1,  //+1 to force a non-zero change
                fee_per_tx_weight,
                tx_weight_parameters,
                max_inputs_allowed,
                input_selector,
                contextual_enote_records))
            return false;

        tx_weight_parameters.m_num_inputs = contextual_enote_records.size();
        nonzero_change_fee_discretized = DiscretizedFee{
                fee_per_tx_weight * SpTxSquashedV1::get_weight(tx_weight_parameters)
            };

        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(nonzero_change_fee_discretized, nonzero_change_fee),
            "getting an input set: could not extract discretized fee for nonzero change + updated inputs case (bug).");
    }

    // c. we are done (non-zero change is covered by input amounts)
    CHECK_AND_ASSERT_THROW_MES(compute_total_amount(contextual_enote_records) > output_amount + nonzero_change_fee,
        "getting an input set: selecting inputs for the non-zero change amount case failed (bug).");

    input_set_out.m_fee_per_tx_weight = fee_per_tx_weight;
    input_set_out.m_tx_fee = nonzero_change_fee_discretized;
    input_set_out.m_contextual_enote_records = std::move(contextual_enote_records);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
