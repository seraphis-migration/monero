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
#include "tx_input_selection.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_builders_outputs.h"
#include "tx_enote_record_types.h"
#include "tx_fee_calculator.h"

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
static std::size_t compute_num_additional_outputs(const rct::key &wallet_spend_pubkey,
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
static void sort_contextual_enote_records_descending(std::list<SpContextualEnoteRecordV1> &contextual_enote_records_inout)
{
    // sort: largest amount first, smallest amount last
    contextual_enote_records_inout.sort(
            [](const SpContextualEnoteRecordV1 &record1, const SpContextualEnoteRecordV1 &record2) -> bool
            {
                return record1.get_amount() > record2.get_amount();
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_replace_excluded_v1(std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // make sure all the inputs are sorted
    sort_contextual_enote_records_descending(added_inputs_inout);
    sort_contextual_enote_records_descending(excluded_inputs_inout);

    // try to use the highest excluded input to replace the lowest amount in the added inputs
    if (excluded_inputs_inout.size() > 0 &&
        excluded_inputs_inout.front().get_amount() > added_inputs_inout.back().get_amount())
    {
        added_inputs_inout.pop_back();
        added_inputs_inout.splice(added_inputs_inout.end(), excluded_inputs_inout, excluded_inputs_inout.begin());

        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_add_excluded_v1(const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // expect the inputs to not be full here
    if (added_inputs_inout.size() >= max_inputs_allowed)
        return false;

    // current tx fee
    const std::size_t num_inputs_current{added_inputs_inout.size()};
    const rct::xmr_amount current_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_current, num_outputs)};

    // next tx fee (from adding one input)
    const std::size_t num_inputs_next{added_inputs_inout.size() + 1};
    const rct::xmr_amount next_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_next, num_outputs)};

    // make sure the excluded inputs are sorted
    sort_contextual_enote_records_descending(excluded_inputs_inout);

    // try to use the highest excluded input to cover and exceed the differential fee from adding it
    CHECK_AND_ASSERT_THROW_MES(next_fee >= current_fee,
        "updating an input set (add excluded): next fee is less than current fee (bug).");

    if (excluded_inputs_inout.size() > 0 &&
        excluded_inputs_inout.front().get_amount() > next_fee - current_fee)
    {
        added_inputs_inout.splice(added_inputs_inout.end(), excluded_inputs_inout, excluded_inputs_inout.begin());

        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_selection_v1(const boost::multiprecision::uint128_t output_amount,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // make sure the added inputs are sorted
    sort_contextual_enote_records_descending(added_inputs_inout);

    // current tx fee
    const std::size_t num_inputs_current{added_inputs_inout.size()};
    const rct::xmr_amount current_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_current, num_outputs)};

    // prepare for finding a new input
    boost::multiprecision::uint128_t selection_amount;
    boost::multiprecision::uint128_t comparison_amount;

    if (added_inputs_inout.size() < max_inputs_allowed)
    {
        // if inputs aren't full, then we will be trying to add a new input to the added inputs list
        const std::size_t num_inputs_next{added_inputs_inout.size() + 1};
        const rct::xmr_amount next_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_next, num_outputs)};

        CHECK_AND_ASSERT_THROW_MES(next_fee >= current_fee,
            "updating an input set (selection): next fee is less than current fee (bug).");

        selection_amount = output_amount + next_fee;
        comparison_amount = next_fee - current_fee;
    }
    else
    {
        // if inputs are full, then we will be trying to replace the lowest amount input
        selection_amount = output_amount + current_fee;
        comparison_amount = added_inputs_inout.back().get_amount();
    }

    // try to get a new input from the selector
    SpContextualEnoteRecordV1 requested_input;

    while (input_selector.try_select_input_v1(selection_amount,
        added_inputs_inout,
        excluded_inputs_inout,
        requested_input))
    {
        // if requested input can cover the comparison amount, add it to the inputs list
        if (requested_input.get_amount() > comparison_amount)
        {
            if (added_inputs_inout.size() >= max_inputs_allowed)
            {
                // for the 'inputs is full' case, we replace the lowest amount input
                added_inputs_inout.pop_back();
            }

            added_inputs_inout.emplace_back(std::move(requested_input));

            return true;
        }
        // otherwise, add it to the excluded list
        else
        {
            excluded_inputs_inout.emplace_back(requested_input);  //don't move - requested_input may be used again
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_range_v1(const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    std::list<SpContextualEnoteRecordV1> &added_inputs_inout,
    std::list<SpContextualEnoteRecordV1> &excluded_inputs_inout)
{
    // expect the added inputs list is not full
    if (added_inputs_inout.size() >= max_inputs_allowed)
        return false;

    // current tx fee
    const std::size_t num_inputs_current{added_inputs_inout.size()};
    const rct::xmr_amount current_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_current, num_outputs)};

    // make sure the excluded inputs are sorted
    sort_contextual_enote_records_descending(excluded_inputs_inout);

    // try to add a range of excluded inputs
    boost::multiprecision::uint128_t range_sum{0};
    std::size_t range_size{0};

    for (auto exclude_it = excluded_inputs_inout.begin(); exclude_it != excluded_inputs_inout.end(); ++exclude_it)
    {
        range_sum += exclude_it->get_amount();
        ++range_size;

        // we have failed if our range exceeds the input limit
        if (added_inputs_inout.size() + range_size > max_inputs_allowed)
            return false;

        // total fee including this range of inputs
        const std::size_t num_inputs_range{added_inputs_inout.size() + range_size};
        const rct::xmr_amount range_fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_range, num_outputs)};

        // if range of excluded inputs can cover the differential fee from those inputs, insert them
        CHECK_AND_ASSERT_THROW_MES(range_fee >= current_fee,
            "updating an input set (range): range fee is less than current fee (bug).");

        if (range_sum > range_fee - current_fee)
        {
            added_inputs_inout.splice(added_inputs_inout.end(),
                excluded_inputs_inout,
                excluded_inputs_inout.begin(),
                exclude_it);

            return true;
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_select_inputs_v1(const boost::multiprecision::uint128_t output_amount,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    std::list<SpContextualEnoteRecordV1> &contextual_enote_records_out)
{
    CHECK_AND_ASSERT_THROW_MES(max_inputs_allowed > 0, "selecting an input set: zero inputs were allowed.");

    // update the input set until the output amount + fee is satisfied (or updating fails)
    std::list<SpContextualEnoteRecordV1> added_inputs;
    std::list<SpContextualEnoteRecordV1> excluded_inputs;

    while (true)
    {
        // 1. check if we have a solution
        CHECK_AND_ASSERT_THROW_MES(added_inputs.size() <= max_inputs_allowed,
            "selecting an input set: there are more inputs than the number allowed (bug).");

        // a. compute current fee
        const std::size_t num_inputs{added_inputs.size()};
        const rct::xmr_amount fee{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs)};

        // b. check if we have covered the required amount
        if (compute_total_amount(added_inputs) >= output_amount + fee)
        {
            contextual_enote_records_out = std::move(added_inputs);
            return true;
        }

        // 2. try to replace an added input with a better excluded input
        if (try_update_added_inputs_replace_excluded_v1(added_inputs, excluded_inputs))
            continue;

        // 3. try to add the best excluded input to the added inputs set
        if (try_update_added_inputs_add_excluded_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 4. try to get a new input that can get us closer to a solution
        if (try_update_added_inputs_selection_v1(output_amount,
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 5. try to use a range of excluded inputs to get us closer to a solution
        if (try_update_added_inputs_range_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                excluded_inputs))
            continue;

        // 6. no attempts to update the added inputs worked, so we have failed
        return false;
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
bool try_get_input_set_v1(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    rct::xmr_amount &final_fee_out,
    std::list<SpContextualEnoteRecordV1> &contextual_enote_records_out)
{
    // 1. select inputs to cover requested output amount (assume 0 change)
    // a. compute output amount
    boost::multiprecision::uint128_t output_amount{0};

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        output_amount += output_proposal.get_amount();

    // b. get number of additional outputs assuming zero change amount
    const std::size_t num_additional_outputs_no_change{
            compute_num_additional_outputs(wallet_spend_pubkey, k_view_balance, output_proposals, 0)
        };

    const std::size_t num_outputs_nochange{output_proposals.size() + num_additional_outputs_no_change};

    // c. select inputs
    contextual_enote_records_out.clear();

    if (!try_select_inputs_v1(output_amount,
            max_inputs_allowed,
            input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs_nochange,
            contextual_enote_records_out))
        return false;

    // 2. compute fee for selected inputs
    const std::size_t num_inputs_first_try{contextual_enote_records_out.size()};
    const rct::xmr_amount zero_change_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_first_try, num_outputs_nochange)
        };

    // 3. return if we are done (zero change is covered by input amounts) (very rare case)
    if (compute_total_amount(contextual_enote_records_out) == output_amount + zero_change_fee)
    {
        final_fee_out = zero_change_fee;
        return true;
    }

    // 4. if non-zero change with computed fee, assume change must be non-zero (typical case)
    // a. update fee assuming non-zero change
    const std::size_t num_additional_outputs_with_change{
            compute_num_additional_outputs(wallet_spend_pubkey, k_view_balance, output_proposals, 1)
        };

    const std::size_t num_outputs_withchange{output_proposals.size() + num_additional_outputs_with_change};
    rct::xmr_amount nonzero_change_fee{
            tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_first_try, num_outputs_withchange)
        };

    CHECK_AND_ASSERT_THROW_MES(zero_change_fee <= nonzero_change_fee,
        "getting an input set: adding a change output reduced the tx fee (bug).");

    // b. if previously selected inputs are insufficient for non-zero change, select inputs again (very rare case)
    if (compute_total_amount(contextual_enote_records_out) <= output_amount + nonzero_change_fee)
    {
        contextual_enote_records_out.clear();

        if (!try_select_inputs_v1(output_amount + 1,  //+1 to force a non-zero change
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs_withchange,
                contextual_enote_records_out))
            return false;

        const std::size_t num_inputs_second_try{contextual_enote_records_out.size()};
        nonzero_change_fee = tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs_second_try, num_outputs_withchange);
    }

    // c. we are done (non-zero change is covered by input amounts)
    CHECK_AND_ASSERT_THROW_MES(compute_total_amount(contextual_enote_records_out) > output_amount + nonzero_change_fee,
        "getting an input set: selecting inputs for the non-zero change amount case failed (bug).");

    final_fee_out = nonzero_change_fee;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
