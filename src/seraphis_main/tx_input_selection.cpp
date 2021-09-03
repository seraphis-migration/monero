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
#include "tx_input_selection.h"

//local headers
#include "contextual_enote_record_types.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_fee_calculator.h"
#include "tx_input_selection_output_context.h"

//third party headers
#include "boost/container/map.hpp"
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <list>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

struct InputSelectionTypePair
{
    InputSelectionType added;
    InputSelectionType candidate;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static InputSelectionType input_selection_type(const ContextualRecordVariant &contextual_enote_record)
{
    struct visitor final : public tools::variant_static_visitor<InputSelectionType>
    {
        using variant_static_visitor::operator();  //for blank overload
        InputSelectionType operator()(const LegacyContextualEnoteRecordV1&) const { return InputSelectionType::LEGACY; }
        InputSelectionType operator()(const SpContextualEnoteRecordV1&) const { return InputSelectionType::SERAPHIS; }
    };

    return contextual_enote_record.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t count_records(const input_set_tracker_t &input_set, const InputSelectionType type)
{
    if (input_set.find(type) == input_set.end())
        return 0;

    return input_set.at(type).size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t total_inputs(const input_set_tracker_t &input_set)
{
    return count_records(input_set, InputSelectionType::LEGACY) +
        count_records(input_set, InputSelectionType::SERAPHIS);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount worst_amount_in_map(
    const boost::container::multimap<rct::xmr_amount, ContextualRecordVariant> &map)
{
    if (map.size() == 0)
        return 0;

    return map.begin()->first;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount best_amount_in_map(
    const boost::container::multimap<rct::xmr_amount, ContextualRecordVariant> &map)
{
    if (map.size() == 0)
        return 0;

    return map.rbegin()->first;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t compute_total_amount(const input_set_tracker_t &input_set)
{
    boost::multiprecision::uint128_t amount_sum{0};

    const auto legacy_set_it = input_set.find(InputSelectionType::LEGACY);
    if (legacy_set_it != input_set.end())
    {
        for (const auto &mapped_record : legacy_set_it->second)
            amount_sum += mapped_record.first;
    }

    const auto sp_set_it = input_set.find(InputSelectionType::SERAPHIS);
    if (sp_set_it != input_set.end())
    {
        for (const auto &mapped_record : sp_set_it->second)
            amount_sum += mapped_record.first;
    }

    return amount_sum;
}
//-------------------------------------------------------------------------------------------------------------------
// differential fee from removing one record of the specified type from the input set
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount diff_fee_of_removing_record(const input_set_tracker_t &input_set,
    const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    if (count_records(input_set, type) == 0)
        return -1;

    const std::size_t num_legacy_inputs_initial{count_records(input_set, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_initial{count_records(input_set, InputSelectionType::SERAPHIS)};
    const bool type_is_legacy{type == InputSelectionType::LEGACY};

    const rct::xmr_amount initial_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_initial,
                num_sp_inputs_initial,
                num_outputs)
        };
    const rct::xmr_amount fee_after_input_removed{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_initial - (type_is_legacy ? 1 : 0),
                num_sp_inputs_initial - (!type_is_legacy ? 1 : 0),
                num_outputs)
        };

    CHECK_AND_ASSERT_THROW_MES(initial_fee >= fee_after_input_removed,
        "input selection (diff fee of removing record): initial fee is lower than fee after input removed.");

    return initial_fee - fee_after_input_removed;
}
//-------------------------------------------------------------------------------------------------------------------
// differential fee from adding one record of the specified type to the input set
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount diff_fee_of_adding_record(const input_set_tracker_t &input_set,
    const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    const std::size_t num_legacy_inputs_initial{count_records(input_set, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_initial{count_records(input_set, InputSelectionType::SERAPHIS)};
    const bool type_is_legacy{type == InputSelectionType::LEGACY};

    const rct::xmr_amount initial_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_initial,
                num_sp_inputs_initial,
                num_outputs)
        };
    const rct::xmr_amount fee_after_input_added{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_initial + (type_is_legacy ? 1 : 0),
                num_sp_inputs_initial + (!type_is_legacy ? 1 : 0),
                num_outputs)
        };

    CHECK_AND_ASSERT_THROW_MES(fee_after_input_added >= initial_fee,
        "input selection (diff fee of adding record): initial fee is greater than fee after input added.");

    return fee_after_input_added - initial_fee;
}
//-------------------------------------------------------------------------------------------------------------------
// differential fee from adding a record of one type to the input set after removing a record of another type
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount diff_fee_of_replacing_record(const input_set_tracker_t &input_set,
    const InputSelectionType type_to_remove,
    const InputSelectionType type_to_add,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs)
{
    if (count_records(input_set, type_to_remove) == 0)
        return -1;

    // 1. calculate fee after input is removed
    const bool removed_type_is_legacy{type_to_add == InputSelectionType::LEGACY};
    const std::size_t num_legacy_inputs_removed{
            count_records(input_set, InputSelectionType::LEGACY) - (removed_type_is_legacy ? 1 : 0)
        };
    const std::size_t num_sp_inputs_removed{
            count_records(input_set, InputSelectionType::SERAPHIS) - (!removed_type_is_legacy ? 1 : 0)
        };

    const rct::xmr_amount fee_after_input_removed{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_removed,
                num_sp_inputs_removed,
                num_outputs)
        };

    // 2. calculate fee after input is added (after the removal step)
    const bool new_type_is_legacy{type_to_add == InputSelectionType::LEGACY};
    const rct::xmr_amount fee_after_input_added{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_removed + (new_type_is_legacy ? 1 : 0),
                num_sp_inputs_removed + (!new_type_is_legacy ? 1 : 0),
                num_outputs)
        };

    // 3. return the marginal fee of the new input compared to before it was added
    CHECK_AND_ASSERT_THROW_MES(fee_after_input_added >= fee_after_input_removed,
        "input selection (fee of replacing record): new fee is lower than fee after input removed.");

    return fee_after_input_added - fee_after_input_removed;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_exclude_useless_input_of_type_v1(const InputSelectionType type,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. fail if no added inputs to remove
    if (count_records(added_inputs_inout, type) == 0)
        return false;

    // 2. get the differential fee of the last input of the specified type
    const rct::xmr_amount last_input_fee{
            diff_fee_of_removing_record(added_inputs_inout,
                type,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };
    const rct::xmr_amount lowest_input_amount{
            worst_amount_in_map(added_inputs_inout.at(type))
        };

    // 3. don't exclude if the smallest-amount input can cover its own differential fee
    if (lowest_input_amount > last_input_fee)
        return false;

    // 4. remove the input
    candidate_inputs_inout[type].insert(
            added_inputs_inout[type].extract(lowest_input_amount)
        );

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_exclude_useless_v1(const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. fail if no added inputs to remove
    const std::size_t total_inputs_initial{total_inputs(added_inputs_inout)};
    if (total_inputs_initial == 0)
        return false;

    // 2. remove all useless added inputs
    // - useless = an input doesn't exceed its own differential fee
    std::size_t previous_total_inputs;

    do
    {
        previous_total_inputs = total_inputs(added_inputs_inout);

        // a. exclude useless legacy input
        try_exclude_useless_input_of_type_v1(InputSelectionType::LEGACY,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout);

        // b. exclude useless seraphis input
        try_exclude_useless_input_of_type_v1(InputSelectionType::SERAPHIS,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout);
    } while (previous_total_inputs > total_inputs(added_inputs_inout));

    // 3. fail if no inputs excluded
    if (total_inputs(added_inputs_inout) == total_inputs_initial)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_swap_pair_v1(const InputSelectionType added_type_to_remove,
    const InputSelectionType candidate_type_to_add,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. fail if swap isn't possible
    if (count_records(added_inputs_inout, added_type_to_remove) == 0 ||
        count_records(candidate_inputs_inout, candidate_type_to_add) == 0)
        return false;

    // 2. differential fee from removing lowest-amount added
    const boost::multiprecision::uint128_t differential_fee_replaceable{
            diff_fee_of_removing_record(added_inputs_inout,
                added_type_to_remove,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };

    // 3. differential fee from adding highest-amount candidate after added is removed
    const boost::multiprecision::uint128_t differential_fee_candidate{
            diff_fee_of_replacing_record(added_inputs_inout,
                added_type_to_remove,
                candidate_type_to_add,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };

    // 3. fail if this combination is not an improvement over the current added set
    //   replaceable_amnt - added_fee >= candidate_amnt - candidate_fee
    //   replaceable_amnt + candidate_fee >= candidate_amnt + added_fee     (no overflow on subtraction)
    const boost::multiprecision::uint128_t candidate_combination_cost{
            worst_amount_in_map(added_inputs_inout.at(added_type_to_remove)) + differential_fee_candidate
        };
    const boost::multiprecision::uint128_t candidate_combination_reward{
            best_amount_in_map(candidate_inputs_inout.at(candidate_type_to_add)) + differential_fee_replaceable
        };
    if (candidate_combination_cost >= candidate_combination_reward)
        return false;

    // 4. swap
    auto worst_added_input =
        added_inputs_inout[added_type_to_remove].extract(
                worst_amount_in_map(added_inputs_inout.at(added_type_to_remove))
            );
    auto best_candidate_input =
        candidate_inputs_inout[candidate_type_to_add].extract(
                best_amount_in_map(candidate_inputs_inout.at(candidate_type_to_add))
            );

    added_inputs_inout[candidate_type_to_add].insert(std::move(best_candidate_input));
    candidate_inputs_inout[added_type_to_remove].insert(std::move(worst_added_input));

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_replace_candidate_v1(const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. fail if no added or candidate inputs
    if (total_inputs(added_inputs_inout) == 0 ||
        total_inputs(candidate_inputs_inout) == 0)
        return false;

    // 2. search for the best solution when removing one added input and adding one candidate input
    // note: only perform one actual swap in case one swap is sufficient to solve the input selection game
    bool found_replacement_combination{false};
    std::list<InputSelectionTypePair> test_combinations =
        {
            {InputSelectionType::LEGACY, InputSelectionType::LEGACY},
            {InputSelectionType::LEGACY, InputSelectionType::SERAPHIS},
            {InputSelectionType::SERAPHIS, InputSelectionType::LEGACY},
            {InputSelectionType::SERAPHIS, InputSelectionType::SERAPHIS}
        };

    for (const InputSelectionTypePair &test_combination : test_combinations)
    {
        // fall-through once a swap succeeds
        found_replacement_combination = found_replacement_combination ||
            try_swap_pair_v1(test_combination.added,
                test_combination.candidate,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs_inout,
                candidate_inputs_inout);
    }

    // 3. fail if no swaps occurred
    if (!found_replacement_combination)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_add_candidate_of_type_v1(const InputSelectionType type,
    const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. expect the inputs to not be full here
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // 2. fail if no candidate inputs available of the specified type
    if (count_records(candidate_inputs_inout, type) == 0)
        return false;

    // 3. get the differential fee and amount of the best candidate
    const rct::xmr_amount next_input_fee_of_type{
            diff_fee_of_adding_record(added_inputs_inout,
                type,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs)
        };
    const rct::xmr_amount best_candidate_amount_of_type{
            best_amount_in_map(candidate_inputs_inout.at(type))
        };

    // 4. fail if the best candidate doesn't exceed the differential fee of adding it
    if (next_input_fee_of_type >= best_candidate_amount_of_type)
        return false;

    // 5. add the best candidate of this type
    added_inputs_inout[type].insert(
            candidate_inputs_inout[type].extract(best_candidate_amount_of_type)
        );

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_added_inputs_add_candidate_v1(const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. expect the inputs to not be full here
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // 2. fail if no candidate inputs available
    if (total_inputs(candidate_inputs_inout) == 0)
        return false;

    // 3. try to acquire a useful legacy input candidate
    if (try_add_candidate_of_type_v1(InputSelectionType::LEGACY,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout))
        return true;

    // 4. try to acquire a useful seraphis input candidate
    if (try_add_candidate_of_type_v1(InputSelectionType::SERAPHIS,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout))
        return true;

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_update_candidate_inputs_selection_v1(const boost::multiprecision::uint128_t output_amount,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    const input_set_tracker_t &added_inputs,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. get current record parameters of the added inputs set
    const std::size_t num_legacy_inputs{count_records(added_inputs, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs{count_records(added_inputs, InputSelectionType::SERAPHIS)};

    const rct::xmr_amount current_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // 2. get the reference amount for the input selection algorithm
    // - this is only the current amount needed; the final amount will likely be higher due to a higher fee from
    //   adding more inputs
    const boost::multiprecision::uint128_t selection_amount{output_amount + current_fee};

    // 3. try to get a new input candidate from the selector
    ContextualRecordVariant input_candidate;

    if (!input_selector.try_select_input_candidate_v1(selection_amount,
            added_inputs,
            candidate_inputs_inout,
            input_candidate))
        return false;

    // 4. save the new candidate input - we will try to move it into the added pile in later passthroughs
    candidate_inputs_inout[input_selection_type(input_candidate)].insert(
            input_set_tracker_t::mapped_type::value_type{amount_ref(input_candidate), std::move(input_candidate)}
        );

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_add_inputs_range_of_type_v1(const InputSelectionType type,
    const std::size_t max_inputs_allowed,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    const std::size_t num_outputs,
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // 1. current tx fee
    const std::size_t initial_inputs_count{total_inputs(added_inputs_inout)};
    std::size_t num_legacy_inputs{count_records(added_inputs_inout, InputSelectionType::LEGACY)};
    std::size_t num_sp_inputs{count_records(added_inputs_inout, InputSelectionType::SERAPHIS)};

    const rct::xmr_amount current_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs,
                num_sp_inputs,
                num_outputs)
        };

    // 2. try to add a range of candidate inputs
    boost::multiprecision::uint128_t range_sum{0};
    std::size_t range_size{0};

    for (auto candidate_it = candidate_inputs_inout[type].rbegin();
        candidate_it != candidate_inputs_inout[type].rend();
        ++candidate_it)
    {
        range_sum += candidate_it->first;
        ++range_size;

        // a. we have failed if our range exceeds the input limit
        if (initial_inputs_count + range_size > max_inputs_allowed)
            return false;

        // b. total fee including this range of inputs
        if (type == InputSelectionType::LEGACY)
            ++num_legacy_inputs;
        else
            ++num_sp_inputs;

        const rct::xmr_amount range_fee{
                tx_fee_calculator.compute_fee(fee_per_tx_weight,
                    num_legacy_inputs,
                    num_sp_inputs,
                    num_outputs)
            };

        // c. if range of candidate inputs can exceed the differential fee from those inputs, add them
        CHECK_AND_ASSERT_THROW_MES(range_fee >= current_fee,
            "input selection (candidate range): range fee is less than current fee (bug).");

        if (range_sum > range_fee - current_fee)
        {
            for (std::size_t num_moved{0}; num_moved < range_size; ++num_moved)
            {
                CHECK_AND_ASSERT_THROW_MES(candidate_inputs_inout[type].size() != 0,
                    "input selection (candidate range): candidate inputs range smaller than expected (bug).");

                added_inputs_inout[type].insert(
                        candidate_inputs_inout[type].extract(best_amount_in_map(candidate_inputs_inout[type]))
                    );
            }

            return true;
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
    input_set_tracker_t &added_inputs_inout,
    input_set_tracker_t &candidate_inputs_inout)
{
    // note: this algorithm assumes only a range of same-type inputs can produce a solution; there may be range solutions
    //       created by combinations of legacy/seraphis inputs, but since discovering those is a brute force exercise,
    //       they are ignored here; in general, as seraphis enotes become relatively more common than legacy enotes, this
    //       algorithm is expected to produce relatively fewer false negatives
    // note2: this algorithm also assumes there is no case where a range of added inputs might be usefully _replaced_ with
    //        a range of candidate inputs (if this case exists at all, it's probably a very niche edge-case)

    // 1. expect the added inputs list is not full
    if (total_inputs(added_inputs_inout) >= max_inputs_allowed)
        return false;

    // 2. try to add a range of candidate legacy inputs
    if (try_add_inputs_range_of_type_v1(InputSelectionType::LEGACY,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout))
        return true;

    // 3. try to add a range of candidate seraphis inputs
    if (try_add_inputs_range_of_type_v1(InputSelectionType::SERAPHIS,
            max_inputs_allowed,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs_inout,
            candidate_inputs_inout))
        return true;

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
    input_set_tracker_t initial_input_set,
    input_set_tracker_t &input_set_out)
{
    CHECK_AND_ASSERT_THROW_MES(max_inputs_allowed > 0, "input selection: zero inputs were allowed.");
    input_set_out.clear();

    // update the input set until the output amount + fee is satisfied (or updating fails)
    input_set_tracker_t added_inputs{std::move(initial_input_set)};
    input_set_tracker_t candidate_inputs;

    while (true)
    {
        // 1. exclude added inputs that don't pay for their differential fees
        // note: this is a clean-up pass, so has precedence over checking for a solution
        try_update_added_inputs_exclude_useless_v1(fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs,
            added_inputs,
            candidate_inputs);

        // 2. check if we have a solution
        CHECK_AND_ASSERT_THROW_MES(total_inputs(added_inputs) <= max_inputs_allowed,
            "input selection: there are more inputs than the number allowed (bug).");

        // a. compute current fee
        const rct::xmr_amount current_fee{
                tx_fee_calculator.compute_fee(fee_per_tx_weight,
                    count_records(added_inputs, InputSelectionType::LEGACY),
                    count_records(added_inputs, InputSelectionType::SERAPHIS),
                    num_outputs)
            };

        // b. check if we have covered the required amount
        if (compute_total_amount(added_inputs) >= output_amount + current_fee)
        {
            input_set_out = std::move(added_inputs);
            return true;
        }

        // 3. try to add the best candidate input to the added inputs set
        if (try_update_added_inputs_add_candidate_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                candidate_inputs))
            continue;

        // 4. try to replace an added input with a better candidate input
        // - do this after trying to add an candidate input for better utilization of selected inputs; typically,
        //   after obtaining a new candidate input in step 5, it will be directly added to the input set in step 3
        //   of the next update cycle; if this step were ordered before step 3, then new candidates would frequently
        //   be swapped with previously added inputs, and the final input set would always contain only the highest
        //   amounts from the selected inputs (even if the input selector was hoping for a different distribution)
        // - the emergent behavior of the input selection process is overall rather opaque, but this ordering of
        //   steps should match the caller's expectations the best
        if (try_update_added_inputs_replace_candidate_v1(fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                candidate_inputs))
            continue;

        // 5. try to obtain a new candidate input from the input selector
        if (try_update_candidate_inputs_selection_v1(output_amount,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                candidate_inputs))
            continue;

        // 6. try to use a range of candidate inputs to get us closer to a solution
        // note: this is an inefficient last-ditch effort, so we only attempt it after no more inputs can be selected
        if (try_update_added_inputs_range_v1(max_inputs_allowed,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs,
                added_inputs,
                candidate_inputs))
            continue;

        // 7. no attempts to update the added inputs worked, so we have failed
        return false;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_input_set_v1(const OutputSetContextForInputSelection &output_set_context,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    rct::xmr_amount &final_fee_out,
    input_set_tracker_t &input_set_out)
{
    input_set_out.clear();

    // 1. select inputs to cover requested output amount (assume 0 change)
    const boost::multiprecision::uint128_t output_amount{output_set_context.total_amount()};
    const std::size_t num_outputs_nochange{output_set_context.num_outputs_nochange()};

    if (!try_select_inputs_v1(output_amount,
            max_inputs_allowed,
            input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            num_outputs_nochange,
            {},
            input_set_out))
        return false;

    // 2. compute fee for selected inputs
    const std::size_t num_legacy_inputs_first_try{count_records(input_set_out, InputSelectionType::LEGACY)};
    const std::size_t num_sp_inputs_first_try{count_records(input_set_out, InputSelectionType::SERAPHIS)};

    const rct::xmr_amount zero_change_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_first_try,
                num_sp_inputs_first_try,
                num_outputs_nochange)
        };

    // 3. return if we are done (zero change is covered by input amounts)
    // - very rare case
    if (compute_total_amount(input_set_out) == output_amount + zero_change_fee)
    {
        final_fee_out = zero_change_fee;
        return true;
    }

    // 4. if non-zero change with computed fee, assume change must be non-zero (typical case)
    // a. update fee assuming non-zero change
    const std::size_t num_outputs_withchange{output_set_context.num_outputs_withchange()};

    rct::xmr_amount nonzero_change_fee{
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_first_try,
                num_sp_inputs_first_try,
                num_outputs_withchange)
        };

    CHECK_AND_ASSERT_THROW_MES(zero_change_fee <= nonzero_change_fee,
        "getting an input set: adding a change output reduced the tx fee (bug).");

    // b. if previously selected inputs are insufficient for non-zero change, select inputs again
    // - very rare case
    if (compute_total_amount(input_set_out) <= output_amount + nonzero_change_fee)
    {
        // i. select inputs
        if (!try_select_inputs_v1(output_amount + 1,  //+1 to force a non-zero change
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                num_outputs_withchange,
                std::move(input_set_out),  //reuse already-selected inputs
                input_set_out))
            return false;

        // ii. update the fee
        const std::size_t num_legacy_inputs_second_try{count_records(input_set_out, InputSelectionType::LEGACY)};
        const std::size_t num_sp_inputs_second_try{count_records(input_set_out, InputSelectionType::SERAPHIS)};

        nonzero_change_fee =
            tx_fee_calculator.compute_fee(fee_per_tx_weight,
                num_legacy_inputs_second_try,
                num_sp_inputs_second_try,
                num_outputs_withchange);
    }

    // c. we are done (non-zero change is covered by input amounts)
    CHECK_AND_ASSERT_THROW_MES(compute_total_amount(input_set_out) > output_amount + nonzero_change_fee,
        "getting an input set: selecting inputs for the non-zero change amount case failed (bug).");

    final_fee_out = nonzero_change_fee;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
