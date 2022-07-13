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

#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_fee_calculator.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_mocks.h"
#include "seraphis/tx_input_selector_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <list>
#include <vector>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_enote_store(const std::vector<rct::xmr_amount> &amounts,
    sp::SpEnoteStoreMockSimpleV1 &enote_store_inout)
{
    for (const rct::xmr_amount amount : amounts)
    {
        sp::SpEnoteRecordV1 temp_record{};
        temp_record.m_enote.gen();
        temp_record.m_amount = amount;
        temp_record.m_key_image = rct::rct2ki(rct::pkGen());

        enote_store_inout.add_record(
                sp::SpContextualEnoteRecordV1{
                    .m_record = temp_record
                }
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void input_selection_test(const std::vector<rct::xmr_amount> &stored_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const std::size_t num_additional_outputs_with_change,
    const rct::xmr_amount fee_per_tx_weight,
    const sp::FeeCalculator &tx_fee_calculator,
    const std::size_t max_inputs_allowed,
    const std::vector<rct::xmr_amount> &input_amounts_expected,
    const bool expected_result)
{
    CHECK_AND_ASSERT_THROW_MES(output_amounts.size() > 0, "insuffient output amounts");
    CHECK_AND_ASSERT_THROW_MES(input_amounts_expected.size() <= max_inputs_allowed, "too many expected input amounts");

    // prepare enote storage (inputs will be selected from this)
    sp::SpEnoteStoreMockSimpleV1 enote_store;
    prepare_enote_store(stored_amounts, enote_store);

    // make input selector
    const sp::InputSelectorMockSimpleV1 input_selector{enote_store};

    // prepare output set context (represents pre-finalization tx outputs)
    const sp::OutputSetContextForInputSelectionMockSimple output_set_context{
            output_amounts,
            num_additional_outputs_with_change
        };

    // collect total output amount
    const boost::multiprecision::uint128_t total_output_amount{output_set_context.get_total_amount()};

    // try to get an input set
    rct::xmr_amount final_fee;
    std::list<sp::SpContextualEnoteRecordV1> inputs_selected;
    const bool result{
            sp::try_get_input_set_v1(output_set_context,
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                final_fee,
                inputs_selected)
        };

    // check results

    // 1. getting an input set had expected result
    CHECK_AND_ASSERT_THROW_MES(result == expected_result, "unexpected result");

    // 2. early return on failures (remaining checks are meaningless and likely to fail)
    if (result == false)
        return;

    // 3. inputs selected have expected amounts in expected order
    CHECK_AND_ASSERT_THROW_MES(inputs_selected.size() == input_amounts_expected.size(),
        "selected inputs quantity mismatch");

    std::size_t input_index{0};
    boost::multiprecision::uint128_t total_input_amount{0};
    for (const sp::SpContextualEnoteRecordV1 &input_selected : inputs_selected)
    {
        CHECK_AND_ASSERT_THROW_MES(input_selected.get_amount() == input_amounts_expected[input_index],
            "selected inputs expected amount mismatch");
        ++input_index;

        total_input_amount += input_selected.get_amount();
    }

    // 4. total input amount is sufficient to cover outputs + fee

    // a. test zero-change case
    const std::size_t num_inputs{inputs_selected.size()};
    const std::size_t num_outputs_nochange{output_amounts.size()};
    const rct::xmr_amount fee_nochange{
            tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_nochange)
        };

    CHECK_AND_ASSERT_THROW_MES(total_input_amount >= total_output_amount + fee_nochange,
        "input amount does not cover output amount + fee_nochange");

    // - early return if inputs selected satisfy the zero-change case
    if (total_input_amount == total_output_amount + fee_nochange)
    {
        CHECK_AND_ASSERT_THROW_MES(final_fee == fee_nochange, "obtained fee doesn't match nochange fee (it should)");
        return;
    }

    // b. test non-zero-change case
    const std::size_t num_outputs_withchange{output_amounts.size() + num_additional_outputs_with_change};
    const rct::xmr_amount fee_withchange{
            tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_withchange)
        };

    CHECK_AND_ASSERT_THROW_MES(total_input_amount > total_output_amount + fee_withchange,
        "input amount does not exceed output amount + fee_withchange");

    CHECK_AND_ASSERT_THROW_MES(final_fee == fee_withchange, "obtained fee doesn't match withchange fee (it should)");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, trivial)
{
    //test(stored_enotes, out_amnts, +outs_w_change, fee/wght, fee_calc, max_ins, expect_in_amnts, result)

    // trivial calculator: fee = fee per weight
    const sp::FeeCalculatorMockTrivial fee_calculator;

    // one input, one output
    EXPECT_NO_THROW(input_selection_test({2}, {1}, 0, 1, fee_calculator, 1, {2}, true));

    // one input, two outputs
    EXPECT_NO_THROW(input_selection_test({3}, {1, 1}, 0, 1, fee_calculator, 1, {3}, true));

    // two inputs, one output
    EXPECT_NO_THROW(input_selection_test({1, 1}, {1}, 0, 1, fee_calculator, 2, {1, 1}, true));

    // two inputs, two outputs
    EXPECT_NO_THROW(input_selection_test({2, 1}, {1, 1}, 0, 1, fee_calculator, 2, {2, 1}, true));

    // search for input
    EXPECT_NO_THROW(input_selection_test({0, 0, 2, 1}, {1}, 0, 1, fee_calculator, 2, {2}, true));

    // search for input (overfill the amount)
    EXPECT_NO_THROW(input_selection_test({0, 0, 1, 2}, {1}, 0, 1, fee_calculator, 2, {1, 2}, true));

    // no solution: max inputs limit
    EXPECT_NO_THROW(input_selection_test({1, 1}, {1}, 0, 1, fee_calculator, 1, {}, false));

    // no solution: insufficient funds
    EXPECT_NO_THROW(input_selection_test({0, 1}, {1}, 0, 1, fee_calculator, 2, {}, false));

    // replacement: max inputs constrain which can be selected
    EXPECT_NO_THROW(input_selection_test({0, 2, 1, 1, 3}, {3}, 0, 1, fee_calculator, 2, {2, 3}, true));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, simple)
{
    //test(stored_enotes, out_amnts, +outs_w_change, fee/wght, fee_calc, max_ins, expect_in_amnts, result)

    // simple calculator: fee = fee per weight * (num_inputs + num_outputs)
    const sp::FeeCalculatorMockSimple fee_calculator;

    // one input, one output
    EXPECT_NO_THROW(input_selection_test({1}, {0}, 1, 1, fee_calculator, 1, {}, false));
    EXPECT_NO_THROW(input_selection_test({2}, {0}, 1, 1, fee_calculator, 1, {2}, true));

    // one input, one output (with change)
    EXPECT_NO_THROW(input_selection_test({3}, {0}, 1, 1, fee_calculator, 1, {}, false));
    EXPECT_NO_THROW(input_selection_test({4}, {0}, 1, 1, fee_calculator, 1, {4}, true));

    // IMPORTANT FAILURE CASE
    // A solution exists but won't be found (requires a brute force search that wasn't implemented).

    // no change: 1 input + 1 output -> fee = 2
    // with change: 1 input + 2 outputs -> fee = 3
    // 1. will select '3' as a solution for 'no change' pass
    // 2. 3 - 2 = change of '1', so try the 'with change' pass
    //    a. the other 'no change' pass solution is '2', which would permit a zero-change final solution
    // 3. the 'with change' solution is '3', but 'with change' solutions must have non-zero change, so we failed
    EXPECT_NO_THROW(input_selection_test({3, 2}, {0}, 1, 1, fee_calculator, 1, {}, false));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, inputs_stepped)
{
    //test(stored_enotes, out_amnts, +outs_w_change, fee/wght, fee_calc, max_ins, expect_in_amnts, result)

    // fee = fee_per_weight * (num_inputs / 2 + num_outputs)
    const sp::FeeCalculatorMockInputsStepped fee_calculator;

    // accumulation: no single input amount can cover the differential fee at each step
    // fee [0 in, 1 out, 3 weight]: 3
    // fee [1 in, 1 out, 3 weight]: 3
    // fee [2 in, 1 out, 3 weight]: 6
    // fee [3 in, 1 out, 3 weight]: 6
    // fee [4 in, 1 out, 3 weight]: 9
    EXPECT_NO_THROW(input_selection_test({2, 2, 2}, {0}, 1, 3, fee_calculator, 2, {}, false));  //input limit
    EXPECT_NO_THROW(input_selection_test({1, 1, 2, 2, 2}, {0}, 1, 3, fee_calculator, 3, {2, 2, 2}, true));

    // don't fall back on accumulation if there is a simpler solution
    EXPECT_NO_THROW(input_selection_test({2, 2, 2, 10}, {0}, 1, 3, fee_calculator, 3, {2, 10}, true));

    // replacement: an excluded input gets re-selected when input limit is encountered
    EXPECT_NO_THROW(input_selection_test({1, 2, 4}, {0}, 1, 3, fee_calculator, 2, {4, 2}, true));
}
//-------------------------------------------------------------------------------------------------------------------
