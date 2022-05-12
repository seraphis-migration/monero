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
#include "ringct/rctTypes.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_store.h"
#include "seraphis/tx_fee_calculator.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selector_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <list>
#include <vector>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static sp::SpEnoteStoreV1 prepare_enote_store(const std::vector<rct::xmr_amount> &amounts)
{
    sp::SpEnoteStoreV1 enote_store;

    for (const rct::xmr_amount amount : amounts)
    {
        enote_store.m_contextual_enote_records.emplace_back();
        enote_store.m_contextual_enote_records.back().m_core.m_enote.gen();
        enote_store.m_contextual_enote_records.back().m_core.m_amount = amount;
    }

    return enote_store;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void input_selection_test(const std::vector<rct::xmr_amount> &stored_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount fee_per_tx_weight,
    const sp::FeeCalculator &tx_fee_calculator,
    const std::size_t max_inputs_allowed,
    const std::vector<rct::xmr_amount> &input_amounts_expected,
    const bool expected_result)
{
    ASSERT_TRUE(output_amounts.size() > 0);

    // prepare enote storage (inputs will be selected from this)
    const sp::SpEnoteStoreV1 enote_store{prepare_enote_store(stored_amounts)};

    // make input selector
    const sp::InputSelectorMockSimpleV1 input_selector{enote_store};

    // prepare output proposals (represents pre-finalization tx outputs)
    std::vector<sp::SpOutputProposalV1> output_proposals;
    output_proposals.reserve(output_amounts.size());
    boost::multiprecision::uint128_t total_output_amount;

    for (const rct::xmr_amount output_amount : output_amounts)
    {
        output_proposals.emplace_back();
        output_proposals.back().gen(output_amount, 0);

        total_output_amount += output_amount;
    }

    // miscellaneous dummy pieces
    const rct::key wallet_spend_pubkey{rct::pkGen()};
    const crypto::secret_key k_view_balance{rct::rct2sk(rct::skGen())};

    // try to get an input set
    std::list<sp::SpContextualEnoteRecordV1> inputs_selected;
    bool result{false};
    EXPECT_NO_THROW(
            result = sp::try_get_input_set_v1(wallet_spend_pubkey,
                k_view_balance,
                output_proposals,
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                inputs_selected)
        );

    // check results

    // 1. getting an input set had expected result
    EXPECT_TRUE(result == expected_result);

    // 2. early return on failures (remaining checks are meaningless and likely to fail)
    if (result == false)
        return;

    // 3. inputs selected have expected amounts in expected order
    EXPECT_TRUE(inputs_selected.size() == input_amounts_expected.size());

    std::size_t input_index{0};
    boost::multiprecision::uint128_t total_input_amount;
    for (const sp::SpContextualEnoteRecordV1 &input_selected : inputs_selected)
    {
        EXPECT_TRUE(input_selected.get_amount() == input_amounts_expected[input_index]);
        ++input_index;

        total_input_amount += input_selected.get_amount();
    }

    // 4. total input amount is sufficient to cover outputs + fee

    // a. test zero-change case
    const std::size_t num_inputs{inputs_selected.size()};
    const std::size_t num_outputs_nochange{output_amounts.size() < 2 ? 2 : output_amounts.size()};
    const rct::xmr_amount fee_nochange{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_nochange)};

    EXPECT_TRUE(total_input_amount >= total_output_amount + fee_nochange);

    // - early return if inputs selected satisfy the zero-change case
    if (total_input_amount == total_output_amount + fee_nochange)
        return;

    // b. test non-zero-change case
    const std::size_t num_outputs_withchange{output_amounts.size() < 2 ? 2 : output_amounts.size() + 1};
    const rct::xmr_amount fee_withchange{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_withchange)};

    EXPECT_TRUE(total_input_amount > total_output_amount + fee_withchange);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, trivial)
{
    //input_selection_test(stored_enotes, out_amnts, fee/wght, fee_calc, max_ins, expected_in_amnts, expected_result);

    // trivial calculator: fee = fee per weight
    sp::FeeCalculatorMockTrivial fee_calculator;

    // one input, one output
    input_selection_test({2}, {1}, 1, fee_calculator, 1, {2}, true);

    // one input, two outputs
    input_selection_test({3}, {1, 1}, 1, fee_calculator, 1, {3}, true);

    // two inputs, one output
    input_selection_test({1, 1}, {1}, 1, fee_calculator, 2, {1, 1}, true);

    // two inputs, two outputs
    input_selection_test({2, 1}, {1, 1}, 1, fee_calculator, 2, {2, 1}, true);
}
//-------------------------------------------------------------------------------------------------------------------
