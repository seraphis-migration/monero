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
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/sp_core_enote_utils.h"
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

struct jamtis_keys
{
    crypto::secret_key k_m;   //master
    crypto::secret_key k_vb;  //view-balance
    crypto::secret_key k_fr;  //find-received
    crypto::secret_key s_ga;  //generate-address
    crypto::secret_key s_ct;  //cipher-tag
    rct::key K_1_base;        //wallet spend base
    rct::key K_fr;            //find-received pubkey
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = make_secret_key();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_keys(jamtis_keys &keys_out)
{
    using namespace sp;
    using namespace jamtis;

    make_secret_key(keys_out.k_m);
    make_secret_key(keys_out.k_vb);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.k_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    make_seraphis_spendkey(keys_out.k_vb, keys_out.k_m, keys_out.K_1_base);
    rct::scalarmultBase(keys_out.K_fr, rct::sk2rct(keys_out.k_fr));
}
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
// make all self-sends so we can test the case where adding a change output increases the output count
//-------------------------------------------------------------------------------------------------------------------
static std::vector<sp::SpOutputProposalV1> prepare_output_proposals(const jamtis_keys &user_keys,
    const std::vector<rct::xmr_amount> &output_amounts)
{
    // user address
    sp::jamtis::address_index_t j;
    j.gen();
    sp::jamtis::JamtisDestinationV1 user_address;

    sp::jamtis::make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.K_fr,
        user_keys.s_ga,
        j,
        user_address);

    // make self-send output proposals
    std::vector<sp::SpOutputProposalV1> output_proposals;
    output_proposals.reserve(output_amounts.size());

    for (const rct::xmr_amount output_amount : output_amounts)
    {
        sp::jamtis::JamtisPaymentProposalSelfSendV1 payment_proposal_selfspend{user_address,
            output_amount,
            sp::jamtis::JamtisSelfSendMAC::SELF_SPEND,
            make_secret_key()};

        output_proposals.emplace_back();
        payment_proposal_selfspend.get_output_proposal_v1(user_keys.k_vb, output_proposals.back());
    }

    return output_proposals;
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
    CHECK_AND_ASSERT_THROW_MES(output_amounts.size() > 0, "insuffient output amounts");
    CHECK_AND_ASSERT_THROW_MES(input_amounts_expected.size() <= max_inputs_allowed, "too many expected input amounts");

    // prepare enote storage (inputs will be selected from this)
    const sp::SpEnoteStoreV1 enote_store{prepare_enote_store(stored_amounts)};

    // make input selector
    const sp::InputSelectorMockSimpleV1 input_selector{enote_store};

    // user keys
    jamtis_keys user_keys;
    make_jamtis_keys(user_keys);

    // prepare output proposals (represents pre-finalization tx outputs)
    const std::vector<sp::SpOutputProposalV1> output_proposals{prepare_output_proposals(user_keys, output_amounts)};

    // collect total output amount
    boost::multiprecision::uint128_t total_output_amount{0};

    for (const sp::SpOutputProposalV1 &output_proposal : output_proposals)
        total_output_amount += output_proposal.get_amount();

    // try to get an input set
    rct::xmr_amount final_fee;
    std::list<sp::SpContextualEnoteRecordV1> inputs_selected;
    bool result{false};
    ASSERT_NO_THROW(
            result = sp::try_get_input_set_v1(user_keys.K_1_base,
                user_keys.k_vb,
                output_proposals,
                max_inputs_allowed,
                input_selector,
                fee_per_tx_weight,
                tx_fee_calculator,
                final_fee,
                inputs_selected)
        );

    // check results

    // 1. getting an input set had expected result
    CHECK_AND_ASSERT_THROW_MES(result == expected_result, "unexpected result");

    // 2. early return on failures (remaining checks are meaningless and likely to fail)
    if (result == false)
        return;

    // 3. inputs selected have expected amounts in expected order
    CHECK_AND_ASSERT_THROW_MES(inputs_selected.size() == input_amounts_expected.size(), "selected inputs quantity mismatch");

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
    const std::size_t num_outputs_nochange{
            output_amounts.size() < 2
            ? 2
            : output_amounts.size() == 2
                ? output_amounts.size() + 1
                : output_amounts.size()
        };
    const rct::xmr_amount fee_nochange{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_nochange)};

    CHECK_AND_ASSERT_THROW_MES(total_input_amount >= total_output_amount + fee_nochange,
        "input amount does not cover output amount + fee_nochange");

    // - early return if inputs selected satisfy the zero-change case
    if (total_input_amount == total_output_amount + fee_nochange)
    {
        CHECK_AND_ASSERT_THROW_MES(final_fee == fee_nochange,
            "obtained fee doesn't match nochange fee (it should)");
        return;
    }

    // b. test non-zero-change case
    const std::size_t num_outputs_withchange{output_amounts.size() < 2 ? 3 : output_amounts.size() + 1};
    const rct::xmr_amount fee_withchange{tx_fee_calculator.get_fee(fee_per_tx_weight, num_inputs, num_outputs_withchange)};

    CHECK_AND_ASSERT_THROW_MES(total_input_amount > total_output_amount + fee_withchange,
        "input amount does not exceed output amount + fee_withchange");

    CHECK_AND_ASSERT_THROW_MES(final_fee == fee_withchange,
        "obtained fee doesn't match withchange fee (it should)");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, trivial)
{
    //input_selection_test(stored_enotes, out_amnts, fee/wght, fee_calc, max_ins, expected_in_amnts, expected_result);

    // trivial calculator: fee = fee per weight
    sp::FeeCalculatorMockTrivial fee_calculator;

    // one input, one output
    EXPECT_NO_THROW(input_selection_test({2}, {1}, 1, fee_calculator, 1, {2}, true));

    // one input, two outputs
    EXPECT_NO_THROW(input_selection_test({3}, {1, 1}, 1, fee_calculator, 1, {3}, true));

    // two inputs, one output
    EXPECT_NO_THROW(input_selection_test({1, 1}, {1}, 1, fee_calculator, 2, {1, 1}, true));

    // two inputs, two outputs
    EXPECT_NO_THROW(input_selection_test({2, 1}, {1, 1}, 1, fee_calculator, 2, {2, 1}, true));

    // search for input
    EXPECT_NO_THROW(input_selection_test({0, 0, 2, 1}, {1}, 1, fee_calculator, 2, {2}, true));

    // search for input (overfill the amount)
    EXPECT_NO_THROW(input_selection_test({0, 0, 1, 2}, {1}, 1, fee_calculator, 2, {1, 2}, true));

    // no solution: max inputs limit
    EXPECT_NO_THROW(input_selection_test({1, 1}, {1}, 1, fee_calculator, 1, {}, false));

    // no solution: insufficient funds
    EXPECT_NO_THROW(input_selection_test({0, 1}, {1}, 1, fee_calculator, 2, {}, false));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_input_selection, simple)
{
    //input_selection_test(stored_enotes, out_amnts, fee/wght, fee_calc, max_ins, expected_in_amnts, expected_result);

    // simple calculator: fee = fee per weight * (num_inputs + num_outputs)
    sp::FeeCalculatorMockSimple fee_calculator;

    // one input, one output (adds 1 output in no-change case)
    EXPECT_NO_THROW(input_selection_test({2}, {0}, 1, fee_calculator, 1, {}, false));
    EXPECT_NO_THROW(input_selection_test({3}, {0}, 1, fee_calculator, 1, {3}, true));

    // one input, one output (adds 2 outputs in non-zero-change case)
    EXPECT_NO_THROW(input_selection_test({4}, {0}, 1, fee_calculator, 1, {}, false));
    EXPECT_NO_THROW(input_selection_test({5}, {0}, 1, fee_calculator, 1, {5}, true));

    // one input, two outputs (adds 1 output in no-change case)
    EXPECT_NO_THROW(input_selection_test({3}, {0, 0}, 1, fee_calculator, 1, {}, false));
    EXPECT_NO_THROW(input_selection_test({4}, {0, 0}, 1, fee_calculator, 1, {4}, true));

    // one input, two outputs (adds 1 output in non-zero-change case)
    EXPECT_NO_THROW(input_selection_test({5}, {0, 0}, 1, fee_calculator, 1, {5}, true));

    // IMPORTANT FAILURE CASE
    // A solution exists but won't be found (requires a brute force search that wasn't implemented).

    // no change: 1 input + 2 outputs -> fee = 3
    // with change: 1 input + 3 outputs -> fee = 4
    // 1. will select '7' as a solution for 'no change' pass
    // 2. 7 - 6 = change of '1', so try the 'with change' pass
    //    a. the other 'no change' pass solution is '6', which would permit a zero-change final solution
    // 3. the 'with change' solution is '4', but 'with change' solutions must have non-zero change, so we failed
    EXPECT_NO_THROW(input_selection_test({4, 3}, {0}, 1, fee_calculator, 1, {}, false));
}
//-------------------------------------------------------------------------------------------------------------------
