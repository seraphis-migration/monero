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
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/tx_base.h"
#include "seraphis/txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <iostream>
#include <memory>
#include <type_traits>
#include <vector>


enum class TestType
{
    ExpectTrue,
    ExpectAnyThrow
};

struct SpTxGenData
{
    std::size_t ref_set_decomp_n{1};
    std::size_t ref_set_decomp_m{1};
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<rct::xmr_amount> output_amounts;
    TestType expected_result{TestType::ExpectTrue};
    bool test_double_spend{false};
};

template <typename SpTxType>
static void run_mock_tx_test(const std::vector<SpTxGenData> &gen_data)
{
    static_assert(std::is_base_of<sp::SpTx, SpTxType>::value, "Invalid mock tx type.");

    std::shared_ptr<sp::MockLedgerContext> ledger_context = std::make_shared<sp::MockLedgerContext>();

    for (const auto &gen : gen_data)
    {
        try
        {
            // mock params
            sp::SpTxParamPack tx_params;

            tx_params.ref_set_decomp_n = gen.ref_set_decomp_n;
            tx_params.ref_set_decomp_m = gen.ref_set_decomp_m;

            // make tx
            std::shared_ptr<SpTxType> tx{
                    sp::make_mock_tx<SpTxType>(tx_params, gen.input_amounts, gen.output_amounts, ledger_context)
                };
            EXPECT_TRUE(tx.get() != nullptr);

            // validate tx
            EXPECT_TRUE(sp::validate_sp_tx(*tx, ledger_context, false));

            if (gen.test_double_spend)
            {
                // add key images once validated
                EXPECT_TRUE(sp::try_add_tx_to_ledger<SpTxType>(ledger_context, *tx));

                // re-validate tx
                // - should fail now that key images were added to the ledger
                EXPECT_FALSE(sp::validate_sp_tx(*tx, ledger_context, false));
            }
        }
        catch (...)
        {
            EXPECT_TRUE(gen.expected_result == TestType::ExpectAnyThrow);
        }
    }
}

template <typename SpTxType>
static void run_mock_tx_test_batch(const std::vector<SpTxGenData> &gen_data)
{
    static_assert(std::is_base_of<sp::SpTx, SpTxType>::value, "Invalid mock tx type.");

    std::shared_ptr<sp::MockLedgerContext> ledger_context = std::make_shared<sp::MockLedgerContext>();
    std::vector<std::shared_ptr<SpTxType>> txs_to_verify;
    txs_to_verify.reserve(gen_data.size());
    TestType expected_result = TestType::ExpectTrue;

    for (const auto &gen : gen_data)
    {
        try
        {
            // update expected result
            expected_result = gen.expected_result;

            // mock params
            sp::SpTxParamPack tx_params;

            tx_params.ref_set_decomp_n = gen.ref_set_decomp_n;
            tx_params.ref_set_decomp_m = gen.ref_set_decomp_m;

            // make tx
            txs_to_verify.push_back(
                    sp::make_mock_tx<SpTxType>(tx_params, gen.input_amounts, gen.output_amounts, ledger_context)
                );
        }
        catch (...)
        {
            EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
        }
    }

    try
    {
        // validate tx
        EXPECT_TRUE(sp::validate_mock_txs<SpTxType>(txs_to_verify, ledger_context));
    }
    catch (...)
    {
        EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
    }
}

static std::vector<SpTxGenData> get_mock_tx_gen_data_misc(const bool test_double_spend)
{
    /// success cases
    std::vector<SpTxGenData> gen_data;
    gen_data.reserve(20);

    // 1-in/1-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.input_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 1-in/2-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.input_amounts.push_back(2);
        temp.output_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 2-in/1-out
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.input_amounts.push_back(1);
        temp.input_amounts.push_back(1);
        temp.output_amounts.push_back(2);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 16-in/16-out; ref set 8
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        for (std::size_t i{0}; i < 16; ++i)
        {
            temp.input_amounts.push_back(1);
            temp.output_amounts.push_back(1);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 16-in/16-out; ref set 27
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.ref_set_decomp_n = 3;
        temp.ref_set_decomp_m = 3;
        for (std::size_t i{0}; i < 16; ++i)
        {
            temp.input_amounts.push_back(1);
            temp.output_amounts.push_back(1);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 16-in/16-out; ref set 64
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.ref_set_decomp_n = 4;
        temp.ref_set_decomp_m = 3;
        for (std::size_t i{0}; i < 16; ++i)
        {
            temp.input_amounts.push_back(1);
            temp.output_amounts.push_back(1);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    // 16-in/16-out + amounts 0
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectTrue;
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;
        for (std::size_t i{0}; i < 16; ++i)
        {
            temp.input_amounts.push_back(0);
            temp.output_amounts.push_back(0);
        }
        temp.test_double_spend = test_double_spend;

        gen_data.push_back(temp);
    }

    /// failure cases

    // no inputs
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.output_amounts.push_back(0);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;

        gen_data.push_back(temp);
    }

    // no outputs
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.input_amounts.push_back(0);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;

        gen_data.push_back(temp);
    }

    // no ref set size
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.input_amounts.push_back(1);
        temp.output_amounts.push_back(1);
        temp.ref_set_decomp_n = 0;

        gen_data.push_back(temp);
    }

    // amounts don't balance
    {
        SpTxGenData temp;
        temp.expected_result = TestType::ExpectAnyThrow;
        temp.input_amounts.push_back(2);
        temp.output_amounts.push_back(1);
        temp.ref_set_decomp_n = 2;
        temp.ref_set_decomp_m = 3;

        gen_data.push_back(temp);
    }

    return gen_data;
}

static std::vector<SpTxGenData> get_mock_tx_gen_data_batching()
{
    /// a batch of 3 tx
    std::vector<SpTxGenData> gen_data;
    gen_data.resize(3);

    for (auto &gen : gen_data)
    {
        gen.input_amounts.push_back(2);
        gen.input_amounts.push_back(1);
        gen.output_amounts.push_back(2);
        gen.output_amounts.push_back(1);
        gen.ref_set_decomp_n = 2;
        gen.ref_set_decomp_m = 3;
    }

    return gen_data;
}


/////////////////////////////////////////////////////////////////////
////////////////////////// Seraphis Squash //////////////////////////
/////////////////////////////////////////////////////////////////////

TEST(mock_tx, seraphis_squashed)
{
    run_mock_tx_test<sp::SpTxSquashedV1>(get_mock_tx_gen_data_misc(true));
}

TEST(mock_tx_batching, seraphis_squashed)
{
    run_mock_tx_test_batch<sp::SpTxSquashedV1>(get_mock_tx_gen_data_batching());
}
