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
#include "mock_tx/mock_ledger_context.h"
#include "mock_tx/mock_tx.h"
#include "mock_tx/mock_rct_clsag.h"
#include "mock_tx/mock_rct_triptych.h"
#include "mock_tx/mock_sp_tx_concise.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

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

struct MockTxGenData
{
  std::size_t ref_set_decomp_n{1};
  std::size_t ref_set_decomp_m{1};
  std::vector<rct::xmr_amount> input_amounts;
  std::vector<rct::xmr_amount> output_amounts;
  std::size_t num_rangeproof_splits{0};
  TestType expected_result{TestType::ExpectTrue};
  bool test_double_spend{false};
};

template <typename MockTxType>
static void run_mock_tx_test(const std::vector<MockTxGenData> &gen_data)
{
  static_assert(std::is_base_of<mock_tx::MockTx, MockTxType>::value, "Invalid mock tx type.");

  std::shared_ptr<mock_tx::MockLedgerContext> ledger_context = std::make_shared<mock_tx::MockLedgerContext>();

  for (const auto &gen : gen_data)
  {
    try
    {
      // mock params
      mock_tx::MockTxParamPack tx_params;

      tx_params.max_rangeproof_splits = gen.num_rangeproof_splits;
      tx_params.ref_set_decomp_n = gen.ref_set_decomp_n;
      tx_params.ref_set_decomp_m = gen.ref_set_decomp_m;

      // make tx
      std::shared_ptr<MockTxType> tx{
          mock_tx::make_mock_tx<MockTxType>(tx_params, gen.input_amounts, gen.output_amounts, ledger_context)
        };
      EXPECT_TRUE(tx.get() != nullptr);

      // validate tx
      EXPECT_TRUE(tx->validate(ledger_context));

      if (gen.test_double_spend)
      {
        // add key images once validated
        tx->add_key_images_to_ledger(ledger_context);

        // re-validate tx
        // - should fail now that key images were added to the ledger
        EXPECT_FALSE(tx->validate(ledger_context));
      }
    }
    catch (...)
    {
      EXPECT_TRUE(gen.expected_result == TestType::ExpectAnyThrow);
    }
  }
}

template <typename MockTxType>
static void run_mock_tx_test_batch(const std::vector<MockTxGenData> &gen_data)
{
  static_assert(std::is_base_of<mock_tx::MockTx, MockTxType>::value, "Invalid mock tx type.");

  std::shared_ptr<mock_tx::MockLedgerContext> ledger_context = std::make_shared<mock_tx::MockLedgerContext>();
  std::vector<std::shared_ptr<MockTxType>> txs_to_verify;
  txs_to_verify.reserve(gen_data.size());
  TestType expected_result = TestType::ExpectTrue;

  for (const auto &gen : gen_data)
  {
    try
    {
      // update expected result
      expected_result = gen.expected_result;

      // mock params
      mock_tx::MockTxParamPack tx_params;
      
      tx_params.max_rangeproof_splits = gen.num_rangeproof_splits;
      tx_params.ref_set_decomp_n = gen.ref_set_decomp_n;
      tx_params.ref_set_decomp_m = gen.ref_set_decomp_m;

      // make tx
      txs_to_verify.push_back(
          mock_tx::make_mock_tx<MockTxType>(tx_params, gen.input_amounts, gen.output_amounts, ledger_context)
        );

      // sanity check that rangeproof split is actually splitting the rangeproof
      if (gen.num_rangeproof_splits > 0 && gen.output_amounts.size() > 1)
      {
        EXPECT_TRUE(txs_to_verify.back()->get_balance_proof().get() != nullptr);
        EXPECT_TRUE(txs_to_verify.back()->get_balance_proof()->m_bpp_proofs.size() > 1);
      }
    }
    catch (...)
    {
      EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
    }
  }

  try
  {
    // validate tx
    EXPECT_TRUE(mock_tx::validate_mock_txs<MockTxType>(txs_to_verify, ledger_context));
  }
  catch (...)
  {
    EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
  }
}



/////////////////////////////////////////////////////////////////////
////////////////////////////// CLSAG ////////////////////////////////
/////////////////////////////////////////////////////////////////////

TEST(mock_tx, clsag)
{
  /// success cases
  std::vector<MockTxGenData> gen_data;
  gen_data.reserve(20);

  // 1-in/1-out; ref set 1
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 1;

    gen_data.push_back(temp);
  }

  // 1-in/1-out; ref set 10
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }

  // 1-in/2-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }

  // 2-in/1-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(2);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 1
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 1;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 10
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 10;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }

    gen_data.push_back(temp);
  }

  // 16-in/16-out + amounts 0
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 10;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(0);
      temp.output_amounts.push_back(0);
    }

    gen_data.push_back(temp);
  }

  /// failure cases

  // no inputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.output_amounts.push_back(0);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }

  // no outputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(0);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }

  // no ref set size
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 0;

    gen_data.push_back(temp);
  }

  // amounts don't balance
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 10;

    gen_data.push_back(temp);
  }


  /// run tests
  run_mock_tx_test<mock_tx::MockTxCLSAG>(gen_data);
}

TEST(mock_tx_batching, clsag)
{
  /// a batch of 3 tx
  std::vector<MockTxGenData> gen_data;
  gen_data.resize(3);

  for (auto &gen : gen_data)
  {
    gen.input_amounts.push_back(2);
    gen.input_amounts.push_back(1);
    gen.output_amounts.push_back(2);
    gen.output_amounts.push_back(1);
    gen.ref_set_decomp_n = 10;  
  }

  /// 3 tx, 11 inputs/outputs each, range proofs split x3
  std::vector<MockTxGenData> gen_data_split;
  gen_data_split.resize(3);

  for (auto &gen : gen_data_split)
  {
    for (int i{0}; i < 11; ++i)
    {
      gen.input_amounts.push_back(2);
      gen.output_amounts.push_back(2);
    }

    gen.ref_set_decomp_n = 10;  
    gen.num_rangeproof_splits = 3;
  }

  /// run tests
  run_mock_tx_test_batch<mock_tx::MockTxCLSAG>(gen_data);
  run_mock_tx_test_batch<mock_tx::MockTxCLSAG>(gen_data_split);
}

/////////////////////////////////////////////////////////////////////
///////////////////////////// Triptych //////////////////////////////
/////////////////////////////////////////////////////////////////////

TEST(mock_tx, triptych)
{
  /// success cases
  std::vector<MockTxGenData> gen_data;
  gen_data.reserve(20);

  // 1-in/1-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // 1-in/2-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // 2-in/1-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(2);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 8
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 27
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 3;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 64
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 4;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }

    gen_data.push_back(temp);
  }

  // 16-in/16-out + amounts 0
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(0);
      temp.output_amounts.push_back(0);
    }

    gen_data.push_back(temp);
  }

  /// failure cases

  // no inputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.output_amounts.push_back(0);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // no outputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(0);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // no ref set size
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 0;

    gen_data.push_back(temp);
  }

  // amounts don't balance
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }


  /// run tests
  run_mock_tx_test<mock_tx::MockTxTriptych>(gen_data);
}

TEST(mock_tx_batching, triptych)
{
  /// a batch of 3 tx
  std::vector<MockTxGenData> gen_data;
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

  /// 3 tx, 11 inputs/outputs each, range proofs split x3
  std::vector<MockTxGenData> gen_data_split;
  gen_data_split.resize(3);

  for (auto &gen : gen_data_split)
  {
    for (int i{0}; i < 11; ++i)
    {
      gen.input_amounts.push_back(2);
      gen.output_amounts.push_back(2);
    }

    gen.ref_set_decomp_n = 2;
    gen.ref_set_decomp_m = 3;
    gen.num_rangeproof_splits = 3;
  }

  /// run tests
  run_mock_tx_test_batch<mock_tx::MockTxTriptych>(gen_data);
  run_mock_tx_test_batch<mock_tx::MockTxTriptych>(gen_data_split);
}

/////////////////////////////////////////////////////////////////////
///////////////////////// Seraphis Concise //////////////////////////
/////////////////////////////////////////////////////////////////////

TEST(mock_tx, seraphis_concise)
{
  /// success cases
  std::vector<MockTxGenData> gen_data;
  gen_data.reserve(20);

  // 1-in/1-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 1-in/2-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 2-in/1-out
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.input_amounts.push_back(1);
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(2);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 8
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 27
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 3;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 16-in/16-out; ref set 64
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 4;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(1);
      temp.output_amounts.push_back(1);
    }
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  // 16-in/16-out + amounts 0
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectTrue;
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;
    for (std::size_t i{0}; i < 16; ++i)
    {
      temp.input_amounts.push_back(0);
      temp.output_amounts.push_back(0);
    }
    temp.test_double_spend = true;

    gen_data.push_back(temp);
  }

  /// failure cases

  // no inputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.output_amounts.push_back(0);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // no outputs
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(0);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }

  // no ref set size
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(1);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 0;

    gen_data.push_back(temp);
  }

  // amounts don't balance
  {
    MockTxGenData temp;
    temp.expected_result = TestType::ExpectAnyThrow;
    temp.input_amounts.push_back(2);
    temp.output_amounts.push_back(1);
    temp.ref_set_decomp_n = 2;
    temp.ref_set_decomp_m = 3;

    gen_data.push_back(temp);
  }


  /// run tests
  run_mock_tx_test<mock_tx::MockTxSpConcise>(gen_data);
}

TEST(mock_tx_batching, seraphis_concise)
{
  /// a batch of 3 tx
  std::vector<MockTxGenData> gen_data;
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

  /// 3 tx, 11 inputs/outputs each, range proofs split x3
  std::vector<MockTxGenData> gen_data_split;
  gen_data_split.resize(3);

  for (auto &gen : gen_data_split)
  {
    for (int i{0}; i < 11; ++i)
    {
      gen.input_amounts.push_back(2);
      gen.output_amounts.push_back(2);
    }

    gen.ref_set_decomp_n = 2;
    gen.ref_set_decomp_m = 3;
    gen.num_rangeproof_splits = 3;
  }

  /// run tests
  run_mock_tx_test_batch<mock_tx::MockTxSpConcise>(gen_data);
  run_mock_tx_test_batch<mock_tx::MockTxSpConcise>(gen_data_split);
}
