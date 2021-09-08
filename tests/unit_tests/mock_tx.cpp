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
#include "mock_tx/mock_rctclsag.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include "gtest/gtest.h"

#include <iostream>
#include <memory>
#include <vector>


enum class TestType
{
  ExpectTrue,
  ExpectAnyThrow
};

struct MockTxGenData
{
  std::size_t ref_set_size{1};
  std::vector<rct::xmr_amount> input_amounts;
  std::vector<rct::xmr_amount> output_amounts;
  TestType expected_result{TestType::ExpectTrue};
  std::size_t num_rangeproof_splits{0};
};

void run_mock_tx_test(const std::vector<MockTxGenData> &gen_data)
{
  for (const auto &gen : gen_data)
  {
    try
    {
      // inputs
      auto inputs{mock_tx::gen_mock_tx_inputs<mock_tx::MockTxCLSAG>(gen.input_amounts, gen.ref_set_size, 1)};

      // destinations
      auto destinations{mock_tx::gen_mock_tx_dests<mock_tx::MockTxCLSAG>(gen.output_amounts)};

      // make tx
      mock_tx::MockTxCLSAGParams tx_params{gen.num_rangeproof_splits};
      mock_tx::MockTxCLSAG tx{inputs, destinations, tx_params};

      // validate tx
      EXPECT_TRUE(tx.validate());
    }
    catch (...)
    {
      EXPECT_TRUE(gen.expected_result == TestType::ExpectAnyThrow);
    }
  }
}

void run_mock_tx_test_batch(const std::vector<MockTxGenData> &gen_data)
{
  std::vector<std::shared_ptr<mock_tx::MockTxCLSAG>> txs_to_verify;
  txs_to_verify.reserve(gen_data.size());
  TestType expected_result = TestType::ExpectTrue;

  for (const auto &gen : gen_data)
  {
    try
    {
      // update expected result
      expected_result = gen.expected_result;

      // inputs
      auto inputs{mock_tx::gen_mock_tx_inputs<mock_tx::MockTxCLSAG>(gen.input_amounts, gen.ref_set_size, 1)};

      // destinations
      auto destinations{mock_tx::gen_mock_tx_dests<mock_tx::MockTxCLSAG>(gen.output_amounts)};

      // make tx to validate
      mock_tx::MockTxCLSAGParams tx_params{gen.num_rangeproof_splits};
      txs_to_verify.push_back(std::make_shared<mock_tx::MockTxCLSAG>(inputs, destinations, tx_params));

      // sanity check that rangeproof split is actually splitting the rangeproof
      if (gen.num_rangeproof_splits > 0 && gen.output_amounts.size() > 1)
        EXPECT_TRUE(txs_to_verify.back()->get_range_proofs().size() > 1);
    }
    catch (...)
    {
      EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
    }
  }

  try
  {
    // validate tx
    EXPECT_TRUE(mock_tx::validate_mock_txs(txs_to_verify));
  }
  catch (...)
  {
    EXPECT_TRUE(expected_result == TestType::ExpectAnyThrow);
  }
}


TEST(mock_tx, clsag)
{
  /// success cases
  std::vector<MockTxGenData> gen_data;
  gen_data.resize(11);

  // 1-in/1-out; ref set 1
  gen_data[0].expected_result = TestType::ExpectTrue;
  gen_data[0].input_amounts.push_back(1);
  gen_data[0].output_amounts.push_back(1);
  gen_data[0].ref_set_size = 1;

  // 1-in/1-out; ref set 10
  gen_data[1].expected_result = TestType::ExpectTrue;
  gen_data[1].input_amounts.push_back(1);
  gen_data[1].output_amounts.push_back(1);
  gen_data[1].ref_set_size = 10;

  // 1-in/2-out
  gen_data[2].expected_result = TestType::ExpectTrue;
  gen_data[2].input_amounts.push_back(2);
  gen_data[2].output_amounts.push_back(1);
  gen_data[2].output_amounts.push_back(1);
  gen_data[2].ref_set_size = 10;

  // 2-in/1-out
  gen_data[3].expected_result = TestType::ExpectTrue;
  gen_data[3].input_amounts.push_back(1);
  gen_data[3].input_amounts.push_back(1);
  gen_data[3].output_amounts.push_back(2);
  gen_data[3].ref_set_size = 10;

  // 16-in/16-out; ref set 1
  gen_data[4].expected_result = TestType::ExpectTrue;
  gen_data[4].ref_set_size = 1;
  for (std::size_t i{0}; i < 16; ++i)
  {
    gen_data[4].input_amounts.push_back(1);
    gen_data[4].output_amounts.push_back(1);
  }

  // 16-in/16-out; ref set 10
  gen_data[5].expected_result = TestType::ExpectTrue;
  gen_data[5].ref_set_size = 10;
  for (std::size_t i{0}; i < 16; ++i)
  {
    gen_data[5].input_amounts.push_back(1);
    gen_data[5].output_amounts.push_back(1);
  }

  // 16-in/16-out + amounts 0
  gen_data[6].expected_result = TestType::ExpectTrue;
  gen_data[6].ref_set_size = 10;
  for (std::size_t i{0}; i < 16; ++i)
  {
    gen_data[6].input_amounts.push_back(0);
    gen_data[6].output_amounts.push_back(0);
  }

  /// failure cases

  // no inputs
  gen_data[7].expected_result = TestType::ExpectAnyThrow;
  gen_data[7].output_amounts.push_back(0);
  gen_data[7].ref_set_size = 10;

  // no outputs
  gen_data[8].expected_result = TestType::ExpectAnyThrow;
  gen_data[8].input_amounts.push_back(0);
  gen_data[8].ref_set_size = 10;

  // no ref set size
  gen_data[9].expected_result = TestType::ExpectAnyThrow;
  gen_data[9].input_amounts.push_back(1);
  gen_data[9].output_amounts.push_back(1);
  gen_data[9].ref_set_size = 0;

  // amounts don't balance
  gen_data[10].expected_result = TestType::ExpectAnyThrow;
  gen_data[10].input_amounts.push_back(2);
  gen_data[10].output_amounts.push_back(1);
  gen_data[10].ref_set_size = 10;


  /// run tests
  run_mock_tx_test(gen_data);
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
    gen.ref_set_size = 10;  
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

    gen.ref_set_size = 10;  
    gen.num_rangeproof_splits = 3;
  }

  /// run tests
  run_mock_tx_test_batch(gen_data);
  run_mock_tx_test_batch(gen_data_split);
}






