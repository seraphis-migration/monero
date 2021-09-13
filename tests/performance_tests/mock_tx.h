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

#pragma once

#include "mock_tx/mock_rct_clsag.h"
#include "mock_tx/mock_rct_triptych.h"
#include "mock_tx/mock_tx_utils.h"
#include "performance_tests.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <iostream>
#include <type_traits>
#include <vector>


struct ParamsShuttleMockTx final : public ParamsShuttle
{
    std::size_t batch_size{1};
    std::size_t in_count{1};
    std::size_t out_count{1};
    // ref set size: n^m
    std::size_t n{2};
    std::size_t m{0};
    std::size_t num_rangeproof_splits{0};
};

template <typename MockTxType>
class test_mock_tx
{
    public:
        static const size_t loop_count = 50;

        bool init(const ParamsShuttleMockTx &params)
        {
            static_assert(std::is_base_of<mock_tx::MockTx, MockTxType>::value, "Invalid mock tx type.");

            m_txs.reserve(params.batch_size);

            // divide max amount into equal-size chunks to distribute among more numerous of inputs vs outputs
            if (params.in_count == 0 || params.out_count == 0)
                return false;

            rct::xmr_amount amount_chunk{
                    rct::xmr_amount{static_cast<rct::xmr_amount>(-1)} / 
                    (params.in_count > params.out_count ? params.in_count : params.out_count)
                };

            // make transactions
            for (std::size_t tx_index{0}; tx_index < params.batch_size; ++tx_index)
            {
                try
                {
                    // input and output amounts
                    std::vector<rct::xmr_amount> input_amounts;
                    std::vector<rct::xmr_amount> output_amounts;
                    input_amounts.resize(params.in_count, amount_chunk);
                    output_amounts.resize(params.out_count, amount_chunk);

                    // put leftovers in last amount of either inputs or outputs if they don't already balance
                    if (params.in_count > params.out_count)
                        output_amounts.back() += amount_chunk*(params.in_count - params.out_count);
                    else if (params.out_count > params.in_count)
                        input_amounts.back() += amount_chunk*(params.out_count - params.in_count);

                    // mock params
                    mock_tx::MockTxParamPack tx_params;
                    
                    tx_params.max_rangeproof_splits = params.num_rangeproof_splits;
                    tx_params.ref_set_decomp_n = params.n;
                    tx_params.ref_set_decomp_m = params.m;

                    // make tx
                    m_txs.push_back(
                            mock_tx::make_mock_tx<MockTxType>(tx_params, input_amounts, output_amounts)
                        );
                }
                catch (...)
                {
                    return false;
                }
            }

            // report tx info
            if (params.batch_size == 1)
            {
                std::cout << m_txs.back()->get_descriptor() << " || "
                          << "Size (bytes): " << m_txs.back()->get_size_bytes() << " || "
                          << "batch size: " << params.batch_size << " || "
                          << "inputs: " << params.in_count << " || "
                          << "outputs: " << params.out_count << " || "
                          << "rangeproof split: " << params.num_rangeproof_splits << " || "
                          << "ref set size (" << params.n << "^" << params.m << "): " <<
                            mock_tx::ref_set_size_from_decomp(params.n, params.m) << '\n';
            }

            return true;
        }

        bool test()
        {
            try
            {
                return mock_tx::validate_mock_txs<MockTxType>(m_txs);
            }
            catch (...)
            {
                return false;
            }
        }

    private:
        std::vector<std::shared_ptr<MockTxType>> m_txs;
};
