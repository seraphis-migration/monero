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

#include "mock_tx/mock_ledger_context.h"
#include "mock_tx/mock_rct_clsag.h"
#include "mock_tx/mock_rct_triptych.h"
#include "mock_tx/mock_sp_txtype_concise_v1.h"
#include "mock_tx/mock_sp_txtype_merge_v1.h"
#include "mock_tx/mock_sp_txtype_squashed_v1.h"
#include "mock_tx/mock_tx_utils.h"
#include "performance_tests.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <iostream>
#include <memory>
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

class MockTxPerfIncrementer final
{
public:
//constructors
    // default constructor
    MockTxPerfIncrementer() = default;

    // normal constructor
    MockTxPerfIncrementer(std::vector<std::size_t> batch_sizes,
        std::vector<std::size_t> rangeproof_splits,
        std::vector<std::size_t> in_counts,
        std::vector<std::size_t> out_counts,
        std::vector<std::size_t> ref_set_decomp_n,
        std::vector<std::size_t> ref_set_decomp_m_limit) :
            m_batch_sizes{std::move(batch_sizes)},
            m_rangeproof_splits{std::move(rangeproof_splits)},
            m_in_counts{std::move(in_counts)},
            m_out_counts{std::move(out_counts)},
            m_ref_set_decomp_n{std::move(ref_set_decomp_n)},
            m_ref_set_decomp_m_limit{std::move(ref_set_decomp_m_limit)}
    {
        init_decomp_m_current();
    }

//member functions
    bool is_done()
    {
        if (m_is_done)
            return true;

        if (m_batch_size_i >= m_batch_sizes.size() ||
            m_rp_splits_i >= m_rangeproof_splits.size() ||
            m_in_i >= m_in_counts.size() ||
            m_out_i >= m_out_counts.size() ||
            m_decomp_i >= m_ref_set_decomp_n.size() ||
            m_decomp_i >= m_ref_set_decomp_m_limit.size() ||
            m_decomp_m_current > m_ref_set_decomp_m_limit[m_decomp_i] ||
            m_ref_set_decomp_n.size() != m_ref_set_decomp_m_limit.size())
        {
            m_is_done = true;
        }

        return m_is_done;
    }

    void get_params(ParamsShuttleMockTx &params)
    {
        if (is_done())
            return;

        params.batch_size = m_batch_sizes[m_batch_size_i];
        params.num_rangeproof_splits = m_rangeproof_splits[m_rp_splits_i];
        params.in_count = m_in_counts[m_in_i];
        params.out_count = m_out_counts[m_out_i];
        params.n = m_ref_set_decomp_n[m_decomp_i];
        params.m = m_decomp_m_current;
    }

    void init_decomp_m_current()
    {
        m_decomp_m_current = 0;

        if (is_done())
            return;

        // heuristic: start at n^2 for n > 2
        if (m_ref_set_decomp_n[m_decomp_i] > 2)
            m_decomp_m_current = 2;
    }

    bool next(ParamsShuttleMockTx &params)
    {
        if (is_done())
            return false;

        if (m_variations_requested == 0)
        {
            get_params(params);
            ++m_variations_requested;

            return true;
        }

        // order:
        // - batch size
        //  - rp splits
        //   - in count
        //    - out count
        //     - decomp n
        //      - decomp m

        if (m_decomp_m_current >= m_ref_set_decomp_m_limit[m_decomp_i])
        {
            if (m_decomp_i + 1 >= m_ref_set_decomp_n.size())
            {
                if (m_out_i + 1 >= m_out_counts.size())
                {
                    if (m_in_i + 1 >= m_in_counts.size())
                    {
                        if (m_rp_splits_i + 1 >= m_rangeproof_splits.size())
                        {
                            if (m_batch_size_i + 1 >= m_batch_sizes.size())
                            {
                                // no where left to go
                                m_is_done = true;
                            }
                            else
                            {
                                ++m_batch_size_i;
                            }

                            m_rp_splits_i = 0;
                        }
                        else
                        {
                            ++m_rp_splits_i;
                        }

                        m_in_i = 0;
                    }
                    else
                    {
                        ++m_in_i;
                    }

                    m_out_i = 0;
                }
                else
                {
                    ++m_out_i;
                }

                m_decomp_i = 0;
            }
            else
            {
                ++m_decomp_i;
            }

            init_decomp_m_current();
        }
        else
        {
            ++m_decomp_m_current;
        }

        get_params(params);
        ++m_variations_requested;

        return !is_done();
    }

private:
//member variables
    // is the incrementer done? (true if incrementer has no param set to return)
    bool m_is_done{false};

    // count number of variations requested
    std::size_t m_variations_requested{0};

    // max number of tx to batch validate
    std::vector<std::size_t> m_batch_sizes;
    std::size_t m_batch_size_i{0};

    // range proof splitting
    std::vector<std::size_t> m_rangeproof_splits;
    std::size_t m_rp_splits_i{0};

    // input counts
    std::vector<std::size_t> m_in_counts;
    std::size_t m_in_i{0};

    // output counts
    std::vector<std::size_t> m_out_counts;
    std::size_t m_out_i{0};

    // ref set: n^m
    std::vector<std::size_t> m_ref_set_decomp_n;
    std::size_t m_decomp_i{0};
    std::vector<std::size_t> m_ref_set_decomp_m_limit;
    std::size_t m_decomp_m_current{0};
};

template <typename MockTxType>
class test_mock_tx
{
public:
    static const size_t loop_count = 1;

    bool init(const ParamsShuttleMockTx &params)
    {
        static_assert(std::is_base_of<mock_tx::MockTx, MockTxType>::value, "Invalid mock tx type.");

        m_txs.reserve(params.batch_size);

        // fresh mock ledger context
        m_ledger_contex = std::make_shared<mock_tx::MockLedgerContext>();

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
                m_txs.emplace_back(
                        mock_tx::make_mock_tx<MockTxType>(tx_params, input_amounts, output_amounts, m_ledger_contex)
                    );
            }
            catch (...)
            {
                return false;
            }
        }

        // report tx info
        std::string report;
        report += m_txs.back()->get_descriptor() + " || ";
        report += std::string{"Size (bytes): "} + std::to_string(m_txs.back()->get_size_bytes()) + " || ";
        report += std::string{"batch size: "} + std::to_string(params.batch_size) + " || ";
        report += std::string{"rangeproof split: "} + std::to_string(params.num_rangeproof_splits) + " || ";
        report += std::string{"inputs: "} + std::to_string(params.in_count) + " || ";
        report += std::string{"outputs: "} + std::to_string(params.out_count) + " || ";
        report += std::string{"ref set size ("} + std::to_string(params.n) + "^" + std::to_string(params.m) + "): ";
        report += std::to_string(mock_tx::ref_set_size_from_decomp(params.n, params.m));

        std::cout << report << '\n';

        // add the info report to timings database so it is saved to file
        if (params.core_params.td.get())
        {
            TimingsDatabase::instance null_instance;
            null_instance.npoints = 0;

            std::string report_csv;
            std::string separator{','};
            report_csv += m_txs.back()->get_descriptor() + separator;
            report_csv += std::to_string(m_txs.back()->get_size_bytes()) + separator;
            report_csv += std::to_string(params.batch_size) + separator;
            report_csv += std::to_string(params.num_rangeproof_splits) + separator;
            report_csv += std::to_string(params.in_count) + separator;
            report_csv += std::to_string(params.out_count) + separator;
            report_csv += std::to_string(params.n) + separator;
            report_csv += std::to_string(params.m) + separator;
            report_csv += std::to_string(mock_tx::ref_set_size_from_decomp(params.n, params.m));

            params.core_params.td->add(report_csv.c_str(), null_instance);
        }

        return true;
    }

    bool test()
    {
        try
        {
            return mock_tx::validate_mock_txs<MockTxType>(m_txs, m_ledger_contex);
        }
        catch (...)
        {
            return false;
        }
    }

private:
    std::vector<std::shared_ptr<MockTxType>> m_txs;
    std::shared_ptr<mock_tx::MockLedgerContext> m_ledger_contex;
};
