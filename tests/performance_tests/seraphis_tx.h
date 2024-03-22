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

#pragma once

#include "performance_tests.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include <iostream>
#include <memory>
#include <type_traits>
#include <vector>


struct ParamsShuttleSpTx final : public ParamsShuttle
{
    std::size_t batch_size{1};
    std::size_t legacy_in_count{1};
    std::size_t sp_in_count{1};
    std::size_t out_count{1};
    // legacy ring size
    std::size_t legacy_ring_size{1};
    // seraphis ref set size: n^m
    std::size_t n{2};
    std::size_t m{0};
};

class SpTxPerfIncrementer final
{
public:
//constructors
    // default constructor
    SpTxPerfIncrementer() = default;

    // normal constructor
    SpTxPerfIncrementer(std::vector<std::size_t> batch_sizes,
        std::vector<std::size_t> legacy_in_counts,
        std::vector<std::size_t> sp_in_counts,
        std::vector<std::size_t> out_counts,
        std::vector<std::size_t> legacy_ring_size,
        std::vector<std::size_t> ref_set_decomp_n,
        std::vector<std::size_t> ref_set_decomp_m_limit) :
            m_batch_sizes{std::move(batch_sizes)},
            m_legacy_in_counts{std::move(legacy_in_counts)},
            m_sp_in_counts{std::move(sp_in_counts)},
            m_out_counts{std::move(out_counts)},
            m_legacy_ring_size{std::move(legacy_ring_size)},
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
            m_legacy_in_i >= m_legacy_in_counts.size() ||
            m_sp_in_i >= m_sp_in_counts.size() ||
            m_out_i >= m_out_counts.size() ||
            m_legacy_ring_size_i >= m_legacy_ring_size.size() ||
            nm_decomp_i >= m_ref_set_decomp_n.size() ||
            nm_decomp_i >= m_ref_set_decomp_m_limit.size() ||
            m_decomp_m_current > m_ref_set_decomp_m_limit[nm_decomp_i] ||
            m_ref_set_decomp_n.size() != m_ref_set_decomp_m_limit.size())
        {
            m_is_done = true;
        }

        return m_is_done;
    }

    void get_params(ParamsShuttleSpTx &params_out)
    {
        if (is_done())
            return;

        params_out.batch_size = m_batch_sizes[m_batch_size_i];
        params_out.legacy_in_count = m_legacy_in_counts[m_legacy_in_i];
        params_out.sp_in_count = m_sp_in_counts[m_sp_in_i];
        params_out.out_count = m_out_counts[m_out_i];
        params_out.legacy_ring_size = m_legacy_ring_size[m_legacy_ring_size_i];
        params_out.n = m_ref_set_decomp_n[nm_decomp_i];
        params_out.m = m_decomp_m_current;
    }

    bool refresh_params(ParamsShuttleSpTx &params_out)
    {
        get_params(params_out);
        ++m_variations_requested;

        return !is_done();
    }

    void init_decomp_m_current()
    {
        m_decomp_m_current = 0;

        if (is_done())
            return;

        // heuristic: start at n^2 for n > 2
        if (m_ref_set_decomp_n[nm_decomp_i] > 2)
            m_decomp_m_current = 2;
    }

    bool next(ParamsShuttleSpTx &params_out)
    {
        if (is_done())
            return false;

        // first variation
        if (m_variations_requested == 0)
            return refresh_params(params_out);

        // nesting order (lowest in list is changed first):
        // - batch size
        // - legacy in count
        // - seraphis in count
        // - out count
        // - legacy ring size
        // - decomp n
        // - decomp m

        if (m_decomp_m_current < m_ref_set_decomp_m_limit[nm_decomp_i])
        {
            ++m_decomp_m_current;
            return this->refresh_params(params_out);
        }
        else
            init_decomp_m_current();

        if (nm_decomp_i + 1 < m_ref_set_decomp_n.size())
        {
            ++nm_decomp_i;
            return this->refresh_params(params_out);
        }
        else
            nm_decomp_i = 0;

        if (m_legacy_ring_size_i + 1 < m_legacy_ring_size.size())
        {
            ++m_legacy_ring_size_i;
            return this->refresh_params(params_out);
        }
        else
            m_legacy_ring_size_i = 0;

        if (m_out_i + 1 < m_out_counts.size())
        {
            ++m_out_i;
            return this->refresh_params(params_out);
        }
        else
            m_out_i = 0;

        if (m_sp_in_i + 1 < m_sp_in_counts.size())
        {
            ++m_sp_in_i;
            return this->refresh_params(params_out);
        }
        else
            m_sp_in_i = 0;

        if (m_legacy_in_i + 1 < m_legacy_in_counts.size())
        {
            ++m_legacy_in_i;
            return this->refresh_params(params_out);
        }
        else
            m_legacy_in_i = 0;

        if (m_batch_size_i + 1 < m_batch_sizes.size())
        {
            ++m_batch_size_i;
            return this->refresh_params(params_out);
        }

        // nowhere left to go
        m_is_done = true;

        return this->refresh_params(params_out);
    }

private:
//member variables
    // is the incrementer done? (true if incrementer has no param set to return)
    bool m_is_done{false};

    // count number of variations requested
    std::size_t m_variations_requested{0};

    // number of tx to batch validate
    std::vector<std::size_t> m_batch_sizes;
    std::size_t m_batch_size_i{0};

    // input counts
    std::vector<std::size_t> m_legacy_in_counts;
    std::size_t m_legacy_in_i{0};
    std::vector<std::size_t> m_sp_in_counts;
    std::size_t m_sp_in_i{0};

    // output counts
    std::vector<std::size_t> m_out_counts;
    std::size_t m_out_i{0};

    // legacy ring size
    std::vector<std::size_t> m_legacy_ring_size;
    std::size_t m_legacy_ring_size_i{0};

    // seraphis ref set: n^m (these are paired together, with only one shared index)
    std::vector<std::size_t> m_ref_set_decomp_n;
    std::size_t nm_decomp_i{0};
    std::vector<std::size_t> m_ref_set_decomp_m_limit;  //increment m from 2 to the specified limit
    std::size_t m_decomp_m_current{0};
};

template <typename SpTxType>
class test_seraphis_tx
{
public:
    static const size_t loop_count = 1;

    bool init(const ParamsShuttleSpTx &params)
    {
        m_txs.reserve(params.batch_size);
        m_tx_ptrs.reserve(params.batch_size);

        // fresh mock ledger context
        m_ledger_contex = std::make_shared<sp::mocks::MockLedgerContext>(0, 1000000);

        // divide max amount into equal-size chunks to distribute among more numerous of inputs vs outputs
        if (params.legacy_in_count + params.sp_in_count == 0 || params.out_count == 0)
            return false;

        const rct::xmr_amount amount_chunk{
                rct::xmr_amount{static_cast<rct::xmr_amount>(-1)} / 
                (
                    (params.legacy_in_count + params.sp_in_count) > params.out_count
                    ? (params.legacy_in_count + params.sp_in_count)
                    : params.out_count
                )
            };

        // make transactions
        for (std::size_t tx_index{0}; tx_index < params.batch_size; ++tx_index)
        {
            try
            {
                // input and output amounts
                std::vector<rct::xmr_amount> legacy_input_amounts;
                std::vector<rct::xmr_amount> sp_input_amounts;
                std::vector<rct::xmr_amount> output_amounts;
                legacy_input_amounts.resize(params.legacy_in_count, amount_chunk);
                sp_input_amounts.resize(params.sp_in_count, amount_chunk);
                output_amounts.resize(params.out_count, amount_chunk);

                // put leftovers in last amount of either inputs or outputs if they don't already balance
                if ((params.legacy_in_count + params.sp_in_count) > params.out_count)
                    output_amounts.back() += amount_chunk*((params.legacy_in_count + params.sp_in_count) - params.out_count);
                else if (params.out_count > (params.legacy_in_count + params.sp_in_count))
                {
                    const rct::xmr_amount leftovers{
                            amount_chunk*(params.out_count - (params.legacy_in_count + params.sp_in_count))
                        };
                    if (params.legacy_in_count > 0)
                        legacy_input_amounts.back() += leftovers;
                    else
                        sp_input_amounts.back() += leftovers;
                }

                // mock params
                sp::mocks::SpTxParamPackV1 tx_params;

                tx_params.legacy_ring_size = params.legacy_ring_size;
                tx_params.ref_set_decomp_n = params.n;
                tx_params.ref_set_decomp_m = params.m;
                tx_params.bin_config =
                    sp::SpBinnedReferenceSetConfigV1{
                        .bin_radius = static_cast<sp::ref_set_bin_dimension_v1_t>(
                                sp::math::uint_pow(params.n, params.m) / 2
                            ),
                        .num_bin_members = static_cast<sp::ref_set_bin_dimension_v1_t>(
                                sp::math::uint_pow(params.n, params.m / 2)
                            )
                    };  //bin config must be compatible with n^m
                tx_params.legacy_input_amounts = std::move(legacy_input_amounts);
                tx_params.sp_input_amounts = std::move(sp_input_amounts);
                tx_params.output_amounts = std::move(output_amounts);
                tx_params.discretized_fee = sp::discretize_fee(0);

                // make tx
                m_txs.emplace_back();
                sp::mocks::make_mock_tx<SpTxType>(tx_params,
                    *m_ledger_contex,
                    m_txs.back());

                m_tx_ptrs.emplace_back(&(m_txs.back()));
            }
            catch (...)
            {
                return false;
            }
        }

        // report tx info
        std::string report;
        report += sp::tx_descriptor<SpTxType>() + " || ";
        report += std::string{"Size (bytes): "} + std::to_string(sp::sp_tx_squashed_v1_size_bytes(m_txs.back())) + " || ";
        report += std::string{"batch size: "} + std::to_string(params.batch_size) + " || ";
        report += std::string{"legacy inputs: "} + std::to_string(params.legacy_in_count) + " || ";
        report += std::string{"sp inputs: "} + std::to_string(params.sp_in_count) + " || ";
        report += std::string{"outputs: "} + std::to_string(params.out_count) + " || ";
        report += std::string{"legacy ring size: "} + std::to_string(params.legacy_ring_size) + " || ";
        report += std::string{"sp ref set size ("} + std::to_string(params.n) + "^" + std::to_string(params.m) + "): ";
        report += std::to_string(sp::math::uint_pow(params.n, params.m));

        std::cout << report << '\n';

        // add the info report to timings database so it is saved to file
        if (params.core_params.td.get())
        {
            TimingsDatabase::instance null_instance;
            null_instance.npoints = 0;

            std::string report_csv;
            std::string separator{','};
            report_csv += sp::tx_descriptor<SpTxType>() + separator;
            report_csv += std::to_string(sp::sp_tx_squashed_v1_size_bytes(m_txs.back())) + separator;
            report_csv += std::to_string(params.batch_size) + separator;
            report_csv += std::to_string(params.legacy_in_count) + separator;
            report_csv += std::to_string(params.sp_in_count) + separator;
            report_csv += std::to_string(params.out_count) + separator;
            report_csv += std::to_string(params.legacy_ring_size) + separator;
            report_csv += std::to_string(params.n) + separator;
            report_csv += std::to_string(params.m) + separator;
            report_csv += std::to_string(sp::math::uint_pow(params.n, params.m));

            params.core_params.td->add(report_csv.c_str(), null_instance);
        }

        return true;
    }

    bool test()
    {
        try
        {
            const sp::mocks::TxValidationContextMock tx_validation_context{*m_ledger_contex};
            return sp::validate_txs(m_tx_ptrs, tx_validation_context);
        }
        catch (...)
        {
            return false;
        }
    }

private:
    std::vector<SpTxType> m_txs;
    std::vector<const SpTxType*> m_tx_ptrs;
    std::shared_ptr<sp::mocks::MockLedgerContext> m_ledger_contex;
};
