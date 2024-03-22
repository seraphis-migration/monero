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

// NOT FOR PRODUCTION

// Mock seraphis transaction builders.

#pragma once

//local headers
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace rct { using xmr_amount = uint64_t; }
namespace sp
{
    struct SpTxCoinbaseV1;
    struct SpTxSquashedV1;
    class TxValidationContext;
namespace mocks
{
    class MockLedgerContext;
}
}

namespace sp
{
namespace mocks
{

/**
* brief: make_mock_tx - make a mock transaction (template)
* type: SpTxType - 
* type: SpTxParamsT -
* param: params -
* inoutparam: ledger_context_inout -
* outparam: tx_out -
*/
template <typename SpTxType, typename SpTxParamsT>
void make_mock_tx(const SpTxParamsT &params,
    MockLedgerContext &ledger_context_inout,
    SpTxType &tx_out);

////
/// SpTxParamPackV1 - parameter pack (for unit tests/mockups/etc.)
///
struct SpTxParamPackV1
{
    std::size_t legacy_ring_size{0};
    std::size_t ref_set_decomp_n{0};
    std::size_t ref_set_decomp_m{0};
    std::size_t num_random_memo_elements{0};
    SpBinnedReferenceSetConfigV1 bin_config{0, 0};
    std::vector<rct::xmr_amount> legacy_input_amounts{};
    std::vector<rct::xmr_amount> sp_input_amounts{};
    std::vector<rct::xmr_amount> output_amounts{};
    DiscretizedFee discretized_fee{sp::discretize_fee(0)};
};
/// make an SpTxCoinbaseV1 transaction
template <>
void make_mock_tx<SpTxCoinbaseV1>(const SpTxParamPackV1 &params,
    MockLedgerContext &ledger_context_inout,
    SpTxCoinbaseV1 &tx_out);
/// make an SpTxSquashedV1 transaction
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPackV1 &params,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out);

} //namespace mocks
} //namespace sp
