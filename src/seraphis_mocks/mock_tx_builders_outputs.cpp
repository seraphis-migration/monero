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

//paired header
#include "mock_tx_builders_outputs.h"

//local headers
#include "common/container_helpers.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/tx_builder_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpCoinbaseOutputProposalV1> gen_mock_sp_coinbase_output_proposals_v1(
    const std::vector<rct::xmr_amount> &out_amounts,
    const std::size_t num_random_memo_elements)
{
    // 1. generate random output proposals
    std::vector<SpCoinbaseOutputProposalV1> output_proposals;
    output_proposals.reserve(out_amounts.size());

    for (const rct::xmr_amount out_amount : out_amounts)
        output_proposals.emplace_back(gen_sp_coinbase_output_proposal_v1(out_amount, num_random_memo_elements));

    // 2. sort them
    std::sort(output_proposals.begin(),
        output_proposals.end(),
        tools::compare_func<SpCoinbaseOutputProposalV1>(compare_Ko));

    return output_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts,
    const std::size_t num_random_memo_elements)
{
    // 1. generate random output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    output_proposals.reserve(out_amounts.size());

    for (const rct::xmr_amount out_amount : out_amounts)
        output_proposals.emplace_back(gen_sp_output_proposal_v1(out_amount, num_random_memo_elements));

    // 2. sort them
    std::sort(output_proposals.begin(), output_proposals.end(), tools::compare_func<SpOutputProposalV1>(compare_Ko));

    return output_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
