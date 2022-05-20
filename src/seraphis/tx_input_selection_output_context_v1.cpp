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

// NOT FOR PRODUCTION

//paired header
#include "tx_input_selection_output_context_v1.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_builders_outputs.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t compute_num_additional_outputs(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::key &input_context,
    const rct::xmr_amount change_amount)
{
    OutputProposalSetExtraTypesContextV1 dummy;
    std::vector<OutputProposalSetExtraTypesV1> additional_outputs;

    get_additional_output_types_for_output_set_v1(wallet_spend_pubkey,
        k_view_balance,
        output_proposals,
        input_context,
        change_amount,
        dummy,
        additional_outputs);

    return additional_outputs.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t OutputSetContextForInputSelectionV1::get_total_amount() const
{
    boost::multiprecision::uint128_t total_output_amount{0};

    for (const SpOutputProposalV1 &output_proposal : m_output_proposals)
        total_output_amount += output_proposal.get_amount();

    return total_output_amount;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::get_num_outputs_nochange() const
{
    const std::size_t num_additional_outputs_no_change{
        compute_num_additional_outputs(m_wallet_spend_pubkey, m_k_view_balance, m_output_proposals, m_input_context, 0)
    };

    return m_output_proposals.size() + num_additional_outputs_no_change;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::get_num_outputs_withchange() const
{
    const std::size_t num_additional_outputs_with_change{
        compute_num_additional_outputs(m_wallet_spend_pubkey, m_k_view_balance, m_output_proposals, m_input_context, 1)
    };

    return m_output_proposals.size() + num_additional_outputs_with_change;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
