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

// Output set context for use during input selection.

#pragma once

//local headers
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_main/tx_input_selection_output_context.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <vector>

//forward declarations


namespace sp
{

class OutputSetContextForInputSelectionV1 final : public OutputSetContextForInputSelection
{
public:
//constructors
    OutputSetContextForInputSelectionV1(const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
        const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals);

//overloaded operators
    /// disable copy/move (this is a scoped manager [concept: context binding])
    OutputSetContextForInputSelectionV1& operator=(OutputSetContextForInputSelectionV1&&) = delete;

//member functions
    /// get total output amount
    boost::multiprecision::uint128_t total_amount() const override;
    /// get number of outputs assuming no change
    std::size_t num_outputs_nochange() const override;
    /// get number of outputs assuming non-zero change
    std::size_t num_outputs_withchange() const override;

//member variables
private:
    std::size_t m_num_outputs;
    bool m_output_ephemeral_pubkeys_are_unique;
    std::vector<jamtis::JamtisSelfSendType> m_self_send_output_types;
    boost::multiprecision::uint128_t m_total_output_amount;
};

} //namespace sp
