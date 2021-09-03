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

// Simple mock output set context for use in input selection.

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "seraphis_main/tx_input_selection_output_context.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers

//forward declarations


namespace sp
{
namespace mocks
{

class OutputSetContextForInputSelectionMockSimple final : public OutputSetContextForInputSelection
{
public:
//constructors
    OutputSetContextForInputSelectionMockSimple(const std::vector<rct::xmr_amount> &output_amounts,
        const std::size_t num_additional_with_change) :
            m_num_outputs{output_amounts.size()},
            m_num_additional_with_change{num_additional_with_change}
    {
        m_output_amount = 0;

        for (const rct::xmr_amount output_amount : output_amounts)
            m_output_amount += output_amount;
    }

//member functions
    /// get total output amount
    boost::multiprecision::uint128_t total_amount() const override { return m_output_amount; }
    /// get number of outputs assuming no change
    std::size_t num_outputs_nochange() const override { return m_num_outputs; }
    /// get number of outputs assuming non-zero change
    std::size_t num_outputs_withchange() const override { return m_num_outputs + m_num_additional_with_change; }

//member variables
private:
    std::size_t m_num_outputs;
    boost::multiprecision::uint128_t m_output_amount;
    std::size_t m_num_additional_with_change;
};

} //namespace mocks
} //namespace sp
