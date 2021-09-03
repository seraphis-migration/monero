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

// Calculate a tx fee (mock-ups for testing).

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "seraphis_main/tx_fee_calculator.h"

//third party headers

//standard headers
#include <cstddef>

//forward declarations


namespace sp
{
namespace mocks
{

/// fee = fee_per_weight
class FeeCalculatorMockTrivial final : public FeeCalculator
{
public:
//member functions
    rct::xmr_amount compute_fee(const std::size_t fee_per_weight,
        const std::size_t num_legacy_inputs,
        const std::size_t num_sp_inputs,
        const std::size_t num_outputs) const override
    {
        return fee_per_weight;
    }
};

/// fee = fee_per_weight * (num_inputs + num_outputs)
class FeeCalculatorMockSimple final : public FeeCalculator
{
public:
//member functions
    rct::xmr_amount compute_fee(const std::size_t fee_per_weight,
        const std::size_t num_legacy_inputs,
        const std::size_t num_sp_inputs,
        const std::size_t num_outputs) const override
    {
        return fee_per_weight * (num_legacy_inputs + num_sp_inputs + num_outputs);
    }
};

/// fee = fee_per_weight * (num_inputs / step_size + num_outputs)
class FeeCalculatorMockInputsStepped final : public FeeCalculator
{
public:
//constructors
    FeeCalculatorMockInputsStepped(const std::size_t step_size) : m_step_size{step_size > 0 ? step_size : 1} {}
//member functions
    rct::xmr_amount compute_fee(const std::size_t fee_per_weight,
        const std::size_t num_legacy_inputs,
        const std::size_t num_sp_inputs,
        const std::size_t num_outputs) const override
    {
        return fee_per_weight * ((num_legacy_inputs + num_sp_inputs) / m_step_size + num_outputs);
    }
//member variables
private:
    std::size_t m_step_size;
};

} //namespace mocks
} //namespace sp
