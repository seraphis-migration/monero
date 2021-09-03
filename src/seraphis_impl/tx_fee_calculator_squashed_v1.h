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

// Calculate the fee for an SpTxSquashedV1 tx.

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_main/tx_fee_calculator.h"
#include "seraphis_main/txtype_squashed_v1.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

class FeeCalculatorSpTxSquashedV1 final : public FeeCalculator
{
public:
//constructors
    FeeCalculatorSpTxSquashedV1(const std::size_t legacy_ring_size,
        const std::size_t ref_set_decomp_n,
        const std::size_t ref_set_decomp_m,
        const std::size_t num_bin_members,
        const std::size_t tx_extra_size);

//member functions
    static rct::xmr_amount compute_fee(const std::size_t fee_per_weight, const std::size_t weight);
    static rct::xmr_amount compute_fee(const std::size_t fee_per_weight, const SpTxSquashedV1 &tx);
    rct::xmr_amount compute_fee(const std::size_t fee_per_weight,
        const std::size_t num_legacy_inputs,
        const std::size_t num_sp_inputs,
        const std::size_t num_outputs) const override;

private:
//member variables
    /// misc. info for calculating tx weight
    std::size_t m_legacy_ring_size;
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
    std::size_t m_num_bin_members;
    std::size_t m_tx_extra_size;
};

} //namespace sp
