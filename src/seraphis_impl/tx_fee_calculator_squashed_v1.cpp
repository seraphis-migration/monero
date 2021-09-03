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

//paired header
#include "tx_fee_calculator_squashed_v1.h"

//local headers
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
FeeCalculatorSpTxSquashedV1::FeeCalculatorSpTxSquashedV1(const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_bin_members,
    const std::size_t tx_extra_size) :
        m_legacy_ring_size{legacy_ring_size},
        m_ref_set_decomp_n{ref_set_decomp_n},
        m_ref_set_decomp_m{ref_set_decomp_m},
        m_num_bin_members{num_bin_members},
        m_tx_extra_size{tx_extra_size}
{}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount FeeCalculatorSpTxSquashedV1::compute_fee(const std::size_t fee_per_weight, const std::size_t weight)
{
    rct::xmr_amount fee_value;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretize_fee(fee_per_weight * weight), fee_value),
        "tx fee getter (SpTxSquashedV1): extracting discretized fee failed (bug).");

    return fee_value;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount FeeCalculatorSpTxSquashedV1::compute_fee(const std::size_t fee_per_weight, const SpTxSquashedV1 &tx)
{
    return FeeCalculatorSpTxSquashedV1::compute_fee(fee_per_weight, sp_tx_squashed_v1_weight(tx));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount FeeCalculatorSpTxSquashedV1::compute_fee(const std::size_t fee_per_weight,
    const std::size_t num_legacy_inputs,
    const std::size_t num_sp_inputs,
    const std::size_t num_outputs) const
{
    const std::size_t weight{
            sp_tx_squashed_v1_weight(num_legacy_inputs,
                num_sp_inputs,
                num_outputs,
                m_legacy_ring_size,
                m_ref_set_decomp_n,
                m_ref_set_decomp_m,
                m_num_bin_members,
                m_tx_extra_size)
        };

    return this->compute_fee(fee_per_weight, weight);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
