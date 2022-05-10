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
#include "tx_fee_getter_squashedv1.h"

//local headers
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_discretized_fee.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
TxFeeGetterSquashedV1::TxFeeGetterSquashedV1(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const std::size_t ref_set_decomp_m,
    const std::size_t ref_set_decomp_n,
    const std::size_t num_bin_members,
    const TxExtra &tx_extra) :
        m_num_inputs{num_inputs},
        m_num_outputs{num_outputs},
        m_ref_set_decomp_m{ref_set_decomp_m},
        m_ref_set_decomp_n{ref_set_decomp_n},
        m_num_bin_members{num_bin_members},
        m_tx_extra{tx_extra}
{}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount TxFeeGetterSquashedV1::get_fee(const std::size_t fee_per_weight, const std::size_t weight)
{
    const DiscretizedFee fee_discretized{fee_per_weight * weight};

    rct::xmr_amount fee_value;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(fee_discretized, fee_value),
        "tx fee getter (SpTxSquashedV1): extracting discretized fee failed (bug).");

    return fee_value;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount TxFeeGetterSquashedV1::get_fee(const std::size_t fee_per_weight, const SpTxSquashedV1 &tx)
{
    return get_fee(fee_per_weight, tx.get_weight());
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount TxFeeGetterSquashedV1::get_fee(const std::size_t fee_per_weight) const
{
    const std::size_t weight{SpTxSquashedV1::get_weight(m_num_inputs,
        m_num_outputs,
        m_ref_set_decomp_m,
        m_ref_set_decomp_n,
        m_num_bin_members,
        m_tx_extra)};

    return get_fee(fee_per_weight, weight);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
