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

// Get an SpTxSquashedV1 weight.


#pragma once

//local headers
#include "tx_extra.h"
#include "tx_weight_getter.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

class TxWeightGetterSquashedV1 final : public TxWeightGetter
{
public:
//constructors
    TxWeightGetterSquashedV1() = default;

    TxWeightGetterSquashedV1(const std::size_t num_inputs,
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

//destructor: default

//getters
    std::size_t get_weight() const override
    {
        return SpTxSquashedV1::get_weight(m_num_inputs,
            m_num_outputs,
            m_ref_set_decomp_m,
            m_ref_set_decomp_n,
            m_num_bin_members,
            m_tx_extra);
    }

//setters
    void set_num_inputs(const std::size_t num_inputs) override { m_num_inputs = num_inputs; }
    void set_num_outputs(const std::size_t num_outputs) override { m_num_outputs = num_outputs; }

private:
//member variables
    std::size_t m_num_inputs;
    std::size_t m_num_outputs;
    std::size_t m_ref_set_decomp_m;
    std::size_t m_ref_set_decomp_n;
    std::size_t m_num_bin_members;
    TxExtra m_tx_extra;
};

} //namespace sp
