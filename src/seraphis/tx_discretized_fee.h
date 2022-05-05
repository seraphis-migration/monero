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

#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <cstdint>

//forward declarations


namespace sp
{

using discretized_fee_level_t = unsigned char;

struct DiscretizedFee
{
    discretized_fee_level_t m_fee_level;

    DiscretizedFee() = default;
    DiscretizedFee(const rct::xmr_amount raw_fee_amount);  //throwing constructor

    bool operator==(const DiscretizedFee &other) const { return m_fee_level == other.m_fee_level; }
    bool operator==(const discretized_fee_level_t other_fee_level) const { return m_fee_level == other_fee_level; }
    bool operator==(const rct::xmr_amount raw_fee_amount) const;

    static std::size_t get_size_bytes() { return sizeof(m_fee_level); }
};

bool operator==(const discretized_fee_level_t fee_level, const DiscretizedFee &discretized_fee);

/**
* brief: try_get_basic_enote_record_v1 - try to extract a basic enote record from an enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: sender_receiver_DH_derivation -
* outparam: basic_record_out -
* return: true if an extraction succeeded
*/
void test_discretized_fees();

//todo
bool try_discretize_fee_value(const std::uint64_t raw_fee_value, DiscretizedFee &discretized_fee_out);
//todo
bool try_get_fee_value(const DiscretizedFee discretized_fee, std::uint64_t &fee_value_out);

} //namespace sp
