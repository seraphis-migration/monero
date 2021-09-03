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

// A discretized fee (i.e. a fee value represented by a discrete identifier).

#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <cstdint>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

using discretized_fee_encoding_t = unsigned char;

////
// DiscretizedFee
// - a discretized fee represents a fee value selected from a limited set of valid fee values
// - a raw fee value is 'discretized' when it is converted into one of those valid fee values (by rounding
//   up to the nearest fee level)
// note: a default-initialized discretized fee encodes the fee value '0'
///
struct DiscretizedFee final
{
    discretized_fee_encoding_t fee_encoding;
};
inline const boost::string_ref container_name(const DiscretizedFee) { return "DiscretizedFee"; }
void append_to_transcript(const DiscretizedFee container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t discretized_fee_size_bytes() { return sizeof(discretized_fee_encoding_t); }

/// equality operators
bool operator==(const DiscretizedFee a, const DiscretizedFee b);
bool operator==(const DiscretizedFee fee, const discretized_fee_encoding_t fee_level);
bool operator==(const discretized_fee_encoding_t fee_level, const DiscretizedFee fee);
bool operator==(const DiscretizedFee fee, const rct::xmr_amount raw_fee_value);

/**
* brief: discretize_fee - convert a raw fee value to a discretized fee (the resulting encoded fee may be >= the raw fee)
* param: raw_fee_value -
* return: discretized fee
*/
DiscretizedFee discretize_fee(const rct::xmr_amount raw_fee_value);
/**
* brief: try_get_fee_value - try to extract a raw fee value from a discretized fee (fails if the encoding is invalid)
* param: discretized_fee -
* outparam: fee_value_out -
* return: true if an extraction succeeded
*/
bool try_get_fee_value(const DiscretizedFee discretized_fee, std::uint64_t &fee_value_out);

} //namespace sp
