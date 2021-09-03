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

// Implementation of the cryptonote tx_extra field, with an enforced 'sorted TLV' format.

#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>
#include <vector>

//forward declarations


namespace sp
{

using TxExtra = std::vector<unsigned char>;

////
// ExtraFieldElement: Type-Length-Value (TLV) format
///
struct ExtraFieldElement final
{
    /// type
    std::uint64_t type;
    /// value length
    //m_value.size()
    /// value
    std::vector<unsigned char> value;
};

/// less-than operator for sorting: sort order = type, length, value bytewise comparison
bool operator<(const ExtraFieldElement &a, const ExtraFieldElement &b);
/// get length of an extra field element
std::size_t length(const ExtraFieldElement &element);
/**
* brief: make_tx_extra - make a tx extra
* param: elements -
* outparam: tx_extra_out -
*/
void make_tx_extra(std::vector<ExtraFieldElement> elements, TxExtra &tx_extra_out);
/**
* brief: try_get_extra_field_elements - try to deserialize a tx extra into extra field elements
* param: tx_extra -
* outparam: elements_out -
* return: true if deserializing succeeds
*/
bool try_get_extra_field_elements(const TxExtra &tx_extra, std::vector<ExtraFieldElement> &elements_out);
/**
* brief: accumulate_extra_field_elements - append extra field elements to an existing set of elements
* param: elements_to_add -
* inoutparam: elements_inout -
*/
void accumulate_extra_field_elements(const std::vector<ExtraFieldElement> &elements_to_add,
    std::vector<ExtraFieldElement> &elements_inout);
void accumulate_extra_field_elements(const TxExtra &partial_memo,
    std::vector<ExtraFieldElement> &elements_inout);
/**
* brief: gen_extra_field_element - generate a random extra field element
* return: a random field element
*/
ExtraFieldElement gen_extra_field_element();

} //namespace sp
