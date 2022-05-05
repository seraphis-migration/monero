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

// Implementation of the cryptonote tx_extra field, with an enforced 'sorted TLV' format.


#pragma once

//local headers

//third party headers

//standard headers
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
    std::size_t m_type;
    /// value length: implicit
    /// value
    std::vector<unsigned char> m_value;

    std::size_t length() const { return m_value.size(); }

    /// less-than operator for sorting: type, value length, value bytewise comparison
    bool operator<(const ExtraFieldElement &other_element) const
    {
        if (m_type < other_element.m_type)
            return true;
        else if (m_type > other_element.m_type)
            return false;
        else //(m_type == other_element.m_type)
            return m_value < other_element.m_value;
    }

    /// convert to bytes and append to the input variable: varint(type) || varint(length) || value
    void append_bytes(std::vector<unsigned char> &bytes_inout) const;

    /// generate a random extra field element
    void gen();
};

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
* inoutparam: elements_inoutt -
*/
void accumulate_extra_field_elements(const std::vector<ExtraFieldElement> &elements_to_add,
    std::vector<ExtraFieldElement> &elements_inout);
void accumulate_extra_field_elements(const TxExtra &partial_memo,
    std::vector<ExtraFieldElement> &elements_inout);

} //namespace sp
