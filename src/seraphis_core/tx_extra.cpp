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
#include "tx_extra.h"

//local headers
#include "common/container_helpers.h"
#include "common/varint.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "span.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static void append_varint(const T value, std::vector<unsigned char> &bytes_inout)
{
    unsigned char v_variable[(sizeof(std::size_t) * 8 + 6) / 7];
    unsigned char *v_variable_end = v_variable;

    // 1. write varint into a temp buffer
    tools::write_varint(v_variable_end, value);
    assert(v_variable_end <= v_variable + sizeof(v_variable));

    // 2. copy into our bytes buffer
    const std::size_t v_length = v_variable_end - v_variable;
    bytes_inout.resize(bytes_inout.size() + v_length);
    memcpy(bytes_inout.data() + bytes_inout.size() - v_length, v_variable, v_length);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void append_bytes(const unsigned char *data,
    const std::size_t length,
    std::vector<unsigned char> &bytes_inout)
{
    // copy data into our bytes buffer
    bytes_inout.resize(bytes_inout.size() + length);
    memcpy(bytes_inout.data() + bytes_inout.size() - length, data, length);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static bool try_parse_bytes_varint(const epee::span<const unsigned char> &bytes, std::size_t &position_inout, T &val_out)
{
    // 1. sanity check range
    if (position_inout >= bytes.size())
        return false;

    // 2. try to read a variant into the value
    const int parse_result{tools::read_varint(bytes.data() + position_inout, bytes.end(), val_out)};

    // 3. check if parsing succeeded
    if (parse_result <= 0)
        return false;

    // 4. return success
    position_inout += parse_result;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
// convert an element to bytes and append to the input bytes: varint(type) || varint(length) || value
//-------------------------------------------------------------------------------------------------------------------
static void grow_extra_field_bytes(const ExtraFieldElement &element, std::vector<unsigned char> &bytes_inout)
{
    // varint(type) || varint(length) || bytes
    bytes_inout.reserve(bytes_inout.size() + 18 + element.value.size());

    // 1. append type
    append_varint(element.type, bytes_inout);

    // 2. append length
    append_varint(element.value.size(), bytes_inout);

    // 3. append value
    append_bytes(element.value.data(), element.value.size(), bytes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// get an extra field element from the specified position in the tx extra field
// - returns false if could not get an element
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_extra_field_element(const epee::span<const unsigned char> &tx_extra,
    std::size_t &element_position_inout,
    ExtraFieldElement &element_out)
{
    // 1. parse the type
    if (!try_parse_bytes_varint(tx_extra, element_position_inout, element_out.type))
        return false;

    // 2. parse the length
    std::uint64_t length{0};
    if (!try_parse_bytes_varint(tx_extra, element_position_inout, length))
        return false;

    // 3. check if the value can be extracted (fail if it extends past the field end)
    if (element_position_inout + length > tx_extra.size())
        return false;

    // 4. parse the value
    append_bytes(tx_extra.data() + element_position_inout, length, element_out.value);
    element_position_inout += length;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool operator<(const ExtraFieldElement &a, const ExtraFieldElement &b)
{
    // 1. check type
    if (a.type < b.type)
        return true;
    if (a.type > b.type)
        return false;

    // 2. check length (type is equal)
    if (a.value.size() < b.value.size())
        return true;
    if (a.value.size() > b.value.size())
        return false;

    // 3. check value (type, length are equal)
    return a.value < b.value;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t length(const ExtraFieldElement &element)
{
    return element.value.size();
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_extra(std::vector<ExtraFieldElement> elements, TxExtra &tx_extra_out)
{
    tx_extra_out.clear();
    tx_extra_out.reserve(elements.size() * (18 + 32));  //assume 32 byte values

    // 1. tx_extra must be sorted
    std::sort(elements.begin(), elements.end());

    // 2. build the tx extra
    for (const ExtraFieldElement &element : elements)
        grow_extra_field_bytes(element, tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_extra_field_elements(const TxExtra &tx_extra, std::vector<ExtraFieldElement> &elements_out)
{
    elements_out.clear();
    elements_out.reserve(tx_extra.size() / 25);  //approximate

    // 1. extract elements from the tx extra field
    std::size_t element_position{0};
    const epee::span<const unsigned char> tx_extra_span{epee::to_span(tx_extra)};

    while (element_position < tx_extra.size())
    {
        if (!try_get_extra_field_element(tx_extra_span, element_position, tools::add_element(elements_out)))
        {
            elements_out.pop_back();
            return false;
        }
    }

    // 2. if we didn't consume all bytes, then the field is malformed
    if (element_position != tx_extra.size())
        return false;

    // 3. if the elements extracted from a tx extra are not sorted, then the field is malformed
    if (!std::is_sorted(elements_out.begin(), elements_out.end()))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void accumulate_extra_field_elements(const std::vector<ExtraFieldElement> &elements_to_add,
    std::vector<ExtraFieldElement> &elements_inout)
{
    elements_inout.reserve(elements_inout.size() + elements_to_add.size());
    elements_inout.insert(elements_inout.end(), elements_to_add.begin(), elements_to_add.end());
}
//-------------------------------------------------------------------------------------------------------------------
void accumulate_extra_field_elements(const TxExtra &partial_memo,
    std::vector<ExtraFieldElement> &elements_inout)
{
    std::vector<ExtraFieldElement> temp_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo, temp_memo_elements),
        "accumulate extra field elements: malformed partial memo.");
    accumulate_extra_field_elements(temp_memo_elements, elements_inout);
}
//-------------------------------------------------------------------------------------------------------------------
ExtraFieldElement gen_extra_field_element()
{
    ExtraFieldElement temp;
    temp.type = crypto::rand_idx<std::uint64_t>(0);
    temp.value.resize(crypto::rand_idx(static_cast<std::size_t>(101)));  //limit length to 100 bytes for performance
    crypto::rand(temp.value.size(), temp.value.data());
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
