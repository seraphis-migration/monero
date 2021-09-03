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

// Supporting types for Jamtis (address index, address tag hint, address tag, etc.).

#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>
#include <cstddef>
#include <functional>

//forward declarations


namespace sp
{
namespace jamtis
{

/// index (little-endian): j
constexpr std::size_t ADDRESS_INDEX_BYTES{16};
struct address_index_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES];

    /// default constructor: default initialize to 0
    address_index_t();
};

/// hint for address tags: addr_tag_hint
constexpr std::size_t ADDRESS_TAG_HINT_BYTES{2};
struct address_tag_hint_t final
{
    unsigned char bytes[ADDRESS_TAG_HINT_BYTES];

    /// default constructor: default initialize to 0
    address_tag_hint_t();
};

/// index ciphered with a cipher key: addr_tag = enc[cipher_key](j) || addr_tag_hint
struct address_tag_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES + ADDRESS_TAG_HINT_BYTES];
};

/// address tag XORd with a user-defined secret: addr_tag_enc = addr_tag XOR addr_tag_enc_secret
using encrypted_address_tag_t = address_tag_t;

/// sizes must be consistent
static_assert(
    sizeof(address_index_t)    == ADDRESS_INDEX_BYTES                           &&
    sizeof(address_tag_hint_t) == ADDRESS_TAG_HINT_BYTES                        &&
    sizeof(address_tag_t)      == ADDRESS_INDEX_BYTES + ADDRESS_TAG_HINT_BYTES  &&
    sizeof(address_tag_t)      == sizeof(encrypted_address_tag_t),
    ""
);

/// jamtis enote types
enum class JamtisEnoteType : unsigned char
{
    PLAIN = 0,
    DUMMY = 1,
    CHANGE = 2,
    SELF_SPEND = 3
};

/// jamtis self-send types, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendType : unsigned char
{
    DUMMY = 0,
    CHANGE = 1,
    SELF_SPEND = 2,
    MAX = SELF_SPEND
};

/// jamtis encoded amount
constexpr std::size_t ENCODED_AMOUNT_BYTES{8};
struct encoded_amount_t final
{
    unsigned char bytes[ENCODED_AMOUNT_BYTES];
};

/// jamtis view tags
using view_tag_t = unsigned char;

/// overloaded operators: address index
bool operator==(const address_index_t &a, const address_index_t &b);
inline bool operator!=(const address_index_t &a, const address_index_t &b) { return !(a == b); }
/// overloaded operators: address tag hint
bool operator==(const address_tag_hint_t &a, const address_tag_hint_t &b);
inline bool operator!=(const address_tag_hint_t &a, const address_tag_hint_t &b) { return !(a == b); }
/// overloaded operators: address tag
bool operator==(const address_tag_t &a, const address_tag_t &b);
inline bool operator!=(const address_tag_t &a, const address_tag_t &b) { return !(a == b); }
address_tag_t operator^(const address_tag_t &a, const address_tag_t &b);

/// overloaded operators: encoded amount
bool operator==(const encoded_amount_t &a, const encoded_amount_t &b);
inline bool operator!=(const encoded_amount_t &a, const encoded_amount_t &b) { return !(a == b); }
encoded_amount_t operator^(const encoded_amount_t &a, const encoded_amount_t &b);

/// max address index
address_index_t max_address_index();
/// make an address index
address_index_t make_address_index(std::uint64_t half1, std::uint64_t half2);
inline address_index_t make_address_index(std::uint64_t half1) { return make_address_index(half1, 0); }
/// make an address tag
address_tag_t make_address_tag(const address_index_t &enc_j, const address_tag_hint_t &addr_tag_hint);
/// generate a random address index
address_index_t gen_address_index();

/// convert between jamtis enote types and self-send types
bool try_get_jamtis_enote_type(const JamtisSelfSendType self_send_type, JamtisEnoteType &enote_type_out);
bool try_get_jamtis_self_send_type(const JamtisEnoteType enote_type, JamtisSelfSendType &self_send_type_out);
bool is_jamtis_selfsend_type(const JamtisEnoteType enote_type);

} //namespace jamtis
} //namespace sp

/// make jamtis address index hashable
namespace sp
{
namespace jamtis
{
static_assert(sizeof(std::size_t) <= sizeof(address_index_t), "");
inline std::size_t hash_value(const address_index_t &_v)
{
    return reinterpret_cast<const std::size_t&>(_v);
}
} //namespace jamtis
} //namespace sp
namespace std
{
template<>
struct hash<sp::jamtis::address_index_t>
{
    std::size_t operator()(const sp::jamtis::address_index_t &_v) const
    {
        return reinterpret_cast<const std::size_t&>(_v);
    }
};
} //namespace std
