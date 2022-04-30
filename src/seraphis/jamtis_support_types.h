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

//third party headers

//standard headers

//forward declarations
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace sp
{
namespace jamtis
{

/// index (little-endian): j
constexpr std::size_t ADDRESS_INDEX_BYTES{15};
struct address_index_t
{
    unsigned char bytes[ADDRESS_INDEX_BYTES];

    address_index_t();
    address_index_t(std::uint64_t half1, std::uint64_t half2);
    address_index_t(std::uint64_t half1) : address_index_t{half1, 0} {}

    void gen();

    /// max address index
    static address_index_t max();

    /// comparison operators
    bool operator==(const address_index_t &other_index) const;
    bool operator!=(const address_index_t &other_index) const { return !(*this == other_index); }
};

/// MAC for address tags (little-endian): addr_tag_MAC
constexpr std::size_t ADDRESS_TAG_MAC_BYTES{1};
struct address_tag_MAC_t
{
    unsigned char bytes[ADDRESS_TAG_MAC_BYTES];

    address_tag_MAC_t();
    address_tag_MAC_t(unsigned char mac);

    /// comparison operators
    bool operator==(const address_tag_MAC_t &other_mac) const;
    bool operator!=(const address_tag_MAC_t &other_mac) const { return !(*this == other_mac); }
};

/// index ciphered with a cipher key: addr_tag = enc[cipher_key](little_endian(j) || little_endian(addr_tag_MAC))
struct address_tag_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES];

    /// comparison operators
    bool operator==(const address_tag_t &other_tag) const;
    bool operator!=(const address_tag_t &other_tag) const { return !(*this == other_tag); }

    /// operator^ for encrypting tags
    address_tag_t operator^(const address_tag_t &other_tag) const;
};

/// address tag XORd with a user-defined secret: addr_tag_enc = addr_tag XOR addr_tag_enc_secret
using encrypted_address_tag_t = address_tag_t;

/// sizes are consistent
static_assert(
    sizeof(address_index_t)   == ADDRESS_INDEX_BYTES                          &&
    sizeof(address_tag_MAC_t) == ADDRESS_TAG_MAC_BYTES                        &&
    sizeof(address_tag_t)     == ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES  &&
    sizeof(address_tag_t)     == sizeof(encrypted_address_tag_t),
    ""
);

/// jamtis enote types
enum class JamtisEnoteType : unsigned char
{
    UNKNOWN = 0,
    PLAIN = 1,
    DUMMY = 2,
    CHANGE = 3,
    SELF_SPEND = 4
};

/// jamtis self-send MACs, used to define enote-construction procedure for self-sends
enum JamtisSelfSendMAC : unsigned char
{
    DUMMY = 0,
    CHANGE = 1,
    SELF_SPEND = 2
};

bool operator==(JamtisSelfSendMAC a, const address_tag_MAC_t b);
inline bool operator==(const address_tag_MAC_t a, const JamtisSelfSendMAC b) { return b == a; }
inline bool operator!=(const JamtisSelfSendMAC a, const address_tag_MAC_t b) { return !(a == b); }
inline bool operator!=(const address_tag_MAC_t a, const JamtisSelfSendMAC b) { return !(a == b); }

bool is_known_self_send_MAC(const address_tag_MAC_t mac);
JamtisEnoteType self_send_MAC_to_type(const JamtisSelfSendMAC mac);
JamtisEnoteType self_send_MAC_to_type(const address_tag_MAC_t mac);

/// jamtis view tags
using view_tag_t = unsigned char;

} //namespace jamtis
} //namespace sp
