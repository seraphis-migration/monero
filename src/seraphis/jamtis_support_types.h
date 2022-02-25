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

/// index (system-endian; only 56 bits are used): j
using address_index_t = std::uint64_t;
constexpr std::size_t ADDRESS_INDEX_BYTES{7};
constexpr address_index_t MAX_ADDRESS_INDEX{(address_index_t{1} << 8*ADDRESS_INDEX_BYTES) - 1};  //2^56 - 1

/// MAC for address tags (system-endian): addr_tag_MAC
constexpr std::size_t ADDRESS_TAG_MAC_BYTES{1};  //if > 1, then endianness must be preserved
using address_tag_MAC_t = unsigned char;

/// index ciphered with view-balance key: addr_tag = enc[k_vb](little_endian(j) || little_endian(addr_tag_MAC))
struct address_tag_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES];

    /// comparison operators
    bool operator==(const address_tag_t &other_tag) const
    {
        return memcmp(bytes, other_tag.bytes, sizeof(address_tag_t)) == 0;
    }
    bool operator!=(const address_tag_t &other_tag) const { return !(*this == other_tag); }

    /// operator^ for encrypting tags
    address_tag_t operator^(const address_tag_t &other_tag) const
    {
        address_tag_t temp;

        for (std::size_t i{0}; i < sizeof(address_tag_t); ++i)
            temp.bytes[i] = bytes[i] ^ other_tag.bytes[i];

        return temp;
    }
};

/// address tag XORd with a user-defined secret: addr_tag_enc = addr_tag XOR addr_tag_enc_secret
using encrypted_address_tag_t = address_tag_t;

/// sizes are consistent
static_assert(
    sizeof(address_index_t)   >= ADDRESS_INDEX_BYTES                          &&
    sizeof(address_tag_MAC_t) >= ADDRESS_TAG_MAC_BYTES                        &&
    sizeof(address_tag_t)     == ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES  &&
    sizeof(address_tag_t)     == sizeof(encrypted_address_tag_t),
    ""
);

/// jamtis enote types
enum class JamtisEnoteType : unsigned int
{
    PLAIN = 0,
    CHANGE = 1,
    SELF_SPEND = 2
};

/// jamtis self-send MACs, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendMAC : address_tag_MAC_t
{
    CHANGE = 0,
    SELF_SPEND = 1
};

inline bool operator==(const JamtisSelfSendMAC a, const address_tag_MAC_t b)
{
    return static_cast<address_tag_MAC_t>(a) == b;
}
inline bool operator==(const address_tag_MAC_t a, const JamtisSelfSendMAC b) { return b == a; }
inline bool operator!=(const JamtisSelfSendMAC a, const address_tag_MAC_t b) { return !(a == b); }
inline bool operator!=(const address_tag_MAC_t a, const JamtisSelfSendMAC b) { return !(a == b); }

/// jamtis view tags
using view_tag_t = unsigned char;

} //namespace jamtis
} //namespace sp
