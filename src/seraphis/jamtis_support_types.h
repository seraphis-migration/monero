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

// Core implementation details for making Jamtis privkeys
// - Jamtis is a specification for Seraphis-compatible addresses

#pragma once

//local headers

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/// index (system-endian; only 56 bits are used): j
using address_index_t = std::uint64_t;
constexpr std::size_t ADDRESS_INDEX_BYTES{7};
constexpr address_index_t ADDRESS_INDEX_MAX{(address_index_t{1} << 8*ADDRESS_INDEX_BYTES) - 1};  //2^56 - 1

/// MAC for address tags (system-endian): addr_tag_MAC
constexpr std::size_t ADDRESS_TAG_MAC_BYTES{1};  //if > 1, then endianness must be preserved
using address_tag_MAC_t = unsigned char;

/// index ciphered with view-balance key: addr_tag = enc(little_endian(j) || little_endian(addr_tag_MAC))
struct address_tag_t
{
    unsigned char bytes[ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES];

    // customize operator^ for encrypting tags
    address_tag_t operator^(const address_tag_t &other_tag) const
    {
        address_tag_t temp;

        for (std::size_t i{0}; i < sizeof(address_tag_t); ++i)
            temp.bytes[i] = *this.bytes[i] ^ other_tag.bytes[i];

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

/// normal proposal type, used to define enote-construction procedure for normal proposals
enum class JamtisPlainType : public address_tag_MAC_t
{
    PLAIN = 0
};

/// self-send proposal type, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendType : public address_tag_MAC_t
{
    CHANGE = 0,
    SELF_SPEND = 1
};

/// view_tag (TODO: use view tags implemented in PR 8061)
using view_tag_t = unsigned char;

} //namespace jamtis
} //namespace sp
