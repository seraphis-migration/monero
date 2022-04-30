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

//paired header
#include "jamtis_support_types.h"

//local headers
#include "crypto/crypto.h"
#include "int-util.h"
#include "misc_log_ex.h"

//third party headers

//standard headers
#include <cstdint>
#include <cstddef>
#include <cstring>


namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
// little-endian swaps
//-------------------------------------------------------------------------------------------------------------------
constexpr unsigned char swap_le(const unsigned char x)
{
    return x;
}
constexpr std::uint16_t swap_le(const std::uint16_t x)
{
    return SWAP16LE(x);
}
constexpr std::uint32_t swap_le(const std::uint32_t x)
{
    return SWAP32LE(x);
}
constexpr std::uint64_t swap_le(const std::uint64_t x)
{
    return SWAP64LE(x);
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t::address_index_t()
{
    std::memset(this->bytes, 0, ADDRESS_INDEX_BYTES);
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t::address_index_t(std::uint64_t half1, std::uint64_t half2)
{
    static_assert(sizeof(half1) + sizeof(half2) >= sizeof(address_index_t) &&
            sizeof(half1) <= sizeof(address_index_t),
        "");

    // copy each half of the index over (as little endian bytes)
    std::memset(this->bytes, 0, ADDRESS_INDEX_BYTES);
    half1 = swap_le(half1);
    half2 = swap_le(half2);
    memcpy(this->bytes, &half1, sizeof(half1));
    memcpy(this->bytes + sizeof(half1), &half2, ADDRESS_INDEX_BYTES - sizeof(half2));
}
//-------------------------------------------------------------------------------------------------------------------
void address_index_t::gen()
{
    crypto::rand(ADDRESS_INDEX_BYTES, this->bytes);
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t address_index_t::max()
{
    address_index_t temp;
    std::memset(temp.bytes, static_cast<unsigned char>(-1), ADDRESS_INDEX_BYTES);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
bool address_index_t::operator==(const address_index_t &other_index) const
{
    return memcmp(this->bytes, other_index.bytes, sizeof(address_index_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_MAC_t::address_tag_MAC_t()
{
    std::memset(this->bytes, 0, ADDRESS_TAG_MAC_BYTES);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_MAC_t::address_tag_MAC_t(unsigned char mac)
{
    static_assert(sizeof(mac) <= ADDRESS_TAG_MAC_BYTES, "");

    // copy the mac over (as little endian bytes)
    std::memset(this->bytes, 0, ADDRESS_TAG_MAC_BYTES);
    mac = swap_le(mac);
    memcpy(this->bytes, &mac, sizeof(mac));
}
//-------------------------------------------------------------------------------------------------------------------
bool address_tag_MAC_t::operator==(const address_tag_MAC_t &other_mac) const
{
    return memcmp(this->bytes, other_mac.bytes, sizeof(address_tag_MAC_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool address_tag_t::operator==(const address_tag_t &other_tag) const
{
    return memcmp(this->bytes, other_tag.bytes, sizeof(address_tag_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t address_tag_t::operator^(const address_tag_t &other_tag) const
{
    address_tag_t temp;
    for (std::size_t i{0}; i < sizeof(address_tag_t); ++i)
        temp.bytes[i] = this->bytes[i] ^ other_tag.bytes[i];

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(JamtisSelfSendMAC a, const address_tag_MAC_t b)
{
    static_assert(sizeof(JamtisSelfSendMAC) <= sizeof(address_tag_MAC_t), "");
    const address_tag_MAC_t temp_mac{a};
    return temp_mac == b;
}
//-------------------------------------------------------------------------------------------------------------------
bool is_known_self_send_MAC(const address_tag_MAC_t mac)
{
    return mac == JamtisSelfSendMAC::DUMMY ||
        mac == JamtisSelfSendMAC::CHANGE ||
        mac == JamtisSelfSendMAC::SELF_SPEND;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisEnoteType self_send_MAC_to_type(const JamtisSelfSendMAC mac)
{
    switch (mac)
    {
        case (JamtisSelfSendMAC::DUMMY)      : return JamtisEnoteType::DUMMY;
        case (JamtisSelfSendMAC::CHANGE)     : return JamtisEnoteType::CHANGE;
        case (JamtisSelfSendMAC::SELF_SPEND) : return JamtisEnoteType::SELF_SPEND;
        default                              : return JamtisEnoteType::UNKNOWN;
    };
}
//-------------------------------------------------------------------------------------------------------------------
JamtisEnoteType self_send_MAC_to_type(const address_tag_MAC_t mac)
{
    static_assert(1 <= sizeof(address_tag_MAC_t), "");
    unsigned char mac_converted;
    memcpy(&mac_converted, mac.bytes, 1);

    return self_send_MAC_to_type(static_cast<JamtisSelfSendMAC>(mac_converted));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
