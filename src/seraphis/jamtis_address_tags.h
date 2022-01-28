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

// Address tags for Jamtis addresses
// note: secret keys are 'rct::key' instead of 'crypto::secret_key' for performance during view-scanning


#pragma once

//local headers
extern "C"
{
#include "crypto/blowfish.h"
}
#include "jamtis_address_utils.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/// MAC for address tags (system-endian): addr_tag_MAC
constexpr std::size_t ADDRESS_TAG_MAC_BYTES{1};  //if > 1, then endianness must be preserved
using address_tag_MAC_t = unsigned char;

/// index ciphered with view-balance key: addr_tag = enc(little_endian(j) || little_endian(addr_tag_MAC))
struct address_tag_t
{
    unsigned char bytes[ADDRESS_INDEX_BYTES + ADDRESS_TAG_MAC_BYTES];
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

/// convert {j, mac} to/from an address tag byte-representation
address_tag_t address_index_to_tag(const address_index_t j,
    const address_tag_MAC_t mac);
address_index_t tag_to_address_index(const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out);

/// {j, addr_tag_MAC} -> addr_tag
address_tag_t make_address_tag(const BLOWFISH_CTX &blowfish_context,
    const address_index_t j,
    const address_tag_MAC_t mac);
address_tag_t make_address_tag_with_key(const rct::key &cipher_key,
    const address_index_t j,
    const address_tag_MAC_t mac);

/// addr_tag -> {j, addr_tag_MAC}
address_tag_MAC_t try_get_address_index(const BLOWFISH_CTX &blowfish_context,
    const address_tag_t addr_tag,
    address_index_t &j_out);
address_tag_MAC_t try_get_address_index_with_key(const rct::key &cipher_key,
    const address_tag_t addr_tag,
    address_index_t &j_out);

/// addr_tag_enc = addr_tag XOR addr_tag_enc_secret
encrypted_address_tag_t make_encrypted_address_tag(const rct::key &encryption_key,
    const address_tag_t addr_tag);

/// addr_tag = addr_tag_enc XOR addr_tag_enc_secret
address_tag_t get_decrypted_address_tag(const rct::key &encryption_key,
    const encrypted_address_tag_t addr_tag_tag_enc);

} //namespace jamtis
} //namespace sp
