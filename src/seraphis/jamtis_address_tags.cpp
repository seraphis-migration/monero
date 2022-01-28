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
#include "jamtis_address_tags.h"

//local headers
#include "cryptonote_config.h"
extern "C"
{
#include "crypto/blowfish.h"
}
#include "int-util.h"
#include "jamtis_address_utils.h"
#include "jamtis_hash_functions.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers


namespace sp
{
namespace jamtis
{
/// secret for encryption address tags
using encrypted_address_tag_secret_t = encrypted_address_tag_t;
static_assert(sizeof(encrypted_address_tag_secret_t) == sizeof(address_tag_t), "");

/// helper for encrypting/decrypting with the Blowfish block cipher
struct Blowfish_LR
{
    std::uint32_t L;
    std::uint32_t R;
};
static_assert(sizeof(Blowfish_LR) == sizeof(address_tag_t), "");

//-------------------------------------------------------------------------------------------------------------------
// j_canonical = little_endian(j)
//-------------------------------------------------------------------------------------------------------------------
static address_index_t address_index_to_canonical(address_index_t j)
{
    static_assert(sizeof(address_index_t) == 8);
    return SWAP64LE(j);
}
//-------------------------------------------------------------------------------------------------------------------
// j = system_endian(j_canonical)
//-------------------------------------------------------------------------------------------------------------------
static address_index_t address_index_from_canonical(address_index_t j_canonical)
{
    static_assert(sizeof(address_index_t) == 8);
    // on big-endian systems, this makes the result big-endian (since it always starts as little-endian)
    return SWAP64LE(j);
}
//-------------------------------------------------------------------------------------------------------------------
// addr_tag_enc = H_8('domain-sep', encryption_key)
//-------------------------------------------------------------------------------------------------------------------
static encrypted_address_tag_secret_t get_encrypted_address_tag_secret(const rct::key &encryption_key)
{
    static_assert(sizeof(encrypted_address_tag_secret_t) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG};

    // addr_tag_enc = H_8('domain-sep', encryption_key)
    encrypted_address_tag_secret_t addr_tag_enc;
    jamtis_hash8(domain_separator, encryption_key.bytes, sizeof(rct::key), addr_tag_enc.bytes);

    return addr_tag_enc;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
address_tag_t address_index_to_tag(const address_index_t j,
    const address_tag_MAC_t mac)
{
    address_index_t j_canonical{address_index_to_canonical(j)};

    // addr_tag = j_canonical || MAC
    address_tag_t addr_tag;
    memcpy(addr_tag.bytes, &j_canonical, ADDRESS_INDEX_BYTES);  //canonical j is little-endian
    memcpy(addr_tag.bytes + ADDRESS_INDEX_BYTES, &mac, ADDRESS_TAG_MAC_BYTES);

    return addr_tag;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t tag_to_address_index(const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out)
{
    // addr_tag -> {j_canonical, MAC}
    address_index_t j_canonical;
    memcpy(&j_canonical, addr_tag.bytes, ADDRESS_INDEX_BYTES);
    memcpy(&mac_out, addr_tag.bytes + ADDRESS_INDEX_BYTES, ADDRESS_TAG_MAC_BYTES);

    // j = system_endian(j_canonical)
    return address_index_from_canonical(j_canonical);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t make_address_tag(const BLOWFISH_CTX &blowfish_context,
    const address_index_t j,
    const address_tag_MAC_t mac)
{
    // concatenate index and MAC
    address_tag_t addr_tag{address_index_to_tag(j, mac)};

    // paste the concatenated packet into a Blowfish-compatible format
    Blowfish_LR addr_tag_formatted;
    memcpy(&addr_tag_formatted, addr_tag.bytes, sizeof(address_tag_t));

    // encrypt the packet
    Blowfish_Encrypt(&blowfish_context, &(addr_tag_formatted.L), &(addr_tag_formatted.R));

    // paste back into the address tag
    memcpy(addr_tag.bytes, &addr_tag_formatted, sizeof(address_tag_t));

    return addr_tag;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t make_address_tag_with_key(const rct::key &cipher_key,
    const address_index_t j,
    const address_tag_MAC_t mac)
{
    // prepare to encrypt the index and MAC
    BLOWFISH_CTX blowfish_context;  //TODO: must be wrapped in a wiper
    Blowfish_Init(&blowfish_context, cipher_key.bytes, sizeof(rct::key));

    // encrypt it
    return make_address_tag(blowfish_context, j, mac);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_MAC_t try_get_address_index(const BLOWFISH_CTX &blowfish_context,
    const address_tag_t addr_tag,
    address_index_t &j_out)
{
    // paste the tag into a Blowfish-compatible format
    Blowfish_LR addr_tag_formatted;
    memcpy(&addr_tag_formatted, addr_tag.bytes, sizeof(address_tag_t));

    // decrypt the tag
    Blowfish_Decrypt(&blowfish_context, &(addr_tag_formatted.L), &(addr_tag_formatted.R));

    // paste back into the address tag
    address_tag_t addr_tag_decrypted;
    memcpy(addr_tag_decrypted.bytes, &addr_tag_formatted, sizeof(address_tag_t));

    // convert to {j, MAC}
    address_tag_MAC_t mac;
    j_out = tag_to_address_index(addr_tag_decrypted, mac);

    return mac;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_MAC_t try_get_address_index_with_key(const rct::key &cipher_key,
    const address_tag_t addr_tag,
    address_index_t &j_out)
{
    // prepare to decrypt the tag
    BLOWFISH_CTX blowfish_context;  //TODO: must be wrapped in a wiper
    Blowfish_Init(&blowfish_context, cipher_key.bytes, sizeof(rct::key));

    // decrypt it
    return try_get_address_index(blowfish_context, addr_tag, j_out);
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_address_tag_t make_encrypted_address_tag(const rct::key &encryption_key,
    const address_tag_t addr_tag)
{
    // addr_tag_tag_enc = addr_tag XOR_8 encryption_secret
    return addr_tag ^ get_encrypted_address_tag_secret(encryption_key);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t get_decrypted_address_tag(const rct::key &encryption_key,
    const encrypted_address_tag_t addr_tag_tag_enc)
{
    // addr_tag = addr_tag_tag_enc XOR_8 encryption_secret
    return addr_tag_tag_enc ^ get_encrypted_address_tag_secret(encryption_key);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
