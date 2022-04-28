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
#include "jamtis_address_tag_utils.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
extern "C"
{
#include "crypto/blowfish.h"
}
#include "int-util.h"
#include "jamtis_hash_functions.h"
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers


namespace sp
{
namespace jamtis
{
/// secret for encrypting address tags
using encrypted_address_tag_secret_t = encrypted_address_tag_t;
static_assert(sizeof(encrypted_address_tag_secret_t) == sizeof(address_tag_t), "");

/// helper for encrypting/decrypting with the Blowfish block cipher
struct Blowfish_LR_wrapper
{
    unsigned char *bytes_ref;

    std::uint32_t* L_addr() { return reinterpret_cast<std::uint32_t*>(bytes_ref); }
    std::uint32_t* R_addr() { return reinterpret_cast<std::uint32_t*>(bytes_ref + 4); }
};

//-------------------------------------------------------------------------------------------------------------------
// little-endian swaps
//-------------------------------------------------------------------------------------------------------------------
static unsigned char swap_le(const unsigned char x)
{
    return x;
}
static std::uint16_t swap_le(const std::uint16_t x)
{
    return SWAP16LE(x);
}
static std::uint32_t swap_le(const std::uint32_t x)
{
    return SWAP32LE(x);
}
static std::uint64_t swap_le(const std::uint64_t x)
{
    return SWAP64LE(x);
}
//-------------------------------------------------------------------------------------------------------------------
// j_canonical = little_endian(j)
//-------------------------------------------------------------------------------------------------------------------
static address_index_t address_index_to_canonical(address_index_t j)
{
    return swap_le(j);
}
//-------------------------------------------------------------------------------------------------------------------
// j = system_endian(j_canonical)
//-------------------------------------------------------------------------------------------------------------------
static address_index_t address_index_from_canonical(address_index_t j_canonical)
{
    // on big-endian systems, this makes the result big-endian (since it always starts as little-endian)
    return swap_le(j_canonical);
}
//-------------------------------------------------------------------------------------------------------------------
// mac_canonical = little_endian(mac)
//-------------------------------------------------------------------------------------------------------------------
static address_tag_MAC_t mac_to_canonical(address_tag_MAC_t mac)
{
    return swap_le(mac);
}
//-------------------------------------------------------------------------------------------------------------------
// mac = system_endian(mac_canonical)
//-------------------------------------------------------------------------------------------------------------------
static address_tag_MAC_t mac_from_canonical(address_tag_MAC_t mac_canonical)
{
    // on big-endian systems, this makes the result big-endian (since it always starts as little-endian)
    return swap_le(mac_canonical);
}
//-------------------------------------------------------------------------------------------------------------------
// encryption_secret = H_8(encryption_key)
//-------------------------------------------------------------------------------------------------------------------
static encrypted_address_tag_secret_t get_encrypted_address_tag_secret(const rct::key &encryption_key)
{
    static_assert(sizeof(encrypted_address_tag_secret_t) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG};

    // encryption_secret = H_8(encryption_key)
    encrypted_address_tag_secret_t encryption_secret;
    jamtis_hash8(domain_separator, encryption_key.bytes, sizeof(rct::key), encryption_secret.bytes);

    return encryption_secret;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void jamtis_address_tag_cipher_context::set_key(const rct::key &cipher_key)
{
    Blowfish_Init(&m_blowfish_context, cipher_key.bytes, sizeof(rct::key));
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t jamtis_address_tag_cipher_context::cipher(const address_index_t j, const address_tag_MAC_t mac) const
{
    // concatenate index and MAC
    address_tag_t addr_tag{address_index_to_tag(j, mac)};

    // wrap the concatenated packet into a Blowfish-compatible format
    static_assert(sizeof(address_tag_t) == 8, "");
    Blowfish_LR_wrapper addr_tag_formatted{addr_tag.bytes};

    // encrypt the packet
    Blowfish_Encrypt(&m_blowfish_context, addr_tag_formatted.L_addr(), addr_tag_formatted.R_addr());

    return addr_tag;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t jamtis_address_tag_cipher_context::decipher(address_tag_t addr_tag, address_tag_MAC_t &mac_out) const
{
    // wrap the tag into a Blowfish-compatible format
    static_assert(sizeof(address_tag_t) == 8, "");
    Blowfish_LR_wrapper addr_tag_formatted{addr_tag.bytes};

    // decrypt the tag
    Blowfish_Decrypt(&m_blowfish_context, addr_tag_formatted.L_addr(), addr_tag_formatted.R_addr());

    // convert to {j, MAC}
    return address_tag_to_index(addr_tag, mac_out);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t address_index_to_tag(const address_index_t j,
    const address_tag_MAC_t mac)
{
    const address_index_t j_canonical{address_index_to_canonical(j)};
    const address_tag_MAC_t mac_canonical{mac_to_canonical(mac)};

    // addr_tag = j_canonical || MAC
    address_tag_t addr_tag;
    memcpy(addr_tag.bytes, &j_canonical, ADDRESS_INDEX_BYTES);  //canonical j is little-endian
    memcpy(addr_tag.bytes + ADDRESS_INDEX_BYTES, &mac_canonical, ADDRESS_TAG_MAC_BYTES);

    return addr_tag;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t address_tag_to_index(const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out)
{
    // addr_tag -> {j_canonical, MAC}
    address_index_t j_canonical{0};
    memcpy(&j_canonical, addr_tag.bytes, ADDRESS_INDEX_BYTES);
    memcpy(&mac_out, addr_tag.bytes + ADDRESS_INDEX_BYTES, ADDRESS_TAG_MAC_BYTES);

    // mac - system_endian(mac_canonical)
    mac_out = mac_from_canonical(mac_out);

    // j = system_endian(j_canonical)
    return address_index_from_canonical(j_canonical);
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_address_tag_cipher(const rct::key &cipher_key, jamtis_address_tag_cipher_context &cipher_context_out)
{
    /*
    oaes_set_option(cipher_context_out.m_aes_context);


    OAES_API OAES_RET oaes_set_option( OAES_CTX * ctx,
            OAES_OPTION option, const void * value );

    OAES_RET oaes_key_import( OAES_CTX * ctx,
        const uint8_t * data, size_t data_len )
    */
    cipher_context_out.set_key(cipher_key);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index_with_context(const jamtis_address_tag_cipher_context &cipher_context,
    const address_index_t j,
    const address_tag_MAC_t mac)
{
    return cipher_context.cipher(j, mac);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index(const rct::key &cipher_key,
    const address_index_t j,
    const address_tag_MAC_t mac)
{
    // prepare to encrypt the index and MAC
    jamtis_address_tag_cipher_context cipher_context;
    prepare_address_tag_cipher(cipher_key, cipher_context);

    // encrypt it
    return cipher_address_index_with_context(cipher_context, j, mac);
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t decipher_address_index_with_context(const jamtis_address_tag_cipher_context &cipher_context,
    address_tag_t addr_tag,
    address_tag_MAC_t &mac_out)
{
    return cipher_context.decipher(addr_tag, mac_out);
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t decipher_address_index(const rct::key &cipher_key,
    const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out)
{
    // prepare to decrypt the tag
    jamtis_address_tag_cipher_context cipher_context;
    prepare_address_tag_cipher(cipher_key, cipher_context);

    // decrypt it
    return decipher_address_index_with_context(cipher_context, addr_tag, mac_out);
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_address_tag_t encrypt_address_tag(const rct::key &encryption_key,
    const address_tag_t addr_tag)
{
    // addr_tag_enc = addr_tag XOR_8 encryption_secret
    return addr_tag ^ get_encrypted_address_tag_secret(encryption_key);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t decrypt_address_tag(const rct::key &encryption_key,
    const encrypted_address_tag_t addr_tag_enc)
{
    // addr_tag = addr_tag_enc XOR_8 encryption_secret
    return addr_tag_enc ^ get_encrypted_address_tag_secret(encryption_key);
}
//-------------------------------------------------------------------------------------------------------------------
void gen_address_tag(address_tag_t &addr_tag_inout)
{
    crypto::rand(sizeof(address_tag_t), reinterpret_cast<unsigned char*>(&addr_tag_inout));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
