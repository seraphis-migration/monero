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

// Address tag handling for Jamtis addresses


#pragma once

//local headers
extern "C"
{
#include "crypto/oaes_lib.h"
#include "crypto/blowfish.h"
}
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

struct jamtis_address_tag_cipher_context
{
public:
//constructors
    /// normal constructor
    jamtis_address_tag_cipher_context(const rct::key &cipher_key)
    {
        //m_aes_context = reinterpret_cast<oaes_ctx*>(oaes_alloc());
        /*
        oaes_set_option(cipher_context_out.m_aes_context);


        OAES_API OAES_RET oaes_set_option( OAES_CTX * ctx,
                OAES_OPTION option, const void * value );

        OAES_RET oaes_key_import( OAES_CTX * ctx,
            const uint8_t * data, size_t data_len )
        */
        Blowfish_Init(&m_blowfish_context, cipher_key.bytes, sizeof(rct::key));
    }

    /// disable copy/move (this is a scoped manager)
    jamtis_address_tag_cipher_context& operator=(jamtis_address_tag_cipher_context&&) = delete;

//destructor
    ~jamtis_address_tag_cipher_context()
    {
        //oaes_free(reinterpret_cast<void**>(&m_aes_context));
        memwipe(&m_blowfish_context, sizeof(BLOWFISH_CTX));
    }

//member functions
    address_tag_t cipher(const address_index_t j, const address_tag_MAC_t mac) const;
    address_index_t decipher(address_tag_t addr_tag, address_tag_MAC_t &mac_out) const;

//member variables
private:
    //oaes_ctx *m_aes_context;
    BLOWFISH_CTX m_blowfish_context;
};

/// convert {j, mac} to/from an address tag byte-representation
address_tag_t address_index_to_tag(const address_index_t j,
    const address_tag_MAC_t mac);
address_index_t address_tag_to_index(const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out);

/// cipher[k](j || addr_tag_MAC) -> addr_tag
address_tag_t cipher_address_index_with_context(const jamtis_address_tag_cipher_context &cipher_context,
    const address_index_t j,
    const address_tag_MAC_t mac);
address_tag_t cipher_address_index(const rct::key &cipher_key,
    const address_index_t j,
    const address_tag_MAC_t mac);

/// cipher_decrypt[k](addr_tag) -> {j, addr_tag_MAC}
address_index_t decipher_address_index_with_context(const jamtis_address_tag_cipher_context &cipher_context,
    address_tag_t addr_tag,
    address_tag_MAC_t &mac_out);
address_index_t decipher_address_index(const rct::key &cipher_key,
    const address_tag_t addr_tag,
    address_tag_MAC_t &mac_out);

/// addr_tag_enc = addr_tag XOR addr_tag_enc_secret
encrypted_address_tag_t encrypt_address_tag(const rct::key &encryption_key,
    const address_tag_t addr_tag);

/// addr_tag = addr_tag_enc XOR addr_tag_enc_secret
address_tag_t decrypt_address_tag(const rct::key &encryption_key,
    const encrypted_address_tag_t addr_tag_enc);

/// generate a random tag
void gen_address_tag(address_tag_t &addr_tag_inout);

} //namespace jamtis
} //namespace sp
