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

// Address tag handling for Jamtis addresses.

#pragma once

//local headers
extern "C"
{
#include "crypto/twofish.h"
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

/// cipher context for making address tags
struct jamtis_address_tag_cipher_context final
{
public:
//constructors
    /// normal constructor
    jamtis_address_tag_cipher_context(const crypto::secret_key &cipher_key);

//destructor
    ~jamtis_address_tag_cipher_context();

//overloaded operators
    /// disable copy/move (this is a scoped manager)
    jamtis_address_tag_cipher_context& operator=(jamtis_address_tag_cipher_context&&) = delete;

//member functions
    address_tag_t cipher(const address_index_t &j) const;
    bool try_decipher(const address_tag_t &addr_tag, address_index_t &j_out) const;

//member variables
private:
    crypto::secret_key m_cipher_key;
    Twofish_key m_twofish_key;
};

/// addr_tag = cipher[k](j) || H_2(k, cipher[k](j))
address_tag_t cipher_address_index(const jamtis_address_tag_cipher_context &cipher_context, const address_index_t &j);
address_tag_t cipher_address_index(const crypto::secret_key &cipher_key, const address_index_t &j);

/// try to get j from an address tag
bool try_decipher_address_index(const jamtis_address_tag_cipher_context &cipher_context,
    const address_tag_t &addr_tag,
    address_index_t &j_out);
bool try_decipher_address_index(const crypto::secret_key &cipher_key,
    const address_tag_t &addr_tag,
    address_index_t &j_out);

/// addr_tag_enc = addr_tag XOR H_32(q, Ko)
encrypted_address_tag_t encrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const address_tag_t &addr_tag);

/// addr_tag = addr_tag_enc XOR H_32(q, Ko)
address_tag_t decrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const encrypted_address_tag_t &addr_tag_enc);

/// generate a random tag
void gen_address_tag(address_tag_t &addr_tag_inout);

} //namespace jamtis
} //namespace sp
