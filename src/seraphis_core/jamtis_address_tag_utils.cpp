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

//paired header
#include "jamtis_address_tag_utils.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
extern "C"
{
#include "crypto/blake2b.h"
#include "crypto/twofish.h"
}
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "span.h"

//third party headers

//standard headers


namespace sp
{
namespace jamtis
{
/// secret for encrypting address tags
using encrypted_address_tag_secret_t = encrypted_address_tag_t;
static_assert(sizeof(encrypted_address_tag_secret_t) == sizeof(address_tag_t), "");

/// block size
constexpr std::size_t TWOFISH_BLOCK_SIZE{16};

//-------------------------------------------------------------------------------------------------------------------
// encryption_secret = truncate_to_addr_tag_size(H_32(q, Ko))
//-------------------------------------------------------------------------------------------------------------------
static encrypted_address_tag_secret_t get_encrypted_address_tag_secret(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_address_tag_secret_t) <= 32, "");

    // temp_encryption_secret = H_32(q, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("Ko", onetime_address);

    rct::key temp_encryption_secret;
    sp_hash_to_32(transcript.data(), transcript.size(), temp_encryption_secret.bytes);

    // truncate to desired size of the secret
    encrypted_address_tag_secret_t encryption_secret;
    memcpy(encryption_secret.bytes, temp_encryption_secret.bytes, sizeof(encrypted_address_tag_secret_t));

    return encryption_secret;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static address_tag_hint_t get_address_tag_hint(const crypto::secret_key &cipher_key,
    const address_index_t &encrypted_address_index)
{
    static_assert(sizeof(address_tag_hint_t) == 2, "");
    static_assert(sizeof(config::TRANSCRIPT_PREFIX) != 0, "");
    static_assert(sizeof(config::HASH_KEY_JAMTIS_ADDRESS_TAG_HINT) != 0, "");

    // assemble hash contents: prefix || 'domain-sep' || k || cipher[k](j)
    // note: use a raw C-style struct here instead of SpKDFTranscript for maximal performance (the string produced is
    //       equivalent to what you'd get from SpKDFTranscript)
    // note2: '-1' removes the null terminator
    struct hash_context_t {
        unsigned char prefix[sizeof(config::TRANSCRIPT_PREFIX) - 1];
        unsigned char domain_separator[sizeof(config::HASH_KEY_JAMTIS_ADDRESS_TAG_HINT) - 1];
        rct::key cipher_key;  //not crypto::secret_key, which has significant construction cost
        address_index_t enc_j;
    } hash_context;
    static_assert(!epee::has_padding<hash_context_t>(), "");

    memcpy(hash_context.prefix, config::TRANSCRIPT_PREFIX, sizeof(config::TRANSCRIPT_PREFIX) - 1);
    memcpy(hash_context.domain_separator,
        config::HASH_KEY_JAMTIS_ADDRESS_TAG_HINT,
        sizeof(config::HASH_KEY_JAMTIS_ADDRESS_TAG_HINT) - 1);
    hash_context.cipher_key = rct::sk2rct(cipher_key);
    hash_context.enc_j = encrypted_address_index;

    // address_tag_hint = H_2(k, cipher[k](j))
    address_tag_hint_t address_tag_hint;
    sp_hash_to_2(&hash_context, sizeof(hash_context), address_tag_hint.bytes);

    // clean up cipher key bytes
    memwipe(hash_context.cipher_key.bytes, 32);

    return address_tag_hint;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
jamtis_address_tag_cipher_context::jamtis_address_tag_cipher_context(const crypto::secret_key &cipher_key)
{
    // cache the cipher key
    m_cipher_key = cipher_key;

    // prepare the Twofish key
    Twofish_initialise();
    Twofish_prepare_key(to_bytes(cipher_key), sizeof(rct::key), &(m_twofish_key));
}
//-------------------------------------------------------------------------------------------------------------------
jamtis_address_tag_cipher_context::~jamtis_address_tag_cipher_context()
{
    memwipe(&m_twofish_key, sizeof(Twofish_key));
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t jamtis_address_tag_cipher_context::cipher(const address_index_t &j) const
{
    // address tag = cipher[k](j) || H_2(k, cipher[k](j))

    // expect address index to fit in one Twofish block (16 bytes)
    static_assert(sizeof(address_index_t) == TWOFISH_BLOCK_SIZE, "");

    // prepare ciphered index
    address_index_t encrypted_j{j};

    // encrypt the address index
    Twofish_encrypt_block(&m_twofish_key, encrypted_j.bytes, encrypted_j.bytes);

    // make the address tag hint and complete the address tag
    return make_address_tag(encrypted_j, get_address_tag_hint(m_cipher_key, encrypted_j));
}
//-------------------------------------------------------------------------------------------------------------------
bool jamtis_address_tag_cipher_context::try_decipher(const address_tag_t &addr_tag, address_index_t &j_out) const
{
    static_assert(sizeof(address_index_t) == TWOFISH_BLOCK_SIZE, "");
    static_assert(sizeof(address_index_t) + sizeof(address_tag_hint_t) == sizeof(address_tag_t), "");

    // extract the encrypted index
    memcpy(j_out.bytes, addr_tag.bytes, sizeof(address_index_t));

    // recover the address tag hint
    const address_tag_hint_t address_tag_hint{get_address_tag_hint(m_cipher_key, j_out)};

    // check the address tag hint
    if (memcmp(addr_tag.bytes + sizeof(address_index_t), address_tag_hint.bytes, sizeof(address_tag_hint_t)) != 0)
        return false;

    // decrypt the address index
    Twofish_decrypt_block(&m_twofish_key, j_out.bytes, j_out.bytes);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index(const jamtis_address_tag_cipher_context &cipher_context, const address_index_t &j)
{
    return cipher_context.cipher(j);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index(const crypto::secret_key &cipher_key, const address_index_t &j)
{
    // prepare to cipher the index
    const jamtis_address_tag_cipher_context cipher_context{cipher_key};

    // cipher it
    return cipher_address_index(cipher_context, j);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_decipher_address_index(const jamtis_address_tag_cipher_context &cipher_context,
    const address_tag_t &addr_tag,
    address_index_t &j_out)
{
    return cipher_context.try_decipher(addr_tag, j_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_decipher_address_index(const crypto::secret_key &cipher_key,
    const address_tag_t &addr_tag,
    address_index_t &j_out)
{
    // prepare to decipher the tag
    const jamtis_address_tag_cipher_context cipher_context{cipher_key};

    // decipher it
    return try_decipher_address_index(cipher_context, addr_tag, j_out);
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_address_tag_t encrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const address_tag_t &addr_tag)
{
    static_assert(sizeof(address_tag_t) == sizeof(encrypted_address_tag_secret_t), "");

    // addr_tag_enc = addr_tag XOR encryption_secret
    return addr_tag ^ get_encrypted_address_tag_secret(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t decrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const encrypted_address_tag_t &addr_tag_enc)
{
    static_assert(sizeof(encrypted_address_tag_t) == sizeof(encrypted_address_tag_secret_t), "");

    // addr_tag = addr_tag_enc XOR encryption_secret
    return addr_tag_enc ^ get_encrypted_address_tag_secret(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void gen_address_tag(address_tag_t &addr_tag_inout)
{
    crypto::rand(sizeof(address_tag_t), reinterpret_cast<unsigned char*>(&addr_tag_inout));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
