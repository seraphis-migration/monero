// Copyright (c) 2025, The Monero Project
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
#include "misc_wallet_utils.h"

//local headers
#include "crypto/chacha.h"
#include "wallet_errors.h"

//third party headers

//standard headers
#include <memory>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.misc"

namespace tools
{
namespace wallet
{
//-------------------------------------------------------------------------------------------------------------------
std::string encrypt_with_ec_key(const char * const plaintext,
    const std::size_t plaintext_len,
    const crypto::secret_key &skey,
    const bool authenticated,
    const std::uint64_t kdf_rounds)
{
    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, kdf_rounds);
    std::string ciphertext;
    crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
    ciphertext.resize(plaintext_len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
    crypto::chacha20(plaintext, plaintext_len, key, iv, &ciphertext[sizeof(iv)]);
    memcpy(&ciphertext[0], &iv, sizeof(iv));
    if (authenticated)
    {
        crypto::hash hash;
        crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(crypto::signature), hash);
        crypto::public_key pkey;
        crypto::secret_key_to_public_key(skey, pkey);
        crypto::signature signature;
        crypto::generate_signature(hash, pkey, skey, signature);
        memcpy(&ciphertext[ciphertext.size() - sizeof(crypto::signature)], &signature, sizeof(signature));
    }
    return ciphertext;
}
//-------------------------------------------------------------------------------------------------------------------
epee::wipeable_string decrypt_with_ec_key(const char * const ciphertext,
    const std::size_t ciphertext_len,
    const crypto::secret_key &skey,
    const bool authenticated,
    const std::uint64_t kdf_rounds)
{
    const size_t prefix_size = sizeof(crypto::chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
    THROW_WALLET_EXCEPTION_IF(ciphertext_len < prefix_size,
        error::wallet_internal_error, "Unexpected ciphertext size");

    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, kdf_rounds);
    const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
    if (authenticated)
    {
        crypto::hash hash;
        crypto::cn_fast_hash(ciphertext, ciphertext_len - sizeof(crypto::signature), hash);
        crypto::public_key pkey;
        crypto::secret_key_to_public_key(skey, pkey);
        crypto::signature signature;
        memcpy(&signature, &ciphertext[ciphertext_len - sizeof(crypto::signature)], sizeof(signature));
        THROW_WALLET_EXCEPTION_IF(!crypto::check_signature(hash, pkey, signature),
        error::wallet_internal_error, "Failed to authenticate ciphertext");
    }
    std::unique_ptr<char[]> buffer{new char[ciphertext_len - prefix_size]};
    auto wiper = epee::misc_utils::create_scope_leave_handler([&]() {
        memwipe(buffer.get(), ciphertext_len - prefix_size); });
    crypto::chacha20(ciphertext + sizeof(iv), ciphertext_len - prefix_size, key, iv, buffer.get());
    return epee::wipeable_string(buffer.get(), ciphertext_len - prefix_size);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace wallet
} //namespace tools
