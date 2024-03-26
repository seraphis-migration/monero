// Copyright (c) 2024, The Monero Project
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

// paired header
#include "key_container.h"

// local headers
#include "crypto/chacha.h"
#include "jamtis_keys.h"
#include "seraphis_wallet/encrypted_file.h"
#include "jamtis_keys.h"

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace seraphis_wallet
{
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(sp::jamtis::JamtisKeys &&keys, const crypto::chacha_key &key) :
    m_keys{keys},
    m_encrypted{false},
    m_encryption_iv{}
{
    encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(sp::jamtis::JamtisKeys &&keys, bool encrypted, const crypto::chacha_iv encryption_iv) :
    m_keys{keys},
    m_encrypted{encrypted},
    m_encryption_iv{encryption_iv}
{
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::load_from_keys_file(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. define serializable
    ser_JamtisKeys ser_keys;

    // 2. get the keys in the encrypted file into the serializable
    CHECK_AND_ASSERT_THROW_MES(
        read_encrypted_file(path, chacha_key, ser_keys), "load_from_keys_file: failed reading encrypted file.");

    // 3. recover jamtis keys 
    sp::jamtis::JamtisKeys recovered_keys{};
    recover_jamtis_keys(ser_keys, recovered_keys);

    // 4. check if keys are valid and move to m_keys if so
    CHECK_AND_ASSERT_THROW_MES(jamtis_keys_valid(recovered_keys, chacha_key), "load_from_keys_file: failed validating jamtis keys.");
    m_keys = std::move(recovered_keys);

    // 5. encrypt keys in memory
    encrypt(chacha_key);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::jamtis_keys_valid(const sp::jamtis::JamtisKeys &keys, const crypto::chacha_key &chacha_key)
{
    // 1. copy original keys
    sp::jamtis::JamtisKeys test_keys{keys};

    // 2. derive keys
    sp::jamtis::derive_jamtis_keys(test_keys);

    // 3. check if the given keys match
    return sp::jamtis::jamtis_keys_equal(test_keys, keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::encrypt(const crypto::chacha_key &chacha_key)
{
    // 1. return false if already encrypted
    if (m_encrypted)
        return false;

    // 2. generate new iv
    m_encryption_iv = crypto::rand<crypto::chacha_iv>();

    // 3. encrypt keys with chacha_key and iv
    sp::jamtis::xor_with_key_stream(chacha_key, m_encryption_iv, m_keys);

    // 4. set encrypted flag true
    m_encrypted = true;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::decrypt(const crypto::chacha_key &chacha_key)
{
    // 1. return false if already decrypted
    if (!m_encrypted)
        return false;

    // 2. decrypt keys with chacha_key and iv
    sp::jamtis::xor_with_key_stream(chacha_key, m_encryption_iv, m_keys);

    // 3. set encrypted flag false
    m_encrypted = false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::generate_keys(const crypto::chacha_key &chacha_key)
{
    // 1. generate new keys and store to m_keys
    make_jamtis_keys(m_keys);

    // 2. encrypt keys if they are decrypted
    if (!m_encrypted)
        encrypt(chacha_key);
}
//-------------------------------------------------------------------------------------------------------------------
sp::jamtis::JamtisKeys &KeyContainer::get_keys(const crypto::chacha_key &chacha_key) {
    if (m_encrypted)
        decrypt(chacha_key);

    return m_keys;
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard KeyContainer::get_keys_guard(const crypto::chacha_key &chacha_key) {
    return KeyGuard{*this, chacha_key};
}
//-------------------------------------------------------------------------------------------------------------------
WalletType KeyContainer::get_wallet_type()
{
    return sp::jamtis::get_wallet_type(m_keys);
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::make_serializable_jamtis_keys(ser_JamtisKeys &serializable_keys)
{
    serializable_keys.k_m      = m_keys.k_m;
    serializable_keys.k_vb     = m_keys.k_vb;
    serializable_keys.d_vr    = m_keys.d_vr;
    serializable_keys.d_fa    = m_keys.d_fa;
    serializable_keys.s_ga     = m_keys.s_ga;
    serializable_keys.s_ct     = m_keys.s_ct;
    serializable_keys.K_s_base = m_keys.K_s_base;
    serializable_keys.D_vr    = m_keys.D_vr;
    serializable_keys.D_fa    = m_keys.D_fa;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::recover_jamtis_keys(const ser_JamtisKeys &ser_keys, sp::jamtis::JamtisKeys &keys_out)
{
    keys_out.k_m      = ser_keys.k_m;
    keys_out.k_vb     = ser_keys.k_vb;
    keys_out.d_vr    = ser_keys.d_vr;
    keys_out.d_fa    = ser_keys.d_fa;
    keys_out.s_ga     = ser_keys.s_ga;
    keys_out.s_ct     = ser_keys.s_ct;
    keys_out.K_s_base = ser_keys.K_s_base;
    keys_out.D_vr    = ser_keys.D_vr;
    keys_out.D_fa    = ser_keys.D_fa;
}
//-------------------------------------------------------------------------------------------------------------------

// KeyGuard
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(const KeyGuard &other) :
    m_ref{other.m_ref + 1},
    m_container{other.m_container},
    m_key{other.m_key}
{
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(KeyContainer &container, const crypto::chacha_key &key) :
    m_container{container},
    m_ref{1},
    m_key{key}
{
    m_container.decrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::~KeyGuard()
{
    if (m_ref == 1)
    {
        m_container.encrypt(m_key);
    }
}
//-------------------------------------------------------------------------------------------------------------------
}  // namespace seraphis_wallet
