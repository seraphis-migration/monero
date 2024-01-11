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
#include "ringct/rctOps.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_wallet/encrypted_file.h"

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace seraphis_wallet
{
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(JamtisKeys &&keys, const crypto::chacha_key &key) :
    m_keys{keys},
    m_encrypted{false},
    m_encryption_iv{}
{
    encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(JamtisKeys &&keys, bool encrypted, const crypto::chacha_iv encryption_iv) :
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
    JamtisKeys recovered_keys{};
    recover_jamtis_keys(ser_keys, recovered_keys);

    // 4. check if keys are valid and move to m_keys if so
    CHECK_AND_ASSERT_THROW_MES(jamtis_keys_valid(recovered_keys, chacha_key), "load_from_keys_file: failed validating jamtis keys.");
    m_keys = std::move(recovered_keys);

    // 5. encrypt keys in memory
    encrypt(chacha_key);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::jamtis_keys_valid(const JamtisKeys &keys, const crypto::chacha_key &chacha_key)
{
    // 1. make test_keys = keys
    JamtisKeys test_keys{keys};

    // 2. derive keys
    switch (get_wallet_type())
    {
        case WalletType::Master:
        {
            sp::jamtis::make_jamtis_unlockamounts_key(test_keys.k_vb, test_keys.xk_ua);
            sp::jamtis::make_jamtis_findreceived_key(test_keys.k_vb, test_keys.xk_fr);
            sp::jamtis::make_jamtis_generateaddress_secret(test_keys.k_vb, test_keys.s_ga);
            sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
            sp::make_seraphis_spendkey(test_keys.k_vb, test_keys.k_m, test_keys.K_1_base);
            sp::jamtis::make_jamtis_unlockamounts_pubkey(test_keys.xk_ua, test_keys.xK_ua);
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::ViewOnly:
        {
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::ViewBalance:
        {
            sp::jamtis::make_jamtis_findreceived_key(test_keys.k_vb, test_keys.xk_fr);
            break;
        }
        default:
        {
            return false;
            break;
        }
    }

    // 3. check if derived keys are correct
    return test_keys == keys;
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
    m_keys.encrypt(chacha_key, m_encryption_iv);

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
    m_keys.decrypt(chacha_key, m_encryption_iv);

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
bool KeyContainer::write_all(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys ser_keys = {
        .k_m      = m_keys.k_m,
        .k_vb     = m_keys.k_vb,
        .xk_ua    = m_keys.xk_ua,
        .xk_fr    = m_keys.xk_fr,
        .s_ga     = m_keys.s_ga,
        .s_ct     = m_keys.s_ct,
        .K_1_base = m_keys.K_1_base,
        .xK_ua    = m_keys.xK_ua,
        .xK_fr    = m_keys.xK_fr,
    };

    // 3. encrypt keys if they are decrypted
    if (!m_encrypted)
        encrypt(chacha_key);

    // 4. write serializable to file
    return write_encrypted_file(path, chacha_key, ser_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_only(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys view_only_keys = {
        .k_m      = {},
        .k_vb     = {},
        .xk_ua    = {},
        .xk_fr    = m_keys.xk_fr,
        .s_ga     = {},
        .s_ct     = {},
        .K_1_base = {},
        .xK_ua    = m_keys.xK_ua,
        .xK_fr    = m_keys.xK_fr,
    };

    // 3. encrypt keys if they are decrypted
    if (!m_encrypted)
        encrypt(chacha_key);

    // 4. write serializable to file
    return write_encrypted_file(path, chacha_key, view_only_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_balance(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys view_balance{
        .k_m      = {},
        .k_vb     = m_keys.k_vb,
        .xk_ua    = {},
        .xk_fr    = m_keys.xk_fr,
        .s_ga     = {},
        .s_ct     = {},
        .K_1_base = {},
        .xK_ua    = m_keys.xK_ua,
        .xK_fr    = m_keys.xK_fr,
    };

    // 3. encrypt keys if they are decrypted
    if (!m_encrypted)
        encrypt(chacha_key);

    // 4. write serializable to file
    return write_encrypted_file(path, chacha_key, view_balance);
}
//-------------------------------------------------------------------------------------------------------------------
WalletType KeyContainer::get_wallet_type()
{
    // 1. check which keys are present
    if (m_keys.k_m == rct::rct2sk(rct::zero()))
    {
        if (m_keys.k_vb == rct::rct2sk(rct::zero()))
            return WalletType::ViewOnly;
        else
            return WalletType::ViewBalance;
    }
    return WalletType::Master;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::make_serializable_jamtis_keys(ser_JamtisKeys &serializable_keys)
{
    serializable_keys.k_m      = m_keys.k_m;
    serializable_keys.k_vb     = m_keys.k_vb;
    serializable_keys.xk_ua    = m_keys.xk_ua;
    serializable_keys.xk_fr    = m_keys.xk_fr;
    serializable_keys.s_ga     = m_keys.s_ga;
    serializable_keys.s_ct     = m_keys.s_ct;
    serializable_keys.K_1_base = m_keys.K_1_base;
    serializable_keys.xK_ua    = m_keys.xK_ua;
    serializable_keys.xK_fr    = m_keys.xK_fr;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::recover_jamtis_keys(const ser_JamtisKeys &ser_keys, JamtisKeys &keys_out)
{
    keys_out.k_m      = ser_keys.k_m;
    keys_out.k_vb     = ser_keys.k_vb;
    keys_out.xk_ua    = ser_keys.xk_ua;
    keys_out.xk_fr    = ser_keys.xk_fr;
    keys_out.s_ga     = ser_keys.s_ga;
    keys_out.s_ct     = ser_keys.s_ct;
    keys_out.K_1_base = ser_keys.K_1_base;
    keys_out.xK_ua    = ser_keys.xK_ua;
    keys_out.xK_fr    = ser_keys.xK_fr;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::compare_keys(KeyContainer &other, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (other.m_encrypted)
        other.decrypt(chacha_key);

    // 2. decrypt if encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    bool r = other.m_keys.k_m == m_keys.k_m && other.m_keys.k_vb == m_keys.k_vb && other.m_keys.xk_ua == m_keys.xk_ua &&
             other.m_keys.xk_fr == m_keys.xk_fr && other.m_keys.s_ga == m_keys.s_ga &&
             other.m_keys.s_ct == m_keys.s_ct && other.m_keys.K_1_base == m_keys.K_1_base &&
             other.m_keys.xK_ua == m_keys.xK_ua && other.m_keys.xK_fr == m_keys.xK_fr;

    // 3. encrypt in memory
    if (!other.m_encrypted)
        other.encrypt(chacha_key);

    // 4. encrypt in memory
    if (!m_encrypted)
        encrypt(chacha_key);

    // 5. return result of comparison
    return r;
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
    m_container.encrypt(key);
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
