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

#pragma once

// local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "serialization/crypto.h"
#include "seraphis_wallet/jamtis_keys.h"
#include "serialization/serialization.h"

// third party headers

// standard headers
#include <string>

// forward declarations

struct ser_JamtisKeys
{
    crypto::secret_key k_m;           //master
    crypto::secret_key k_vb;          //view-balance
    crypto::x25519_secret_key d_vr;   //view-received
    crypto::x25519_secret_key d_fa;   //filter-assist
    crypto::secret_key s_ga;          //generate-address
    crypto::secret_key s_ct;          //cipher-tag
    rct::key K_s_base;                //jamtis spend base    = k_vb X + k_m U
    crypto::x25519_pubkey D_vr;       //view-received pubkey = d_vr D_base
    crypto::x25519_pubkey D_fa;       //filter-assist pubkey = d_fa D_base
    crypto::x25519_pubkey D_base;     //exchange-base pubkey = d_vr xG

    BEGIN_SERIALIZE()
        FIELD(k_m)
        FIELD(k_vb)
        FIELD(d_vr)
        FIELD(d_fa)
        FIELD(s_ga)
        FIELD(s_ct)
        FIELD(K_s_base)
        FIELD(D_vr)
        FIELD(D_fa)
        FIELD(D_base)
    END_SERIALIZE()
};

BLOB_SERIALIZER(ser_JamtisKeys);

namespace seraphis_wallet
{

// forward declaration
class KeyGuard;

enum class WalletType
{
    Empty,
    FilterAssist,
    AddressGenerator,
    FilterAssistAndAddressGen,
    PaymentValidator,
    ViewAll,
    Master,
};

/// KeyContainer
// - it handles (store, load, etc) the private keys.
///
class KeyContainer
{
public:
    KeyContainer(sp::jamtis::JamtisKeys &&keys, const crypto::chacha_key &key);

    KeyContainer() : m_keys{}, m_encryption_iv{}, m_encrypted{false} {}

    KeyContainer(sp::jamtis::JamtisKeys &&keys,
        bool encrypted,
        const crypto::chacha_iv encryption_iv);

    // member functions

    /// verify if is encrypted
    bool is_encrypted() { return m_encrypted; }

    /// load keys from a file and ensure their validity
    bool load_from_keys_file(const std::string &path, const crypto::chacha_key &chacha_key);

    /// check if keys are valid 
    bool jamtis_keys_valid(const sp::jamtis::JamtisKeys &keys, const crypto::chacha_key &chacha_key);

    sp::jamtis::JamtisKeys &get_keys(const crypto::chacha_key &chacha_key);

    /// get keys, protected by a guard
    KeyGuard get_keys_guard(const crypto::chacha_key &chacha_key);

    /// encrypt the keys in-memory
    bool encrypt(const crypto::chacha_key &chacha_key);

    /// decrypt the keys in-memory
    bool decrypt(const crypto::chacha_key &chacha_key);

    /// generate new keys
    void generate_keys(const crypto::chacha_key &chacha_key);

    /// get the wallet type of the loaded keys
    WalletType get_wallet_type();

    /// make jamtis_keys serializable
    void make_serializable_jamtis_keys(ser_JamtisKeys &serializable_keys);

    /// recover keys from serializable
    void recover_jamtis_keys(const ser_JamtisKeys &ser_keys, sp::jamtis::JamtisKeys &keys_out);

    /// compare the keys of two containers that have the same chacha_key
    bool compare_keys(KeyContainer &other, const crypto::chacha_key &chacha_key);

private:
    /// initialization vector
    crypto::chacha_iv m_encryption_iv;

    /// struct that contains the keys so that
    /// they wouldn't get swapped out of memory
    epee::mlocked<sp::jamtis::JamtisKeys> m_keys;

    /// true if keys are encrypted in memory
    bool m_encrypted;
};

class KeyGuard
{
public:
    KeyGuard(KeyContainer &, const crypto::chacha_key &);

    KeyGuard(const KeyGuard &other);

    ~KeyGuard();

private:
    const crypto::chacha_key &m_key;
    int m_ref;
    KeyContainer &m_container;
};

} // namespace seraphis_wallet
