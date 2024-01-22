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

////
// Jamtis keys
//
// reference: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
///

#pragma once

//local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"

//third party headers

//standard headers

//forward declarations
namespace seraphis_wallet {

enum class WalletType;

}

namespace sp
{
namespace jamtis
{

struct JamtisKeys
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
};

/// make a set of jamtis keys
void make_jamtis_keys(JamtisKeys &keys_out);
/// derive a set of jamtis keys from existing non-zero entries
void derive_jamtis_keys(JamtisKeys &keys);
/// make a jamtis address for the given privkeys and address index
void make_address_for_user(const JamtisKeys &user_keys,
    const address_index_t &j,
    JamtisDestinationV1 &user_address_out);
/// make a random jamtis address for the given privkeys
void make_random_address_for_user(const JamtisKeys &user_keys,
    JamtisDestinationV1 &user_address_out);
/// encrypt a set of jamtis keys in-place
void xor_with_key_stream(const crypto::chacha_key &chacha_key,
    const crypto::chacha_iv chacha_iv,
    JamtisKeys &keys);

/// get keys' wallet type from the existing keys
seraphis_wallet::WalletType get_wallet_type(const JamtisKeys &keys);

/// compare two key structures; both should be in the same decrypted/encrypted state
bool jamtis_keys_equal(const JamtisKeys &keys, const JamtisKeys &other);

} //namespace jamtis
} //namespace sp
