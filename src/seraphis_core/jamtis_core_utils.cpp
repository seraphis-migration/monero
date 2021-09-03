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
#include "jamtis_core_utils.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "ringct/rctOps.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_unlockamounts_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &xk_unlock_amounts_out)
{
    // xk_ua = H_n_x25519[k_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_UNLOCKAMOUNTS_KEY, 0};
    sp_derive_x25519_key(to_bytes(k_view_balance), transcript.data(), transcript.size(), xk_unlock_amounts_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_unlockamounts_pubkey(const crypto::x25519_secret_key &xk_unlock_amounts,
    crypto::x25519_pubkey &unlockamounts_pubkey_out)
{
    // xK_ua = xk_ua * xG
    x25519_scmul_base(xk_unlock_amounts, unlockamounts_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_findreceived_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &xk_find_received_out)
{
    // xk_fr = H_n_x25519[k_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_FINDRECEIVED_KEY, 0};
    sp_derive_x25519_key(to_bytes(k_view_balance), transcript.data(), transcript.size(), xk_find_received_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_findreceived_pubkey(const crypto::x25519_secret_key &xk_find_received,
    const crypto::x25519_pubkey &unlockamounts_pubkey,
    crypto::x25519_pubkey &findreceived_pubkey_out)
{
    // xK_fr = xk_fr * xK_ua
    x25519_scmul_key(xk_find_received, unlockamounts_pubkey, findreceived_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_generateaddress_secret(const crypto::secret_key &k_view_balance,
    crypto::secret_key &s_generate_address_out)
{
    // s_ga = H_32[k_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_GENERATEADDRESS_SECRET, 0};
    sp_derive_secret(to_bytes(k_view_balance), transcript.data(), transcript.size(), to_bytes(s_generate_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_ciphertag_secret(const crypto::secret_key &s_generate_address,
    crypto::secret_key &s_cipher_tag_out)
{
    // s_ct = H_32[s_ga]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_CIPHERTAG_SECRET, 0};
    sp_derive_secret(to_bytes(s_generate_address), transcript.data(), transcript.size(), to_bytes(s_cipher_tag_out));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
