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

////
// Core implementation details for making Jamtis privkeys and secrets.
// - Jamtis is a specification for Seraphis-compatible addresses
//
// reference: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace jamtis
{

////
// A set of jamtis keys for mock-ups/unit testing
///
struct jamtis_mock_keys
{
    crypto::secret_key k_m;   //master
    crypto::secret_key k_vb;  //view-balance
    x25519_secret_key xk_ua;  //unlock-amounts
    x25519_secret_key xk_fr;  //find-received
    crypto::secret_key s_ga;  //generate-address
    crypto::secret_key s_ct;  //cipher-tag
    rct::key K_1_base;        //wallet spend base = k_vb X + k_m U
    x25519_pubkey xK_ua;     //unlock-amounts pubkey = xk_ua xG
    x25519_pubkey xK_fr;     //find-received pubkey = xk_fr xk_ua xG
};

/**
* brief: make_jamtis_unlockamounts_key - unlock-amounts key, for decrypting amounts and reconstructing amount commitments
*   xk_ua = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: xk_unlock_amounts_out - xk_ua
*/
void make_jamtis_unlockamounts_key(const crypto::secret_key &k_view_balance,
    x25519_secret_key &xk_unlock_amounts_out);
/**
* brief: make_jamtis_findreceived_key - find-received key, for finding enotes received by the wallet
*   - use to compute view tags and nominal spend keys
*   xk_fr = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: xk_find_received_out - xk_fr
*/
void make_jamtis_findreceived_key(const crypto::secret_key &k_view_balance,
    x25519_secret_key &xk_find_received_out);
/**
* brief: make_jamtis_generateaddress_secret - generate-address secret, for generating addresses
*   s_ga = H_32[k_vb]()
* param: k_view_balance - k_vb
* outparam: s_generate_address_out - s_ga
*/
void make_jamtis_generateaddress_secret(const crypto::secret_key &k_view_balance,
    crypto::secret_key &s_generate_address_out);
/**
* brief: make_jamtis_ciphertag_secret - cipher-tag secret, for ciphering address indices to/from address tags
*   s_ct = H_32[s_ga]()
* param: s_generate_address - s_ga
* outparam: s_cipher_tag_out - s_ct
*/
void make_jamtis_ciphertag_secret(const crypto::secret_key &s_generate_address,
    crypto::secret_key &s_cipher_tag_out);


/**
* brief: make_jamtis_mock_keys - make a set of mock jamtis keys (for mock-ups/unit testing)
* outparam: jamtis_mock_keys -
*/
void make_jamtis_mock_keys(jamtis_mock_keys &keys_out);

} //namespace jamtis
} //namespace sp
