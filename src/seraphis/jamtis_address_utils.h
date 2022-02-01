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

// Core types for making enotes with Jamtis addresses
// - Jamtis is a specification for Seraphis-compatible addresses


#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_destination.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_spendkey_extension -
*   - k^j_x = H_n(Pad136(s_ga), j)
* param: s_generate_address - s_ga
* param: j - address index
* outparam: extension_out - k^j_x
*/
void make_jamtis_spendkey_extension(const crypto::secret_key s_generate_address,
    const address_index_t j,
    crypto::secret_key &extension_out);
/**
* brief: make_jamtis_address_privkey -
*   - k^j_a = H_n(Pad136(s_ga), j)
* param: s_generate_address - s_ga
* param: j - address index
* outparam: address_privkey_out - k^j_a
*/
void make_jamtis_address_privkey(const crypto::secret_key s_generate_address,
    const address_index_t j,
    crypto::secret_key &address_privkey_out);
/**
* brief: make_jamtis_address_spend_key -
*   - K_1 = k^j_x X + K_s
* param: wallet_spend_pubkey - K_s
* param: s_generate_address - s_ga
* param: j - address index
* outparam: address_spendkey_out - K_1
*/
void make_jamtis_address_spend_key(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    rct::key &address_spendkey_out);
/**
* brief: make_jamtis_destination_v1 - make a JamtisDestinationV1 (full destination address)
* param: wallet_spend_pubkey - K_s = k_vb X + k_m U
* param: findreceived_pubkey - K_fr = k_fr G
* param: s_generate_address - s_ga
* param: j - address_index
* outparam: destination_out - the full address, with address tag
*/
void make_jamtis_destination_v1(const rct::key &wallet_spend_pubkey,
    const rct::key &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    JamtisDestinationV1 &destination_out);
/**
* brief: test_jamtis_nominal_spend_key - see if a spend key is owned by this wallet
* param: wallet_spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address_index
* param: nominal_spend_key - spend key to test
* return: true if the nominal spend key matches this wallet's spend key at address index 'j'
*/
bool test_jamtis_nominal_spend_key(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    const rct::key &nominal_spend_key);

} //namespace jamtis
} //namespace sp
