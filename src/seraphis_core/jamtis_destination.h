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

// A Jamtis 'destination', i.e. an address that can receive funds.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

////
// JamtisDestinationV1
// - a user address, aka a 'destination for funds'
///
struct JamtisDestinationV1 final
{
    /// K_1 = k^j_g G + k^j_x X + k^j_u U + K_s   (address spend key)
    rct::key addr_K1;
    /// xK_2 = xk^j_a xK_fr                       (address view key)
    crypto::x25519_pubkey addr_K2;
    /// xK_3 = xk^j_a xK_ua                       (DH base key)
    crypto::x25519_pubkey addr_K3;
    /// addr_tag
    address_tag_t addr_tag;
};

/// equivalence test (false on partial equality)
bool operator==(const JamtisDestinationV1 &a, const JamtisDestinationV1 &b);

/**
* brief: make_jamtis_destination_v1 - make a destination address
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: unlockamounts_pubkey - xK_ua = xk_ua xG
* param: findreceived_pubkey - xK_fr = xk_fr xk_ua xG
* param: s_generate_address - s_ga
* param: j - address_index
* outparam: destination_out - the full address, with address tag
*/
void make_jamtis_destination_v1(const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &unlockamounts_pubkey,
    const crypto::x25519_pubkey &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    JamtisDestinationV1 &destination_out);
/**
* brief: try_get_jamtis_index_from_destination_v1 - check if a destination can be recreated, then return its address index
*   - note: partial-recreation of a destination will return FALSE
* param: destination - destination address to recreate
* param: spend_pubkey - K_s
* param: unlockamounts_pubkey - xK_ua = xk_ua xG
* param: findreceived_pubkey - xK_fr = xk_fr xk_ua xG
* param: s_generate_address - s_ga
* outparam: j_out - address index (if successful)
* return: true if the destination can be recreated
*/
bool try_get_jamtis_index_from_destination_v1(const JamtisDestinationV1 &destination,
    const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &unlockamounts_pubkey,
    const crypto::x25519_pubkey &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    address_index_t &j_out);
/**
* brief: gen_jamtis_destination_v1 - generate a random destination
* return: a random destination
*/
JamtisDestinationV1 gen_jamtis_destination_v1();

} //namespace jamtis
} //namespace sp
