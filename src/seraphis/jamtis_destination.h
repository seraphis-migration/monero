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

// A Jamtis 'destination', i.e. an address that can receive funds


#pragma once

//local headers
#include "crypto/crypto.h"
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
    /// K_1 = k^j_x X + K_s  (address spend key)
    rct::key m_addr_K1;
    /// K_2 = k^j_a K_fr     (address view key)
    rct::key m_addr_K2;
    /// K_3 = k^j_a G        (DH base key)
    rct::key m_addr_K3;
    /// addr_tag
    address_tag_t m_addr_tag;

    /// comparison operator
    bool operator==(const JamtisDestinationV1 &other) const
    {
        return (m_addr_K1 == other.m_addr_K1) &&
            (m_addr_K2 == other.m_addr_K2) &&
            (m_addr_K3 == other.m_addr_K3) &&
            (m_addr_tag == other.m_addr_tag);
    }

    /**
    * brief: gen - generate a random destination
    */
    void gen();
};

/**
* brief: make_jamtis_destination_v1 - make a destination address
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
* brief: is_destination_of_wallet - check if a destination can be recreated
*    - note: partial-recreation of a destination will return FALSE
* param: destination - destination address to recreate
* param: wallet_spend_pubkey - K_s
* param: findreceived_pubkey - K_fr = k_fr G
* param: s_generate_address - s_ga
* return: true if the destination can be recreated
*/
bool is_destination_of_wallet(const JamtisDestinationV1 &destination,
    const rct::key &wallet_spend_pubkey,
    const rct::key &findreceived_pubkey,
    const crypto::secret_key &s_generate_address);

} //namespace jamtis
} //namespace sp
