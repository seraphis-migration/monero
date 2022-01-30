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

//paired header
#include "jamtis_destination.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void JamtisDestinationV1::gen()
{
    m_addr_K1 = rct::pkGen();
    m_addr_K2 = rct::pkGen();
    m_addr_K3 = rct::pkGen();
    m_address_index = crypto::rand_idx(ADDRESS_INDEX_MAX);
}
//-------------------------------------------------------------------------------------------------------------------
bool is_destination_of_wallet(const JamtisDestinationV1 &destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_generate_address)
{
    // ciphertag secret
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(k_generate_address, ciphertag_secret);

    // get the nominal address index from the destination's address tag
    address_tag_MAC_t address_index_mac;
    address_index_t nominal_address_index{
            decipher_address_index(ciphertag_secret, destination.m_addr_tag, address_index_mac)
        };

    if (address_index_mac != address_tag_MAC_t{0})
        return false;

    // check if the destination's key K_1 is owned by this wallet
    return test_nominal_spend_key(wallet_spend_pubkey,
        k_generate_address,
        nominal_address_index,
        destination.m_addr_K1);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
