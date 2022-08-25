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
extern "C"
{
#include "mx25519.h"
}
#include "crypto/crypto.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

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
    m_addr_K2 = x25519_pubkey_gen();
    m_addr_K3 = x25519_pubkey_gen();
    crypto::rand(sizeof(address_tag_t), m_addr_tag.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1(const rct::key &wallet_spend_pubkey,
    const x25519_pubkey &unlockamounts_pubkey,
    const x25519_pubkey &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    JamtisDestinationV1 &destination_out)
{
    // K_1 = k^j_x X + K_s
    make_jamtis_address_spend_key(wallet_spend_pubkey, s_generate_address, j, destination_out.m_addr_K1);

    // xK_2 = xk^j_a xK_fr
    x25519_secret_key address_privkey;
    make_jamtis_address_privkey(s_generate_address, j, address_privkey);  //xk^j_a

    mx25519_scmul_key(mx25519_select_impl(mx25519_type::MX25519_TYPE_AUTO),
        &destination_out.m_addr_K2,
        &address_privkey,
        &findreceived_pubkey);

    // xK_3 = xk^j_a xK_ua
    mx25519_scmul_key(mx25519_select_impl(mx25519_type::MX25519_TYPE_AUTO),
        &destination_out.m_addr_K3,
        &address_privkey,
        &unlockamounts_pubkey);

    // addr_tag = blowfish[s_ct](j, mac)
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(s_generate_address, ciphertag_secret);

    destination_out.m_addr_tag = cipher_address_index(rct::sk2rct(ciphertag_secret), j);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_index_from_destination_v1(const JamtisDestinationV1 &destination,
    const rct::key &wallet_spend_pubkey,
    const x25519_pubkey &unlockamounts_pubkey,
    const x25519_pubkey &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    address_index_t &j_out)
{
    // ciphertag secret
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(s_generate_address, ciphertag_secret);

    // get the nominal address index from the destination's address tag
    address_index_t nominal_address_index;

    if (!try_decipher_address_index(rct::sk2rct(ciphertag_secret), destination.m_addr_tag, nominal_address_index))
        return false;

    // recreate the destination
    JamtisDestinationV1 test_destination;

    make_jamtis_destination_v1(wallet_spend_pubkey,
        unlockamounts_pubkey,
        findreceived_pubkey,
        s_generate_address,
        nominal_address_index,
        test_destination);

    // check the destinations are the same
    // note: partial equality will return false
    if (!(test_destination == destination))
        return false;

    j_out = nominal_address_index;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
