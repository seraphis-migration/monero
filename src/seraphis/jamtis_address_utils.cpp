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
#include "jamtis_address_utils.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_core_utils.h"
#include "jamtis_destination.h"
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
void make_jamtis_address_key(const crypto::secret_key s_generate_address,
    const address_index_t j,
    crypto::secret_key &address_key_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_ADDRESS_KEY};

    // k^j_a = H_n(Pad136(s_ga), j)
    address_tag_t raw_address_index{address_index_to_tag(j, 0)};

    jamtis_derive_key(domain_separator,
        &s_generate_address,
        raw_address_index.bytes,
        ADDRESS_INDEX_BYTES,
        &address_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_extension_key(const crypto::secret_key s_generate_address,
    const address_index_t j,
    crypto::secret_key &address_extension_key_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_ADDRESS_EXTENSION_KEY};

    // k^j_x = H_n(Pad136(s_ga), j)
    address_tag_t raw_address_index{address_index_to_tag(j, 0)};

    jamtis_derive_key(domain_separator,
        &s_generate_address,
        raw_address_index.bytes,
        ADDRESS_INDEX_BYTES,
        &address_extension_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_spend_key(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    rct::key &address_spendkey_out)
{
    // K_1 = k^j_x X + K_s
    crypto::secret_key address_extension_key;
    make_jamtis_address_extension_key(s_generate_address, j, address_extension_key);

    address_spendkey_out = wallet_spend_pubkey;
    extend_seraphis_spendkey(address_extension_key, address_spendkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1(const rct::key &wallet_spend_pubkey,
    const rct::key &findreceived_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    JamtisDestinationV1 &destination_out)
{
    // K_1 = k^j_x X + K_s
    make_jamtis_address_spend_key(wallet_spend_pubkey, s_generate_address, j, destination_out.m_addr_K1);

    // K_2 = k^j_a K_fr
    crypto::secret_key address_key;
    make_jamtis_address_key(s_generate_address, j, address_key);

    rct::scalarmultKey(destination_out.m_addr_K2, findreceived_pubkey, rct::sk2rct(address_key));

    // K_3 = k^j_a G
    rct::scalarmultBase(destination_out.m_addr_K3, rct::sk2rct(address_key));

    // addr_tag = blowfish[s_ct](j, mac)
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(generateaddress_secret, ciphertag_secret);

    destination_out.m_addr_tag = cipher_address_index_with_key(rct::sk2rct(ciphertag_secret), j, 0);
}
//-------------------------------------------------------------------------------------------------------------------
bool test_nominal_spend_key(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t j,
    const rct::key &nominal_spend_key)
{
    // get the spend key of the address at the uncovered index: K_1
    rct::key address_spendkey;
    make_jamtis_address_spend_key(wallet_spend_pubkey, s_generate_address, j, address_spendkey);

    // check if the nominal spend key matches the real spend key: K'_1 ?= K_1
    return nominal_spend_key == address_spendkey;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
