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

// Utilities for building Jamtis addresses.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
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
* brief: make_jamtis_index_extension_generator - s^j_gen
*   - s^j_gen = H_32[s_ga](j)
* param: s_generate_address - s_ga
* param: j - address index
* outparam: generator_out - s^j_gen
*/
void make_jamtis_index_extension_generator(const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &generator_out);
/**
* brief: make_jamtis_spendkey_extension - k^j_?
*   - k^j_? = H_n("domain separator", K_s, j, s^j_gen)
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: j - address index
* param: generator - s^j_gen
* outparam: extension_out - k^j_g
*/
void make_jamtis_spendkey_extension(const boost::string_ref domain_separator,
    const rct::key &spend_pubkey,
    const address_index_t &j,
    const crypto::secret_key &generator,
    crypto::secret_key &extension_out);
void make_jamtis_spendkey_extension(const boost::string_ref domain_separator,
    const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out);
/**
* brief: make_jamtis_spendkey_extension_g - k^j_g
*   - k^j_g = H_n("..g..", K_s, j, s^j_gen)
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address index
* outparam: extension_out - k^j_g
*/
void make_jamtis_spendkey_extension_g(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out);
/**
* brief: make_jamtis_spendkey_extension_x - k^j_x
*   - k^j_x = H_n("..x..", K_s, j, s^j_gen)
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address index
* outparam: extension_out - k^j_x
*/
void make_jamtis_spendkey_extension_x(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out);
/**
* brief: make_jamtis_spendkey_extension_u - k^j_u
*   - k^j_u = H_n("..u..", K_s, j, s^j_gen)
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address index
* outparam: extension_out - k^j_u
*/
void make_jamtis_spendkey_extension_u(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out);
/**
* brief: make_jamtis_address_privkey - xk^j_a
*   - xk^j_a = H_n_x25519(K_s, j, s^j_gen)
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address index
* outparam: address_privkey_out - xk^j_a
*/
void make_jamtis_address_privkey(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::x25519_secret_key &address_privkey_out);
/**
* brief: make_jamtis_address_spend_key - K_1
*   - K_1 = k^j_g G + k^j_x X + k^j_u U + K_s
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: s_generate_address - s_ga
* param: j - address index
* outparam: address_spendkey_out - K_1
*/
void make_jamtis_address_spend_key(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    rct::key &address_spendkey_out);
/**
* brief: make_seraphis_key_image_jamtis_style - KI
*   - KI = ((k^o_u + k^j_u + k_m)/(k^o_x + k^j_x + k_vb)) U
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: k_view_balance - k_vb
* param: spendkey_extension_x - k^j_x
* param: spendkey_extension_u - k^j_u
* param: sender_extension_x - k^o_x
* param: sender_extension_u - k^o_u
* outparam: key_image_out - KI
*/
void make_seraphis_key_image_jamtis_style(const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &spendkey_extension_x,
    const crypto::secret_key &spendkey_extension_u,
    const crypto::secret_key &sender_extension_x,
    const crypto::secret_key &sender_extension_u,
    crypto::key_image &key_image_out);

} //namespace jamtis
} //namespace sp
