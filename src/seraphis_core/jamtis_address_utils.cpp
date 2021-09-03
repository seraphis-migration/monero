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
#include "jamtis_address_utils.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "jamtis_core_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_index_extension_generator(const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &generator_out)
{
    // s^j_gen = H_32[s_ga](j)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_INDEX_EXTENSION_GENERATOR, ADDRESS_INDEX_BYTES};
    transcript.append("j", j.bytes);

    sp_derive_secret(to_bytes(s_generate_address), transcript.data(), transcript.size(), to_bytes(generator_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension(const boost::string_ref domain_separator,
    const rct::key &spend_pubkey,
    const address_index_t &j,
    const crypto::secret_key &generator,
    crypto::secret_key &extension_out)
{
    // k^j_? = H_n(K_s, j, s^j_gen)
    SpKDFTranscript transcript{domain_separator, 2*32 + ADDRESS_INDEX_BYTES};
    transcript.append("K_s", spend_pubkey);
    transcript.append("j", j.bytes);
    transcript.append("generator", generator);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension(const boost::string_ref domain_separator,
    const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out)
{
    // s^j_gen
    crypto::secret_key generator;
    make_jamtis_index_extension_generator(s_generate_address, j, generator);

    // k^j_?
    make_jamtis_spendkey_extension(domain_separator, spend_pubkey, j, generator, extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_g(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out)
{
    // k^j_g = H_n("..g..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_G,
        spend_pubkey,
        s_generate_address,
        j,
        extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_x(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out)
{
    // k^j_x = H_n("..x..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_X,
        spend_pubkey,
        s_generate_address,
        j,
        extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_spendkey_extension_u(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::secret_key &extension_out)
{
    // k^j_u = H_n("..u..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_U,
        spend_pubkey,
        s_generate_address,
        j,
        extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_privkey(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    crypto::x25519_secret_key &address_privkey_out)
{
    // s^j_gen
    crypto::secret_key generator;
    make_jamtis_index_extension_generator(s_generate_address, j, generator);

    // xk^j_a = H_n_x25519(K_s, j, H_32[s_ga](j))
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ADDRESS_PRIVKEY, ADDRESS_INDEX_BYTES};
    transcript.append("K_s", spend_pubkey);
    transcript.append("j", j.bytes);
    transcript.append("generator", generator);

    sp_hash_to_x25519_scalar(transcript.data(), transcript.size(), address_privkey_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_address_spend_key(const rct::key &spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    rct::key &address_spendkey_out)
{
    // K_1 = k^j_g G + k^j_x X + k^j_u U + K_s
    crypto::secret_key address_extension_key_u;
    crypto::secret_key address_extension_key_x;
    crypto::secret_key address_extension_key_g;
    make_jamtis_spendkey_extension_u(spend_pubkey, s_generate_address, j, address_extension_key_u);  //k^j_u
    make_jamtis_spendkey_extension_x(spend_pubkey, s_generate_address, j, address_extension_key_x);  //k^j_x
    make_jamtis_spendkey_extension_g(spend_pubkey, s_generate_address, j, address_extension_key_g);  //k^j_g

    address_spendkey_out = spend_pubkey;  //K_s
    extend_seraphis_spendkey_u(address_extension_key_u, address_spendkey_out);      //k^j_u U + K_s
    extend_seraphis_spendkey_x(address_extension_key_x, address_spendkey_out);      //k^j_x X + k^j_u U + K_s
    mask_key(address_extension_key_g, address_spendkey_out, address_spendkey_out);  //k^j_g G + k^j_x X + k^j_u U + K_s
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image_jamtis_style(const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &spendkey_extension_x,
    const crypto::secret_key &spendkey_extension_u,
    const crypto::secret_key &sender_extension_x,
    const crypto::secret_key &sender_extension_u,
    crypto::key_image &key_image_out)
{
    // KI = ((k^o_u + k^j_u + k_m)/(k^o_x + k^j_x + k_vb)) U

    // k_m U = K_s - k_vb X
    rct::key zU{spend_pubkey};  //K_s = k_vb X + k_m U
    reduce_seraphis_spendkey_x(k_view_balance, zU);  //k_m U

    // z U = (k_u + k_m) U = k^o_u U + k^j_u U + k_m U
    extend_seraphis_spendkey_u(spendkey_extension_u, zU);  //k^j_u U + k_m U
    extend_seraphis_spendkey_u(sender_extension_u, zU);  //k^o_u U + k^j_u U + k_m U

    // y = k^o_x + k^j_x + k_vb
    crypto::secret_key y;
    sc_add(to_bytes(y), to_bytes(sender_extension_x), to_bytes(spendkey_extension_x));  //k^o_x + k^j_x
    sc_add(to_bytes(y), to_bytes(y), to_bytes(k_view_balance));  //+ k_vb

    // KI = (1/y)*(k_u + k_m)*U
    make_seraphis_key_image(y, rct::rct2pk(zU), key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
