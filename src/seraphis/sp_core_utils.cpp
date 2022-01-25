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
#include "sp_core_utils.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const rct::key &zU, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "y must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(!(zU == rct::identity()), "zU must not be identity element for making a key image!");

    // KI = (z/y)*U
    rct::key temp = sp::invert(rct::sk2rct(y)); // 1/y
    rct::scalarmultKey(temp, zU, temp); // (z/y)*U

    key_image_out = rct::rct2ki(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&z), "z must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "y must be nonzero for making a key image!");

    // KI = (z/y)*U
    rct::key temp = sp::invert(rct::sk2rct(y)); // 1/y
    sc_mul(temp.bytes, &z, temp.bytes); // z*(1/y)
    rct::scalarmultKey(temp, sp::get_U_gen(), temp); // (z/y)*U

    key_image_out = rct::rct2ki(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image_from_parts(const crypto::secret_key &k_a_sender,
    const crypto::secret_key &k_a_recipient,
    const rct::key &k_bU,
    crypto::key_image &key_image_out)
{
    // KI = (k_b/(k_a_sender + k_a_recipient))*U
    crypto::secret_key k_a_combined;
    sc_add(&k_a_combined, &k_a_sender, &k_a_recipient);

    make_seraphis_key_image(k_a_combined, k_bU, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendbase(const crypto::secret_key &spendbase_privkey, rct::key &spendbase_pubkey_out)
{
    // spendbase = k_{b, recipient} U
    rct::scalarmultKey(spendbase_pubkey_out, sp::get_U_gen(), rct::sk2rct(spendbase_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void extend_seraphis_spendkey(const crypto::secret_key &k_a_extender, rct::key &spendkey_inout)
{
    // K = k_a_extender X + K_original
    rct::key extender_key;

    rct::scalarmultKey(extender_key, sp::get_X_gen(), rct::sk2rct(k_a_extender));
    rct::addKeys(spendkey_inout, extender_key, spendkey_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendkey(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &spendkey_out)
{
    // K = k_a X + k_b U
    make_seraphis_spendbase(k_b, spendkey_out);

    // finish address
    extend_seraphis_spendkey(k_a, spendkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_squash_prefix(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    crypto::secret_key &squash_prefix_out)
{
    static const std::string domain_separator{config::HASH_KEY_SERAPHIS_SQUASHED_ENOTE};

    // H("domain-sep", Ko, C)
    std::string hash;
    hash.reserve(domain_separator.size() + 2*sizeof(rct::key));
    hash = domain_separator;
    hash.append((const char*) onetime_address.bytes, sizeof(rct::key));
    hash.append((const char*) amount_commitment.bytes, sizeof(rct::key));

    // hash to the result
    crypto::hash_to_scalar(hash.data(), hash.size(), squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void squash_seraphis_address(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squashed_address_out)
{
    // Ko^t = H(Ko,C) Ko
    crypto::secret_key squash_prefix;
    make_seraphis_squash_prefix(onetime_address, amount_commitment, squash_prefix);

    rct::scalarmultKey(squashed_address_out, onetime_address, rct::sk2rct(squash_prefix));
}
//-------------------------------------------------------------------------------------------------------------------
void seraphis_squashed_enote_Q(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squashed_enote_out)
{
    // Ko^t
    squash_seraphis_address(onetime_address, amount_commitment, squashed_enote_out);

    // Q = Ko^t + C^t
    rct::addKeys(squashed_enote_out, squashed_enote_out, amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
