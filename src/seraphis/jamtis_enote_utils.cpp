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
#include "jamtis_enote_utils.h"

//local headers
#include "common/varint.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_utils.h"
#include "sp_crypto_utils.h"
#include "tx_misc_utils.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_enote_pubkey(const crypto::secret_key &enote_privkey,
    const rct::key &DH_base,
    rct::key &enote_pubkey_out)
{
    // R_t = r_t K^{DH}_t
    rct::scalarmultKey(enote_pubkey_out, DH_base, rct::sk2rct(enote_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const std::size_t output_index,
    hw::device &hwdev,
    rct::key &sender_receiver_secret_out)
{
    // 8 * privkey * DH_key
    crypto::key_derivation derivation;
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        memwipe(&derivation, sizeof(crypto::key_derivation));
    });

    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation);

    // q_t = H(r_t * k^{vr} * K^{DH}, t) => H("domain sep", privkey * DH_key, output_index)
    make_jamtis_sender_receiver_secret(derivation, output_index, sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index,
    rct::key &sender_receiver_secret_out)
{
    static const std::string salt{config::HASH_KEY_SERAPHIS_SENDER_RECEIVER_SECRET};

    // q_t = H(8 * r_t * k^{vr} * K^{DH}, t) => H("domain sep", 8 * privkey * DH_key, output_index)
    sp::domain_separate_derivation_hash(salt,
        sender_receiver_DH_derivation,
        output_index,
        sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_address_extension(const crypto::secret_key &sender_receiver_secret,
    crypto::secret_key &sender_address_extension_out)
{
    static const std::string salt{config::HASH_KEY_SERAPHIS_SENDER_ADDRESS_EXTENSION};

    // k_{a, sender} = H("domain-sep", q_t)
    sp::domain_separate_rct_hash(salt, rct::sk2rct(sender_receiver_secret), sender_address_extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
unsigned char make_jamtis_view_tag(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const std::size_t output_index,
    hw::device &hwdev)
{
    // 8 * privkey * DH_key
    crypto::key_derivation derivation;
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        memwipe(&derivation, sizeof(crypto::key_derivation));
    });

    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation);

    // tag_t = H("domain-sep", derivation, t)
    return make_jamtis_view_tag(derivation, output_index);
}
//-------------------------------------------------------------------------------------------------------------------
unsigned char make_jamtis_view_tag(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index)
{
    static const std::string salt{config::HASH_KEY_SERAPHIS_VIEW_TAG};

    // tag_t = H("domain-sep", derivation, t)
    // note: the view tag is not a secret, so it doesn't need to be memory-safe (e.g. with crypto::secret_key)
    //   - using crypto::secret_key can slow down view-key scanning if scanning is multithreaded (due to memlock)
    // TODO: consider using a simpler/cheaper hash function for view tags
    rct::key view_tag_scalar;

    sp::domain_separate_derivation_hash(salt,
        sender_receiver_DH_derivation,
        output_index,
        view_tag_scalar);

    return static_cast<unsigned char>(view_tag_scalar.bytes[0]);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount enc_dec_jamtis_amount(const crypto::secret_key &sender_receiver_secret,
    const rct::key &baked_key,
    const rct::xmr_amount original)
{
    static const std::string salt{config::HASH_KEY_SERAPHIS_AMOUNT_ENC};

    // ret = H("domain-sep", q_t, [OPTIONAL: baked_key]) XOR_64 original
    crypto::secret_key hash_result;
    sp::domain_separate_rct_hash_with_extra(salt, rct::sk2rct(sender_receiver_secret), baked_key, hash_result);

    rct::xmr_amount mask{0};
    rct::xmr_amount temp{0};

    for (int i = 0; i < 8; ++i)
    {
        temp = hash_result.data[i];
        mask ^= (temp << i*8);
    }

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_commitment_mask(const crypto::secret_key &sender_receiver_secret,
    const rct::key &baked_key,
    crypto::secret_key &mask_out)
{
    static const std::string salt{config::HASH_KEY_SERAPHIS_AMOUNT_COMMITMENT_BLINDING_FACTOR};

    // x_t = H("domain-sep", q_t, [OPTIONAL: baked_key])
    sp::domain_separate_rct_hash_with_extra(salt, rct::sk2rct(sender_receiver_secret), baked_key, mask_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_nominal_spend_key(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index,
    const rct::key &onetime_address,
    const unsigned char view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out)
{
    // tag'_t
    unsigned char nominal_view_tag{make_jamtis_view_tag(sender_receiver_DH_derivation, output_index)};

    // check that recomputed tag matches original tag; short-circuit on failure
    if (nominal_view_tag != view_tag)
        return false;

    // q_t
    // note: computing this after view tag check is an optimization
    make_jamtis_sender_receiver_secret(sender_receiver_DH_derivation,
        output_index,
        sender_receiver_secret_out);

    // K'^s_t = Ko_t - H(q_t) X
    crypto::secret_key k_a_extender;
    make_jamtis_sender_address_extension(rct::rct2sk(sender_receiver_secret_out), k_a_extender);  // H(q_t)
    sc_mul(&k_a_extender, sp::MINUS_ONE.bytes, &k_a_extender);  // -H(q_t)
    nominal_spend_key_out = onetime_address;  // Ko_t
    extend_seraphis_spendkey(k_a_extender, nominal_spend_key_out); // (-H(q_t)) X + Ko_t

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount(const crypto::secret_key &sender_receiver_secret,
    const rct::key &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out)
{
    // a' = dec(encoded_amount)
    rct::xmr_amount nominal_amount{enc_dec_jamtis_amount(sender_receiver_secret, baked_key, encoded_amount)};

    // C' = x' G + a' H
    crypto::secret_key nominal_amount_commitment_mask;
    make_jamtis_amount_commitment_mask(sender_receiver_secret, baked_key, nominal_amount_commitment_mask);  // x'
    rct::key nominal_amount_commitment = rct::commit(nominal_amount, rct::sk2rct(nominal_amount_commitment_mask));

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // success
    amount_out = nominal_amount;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
