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
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "int-util.h"
#include "jamtis_hash_functions.h"
#include "jamtis_support_types.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
// derivation = 8 * privkey * DH_key
//-------------------------------------------------------------------------------------------------------------------
static auto make_derivation_with_wiper(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    crypto::key_derivation &derivation_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&derivation_out]()
            {
                memwipe(&derivation_out, sizeof(crypto::key_derivation));
            }
        );

    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation_out);

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
// key1 || key2
// - assumes both keys are 32 bytes
//-------------------------------------------------------------------------------------------------------------------
static void get_doublekey_hash_data(const unsigned char *key1,
    const unsigned char *key2,
    epee::wipeable_string &data_out)
{
    data_out.clear();
    data_out.reserve(2 * 32);

    data_out.append(reinterpret_cast<const char *>(key1), 32);
    data_out.append(reinterpret_cast<const char *>(key2), 32);
}
//-------------------------------------------------------------------------------------------------------------------
// a = a_enc XOR H_8(q, 8 r G)
// a_enc = a XOR H_8(q, 8 r G)
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount enc_dec_jamtis_amount_plain(const rct::xmr_amount original,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    static_assert(sizeof(rct::xmr_amount) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN};

    // ret = H_8(q, 8 r G) XOR_64 original
    epee::wipeable_string data;
    get_doublekey_hash_data(sender_receiver_secret.bytes, &baked_key, data);

    crypto::secret_key hash_result;
    jamtis_hash8(domain_separator, reinterpret_cast<unsigned char *>(data.data()), data.size(), &hash_result);

    rct::xmr_amount mask;
    memcpy(&mask, &hash_result, 8);

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
// a = a_enc XOR H_8(q)
// a_enc = a XOR H_8(q)
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount enc_dec_jamtis_amount_selfsend(const rct::xmr_amount original,
    const rct::key &sender_receiver_secret)
{
    static_assert(sizeof(rct::xmr_amount) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF};

    // ret = H_8(q) XOR_64 original
    crypto::secret_key hash_result;
    jamtis_hash8(domain_separator, sender_receiver_secret.bytes, sizeof(crypto::secret_key), &hash_result);

    rct::xmr_amount mask;
    memcpy(&mask, &hash_result, 8);

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_enote_ephemeral_pubkey(const crypto::secret_key &enote_privkey,
    const rct::key &DH_base,
    rct::key &enote_ephemeral_pubkey_out)
{
    // K_e = r K_3
    rct::scalarmultKey(enote_ephemeral_pubkey_out, DH_base, rct::sk2rct(enote_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
view_tag_t make_jamtis_view_tag(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address)
{
    static_assert(sizeof(view_tag_t) == 1, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_VIEW_TAG};

    // view_tag = H_1(K_d, Ko)
    // TODO: consider using a simpler/cheaper hash function for view tags
    epee::wipeable_string data;
    get_doublekey_hash_data(&sender_receiver_DH_derivation, onetime_address.bytes, data);

    view_tag_t view_tag;
    jamtis_hash1(domain_separator, reinterpret_cast<unsigned char *>(data.data()), data.size(), &view_tag);

    return view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
view_tag_t make_jamtis_view_tag(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    const rct::key &onetime_address)
{
    // K_d = 8 * privkey * DH_key
    //TODO: consider using curve25519/x25519 variable-scalar-mult to get the derivation instead (faster?)
    crypto::key_derivation derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, hwdev, derivation);

    // view_tag = H_1(K_d, Ko)
    return make_jamtis_view_tag(derivation, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    rct::key &sender_receiver_secret_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_PLAIN};

    // q = H_32(DH_derivation)
    jamtis_hash32(domain_separator,
        &sender_receiver_DH_derivation,
        sizeof(crypto::key_derivation),
        sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    rct::key &sender_receiver_secret_out)
{
    // 8 * privkey * DH_key
    crypto::key_derivation derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, hwdev, derivation);

    // q = H_32(DH_derivation)
    make_jamtis_sender_receiver_secret_plain(derivation, sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const rct::key &enote_ephemeral_pubkey,
    rct::key &sender_receiver_secret_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF};

    // q = H_32[k_vb](K_e)
    jamtis_derive_secret(domain_separator,
        &k_view_balance,
        enote_ephemeral_pubkey.bytes,
        sizeof(rct::key),
        sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension(const rct::key &sender_receiver_secret,
    crypto::secret_key &sender_extension_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION};

    // k_{a, sender} = H_n(q)
    jamtis_hash_scalar(domain_separator, sender_receiver_secret.bytes, sizeof(rct::key), &sender_extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &recipient_spend_key,
    rct::key &onetime_address_out)
{
    // Ko = H_n(q) X + K_1
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, extension);  //H_n(q)

    onetime_address_out = recipient_spend_key;
    extend_seraphis_spendkey(extension, onetime_address_out);  //H_n(q) X + K_1
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_sender(const crypto::secret_key &enote_privkey,
    crypto::key_derivation &baked_key_out)
{
    // 8 r G
    crypto::generate_key_derivation(rct::rct2pk(rct::G), enote_privkey, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_recipient(const crypto::secret_key &address_privkey,
    const rct::key &enote_ephemeral_pubkey,
    crypto::key_derivation &baked_key_out)
{
    // 8 * (1/k^j_a) * K_e = 8 r G
    //TODO: does this create a temporary that isn't properly memwiped?
    crypto::secret_key address_privkey_inverted{rct::rct2sk(invert(rct::sk2rct(address_privkey)))};  //(1/k^j_a)
    crypto::generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), address_privkey_inverted, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    crypto::secret_key &mask_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN};

    // x = H_n(q, 8 r G)
    epee::wipeable_string data;
    get_doublekey_hash_data(sender_receiver_secret.bytes, &baked_key, data);  //q || 8 r G

    jamtis_hash_scalar(domain_separator, reinterpret_cast<unsigned char *>(data.data()), data.size(), &mask_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_selfsend(const rct::key &sender_receiver_secret,
    crypto::secret_key &mask_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF};

    // x = H_n(q)
    jamtis_hash_scalar(domain_separator, sender_receiver_secret.bytes, sizeof(rct::key), &mask_out);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount encode_jamtis_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    // a_enc = little_endian(a) XOR H_8(q, 8 r G)
    return enc_dec_jamtis_amount_plain(SWAP64LE(amount), sender_receiver_secret, baked_key);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    // a = system_endian( a_enc XOR H_8(q, 8 r G) )
    return SWAP64LE(enc_dec_jamtis_amount_plain(encoded_amount, sender_receiver_secret, baked_key));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount encode_jamtis_amount_selfsend(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret)
{
    // a_enc = little_endian(a) XOR H_8(q)
    return enc_dec_jamtis_amount_selfsend(SWAP64LE(amount), sender_receiver_secret);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decode_jamtis_amount_selfsend(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret)
{
    // a = system_endian( a_enc XOR H_8(q) )
    return SWAP64LE(enc_dec_jamtis_amount_selfsend(encoded_amount, sender_receiver_secret));
}
//-------------------------------------------------------------------------------------------------------------------
void get_jamtis_nominal_spend_key(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    rct::key &nominal_spend_key_out)
{
    // K'_1 = Ko - H_n(q) X
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, extension);  //H_n(q)
    sc_mul(&extension, sp::MINUS_ONE.bytes, &extension);  // -H_n(q)
    nominal_spend_key_out = onetime_address;  // Ko_t
    extend_seraphis_spendkey(extension, nominal_spend_key_out);  // (-H(q_t)) X + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_nominal_spend_key_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out)
{
    // recompute view tag and check that it matches; short-circuit on failure
    if (make_jamtis_view_tag(sender_receiver_DH_derivation, onetime_address) != view_tag)
        return false;

    // q (normal derivation path)
    make_jamtis_sender_receiver_secret_plain(sender_receiver_DH_derivation,
        sender_receiver_secret_out);

    // K'_1 = Ko - H_n(q) X
    get_jamtis_nominal_spend_key(sender_receiver_secret_out, onetime_address, nominal_spend_key_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_nominal_spend_key_selfsend(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const crypto::secret_key &k_view_balance,
    const rct::key &enote_ephemeral_pubkey,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out)
{
    // recompute view tag and check that it matches; short-circuit on failure
    if (make_jamtis_view_tag(sender_receiver_DH_derivation, onetime_address) != view_tag)
        return false;

    // q (self-send derivation path)
    make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        sender_receiver_secret_out);

    // K'_1 = Ko - H_n(q) X
    get_jamtis_nominal_spend_key(sender_receiver_secret_out, onetime_address, nominal_spend_key_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out)
{
    // a' = dec(enc_a)
    rct::xmr_amount nominal_amount{decode_jamtis_amount_plain(encoded_amount, sender_receiver_secret, baked_key)};

    // C' = x' G + a' H
    crypto::secret_key nominal_amount_blinding_factor;
    make_jamtis_amount_blinding_factor_plain(sender_receiver_secret, baked_key, nominal_amount_blinding_factor);  // x'
    rct::key nominal_amount_commitment = rct::commit(nominal_amount, rct::sk2rct(nominal_amount_blinding_factor));

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // success
    amount_out = nominal_amount;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount_selfsend(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out)
{
    // a' = dec(enc_a)
    rct::xmr_amount nominal_amount{decode_jamtis_amount_selfsend(encoded_amount, sender_receiver_secret)};

    // C' = x' G + a' H
    crypto::secret_key nominal_amount_blinding_factor;
    make_jamtis_amount_blinding_factor_selfsend(sender_receiver_secret, nominal_amount_blinding_factor);  // x'
    rct::key nominal_amount_commitment = rct::commit(nominal_amount, rct::sk2rct(nominal_amount_blinding_factor));

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // success
    amount_out = nominal_amount;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image_jamtis_style(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_privkey,
    const crypto::secret_key &address_extension,
    crypto::key_image &key_image_out)
{
    // KI = (k_m/(k_vb + k^j_a + H_n(q))) U

    // k_b U = k_m U = K_s - k_vb X
    rct::key master_pubkey{wallet_spend_pubkey};  //K_s
    crypto::secret_key minus_k_vb{k_view_balance};
    sc_mul(&minus_k_vb, sp::MINUS_ONE.bytes, &minus_k_vb);  //-k_vb
    extend_seraphis_spendkey(minus_k_vb, master_pubkey);  // (-k_vb) X + K_s = k_m U

    // k_a_recipient = k_vb + k^j_a
    crypto::secret_key k_a_recipient;
    sc_add(&k_a_recipient, &k_view_balance, &address_privkey);  //k_vb + k^j_a

    // k_a_sender = H_n(q)
    // KI = (1/(k_a_sender + k_a_recipient))*k_b*U
    make_seraphis_key_image_from_parts(address_extension, k_a_recipient, master_pubkey, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
