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
#include "seraphis_config_temp.h"
#include "int-util.h"
#include "jamtis_support_types.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
// derivation = privkey * DH_key (with X25519)
// note: X25519 DH derivations are implicitly mul 8
//-------------------------------------------------------------------------------------------------------------------
static auto make_derivation_with_wiper(const x25519_secret_key &privkey,
    const x25519_pubkey &DH_key,
    x25519_pubkey &derivation_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&derivation_out]()
            {
                memwipe(&derivation_out, sizeof(derivation_out));
            }
        );

    x25519_scmul_key(privkey, DH_key, derivation_out);

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
// a = a_enc XOR H_8(q, xr xG)
// a_enc = a XOR H_8(q, xr xG)
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount enc_dec_jamtis_amount_plain(const rct::xmr_amount original,
    const rct::key &sender_receiver_secret,
    const x25519_pubkey &baked_key)
{
    static_assert(sizeof(rct::xmr_amount) == 8, "");

    // ret = H_8(q, xr xG) XOR_64 original
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("baked_key", baked_key);

    crypto::secret_key hash_result;
    sp_hash_to_8(transcript, to_bytes(hash_result));

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

    // ret = H_8(q) XOR_64 original
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF, sizeof(sender_receiver_secret)};
    transcript.append("q", sender_receiver_secret);

    crypto::secret_key hash_result;
    sp_hash_to_8(transcript, to_bytes(hash_result));

    rct::xmr_amount mask;
    memcpy(&mask, &hash_result, 8);

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_enote_ephemeral_pubkey(const x25519_secret_key &enote_ephemeral_privkey,
    const x25519_pubkey &DH_base,
    x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // xK_e = xr xK_3
    x25519_scmul_key(enote_ephemeral_privkey, DH_base, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const x25519_pubkey &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out)
{
    static_assert(sizeof(view_tag_t) == 1, "");

    // view_tag = H_1(xK_d, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEW_TAG, 2*sizeof(rct::key)};
    transcript.append("xK_d", sender_receiver_DH_derivation);
    transcript.append("Ko", onetime_address);

    sp_hash_to_1(transcript, &view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const x25519_secret_key &privkey,
    const x25519_pubkey &DH_key,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out)
{
    // xK_d = privkey * DH_key
    x25519_pubkey derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, derivation);

    // view_tag = H_1(xK_d, Ko)
    make_jamtis_view_tag(derivation, onetime_address, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_coinbase(const std::uint64_t block_height, rct::key &input_context_out)
{
    // block height as varint
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_INPUT_CONTEXT_COINBASE, 4};
    transcript.append("height", block_height);

    // input_context (coinbase) = H_32(block height)
    sp_hash_to_32(transcript, input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_standard(const std::vector<crypto::key_image> &input_key_images,
    rct::key &input_context_out)
{
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(input_key_images.begin(), input_key_images.end()),
        "jamtis input context (standard): key images are not sorted.");

    // {KI}
    SpKDFTranscript transcript{
            config::HASH_KEY_JAMTIS_INPUT_CONTEXT_STANDARD,
            input_key_images.size()*sizeof(crypto::key_image)
        };
    transcript.append("input_KI", input_key_images);

    // input_context (standard) = H_32({KI})
    sp_hash_to_32(transcript, input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const x25519_pubkey &sender_receiver_DH_derivation,
    const x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out)
{
    // q = H_32(xK_d, xK_e, input_context)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_PLAIN, 3*sizeof(rct::key)};
    transcript.append("xK_d", sender_receiver_DH_derivation);
    transcript.append("xK_e", enote_ephemeral_pubkey);
    transcript.append("input_context", input_context);

    sp_hash_to_32(transcript, sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const x25519_secret_key &privkey,
    const x25519_pubkey &DH_key,
    const x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out)
{
    // privkey * DH_key
    x25519_pubkey derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, derivation);

    // q = H_32(xK_d, xK_e, input_context)
    make_jamtis_sender_receiver_secret_plain(derivation,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::JamtisSelfSendType self_send_type,
    rct::key &sender_receiver_secret_out)
{
    static const std::string dummy_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_DUMMY
        };
    static const std::string change_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_CHANGE
        };
    static const std::string self_spend_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_SELF_SPEND
        };

    CHECK_AND_ASSERT_THROW_MES(self_send_type <= jamtis::JamtisSelfSendType::MAX,
        "jamtis self-send sender-receiver secret: unknown self-send type.");

    const std::string &domain_separator{
            [&]() -> const std::string&
            {
                if (self_send_type == jamtis::JamtisSelfSendType::DUMMY)
                    return dummy_separator;
                else if (self_send_type == jamtis::JamtisSelfSendType::CHANGE)
                    return change_separator;
                else if (self_send_type == jamtis::JamtisSelfSendType::SELF_SPEND)
                    return self_spend_separator;
                else
                {
                    CHECK_AND_ASSERT_THROW_MES(false, "jamtis self-send sender-receiver secret domain separator error");
                    return dummy_separator;
                }
            }()
        };

    // q = H_32[k_vb](xK_e, input_context)
    SpKDFTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append("xK_e", enote_ephemeral_pubkey);
    transcript.append("input_context", input_context);

    sp_derive_secret(to_bytes(k_view_balance), transcript, sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{a, sender} = H_n(q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript, to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &recipient_spend_key,
    rct::key &onetime_address_out)
{
    // Ko = H_n(q, C) X + K_1
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, amount_commitment, extension);  //H_n(q, C)

    onetime_address_out = recipient_spend_key;
    extend_seraphis_spendkey(extension, onetime_address_out);  //H_n(q, C) X + K_1
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_sender(const x25519_secret_key &enote_ephemeral_privkey,
    x25519_pubkey &baked_key_out)
{
    // xr xG
    x25519_scmul_base(enote_ephemeral_privkey, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_recipient(const x25519_secret_key &address_privkey,
    const x25519_secret_key &xk_unlock_amounts,
    const x25519_pubkey &enote_ephemeral_pubkey,
    x25519_pubkey &baked_key_out)
{
    // (1/(xk^j_a * xk_ua)) * xK_e = xr xG
    x25519_invmul_key({address_privkey, xk_unlock_amounts}, enote_ephemeral_pubkey, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const x25519_pubkey &baked_key,
    crypto::secret_key &mask_out)
{
    // x = H_n(q, xr xG)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("baked_key", baked_key);  //q || xr xG

    sp_hash_to_scalar(transcript, to_bytes(mask_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_selfsend(const rct::key &sender_receiver_secret,
    crypto::secret_key &mask_out)
{
    // x = H_n(q)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF, sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);

    sp_hash_to_scalar(transcript, to_bytes(mask_out));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount encode_jamtis_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const x25519_pubkey &baked_key)
{
    // a_enc = little_endian(a) XOR H_8(q, xr xG)
    return enc_dec_jamtis_amount_plain(SWAP64LE(amount), sender_receiver_secret, baked_key);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const x25519_pubkey &baked_key)
{
    // a = system_endian( a_enc XOR H_8(q, xr xG) )
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
void make_jamtis_nominal_spend_key(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &nominal_spend_key_out)
{
    // K'_1 = Ko - H_n(q, C) X
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, amount_commitment, extension);  //H_n(q, C)
    nominal_spend_key_out = onetime_address;  //Ko_t
    reduce_seraphis_spendkey(extension, nominal_spend_key_out);  //(-H_n(q, C)) X + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_sender_receiver_secret_plain(const x25519_pubkey &sender_receiver_DH_derivation,
    const x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out)
{
    // recompute view tag and check that it matches; short-circuit on failure
    view_tag_t recomputed_view_tag;
    make_jamtis_view_tag(sender_receiver_DH_derivation, onetime_address, recomputed_view_tag);

    if (recomputed_view_tag != view_tag)
        return false;

    // q (normal derivation path)
    make_jamtis_sender_receiver_secret_plain(sender_receiver_DH_derivation,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount_plain(const rct::key &sender_receiver_secret,
    const x25519_pubkey &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decode_jamtis_amount_plain(encoded_amount, sender_receiver_secret, baked_key)};

    // C' = x' G + a' H
    make_jamtis_amount_blinding_factor_plain(sender_receiver_secret, baked_key, amount_blinding_factor_out);  // x'
    const rct::key nominal_amount_commitment{rct::commit(nominal_amount, rct::sk2rct(amount_blinding_factor_out))};

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
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decode_jamtis_amount_selfsend(encoded_amount, sender_receiver_secret)};

    // C' = x' G + a' H
    make_jamtis_amount_blinding_factor_selfsend(sender_receiver_secret, amount_blinding_factor_out);  // x'
    const rct::key nominal_amount_commitment{rct::commit(nominal_amount, rct::sk2rct(amount_blinding_factor_out))};

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
