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
#include "legacy_core_utils.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "int-util.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_extra.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_subaddress_spendkey(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const cryptonote::subaddress_index &subaddress_index,
    hw::device &hwdev,
    rct::key &subaddress_spendkey_out)
{
    // Hn(k^v, i) = Hn("SubAddr" || k^v || index_major || index_minor)
    const crypto::secret_key subaddress_modifier{
            hwdev.get_subaddress_secret_key(legacy_view_privkey, subaddress_index)
        };

    // Hn(k^v, i) G
    rct::key subaddress_extension;
    hwdev.scalarmultBase(subaddress_extension, rct::sk2rct(subaddress_modifier));

    // K^{s,i} = Hn(k^v, i) G + k^s G
    rct::addKeys(subaddress_spendkey_out, subaddress_extension, legacy_base_spend_pubkey);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_sender_receiver_secret(const rct::key &base_key,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &DH_privkey,
    hw::device &hwdev,
    crypto::secret_key &legacy_sender_receiver_secret_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(base_key), DH_privkey, derivation);

    // Hn(r K^v, t)
    hwdev.derivation_to_scalar(derivation, tx_output_index, legacy_sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_view_extension(const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const crypto::secret_key &legacy_view_privkey,
    const boost::optional<cryptonote::subaddress_index> &subaddress_index,
    hw::device &hwdev,
    crypto::secret_key &enote_view_extension_out)
{
    // Hn(r K^v, t)
    hwdev.derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, enote_view_extension_out);

    // subaddress index modifier
    if (subaddress_index)
    {
        // Hn(k^v, i) = Hn(k^v || index_major || index_minor)
        const crypto::secret_key subaddress_modifier{
                hwdev.get_subaddress_secret_key(legacy_view_privkey, *subaddress_index)
            };

        // Hn(r K^v, t) + Hn(k^v, i)
        hwdev.sc_secret_add(enote_view_extension_out, enote_view_extension_out, subaddress_modifier);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_onetime_address(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    rct::key &onetime_address_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(destination_viewkey), enote_ephemeral_privkey, derivation);

    // K^o = Hn(r K^v, t) G + K^s
    crypto::public_key onetime_address_temp;
    hwdev.derive_public_key(derivation, tx_output_index, rct::rct2pk(destination_spendkey), onetime_address_temp);

    onetime_address_out = rct::pk2rct(onetime_address_temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_key_image(const crypto::secret_key &enote_view_extension,
    const crypto::secret_key &legacy_spend_privkey,
    const rct::key &onetime_address,
    hw::device &hwdev,
    crypto::key_image &key_image_out)
{
    // KI = (view_key_stuff + k^s) * Hp(Ko)
    crypto::secret_key onetime_address_privkey;
    hwdev.sc_secret_add(onetime_address_privkey, enote_view_extension, legacy_spend_privkey);

    hwdev.generate_key_image(rct::rct2pk(onetime_address), onetime_address_privkey, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_auxilliary_key_image_v1(const crypto::secret_key &commitment_mask,
    const rct::key &onetime_address,
    hw::device &hwdev,
    crypto::key_image &auxilliary_key_image_out)
{
    // mask Hp(Ko)
    hwdev.generate_key_image(rct::rct2pk(onetime_address), commitment_mask, auxilliary_key_image_out);

    // z Hp(Ko) = - mask Hp(Ko)
    // note: do this after making the key image instead of computing it directly because there is no way to
    //       compute the scalar 'z = - mask' with hwdev
    auxilliary_key_image_out = rct::rct2ki(rct::scalarmultKey(rct::ki2rct(auxilliary_key_image_out), minus_one()));
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_amount_blinding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out)
{
    // Hn("commitment_mask", Hn(r K^v, t))
    amount_blinding_factor_out = rct::rct2sk(hwdev.genCommitmentMask(rct::sk2rct(sender_receiver_secret)));
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_amount_blinding_factor_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        hwdev,
        sender_receiver_secret);

    // amount mask: Hn("commitment_mask", Hn(r K^v, t))
    make_legacy_amount_blinding_factor_v2(sender_receiver_secret, hwdev, amount_blinding_factor_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_encoded_amount_v1(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::secret_key &amount_mask,
    const rct::xmr_amount amount,
    hw::device &hwdev,
    rct::key &encoded_amount_blinding_factor_out,
    rct::key &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        hwdev,
        sender_receiver_secret);

    // encoded amount blinding factor: enc(x) = x + Hn(Hn(r K^v, t))
    // encoded amount: enc(a) = to_key(little_endian(a)) + Hn(Hn(Hn(r K^v, t)))
    rct::ecdhTuple encoded_amount_info{
            .mask   = rct::sk2rct(amount_mask),
            .amount = rct::d2h(amount)
        };
    hwdev.ecdhEncode(encoded_amount_info, rct::sk2rct(sender_receiver_secret), false);

    encoded_amount_blinding_factor_out = encoded_amount_info.mask;
    encoded_amount_out                 = encoded_amount_info.amount;
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_encoded_amount_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount amount,
    hw::device &hwdev,
    jamtis::encoded_amount_t &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        hwdev,
        sender_receiver_secret);

    // encoded amount: enc(a) = a XOR_8 H32("amount", Hn(r K^v, t))
    rct::ecdhTuple encoded_amount_info{
            .mask   = rct::zero(),
            .amount = rct::d2h(amount)
        };
    hwdev.ecdhEncode(encoded_amount_info, rct::sk2rct(sender_receiver_secret), true);

    static_assert(sizeof(encoded_amount_info.amount) >= sizeof(encoded_amount_out), "");
    memcpy(encoded_amount_out.bytes, encoded_amount_info.amount.bytes, sizeof(encoded_amount_out));
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_amount_v1(const rct::key &expected_amount_commitment,
    const crypto::secret_key &sender_receiver_secret,
    const rct::key &encoded_amount_blinding_factor,
    const rct::key &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out)
{
    // 1. get amount and blinding factor
    // x = enc(x) - Hn(Hn(r K^v, t))
    // a = system_endian(trunc_8(enc(a) - Hn(Hn(Hn(r K^v, t)))))
    rct::ecdhTuple decoded_amount_info{
            .mask   = encoded_amount_blinding_factor,
            .amount = encoded_amount
        };
    hwdev.ecdhDecode(decoded_amount_info, rct::sk2rct(sender_receiver_secret), false);

    amount_blinding_factor_out = rct::rct2sk(decoded_amount_info.mask);
    amount_out                 = h2d(decoded_amount_info.amount);  //todo: is this endian-aware?

    // 2. try to reproduce the amount commitment (sanity check)
    if (!(rct::commit(amount_out, rct::sk2rct(amount_blinding_factor_out)) == expected_amount_commitment))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_amount_v1(const rct::key &expected_amount_commitment,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::key &encoded_amount_blinding_factor,
    const rct::key &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        hwdev,
        sender_receiver_secret);

    // complete the decoding
    return try_get_legacy_amount_v1(expected_amount_commitment,
        sender_receiver_secret,
        encoded_amount_blinding_factor,
        encoded_amount,
        hwdev,
        amount_blinding_factor_out,
        amount_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_amount_v2(const rct::key &expected_amount_commitment,
    const crypto::secret_key &sender_receiver_secret,
    const jamtis::encoded_amount_t &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out)
{
    // 1. a = enc(a) XOR_8 H32("amount", Hn(r K^v, t))
    rct::ecdhTuple decoded_amount_info;
    static_assert(sizeof(decoded_amount_info.amount) >= sizeof(encoded_amount), "");
    memcpy(decoded_amount_info.amount.bytes, encoded_amount.bytes, sizeof(encoded_amount));
    hwdev.ecdhDecode(decoded_amount_info, rct::sk2rct(sender_receiver_secret), true);

    amount_out = h2d(decoded_amount_info.amount);  //todo: is this endian-aware?

    // 2. x = Hn("commitment_mask", Hn(r K^v, t))
    make_legacy_amount_blinding_factor_v2(sender_receiver_secret, hwdev, amount_blinding_factor_out);

    // 3. try to reproduce the amount commitment (sanity check)
    if (!(rct::commit(amount_out, rct::sk2rct(amount_blinding_factor_out)) == expected_amount_commitment))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_amount_v2(const rct::key &expected_amount_commitment,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const jamtis::encoded_amount_t &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        hwdev,
        sender_receiver_secret);

    // complete the decoding
    return try_get_legacy_amount_v2(expected_amount_commitment,
        sender_receiver_secret,
        encoded_amount,
        hwdev,
        amount_blinding_factor_out,
        amount_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_view_tag(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    crypto::view_tag &view_tag_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(destination_viewkey),
        enote_ephemeral_privkey,
        derivation);

    // view_tag = H_1("view_tag", r K^v, t)
    hwdev.derive_view_tag(derivation, tx_output_index, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(const std::vector<rct::key> &enote_ephemeral_pubkeys,
    TxExtra &tx_extra_inout)
{
    std::vector<crypto::public_key> enote_ephemeral_pubkeys_typed;
    enote_ephemeral_pubkeys_typed.reserve(enote_ephemeral_pubkeys.size());

    for (const rct::key &enote_ephemeral_pubkey : enote_ephemeral_pubkeys)
        enote_ephemeral_pubkeys_typed.emplace_back(rct::rct2pk(enote_ephemeral_pubkey));

    return cryptonote::add_additional_tx_pub_keys_to_extra(tx_extra_inout, enote_ephemeral_pubkeys_typed);
}
//-------------------------------------------------------------------------------------------------------------------
void extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(const TxExtra &tx_extra,
    crypto::public_key &legacy_main_enote_ephemeral_pubkey_out,
    std::vector<crypto::public_key> &legacy_additional_enote_ephemeral_pubkeys)
{
    // 1. parse field
    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);

    // 2. try to get solitary enote ephemeral pubkey: r G
    // note: we must ALWAYS get this even if there are 'additional pub keys' because change outputs always use the
    //       main enote ephemeral pubkey for key derivations
    cryptonote::tx_extra_pub_key pub_key_field;

    if (cryptonote::find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
        legacy_main_enote_ephemeral_pubkey_out = pub_key_field.pub_key;
    else
        legacy_main_enote_ephemeral_pubkey_out = rct::rct2pk(rct::I);

    // 3. try to get 'additional' enote ephemeral pubkeys (one per output): r_t K^v_t
    cryptonote::tx_extra_additional_pub_keys additional_pub_keys_field;
    legacy_additional_enote_ephemeral_pubkeys.clear();

    if (cryptonote::find_tx_extra_field_by_type(tx_extra_fields, additional_pub_keys_field))
        legacy_additional_enote_ephemeral_pubkeys = additional_pub_keys_field.data;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
