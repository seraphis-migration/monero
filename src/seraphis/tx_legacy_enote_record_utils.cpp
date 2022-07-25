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
#include "tx_legacy_enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
#include "crypto/hash-ops.h"
}
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "int-util.h"
#include "legacy_core_utils.h"
#include "legacy_enote_types.h"
#include "legacy_enote_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_enote_record_types.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_check_legacy_view_tag(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation)
{
    // only legacy enote v4 has a view tag
    if (!enote.is_type<LegacyEnoteV4>())
        return true;

    // view_tag = H_1("view_tag", r K^v, t)
    crypto::view_tag nominal_view_tag;
    crypto::derive_view_tag(sender_receiver_DH_derivation, tx_output_index, nominal_view_tag);

    return nominal_view_tag == enote.get_enote<LegacyEnoteV4>().m_view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_check_legacy_nominal_spendkey(const rct::key &onetime_address,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    hw::device &hwdev,
    boost::optional<cryptonote::subaddress_index> &address_index_out)
{
    // Ko - Hn(r Kv, t) G
    crypto::public_key nominal_spendkey;
    hwdev.derive_subaddress_public_key(rct::rct2pk(onetime_address),
        sender_receiver_DH_derivation,
        tx_output_index,
        nominal_spendkey);

    // check base spendkey
    if (rct::pk2rct(nominal_spendkey) == legacy_base_spend_pubkey)
    {
        address_index_out = boost::none;
        return true;
    }

    // check subaddress map
    if (legacy_subaddress_map.find(rct::pk2rct(nominal_spendkey)) != legacy_subaddress_map.end())
    {
        address_index_out = legacy_subaddress_map.at(rct::pk2rct(nominal_spendkey));
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information_v1(const rct::xmr_amount &enote_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    amount_out = enote_amount;
    amount_blinding_factor_out = rct::rct2sk(rct::identity());

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information_v2(const rct::key &amount_commitment,
    const rct::key &encoded_amount_mask,
    const rct::key &encoded_amount,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. recover amount and blinding factor
    // a. Hn(k^v R_t, t)
    crypto::secret_key sender_receiver_secret;
    crypto::derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, sender_receiver_secret);

    // b. decode amount mask: x = enc(x) - Hn(Hn(r K^v, t))
    const rct::key mask_factor{rct::hash_to_scalar(rct::sk2rct(sender_receiver_secret))};  //Hn(Hn(r K^v, t))
    sc_sub(to_bytes(amount_blinding_factor_out), encoded_amount_mask.bytes, mask_factor.bytes);

    // c. decode amount: to_key(a) = enc(a) - Hn(Hn(Hn(r K^v, t)))
    const rct::key amount_factor{rct::hash_to_scalar(mask_factor)};                        //Hn(Hn(Hn(r K^v, t)))
    rct::key amount_serialized;
    sc_sub(amount_serialized.bytes, encoded_amount.bytes, amount_factor.bytes);
    amount_out = h2d(amount_serialized);

    // 2. try to reproduce amount commitment (sanity check)
    return rct::commit(amount_out, rct::sk2rct(amount_blinding_factor_out)) == amount_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information_v3(const rct::key &amount_commitment,
const rct::xmr_amount &encoded_amount,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. recover amount and blinding factor
    // a. Hn(k^v R_t, t)
    crypto::secret_key sender_receiver_secret;
    crypto::derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, sender_receiver_secret);

    // b. recover amount mask: x = Hn("commitment_mask", Hn(r K^v, t))
    make_legacy_amount_blinding_factor_v2(sender_receiver_secret, amount_blinding_factor_out);

    // c. decode amount: a = enc(a) XOR8 Hn("amount", Hn(r K^v, t)))
    rct::key amount_encoding_factor;
    make_legacy_amount_encoding_factor_v2(sender_receiver_secret, amount_encoding_factor);
    amount_out = legacy_xor_encoded_amount(encoded_amount, amount_encoding_factor);

    // 2. try to reproduce amount commitment (sanity check)
    return rct::commit(amount_out, rct::sk2rct(amount_blinding_factor_out)) == amount_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information(const LegacyEnoteVariant &enote,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    if (enote.is_type<LegacyEnoteV1>())
    {
        return try_get_amount_commitment_information_v1(enote.get_enote<LegacyEnoteV1>().m_amount,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (enote.is_type<LegacyEnoteV2>())
    {
        return try_get_amount_commitment_information_v2(enote.get_enote<LegacyEnoteV2>().m_amount_commitment,
            enote.get_enote<LegacyEnoteV2>().m_encoded_amount_blinding_factor,
            enote.get_enote<LegacyEnoteV2>().m_encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (enote.is_type<LegacyEnoteV3>())
    {
        return try_get_amount_commitment_information_v3(enote.get_enote<LegacyEnoteV3>().m_amount_commitment,
            enote.get_enote<LegacyEnoteV3>().m_encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (enote.is_type<LegacyEnoteV4>())
    {
        return try_get_amount_commitment_information_v3(enote.get_enote<LegacyEnoteV4>().m_amount_commitment,
            enote.get_enote<LegacyEnoteV4>().m_encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            amount_out,
            amount_blinding_factor_out);
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_legacy_enote_record_info(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    crypto::secret_key &enote_view_privkey_out,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out,
    boost::optional<cryptonote::subaddress_index> &subaddress_index_out)
{
    // r K^v = k^v R
    crypto::key_derivation sender_receiver_DH_derivation;
    crypto::generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey),
        legacy_view_privkey,
        sender_receiver_DH_derivation);

    // check view tag (for enotes that have it)
    if (!try_check_legacy_view_tag(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            sender_receiver_DH_derivation))
        return false;

    // nominal spendkey check (and get subaddress index if applicable)
    if (!try_check_legacy_nominal_spendkey(enote.onetime_address(),
            tx_output_index,
            sender_receiver_DH_derivation,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            hw::get_device("default"),
            subaddress_index_out))
        return false;

    // compute enote view privkey
    make_legacy_enote_view_privkey(tx_output_index,
        sender_receiver_DH_derivation,
        legacy_view_privkey,
        subaddress_index_out,
        enote_view_privkey_out);

    // try to get amount commitment information
    if (!try_get_amount_commitment_information(enote,
            tx_output_index,
            sender_receiver_DH_derivation,
            amount_out,
            amount_blinding_factor_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_basic_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    hw::device &hwdev,
    LegacyBasicEnoteRecord &basic_record_out)
{
    // check view tag (for enotes that have it)
    if (!try_check_legacy_view_tag(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            sender_receiver_DH_derivation))
        return false;

    // nominal spendkey check (and get subaddress index if applicable)
    if (!try_check_legacy_nominal_spendkey(enote.onetime_address(),
            tx_output_index,
            sender_receiver_DH_derivation,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            hwdev,
            basic_record_out.m_address_index))
        return false;

    // set miscellaneous fields
    basic_record_out.m_enote = enote;
    basic_record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    basic_record_out.m_tx_output_index = tx_output_index;
    basic_record_out.m_unlock_time = unlock_time;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_basic_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyBasicEnoteRecord &basic_record_out)
{
    // r K^v = k^v R
    crypto::key_derivation sender_receiver_DH_derivation;
    hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), legacy_view_privkey, sender_receiver_DH_derivation);

    // finish getting record
    return try_get_legacy_basic_enote_record(enote,
        enote_ephemeral_pubkey,
        tx_output_index,
        unlock_time,
        sender_receiver_DH_derivation,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        hwdev,
        basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_intermediate_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    LegacyIntermediateEnoteRecord &record_out)
{
    // try to get intermediate info
    if (!try_get_intermediate_legacy_enote_record_info(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            record_out.m_enote_view_privkey,
            record_out.m_amount,
            record_out.m_amount_blinding_factor,
            record_out.m_address_index))
        return false;

    // collect miscellaneous pieces
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_tx_output_index = tx_output_index;
    record_out.m_unlock_time = unlock_time;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_intermediate_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    LegacyIntermediateEnoteRecord &record_out)
{
    // if the enote is owned by a subaddress, make the subaddress spendkey
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    if (basic_record.m_address_index)
    {
        rct::key subaddress_spendkey;
        make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
            legacy_view_privkey,
            *(basic_record.m_address_index),
            subaddress_spendkey);

        legacy_subaddress_map[subaddress_spendkey] = *(basic_record.m_address_index);
    }

    // finish getting the intermediate enote record
    return try_get_legacy_intermediate_enote_record(basic_record.m_enote,
        basic_record.m_enote_ephemeral_pubkey,
        basic_record.m_tx_output_index,
        basic_record.m_unlock_time,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    LegacyEnoteRecord &record_out)
{
    // try to get intermediate info (non-spendkey information)
    if (!try_get_intermediate_legacy_enote_record_info(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            record_out.m_enote_view_privkey,
            record_out.m_amount,
            record_out.m_amount_blinding_factor,
            record_out.m_address_index))
        return false;

    // compute the key image
    make_legacy_key_image(record_out.m_enote_view_privkey,
        legacy_spend_privkey,
        enote.onetime_address(),
        record_out.m_key_image);

    // collect miscellaneous pieces
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_tx_output_index = tx_output_index;
    record_out.m_unlock_time = unlock_time;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    LegacyEnoteRecord &record_out)
{
    // if the enote is owned by a subaddress, make the subaddress spendkey
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    if (basic_record.m_address_index)
    {
        rct::key subaddress_spendkey;
        make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
            legacy_view_privkey,
            *(basic_record.m_address_index),
            subaddress_spendkey);

        legacy_subaddress_map[subaddress_spendkey] = *(basic_record.m_address_index);
    }

    // finish getting the full enote record
    return try_get_legacy_enote_record(basic_record.m_enote,
        basic_record.m_enote_ephemeral_pubkey,
        basic_record.m_tx_output_index,
        basic_record.m_unlock_time,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::key_image &key_image,
    LegacyEnoteRecord &record_out)
{
    record_out.m_enote = intermediate_record.m_enote;
    record_out.m_enote_ephemeral_pubkey = intermediate_record.m_enote_ephemeral_pubkey;
    record_out.m_enote_view_privkey = intermediate_record.m_enote_view_privkey;
    record_out.m_amount = intermediate_record.m_amount;
    record_out.m_amount_blinding_factor = intermediate_record.m_amount_blinding_factor;
    record_out.m_key_image = key_image;
    record_out.m_address_index = intermediate_record.m_address_index;
    record_out.m_tx_output_index = intermediate_record.m_tx_output_index;
    record_out.m_unlock_time = intermediate_record.m_unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyEnoteRecord &record_out)
{
    // make key image: ((view key stuff) + k^s) * Hp(Ko)
    crypto::key_image key_image;
    make_legacy_key_image(intermediate_record.m_enote_view_privkey,
        legacy_spend_privkey,
        intermediate_record.m_enote.onetime_address(),
        key_image);

    // assemble data
    get_legacy_enote_record(intermediate_record, key_image, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
