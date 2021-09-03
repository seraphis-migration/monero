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
#include "enote_record_utils_legacy.h"

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <unordered_map>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_add_legacy_subaddress_spendkey(const boost::optional<cryptonote::subaddress_index> &address_index,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map_inout)
{
    // 1. check if there is an address index
    if (!address_index)
        return false;

    // 2. make the subaddress spendkey
    rct::key subaddress_spendkey;
    make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
        legacy_view_privkey,
        *address_index,
        hwdev,
        subaddress_spendkey);

    // 3. add it to the map
    legacy_subaddress_map_inout[subaddress_spendkey] = *address_index;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_check_legacy_view_tag(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    hw::device &hwdev)
{
    // 1. obtain the view tag
    // - only legacy enotes v4 and v5 have a view tag
    struct visitor final : public tools::variant_static_visitor<boost::optional<crypto::view_tag>>
    {
        using variant_static_visitor::operator();  //for blank overload
        boost::optional<crypto::view_tag> operator()(const LegacyEnoteV1 &enote) const { return boost::none; }
        boost::optional<crypto::view_tag> operator()(const LegacyEnoteV2 &enote) const { return boost::none; }
        boost::optional<crypto::view_tag> operator()(const LegacyEnoteV3 &enote) const { return boost::none; }
        boost::optional<crypto::view_tag> operator()(const LegacyEnoteV4 &enote) const { return enote.view_tag; }
        boost::optional<crypto::view_tag> operator()(const LegacyEnoteV5 &enote) const { return enote.view_tag; }
    };

    const boost::optional<crypto::view_tag> enote_view_tag{enote.visit(visitor{})};

    if (!enote_view_tag)
        return true;  //check succeeds automatically for enotes with no view tag

    // 2. view_tag = H_1("view_tag", r K^v, t)
    crypto::view_tag nominal_view_tag;
    hwdev.derive_view_tag(sender_receiver_DH_derivation, tx_output_index, nominal_view_tag);

    // 3. check the view tag
    if (nominal_view_tag == *enote_view_tag)
        return true;

    return false;
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
    // 1. nominal spendkey = Ko - Hn(r Kv, t) G
    crypto::public_key nominal_spendkey;
    hwdev.derive_subaddress_public_key(rct::rct2pk(onetime_address),
        sender_receiver_DH_derivation,
        tx_output_index,
        nominal_spendkey);

    // 2. check base spendkey
    if (rct::pk2rct(nominal_spendkey) == legacy_base_spend_pubkey)
    {
        address_index_out = boost::none;
        return true;
    }

    // 3. check subaddress map
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
    amount_out                 = enote_amount;
    amount_blinding_factor_out = rct::rct2sk(rct::I);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information_v2(const rct::key &amount_commitment,
    const rct::key &encoded_amount_mask,
    const rct::key &encoded_amount,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    hw::device &hwdev,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. Hn(k^v R_t, t)
    crypto::secret_key sender_receiver_secret;
    hwdev.derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, sender_receiver_secret);

    // 2. recover the amount mask and amount
    if (!try_get_legacy_amount_v1(amount_commitment,
            sender_receiver_secret,
            encoded_amount_mask,
            encoded_amount,
            hwdev,
            amount_blinding_factor_out,
            amount_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information_v3(const rct::key &amount_commitment,
    const jamtis::encoded_amount_t &encoded_amount,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    hw::device &hwdev,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. Hn(k^v R_t, t)
    crypto::secret_key sender_receiver_secret;
    hwdev.derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, sender_receiver_secret);

    // 2. recover the amount mask and amount
    if (!try_get_legacy_amount_v2(amount_commitment,
            sender_receiver_secret,
            encoded_amount,
            hwdev,
            amount_blinding_factor_out,
            amount_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information(const LegacyEnoteVariant &enote,
    const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    hw::device &hwdev,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    if (const LegacyEnoteV1 *enote_ptr = enote.try_unwrap<LegacyEnoteV1>())
    {
        return try_get_amount_commitment_information_v1(enote_ptr->amount,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (const LegacyEnoteV2 *enote_ptr = enote.try_unwrap<LegacyEnoteV2>())
    {
        return try_get_amount_commitment_information_v2(enote_ptr->amount_commitment,
            enote_ptr->encoded_amount_blinding_factor,
            enote_ptr->encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (const LegacyEnoteV3 *enote_ptr = enote.try_unwrap<LegacyEnoteV3>())
    {
        return try_get_amount_commitment_information_v3(enote_ptr->amount_commitment,
            enote_ptr->encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (const LegacyEnoteV4 *enote_ptr = enote.try_unwrap<LegacyEnoteV4>())
    {
        return try_get_amount_commitment_information_v1(enote_ptr->amount,
            amount_out,
            amount_blinding_factor_out);
    }
    else if (const LegacyEnoteV5 *enote_ptr = enote.try_unwrap<LegacyEnoteV5>())
    {
        return try_get_amount_commitment_information_v3(enote_ptr->amount_commitment,
            enote_ptr->encoded_amount,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev,
            amount_out,
            amount_blinding_factor_out);
    }
    else
        CHECK_AND_ASSERT_THROW_MES(false, "try get legacy amount commitment information: unknown enote type.");

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
    hw::device &hwdev,
    crypto::secret_key &enote_view_extension_out,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out,
    boost::optional<cryptonote::subaddress_index> &subaddress_index_out)
{
    // 1. r K^v = k^v R
    crypto::key_derivation sender_receiver_DH_derivation;
    hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey),
        legacy_view_privkey,
        sender_receiver_DH_derivation);

    // 2. check view tag (for enotes that have it)
    if (!try_check_legacy_view_tag(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev))
        return false;

    // 3. nominal spendkey check (and get subaddress index if applicable)
    if (!try_check_legacy_nominal_spendkey(onetime_address_ref(enote),
            tx_output_index,
            sender_receiver_DH_derivation,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            hwdev,
            subaddress_index_out))
        return false;

    // 4. compute enote view privkey
    make_legacy_enote_view_extension(tx_output_index,
        sender_receiver_DH_derivation,
        legacy_view_privkey,
        subaddress_index_out,
        hwdev,
        enote_view_extension_out);

    // 5. try to get amount commitment information
    if (!try_get_amount_commitment_information(enote,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev,
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
    // 1. check view tag (for enotes that have it)
    if (!try_check_legacy_view_tag(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            sender_receiver_DH_derivation,
            hwdev))
        return false;

    // 2. nominal spendkey check (and get subaddress index if applicable)
    if (!try_check_legacy_nominal_spendkey(onetime_address_ref(enote),
            tx_output_index,
            sender_receiver_DH_derivation,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            hwdev,
            basic_record_out.address_index))
        return false;

    // 3. set miscellaneous fields
    basic_record_out.enote                  = enote;
    basic_record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    basic_record_out.tx_output_index        = tx_output_index;
    basic_record_out.unlock_time            = unlock_time;

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
    // 1. r K^v = k^v R
    crypto::key_derivation sender_receiver_DH_derivation;
    hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey),
        legacy_view_privkey,
        sender_receiver_DH_derivation);

    // 2. finish getting the record
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
    hw::device &hwdev,
    LegacyIntermediateEnoteRecord &record_out)
{
    // 1. try to get intermediate info
    if (!try_get_intermediate_legacy_enote_record_info(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            hwdev,
            record_out.enote_view_extension,
            record_out.amount,
            record_out.amount_blinding_factor,
            record_out.address_index))
        return false;

    // 2. collect miscellaneous pieces
    record_out.enote                  = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.tx_output_index        = tx_output_index;
    record_out.unlock_time            = unlock_time;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_intermediate_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyIntermediateEnoteRecord &record_out)
{
    // 1. if the enote is owned by a subaddress, make the subaddress spendkey
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    try_add_legacy_subaddress_spendkey(basic_record.address_index,
        legacy_base_spend_pubkey,
        legacy_view_privkey,
        hwdev,
        legacy_subaddress_map);

    // 2. finish getting the intermediate enote record
    return try_get_legacy_intermediate_enote_record(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.tx_output_index,
        basic_record.unlock_time,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        hwdev,
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
    hw::device &hwdev,
    LegacyEnoteRecord &record_out)
{
    // 1. try to get intermediate info
    if (!try_get_intermediate_legacy_enote_record_info(enote,
            enote_ephemeral_pubkey,
            tx_output_index,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            hwdev,
            record_out.enote_view_extension,
            record_out.amount,
            record_out.amount_blinding_factor,
            record_out.address_index))
        return false;

    // 2. compute the key image
    make_legacy_key_image(record_out.enote_view_extension,
        legacy_spend_privkey,
        onetime_address_ref(enote),
        hwdev,
        record_out.key_image);

    // 3. collect miscellaneous pieces
    record_out.enote                  = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.tx_output_index        = tx_output_index;
    record_out.unlock_time            = unlock_time;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_legacy_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyEnoteRecord &record_out)
{
    // 1. if the enote is owned by a subaddress, make the subaddress spendkey
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    try_add_legacy_subaddress_spendkey(basic_record.address_index,
        legacy_base_spend_pubkey,
        legacy_view_privkey,
        hwdev,
        legacy_subaddress_map);

    // 2. finish getting the full enote record
    return try_get_legacy_enote_record(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.tx_output_index,
        basic_record.unlock_time,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        hwdev,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::key_image &key_image,
    LegacyEnoteRecord &record_out)
{
    record_out.enote                  = intermediate_record.enote;
    record_out.enote_ephemeral_pubkey = intermediate_record.enote_ephemeral_pubkey;
    record_out.enote_view_extension   = intermediate_record.enote_view_extension;
    record_out.amount                 = intermediate_record.amount;
    record_out.amount_blinding_factor = intermediate_record.amount_blinding_factor;
    record_out.key_image              = key_image;
    record_out.address_index          = intermediate_record.address_index;
    record_out.tx_output_index        = intermediate_record.tx_output_index;
    record_out.unlock_time            = intermediate_record.unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyEnoteRecord &record_out)
{
    // 1. make key image: ((view key stuff) + k^s) * Hp(Ko)
    crypto::key_image key_image;
    make_legacy_key_image(intermediate_record.enote_view_extension,
        legacy_spend_privkey,
        onetime_address_ref(intermediate_record.enote),
        hwdev,
        key_image);

    // 2. assemble data
    get_legacy_enote_record(intermediate_record, key_image, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
