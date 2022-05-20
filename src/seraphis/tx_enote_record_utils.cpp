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
#include "tx_enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "seraphis/jamtis_support_types.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_privkey_helper(const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t j,
    const rct::key &sender_receiver_secret,
    crypto::secret_key &enote_view_privkey_out)
{
    // enote view privkey: k_a = H_n(q) + k^j_x + k_vb
    crypto::secret_key spendkey_extension;  //k^j_x
    crypto::secret_key sender_extension;    //H_n(q)
    jamtis::make_jamtis_spendkey_extension(s_generate_address, j, spendkey_extension);
    jamtis::make_jamtis_onetime_address_extension(sender_receiver_secret, sender_extension);

    // k_vb
    enote_view_privkey_out = k_view_balance;
    // k^j_x + k_vb
    sc_add(to_bytes(enote_view_privkey_out), to_bytes(spendkey_extension), to_bytes(enote_view_privkey_out));
    // H_n(q) + k^j_x + k_vb
    sc_add(to_bytes(enote_view_privkey_out), to_bytes(sender_extension), to_bytes(enote_view_privkey_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_seraphis_key_image_helper(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &enote_view_privkey,
    crypto::key_image &key_image_out)
{
    // make key image: k_m/k_a U
    rct::key wallet_spend_pubkey_base{wallet_spend_pubkey};  //k_vb X + k_m U
    reduce_seraphis_spendkey(k_view_balance, wallet_spend_pubkey_base);  //k_m U
    make_seraphis_key_image(enote_view_privkey, rct::rct2pk(wallet_spend_pubkey_base), key_image_out);  //k_m/k_a U
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_enote_record_info_v1_helper(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    jamtis::address_index_t &address_index_out,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // get intermediate info (address index, amount, amount blinding factor) for a plain jamtis enote

    // j (fails if mac is 0)
    if (!jamtis::try_decipher_address_index(cipher_context, basic_record.m_nominal_address_tag, address_index_out))
        return false;

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(wallet_spend_pubkey,
            s_generate_address,
            address_index_out,
            basic_record.m_nominal_spend_key))
        return false;

    // make amount commitment baked key
    crypto::secret_key address_privkey;
    jamtis::make_jamtis_address_privkey(s_generate_address, address_index_out, address_privkey);

    crypto::key_derivation amount_baked_key;
    jamtis::make_jamtis_amount_baked_key_plain_recipient(address_privkey,
        basic_record.m_enote_ephemeral_pubkey,
        amount_baked_key);

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_plain(basic_record.m_nominal_sender_receiver_secret,
            amount_baked_key,
            basic_record.m_enote.m_core.m_amount_commitment,
            basic_record.m_enote.m_encoded_amount,
            amount_out,
            amount_blinding_factor_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_final_enote_record_info_v1_helper(const rct::key &sender_receiver_secret,
    const jamtis::address_index_t j,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    crypto::secret_key &enote_view_privkey_out,
    crypto::key_image &key_image_out)
{
    // get final info (enote view privkey, key image)

    // construct enote view privkey: k_a = H_n(q) + k^j_x + k_vb
    make_enote_view_privkey_helper(k_view_balance,
        s_generate_address,
        j,
        sender_receiver_secret,
        enote_view_privkey_out);

    // make key image: k_m/k_a U
    make_seraphis_key_image_helper(wallet_spend_pubkey, k_view_balance, enote_view_privkey_out, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &input_context,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // get basic record

    // q', K'_1 (jamtis plain variants)
    if (!jamtis::try_get_jamtis_nominal_spend_key_plain(sender_receiver_DH_derivation,
            input_context,
            enote.m_core.m_onetime_address,
            enote.m_view_tag,
            basic_record_out.m_nominal_sender_receiver_secret,
            basic_record_out.m_nominal_spend_key))
        return false;

    // t'_addr
    basic_record_out.m_nominal_address_tag =
        jamtis::decrypt_address_tag(basic_record_out.m_nominal_sender_receiver_secret, enote.m_addr_tag_enc);

    // copy enote
    basic_record_out.m_enote = enote;
    basic_record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_find_received,
    hw::device &hwdev,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // compute DH derivation then get basic record

    // sender-receiver DH derivation
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), k_find_received, derivation);

    return try_get_basic_enote_record_v1(enote, enote_ephemeral_pubkey, derivation, input_context, basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // get intermediate enote record

    // use helper to get info
    if (!try_get_intermediate_enote_record_info_v1_helper(basic_record,
            wallet_spend_pubkey,
            s_generate_address,
            cipher_context,
            record_out.m_address_index,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // copy enote and record sender-receiver secret
    record_out.m_enote = basic_record.m_enote;
    record_out.m_enote_ephemeral_pubkey = basic_record.m_enote_ephemeral_pubkey;
    record_out.m_nominal_sender_receiver_secret = basic_record.m_nominal_sender_receiver_secret;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // make blowfish context then get intermediate enote record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    return try_get_intermediate_enote_record_v1(basic_record,
        wallet_spend_pubkey,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // make basic record then get intermediate record
    SpBasicEnoteRecordV1 basic_record;
    if (!try_get_basic_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            k_find_received,
            hw::get_device("default"),
            basic_record))
        return false;

    return try_get_intermediate_enote_record_v1(basic_record, wallet_spend_pubkey, s_generate_address, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    // get enote record

    // use helper to get intermediate info (address index, amount, amount blinding factor)
    if (!try_get_intermediate_enote_record_info_v1_helper(basic_record,
            wallet_spend_pubkey,
            s_generate_address,
            cipher_context,
            record_out.m_address_index,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // use helper to get final info (enote view privkey, key image)
    get_final_enote_record_info_v1_helper(basic_record.m_nominal_sender_receiver_secret,
        record_out.m_address_index,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        record_out.m_enote_view_privkey,
        record_out.m_key_image);

    // copy enote and set type
    record_out.m_enote = basic_record.m_enote;
    record_out.m_enote_ephemeral_pubkey = basic_record.m_enote_ephemeral_pubkey;
    record_out.m_type = jamtis::JamtisEnoteType::PLAIN;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make secrets then get enote record
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    return try_get_enote_record_v1_plain(basic_record,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // get basic record then get enote record
    crypto::secret_key k_find_received;
    jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);

    SpBasicEnoteRecordV1 basic_record;
    if (!try_get_basic_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            k_find_received,
            hw::get_device("default"),
            basic_record))
        return false;

    return try_get_enote_record_v1_plain(basic_record, wallet_spend_pubkey, k_view_balance, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out)
{
    // get final info then copy remaining pieces from an intermediate record

    // use helper to get final info (enote view privkey, key image)
    get_final_enote_record_info_v1_helper(intermediate_record.m_nominal_sender_receiver_secret,
        intermediate_record.m_address_index,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        record_out.m_enote_view_privkey,
        record_out.m_key_image);

    // copy misc pieces from the intermediate record
    record_out.m_enote = intermediate_record.m_enote;
    record_out.m_enote_ephemeral_pubkey = intermediate_record.m_enote_ephemeral_pubkey;
    record_out.m_amount = intermediate_record.m_amount;
    record_out.m_amount_blinding_factor = intermediate_record.m_amount_blinding_factor;
    record_out.m_address_index = intermediate_record.m_address_index;
    record_out.m_type = jamtis::JamtisEnoteType::PLAIN;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend_for_type(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::JamtisSelfSendType expected_type,
    SpEnoteRecordV1 &record_out)
{
    // sender-receiver secret for expected self-send type
    rct::key q;
    jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        input_context,
        expected_type,
        q);

    // decrypt encrypted address tag
    const jamtis::address_tag_t decrypted_addr_tag{decrypt_address_tag(q, enote.m_addr_tag_enc)};

    // try to get the address index (includes MAC check)
    if (!try_get_address_index(decrypted_addr_tag, record_out.m_address_index))
        return false;

    // nominal spend key
    rct::key nominal_recipient_spendkey;
    jamtis::make_jamtis_nominal_spend_key(q, enote.m_core.m_onetime_address, nominal_recipient_spendkey);

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(wallet_spend_pubkey,
            s_generate_address,
            record_out.m_address_index,
            nominal_recipient_spendkey))
        return false;

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_selfsend(q,
            enote.m_core.m_amount_commitment,
            enote.m_encoded_amount,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // construct enote view privkey: k_a = H_n(q) + k^j_x + k_vb
    make_enote_view_privkey_helper(k_view_balance,
        s_generate_address,
        record_out.m_address_index,
        q,
        record_out.m_enote_view_privkey);

    // make key image: k_m/k_a U
    make_seraphis_key_image_helper(wallet_spend_pubkey,
        k_view_balance,
        record_out.m_enote_view_privkey,
        record_out.m_key_image);

    // copy enote and set type
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_type = jamtis::self_send_type_to_enote_type(expected_type);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out)
{
    // try to get an enote record with all the self-send types
    for (unsigned char self_send_type{0};
        self_send_type <= static_cast<unsigned char>(jamtis::JamtisSelfSendType::MAX);
        ++self_send_type)
    {
        if (try_get_enote_record_v1_selfsend_for_type(enote,
            enote_ephemeral_pubkey,
            input_context,
            wallet_spend_pubkey,
            k_view_balance,
            s_generate_address,
            static_cast<jamtis::JamtisSelfSendType>(self_send_type),
            record_out))
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make generate-address secret then get enote record
    crypto::secret_key s_generate_address;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);

    return try_get_enote_record_v1_selfsend(enote,
        enote_ephemeral_pubkey,
        input_context,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // note: check for selfsend first since it is more efficient
    //       (assumes selfsends and plain enotes appear in similar quantities)
    return try_get_enote_record_v1_selfsend(enote,
            enote_ephemeral_pubkey,
            input_context,
            wallet_spend_pubkey,
            k_view_balance,
            record_out) ||
        try_get_enote_record_v1_plain(enote,
            enote_ephemeral_pubkey,
            input_context,
            wallet_spend_pubkey,
            k_view_balance,
            record_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_spent_enote_v1(const SpContextualEnoteRecordV1 &contextual_enote_record,
    const SpEnoteRecordSpentContextV1 &spent_context,
    SpSpentEnoteV1 &spent_enote_out)
{
    spent_enote_out.m_contextual_enote_record = contextual_enote_record;
    spent_enote_out.m_spent_context = spent_context;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_spent_enote_v1(const SpContextualEnoteRecordV1 &contextual_enote_record,
    const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpSpentEnoteV1 &spent_enote_out)
{
    if (!contextual_key_image_set.has_key_image(contextual_enote_record.m_record.m_key_image))
        return false;

    make_spent_enote_v1(contextual_enote_record, contextual_key_image_set.m_spent_context, spent_enote_out);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
