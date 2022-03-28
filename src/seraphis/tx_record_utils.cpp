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
#include "tx_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "seraphis/jamtis_support_types.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "jamtis_address_tags.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_record_types.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_privkey(const crypto::secret_key &k_view_balance,
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
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    SpIntermediateEnoteRecordV1 &intermediate_record_out)
{
    // get intermediate record

    // q', K'_1 (jamtis plain variants)
    if (!jamtis::try_get_jamtis_nominal_spend_key_plain(sender_receiver_DH_derivation,
            enote.m_core.m_onetime_address,
            enote.m_view_tag,
            intermediate_record_out.m_nominal_sender_receiver_secret,
            intermediate_record_out.m_nominal_spend_key))
        return false;

    // t'_addr
    intermediate_record_out.m_nominal_address_tag =
        jamtis::decrypt_address_tag(intermediate_record_out.m_nominal_sender_receiver_secret, enote.m_addr_tag_enc);

    // copy enote
    intermediate_record_out.m_enote = enote;
    intermediate_record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &k_find_received,
    hw::device &hwdev,
    SpIntermediateEnoteRecordV1 &intermediate_record_out)
{
    // compute DH derivation then get intermediate record

    // sender-receiver DH derivation
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), k_find_received, derivation);

    return try_get_intermediate_enote_record_v1(enote, enote_ephemeral_pubkey, derivation, intermediate_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const crypto::secret_key &s_cipher_tag,
    SpEnoteRecordV1 &record_out)
{
    // get enote record

    // j
    jamtis::address_tag_MAC_t enote_tag_mac;
    record_out.m_address_index =
        jamtis::decipher_address_index(rct::sk2rct(s_cipher_tag), intermediate_record.m_nominal_address_tag, enote_tag_mac);

    // check if deciphering j succeeded
    if (enote_tag_mac != 0)
        return false;

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(wallet_spend_pubkey,
            s_generate_address,
            record_out.m_address_index,
            intermediate_record.m_nominal_spend_key))
        return false;

    // make amount commitment baked key
    crypto::secret_key address_privkey;
    jamtis::make_jamtis_address_privkey(s_generate_address, record_out.m_address_index, address_privkey);

    crypto::key_derivation amount_baked_key;
    jamtis::make_jamtis_amount_baked_key_plain_recipient(address_privkey,
        intermediate_record.m_enote_ephemeral_pubkey,
        amount_baked_key);

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_plain(intermediate_record.m_nominal_sender_receiver_secret,
            amount_baked_key,
            intermediate_record.m_enote.m_core.m_amount_commitment,
            intermediate_record.m_enote.m_encoded_amount,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // construct enote view privkey: k_a = H_n(q) + k^j_x + k_vb
    make_enote_view_privkey(k_view_balance,
        s_generate_address,
        record_out.m_address_index,
        intermediate_record.m_nominal_sender_receiver_secret,
        record_out.m_enote_view_privkey);

    // make key image
    make_seraphis_key_image(record_out.m_enote_view_privkey, rct::rct2pk(wallet_spend_pubkey), record_out.m_key_image);

    // copy enote and set type
    record_out.m_enote = intermediate_record.m_enote;
    record_out.m_enote_ephemeral_pubkey = intermediate_record.m_enote_ephemeral_pubkey;
    record_out.m_type = jamtis::JamtisEnoteType::PLAIN;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make secrets then get enote record
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    return try_get_enote_record_v1_plain(intermediate_record,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        s_cipher_tag,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // get intermediate record then get enote record
    crypto::secret_key k_find_received;
    jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);

    SpIntermediateEnoteRecordV1 intermediate_record;
    if (!try_get_intermediate_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            k_find_received,
            hw::get_device("default"),
            intermediate_record))
        return false;

    return try_get_enote_record_v1_plain(intermediate_record, wallet_spend_pubkey, k_view_balance, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const crypto::secret_key &k_find_received,
    SpEnoteRecordV1 &record_out)
{
    // sender-receiver DH derivation
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), k_find_received, derivation);

    // sender-receiver secret, nominal spend key
    rct::key sender_receiver_secret;
    rct::key nominal_recipient_spendkey;

    if(!jamtis::try_get_jamtis_nominal_spend_key_selfsend(derivation,
            enote.m_core.m_onetime_address,
            enote.m_view_tag,
            k_view_balance,
            enote_ephemeral_pubkey,
            sender_receiver_secret,
            nominal_recipient_spendkey))
        return false;

    // decrypt encrypted address tag
    jamtis::address_tag_t decrypted_addr_tag{decrypt_address_tag(sender_receiver_secret, enote.m_addr_tag_enc)};

    // convert raw address tag to address index
    jamtis::address_tag_MAC_t enote_tag_mac;
    record_out.m_address_index = address_tag_to_index(decrypted_addr_tag, enote_tag_mac);
    
    // check if deciphering j succeeded
    if (!jamtis::is_known_self_send_MAC(enote_tag_mac))
        return false;

    // check nominal spend key
    if (!jamtis::test_jamtis_nominal_spend_key(wallet_spend_pubkey,
            s_generate_address,
            record_out.m_address_index,
            nominal_recipient_spendkey))
        return false;

    // try to recover the amount
    if (!jamtis::try_get_jamtis_amount_selfsend(sender_receiver_secret,
            enote.m_core.m_amount_commitment,
            enote.m_encoded_amount,
            record_out.m_amount,
            record_out.m_amount_blinding_factor))
        return false;

    // construct enote view privkey: k_a = H_n(q) + k^j_x + k_vb
    make_enote_view_privkey(k_view_balance,
        s_generate_address,
        record_out.m_address_index,
        sender_receiver_secret,
        record_out.m_enote_view_privkey);

    // copy enote and set type
    record_out.m_enote = enote;
    record_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.m_type = jamtis::self_send_MAC_to_type(static_cast<jamtis::JamtisSelfSendMAC>(enote_tag_mac));

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make generate-address secret then get enote record
    crypto::secret_key s_generate_address;
    crypto::secret_key k_find_received;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);

    return try_get_enote_record_v1_selfsend(enote,
        enote_ephemeral_pubkey,
        wallet_spend_pubkey,
        k_view_balance,
        s_generate_address,
        k_find_received,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    return try_get_enote_record_v1_plain(enote, enote_ephemeral_pubkey, wallet_spend_pubkey, k_view_balance, record_out) ||
        try_get_enote_record_v1_selfsend(enote, enote_ephemeral_pubkey, wallet_spend_pubkey, k_view_balance, record_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_contextual_enote_record_v1(const SpEnoteRecordV1 &core_record,
    TxExtra memo,
    const rct::key &transaction_id,
    const std::uint64_t transaction_height,
    SpContextualEnoteRecordV1 &contextual_record_out)
{
    contextual_record_out.m_core = core_record;
    contextual_record_out.m_memo = std::move(memo);
    contextual_record_out.m_transaction_id = transaction_id;
    contextual_record_out.m_transaction_height = transaction_height;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
