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

// Seraphis transaction-reading utilities

#pragma once

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "jamtis_address_tag_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{


/**
* brief: try_get_basic_enote_record_v1 - try to extract a basic enote record from an enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: sender_receiver_DH_derivation -
* outparam: basic_record_out -
* return: true if an extraction succeeded
*/
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    SpBasicEnoteRecordV1 &basic_record_out);
bool try_get_basic_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &k_find_received,
    hw::device &hwdev,
    SpBasicEnoteRecordV1 &basic_record_out);
/**
* brief: try_get_intermediate_enote_record_v1 - try to extract an intermediate enote record from an enote
* param: basic_record -
* param: wallet_spend_pubkey -
* param: s_generate_address -
* param: cipher_context -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out);
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out);
bool try_get_intermediate_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out);
/**
* brief: try_get_enote_record_v1_plain - try to extract an enote record from an enote treated as a plain jamtis enote
* param: basic_record -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: s_generate_address -
* param: cipher_context -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out);
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out);
bool try_get_enote_record_v1_plain(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out);
/**
* brief: get_enote_record_v1_plain - get an enote record from an enote treated as a plain jamtis enote
*   - precondition: data stored in the intermediate record is assumed to be correct/valid for this user
* param: intermediate_record -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: s_generate_address -
* outparam: record_out -
*/
void get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out);
/**
* brief: try_get_enote_record_v1_selfsend - try to extract an enote record from an enote treated as a selfsend jamtis enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: s_generate_address -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out);
bool try_get_enote_record_v1_selfsend(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out);
/**
* brief: try_get_enote_record_v1 - try to extract an enote record from an enote (which can be any jamtis enote type)
* param: enote -
* param: enote_ephemeral_pubkey -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_enote_record_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out);
/**
* brief: make_contextual_enote_record_v1 - make a contextual enote record from a normal enote record
* param: core_record -
* param: memo -
* param: transaction_id -
* param: transaction_height -
* param: ledger_index -
* outparam: contextual_record_out -
*/
void make_contextual_enote_record_v1(const SpEnoteRecordV1 &core_record,
    TxExtra memo,
    const rct::key &transaction_id,
    const std::uint64_t transaction_height,
    const std::uint64_t ledger_index,
    SpContextualEnoteRecordV1 &contextual_record_out);

} //namespace sp
