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

// Utilities for performing balance recovery.

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers

//standard headers
#include <functional>
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{
namespace scanning
{

/**
* brief: try_find_legacy_enotes_in_tx - obtain contextual basic records from a legacy tx's contents
* param: legacy_base_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: block_index -
* param: block_timestamp -
* param: transaction_id -
* param: total_enotes_before_tx - number of legacy enotes ordered before this tx (set to '0' if tx is non-ledger)
* param: unlock_time -
* param: tx_memo -
* param: enotes_in_tx -
* param: origin_status -
* inoutparam: hwdev -
* outparam: basic_records_in_tx_out -
*/
bool try_find_legacy_enotes_in_tx(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<LegacyEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out);
/**
* brief: try_find_sp_enotes_in_tx - obtain contextual basic records from a seraphis tx's contents
* param: xk_find_received -
* param: block_index -
* param: block_timestamp -
* param: transaction_id -
* param: total_enotes_before_tx - number of seraphis enotes ordered before this tx (set to '0' if tx is non-ledger)
* param: input_context -
* param: tx_supplement -
* param: enotes_in_tx -
* param: origin_status -
* outparam: basic_records_in_tx_out -
*/
bool try_find_sp_enotes_in_tx(const crypto::x25519_secret_key &xk_find_received,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out);
/**
* brief: try_collect_key_images_from_tx - if a tx has key images, collect them into a contextual key image set
* param: block_index -
* param: block_timestamp -
* param: transaction_id -
* param: legacy_key_images_in_tx -
* param: sp_key_images_in_tx -
* param: spent_status -
* outparam: contextual_key_images_out -
* return: true if a set was made (there was at least one key image available)
*/
bool try_collect_key_images_from_tx(const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    std::vector<crypto::key_image> legacy_key_images_in_tx,
    std::vector<crypto::key_image> sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    SpContextualKeyImageSetV1 &contextual_key_images_out);
/**
* brief: process_chunk_intermediate_legacy - process a chunk of contextual basic records with a legacy view privkey
* param: legacy_base_spend_pubkey -
* param: legacy_view_privkey -
* param: check_key_image_is_known_func - callback for checking if a key image is known by the caller
* param: chunk_basic_records_per_tx - [ tx id : contextual basic record ]
* param: chunk_contextual_key_images -
* inoutparam: hwdev -
* outparam: found_enote_records_out - [ H32(Ko, a) : legacy contextual intermediate enote record ]
*   note: mapped to H32(Ko, a) so enotes with the same key image but different amounts will be recovered
* outparam: found_spent_key_images_out - [ KI : spent context ]
*/
void process_chunk_intermediate_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    // note: mapped to H32(Ko, a) so enotes with the same key image but different amounts will be recovered
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out);
/**
* brief: process_chunk_full_legacy - process a chunk of contextual basic records with legacy view and spend privkeys
* param: legacy_base_spend_pubkey -
* param: legacy_spend_privkey -
* param: legacy_view_privkey -
* param: check_key_image_is_known_func - callback for checking if a key image is known by the caller
* param: chunk_basic_records_per_tx - [ tx id : contextual basic record ]
* param: chunk_contextual_key_images -
* inoutparam: hwdev -
* outparam: found_enote_records_out - [ H32(Ko, a) : legacy contextual intermediate enote record ]
*   note: mapped to H32(Ko, a) so enotes with the same key image but different amounts will be recovered
* outparam: found_spent_key_images_out - [ KI : spent context ]
*/
void process_chunk_full_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out);
/**
* brief: process_chunk_intermediate_sp - process a chunk of contextual basic records with seraphis {kx_ua, kx_fr, s_ga}
* param: jamtis_spend_pubkey -
* param: xk_unlock_amounts -
* param: xk_find_received -
* param: s_generate_address -
* param: cipher_context -
* param: chunk_basic_records_per_tx - [ tx id : contextual basic record ]
* outparam: found_enote_records_out - [ Ko : legacy contextual intermediate enote record ]
*/
void process_chunk_intermediate_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_out);
/**
* brief: process_chunk_full_sp - process a chunk of contextual basic records with seraphis view-balance privkey
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* param: xk_unlock_amounts -
* param: xk_find_received -
* param: s_generate_address -
* param: cipher_context -
* param: check_key_image_is_known_func - callback for checking if a key image is known by the caller
* param: chunk_basic_records_per_tx - [ tx id : contextual basic record ]
* param: chunk_contextual_key_images -
* outparam: found_enote_records_out - [ seraphis KI : legacy contextual intermediate enote record ]
* outparam: found_spent_sp_key_images_out - [ seraphis KI : spent context ]
* outparam: legacy_key_images_in_sp_selfspends_out - [ legacy KI : spent context ]
*/
void process_chunk_full_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_sp_key_images_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfspends_out);

} //namespace scanning
} //namespace sp
