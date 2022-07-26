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

//todo


#pragma once

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "jamtis_address_tag_utils.h"
#include "sp_crypto_utils.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers
#include <functional>
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations

namespace sp
{

//todo
bool try_find_sp_enotes_in_tx(const crypto::secret_key &k_find_received,
    const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &basic_records_per_tx_inout);
void collect_key_images_from_tx(const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::vector<crypto::key_image> &legacy_key_images_in_tx,
    const std::vector<crypto::key_image> &sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    std::list<SpContextualKeyImageSetV1> &contextual_key_images_inout);

//todo
void process_chunk_intermediate(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout);
void process_chunk_full(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout);

} //namespace sp
