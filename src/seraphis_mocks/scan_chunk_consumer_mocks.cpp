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

// NOT FOR PRODUCTION

//paired header
#include "scan_chunk_consumer_mocks.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "enote_finding_context_mocks.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/scan_balance_recovery_utils.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_machine_types.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
// Legacy Intermediate
//-------------------------------------------------------------------------------------------------------------------
ChunkConsumerMockLegacyIntermediate::ChunkConsumerMockLegacyIntermediate(
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const LegacyScanMode legacy_scan_mode,
    SpEnoteStore &enote_store) :
        m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
        m_legacy_view_privkey{legacy_view_privkey},
        m_legacy_scan_mode{legacy_scan_mode},
        m_enote_store{enote_store}
{}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockLegacyIntermediate::refresh_index() const
{
    return m_enote_store.legacy_refresh_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockLegacyIntermediate::desired_first_block() const
{
    if (m_legacy_scan_mode == LegacyScanMode::KEY_IMAGES_ONLY)
        return m_enote_store.top_legacy_fullscanned_block_index() + 1;
    else
        return m_enote_store.top_legacy_partialscanned_block_index() + 1;
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockLegacyIntermediate::get_next_block(const std::uint64_t block_index) const
{
    if (m_legacy_scan_mode == LegacyScanMode::KEY_IMAGES_ONLY)
        return get_next_legacy_fullscanned_block(m_enote_store, block_index);
    else
        return get_next_legacy_partialscanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockLegacyIntermediate::get_nearest_block(const std::uint64_t block_index) const
{
    if (m_legacy_scan_mode == LegacyScanMode::KEY_IMAGES_ONLY)
        return get_nearest_legacy_fullscanned_block(m_enote_store, block_index);
    else
        return get_nearest_legacy_partialscanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockLegacyIntermediate::consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
    const scanning::ChunkData &chunk_data)
{
    // 1. process the chunk
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

    scanning::process_chunk_intermediate_legacy(m_legacy_base_spend_pubkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data.basic_records_per_tx,
        chunk_data.contextual_key_images,
        hw::get_device("default"),
        found_enote_records,
        found_spent_key_images);

    // 2. save the results
    std::list<EnoteStoreEvent> events;
    if (m_legacy_scan_mode == LegacyScanMode::KEY_IMAGES_ONLY)
        m_enote_store.update_with_intermediate_legacy_found_spent_key_images(found_spent_key_images, events);
    else
    {
        m_enote_store.update_with_intermediate_legacy_records_from_nonledger(nonledger_origin_status,
            found_enote_records,
            found_spent_key_images,
            events);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockLegacyIntermediate::consume_onchain_chunk(const scanning::LedgerChunk &chunk,
    const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. extract the data
    const scanning::ChunkData *chunk_data{chunk.try_get_data(rct::zero())};
    CHECK_AND_ASSERT_THROW_MES(chunk_data, "chunk consumer mock legacy intermediate: no chunk data.");

    // 2. process the chunk
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

    scanning::process_chunk_intermediate_legacy(m_legacy_base_spend_pubkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data->basic_records_per_tx,
        chunk_data->contextual_key_images,
        hw::get_device("default"),
        found_enote_records,
        found_spent_key_images);

    // 3. save the results
    std::list<EnoteStoreEvent> events;
    if (m_legacy_scan_mode == LegacyScanMode::KEY_IMAGES_ONLY)
        m_enote_store.update_with_intermediate_legacy_found_spent_key_images(found_spent_key_images, events);
    else
    {
        m_enote_store.update_with_intermediate_legacy_records_from_ledger(alignment_block_id,
            first_new_block,
            new_block_ids,
            found_enote_records,
            found_spent_key_images,
            events);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// Legacy
//-------------------------------------------------------------------------------------------------------------------
ChunkConsumerMockLegacy::ChunkConsumerMockLegacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    SpEnoteStore &enote_store) :
        m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
        m_legacy_spend_privkey{legacy_spend_privkey},
        m_legacy_view_privkey{legacy_view_privkey},
        m_enote_store{enote_store}
{}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockLegacy::refresh_index() const
{
    return m_enote_store.legacy_refresh_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockLegacy::desired_first_block() const
{
    return m_enote_store.top_legacy_fullscanned_block_index() + 1;
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockLegacy::get_next_block(const std::uint64_t block_index) const
{
    return get_next_legacy_fullscanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockLegacy::get_nearest_block(const std::uint64_t block_index) const
{
    return get_nearest_legacy_fullscanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockLegacy::consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
    const scanning::ChunkData &chunk_data)
{
    // 1. process the chunk
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

    scanning::process_chunk_full_legacy(m_legacy_base_spend_pubkey,
        m_legacy_spend_privkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data.basic_records_per_tx,
        chunk_data.contextual_key_images,
        hw::get_device("default"),
        found_enote_records,
        found_spent_key_images);

    // 2. save the results
    std::list<EnoteStoreEvent> events;
    m_enote_store.update_with_legacy_records_from_nonledger(nonledger_origin_status,
        found_enote_records,
        found_spent_key_images,
        events);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockLegacy::consume_onchain_chunk(const scanning::LedgerChunk &chunk,
    const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. extract the data
    const scanning::ChunkData *chunk_data{chunk.try_get_data(rct::zero())};
    CHECK_AND_ASSERT_THROW_MES(chunk_data, "chunk consumer mock legacy: no chunk data.");

    // 2. process the chunk
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

    scanning::process_chunk_full_legacy(m_legacy_base_spend_pubkey,
        m_legacy_spend_privkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data->basic_records_per_tx,
        chunk_data->contextual_key_images,
        hw::get_device("default"),
        found_enote_records,
        found_spent_key_images);

    // 3. save the results
    std::list<EnoteStoreEvent> events;
    m_enote_store.update_with_legacy_records_from_ledger(alignment_block_id,
        first_new_block,
        new_block_ids,
        found_enote_records,
        found_spent_key_images,
        events);
}
//-------------------------------------------------------------------------------------------------------------------
// Seraphis Intermediate
//-------------------------------------------------------------------------------------------------------------------
ChunkConsumerMockSpIntermediate::ChunkConsumerMockSpIntermediate(const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    SpEnoteStorePaymentValidator &enote_store) :
        m_jamtis_spend_pubkey{jamtis_spend_pubkey},
        m_xk_unlock_amounts{xk_unlock_amounts},
        m_xk_find_received{xk_find_received},
        m_s_generate_address{s_generate_address},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(m_s_cipher_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockSpIntermediate::refresh_index() const
{
    return m_enote_store.refresh_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockSpIntermediate::desired_first_block() const
{
    return m_enote_store.top_block_index() + 1;
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockSpIntermediate::get_next_block(const std::uint64_t block_index) const
{
    return get_next_sp_scanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockSpIntermediate::get_nearest_block(const std::uint64_t block_index) const
{
    return get_nearest_sp_scanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockSpIntermediate::consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
    const scanning::ChunkData &chunk_data)
{
    // 1. process the chunk
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> found_enote_records;

    scanning::process_chunk_intermediate_sp(m_jamtis_spend_pubkey,
        m_xk_unlock_amounts,
        m_xk_find_received,
        m_s_generate_address,
        *m_cipher_context,
        chunk_data.basic_records_per_tx,
        found_enote_records);

    // 2. save the results
    std::list<PaymentValidatorStoreEvent> events;
    m_enote_store.update_with_sp_records_from_nonledger(nonledger_origin_status, found_enote_records, events);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockSpIntermediate::consume_onchain_chunk(const scanning::LedgerChunk &chunk,
    const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. extract the data
    const scanning::ChunkData *chunk_data{chunk.try_get_data(rct::zero())};
    CHECK_AND_ASSERT_THROW_MES(chunk_data, "chunk consumer mock sp intermediate: no chunk data.");

    // 2. process the chunk
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> found_enote_records;

    scanning::process_chunk_intermediate_sp(m_jamtis_spend_pubkey,
        m_xk_unlock_amounts,
        m_xk_find_received,
        m_s_generate_address,
        *m_cipher_context,
        chunk_data->basic_records_per_tx,
        found_enote_records);

    // 3. save the results
    std::list<PaymentValidatorStoreEvent> events;
    m_enote_store.update_with_sp_records_from_ledger(alignment_block_id,
        first_new_block,
        new_block_ids,
        found_enote_records,
        events);
}
//-------------------------------------------------------------------------------------------------------------------
// Seraphis
//-------------------------------------------------------------------------------------------------------------------
ChunkConsumerMockSp::ChunkConsumerMockSp(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteStore &enote_store) :
        m_jamtis_spend_pubkey{jamtis_spend_pubkey},
        m_k_view_balance{k_view_balance},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_unlockamounts_key(m_k_view_balance, m_xk_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(m_k_view_balance, m_xk_find_received);
    jamtis::make_jamtis_generateaddress_secret(m_k_view_balance, m_s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(m_s_cipher_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockSp::refresh_index() const
{
    return m_enote_store.sp_refresh_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t ChunkConsumerMockSp::desired_first_block() const
{
    return m_enote_store.top_sp_scanned_block_index() + 1;
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockSp::get_next_block(const std::uint64_t block_index) const
{
    return get_next_sp_scanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker ChunkConsumerMockSp::get_nearest_block(const std::uint64_t block_index) const
{
    return get_nearest_sp_scanned_block(m_enote_store, block_index);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockSp::consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
    const scanning::ChunkData &chunk_data)
{
    // 1. process the chunk
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> legacy_key_images_in_sp_selfsends;

    scanning::process_chunk_full_sp(m_jamtis_spend_pubkey,
        m_k_view_balance,
        m_xk_unlock_amounts,
        m_xk_find_received,
        m_s_generate_address,
        *m_cipher_context,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data.basic_records_per_tx,
        chunk_data.contextual_key_images,
        found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends);

    // 2. save the results
    std::list<EnoteStoreEvent> events;
    m_enote_store.update_with_sp_records_from_nonledger(nonledger_origin_status,
        found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends,
        events);
}
//-------------------------------------------------------------------------------------------------------------------
void ChunkConsumerMockSp::consume_onchain_chunk(const scanning::LedgerChunk &chunk,
    const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. extract the data
    const scanning::ChunkData *chunk_data{chunk.try_get_data(rct::zero())};
    CHECK_AND_ASSERT_THROW_MES(chunk_data, "chunk consumer mock sp: no chunk data.");

    // 2. process the chunk
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> legacy_key_images_in_sp_selfsends;

    scanning::process_chunk_full_sp(m_jamtis_spend_pubkey,
        m_k_view_balance,
        m_xk_unlock_amounts,
        m_xk_find_received,
        m_s_generate_address,
        *m_cipher_context,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_data->basic_records_per_tx,
        chunk_data->contextual_key_images,
        found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends);

    // 2. save the results
    std::list<EnoteStoreEvent> events;
    m_enote_store.update_with_sp_records_from_ledger(alignment_block_id,
        first_new_block,
        new_block_ids,
        found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends,
        events);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
