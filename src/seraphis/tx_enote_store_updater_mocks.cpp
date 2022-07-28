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
#include "tx_enote_store_updater_mocks.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_core_utils.h"
#include "ringct/rctTypes.h"
#include "tx_enote_record_types.h"
#include "tx_enote_scanning_utils.h"
#include "tx_enote_store_mocks.h"

//third party headers

//standard headers
#include <list>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterLedgerMockLegacy::EnoteStoreUpdaterLedgerMockLegacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const crypto::secret_key &legacy_spend_privkey,
    SpEnoteStoreMockV1 &enote_store) :
        m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
        m_legacy_view_privkey{legacy_view_privkey},
        m_legacy_spend_privkey{legacy_spend_privkey},
        m_enote_store{enote_store}
{}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacy::start_chunk_handling_session()
{
    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacy::process_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images)
{
    process_chunk_full_legacy(m_legacy_base_spend_pubkey,
        m_legacy_spend_privkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_basic_records_per_tx,
        chunk_contextual_key_images,
        m_found_enote_records,
        m_found_spent_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacy::end_chunk_handling_session(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids)
{
    m_enote_store.update_with_legacy_records_from_ledger(first_new_block,
        alignment_block_id,
        new_block_ids,
        m_found_enote_records,
        m_found_spent_key_images);

    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
bool EnoteStoreUpdaterLedgerMockLegacy::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    return m_enote_store.try_get_block_id(block_height, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockLegacy::get_refresh_height() const
{
    return m_enote_store.get_refresh_height();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockLegacy::get_top_block_height() const
{
    return m_enote_store.get_top_legacy_fullscanned_block_height();
}
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterLedgerMock::EnoteStoreUpdaterLedgerMock(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteStoreMockV1 &enote_store) :
        m_wallet_spend_pubkey{wallet_spend_pubkey},
        m_k_view_balance{k_view_balance},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_unlockamounts_key(m_k_view_balance, m_k_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(m_k_view_balance, m_k_find_received);
    jamtis::make_jamtis_generateaddress_secret(m_k_view_balance, m_s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(rct::sk2rct(m_s_cipher_tag));
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMock::start_chunk_handling_session()
{
    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
    m_legacy_key_images_in_sp_selfsends.clear();
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMock::process_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images)
{
    process_chunk_full_sp(m_wallet_spend_pubkey,
        m_k_view_balance,
        m_k_unlock_amounts,
        m_k_find_received,
        m_s_generate_address,
        *m_cipher_context,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_basic_records_per_tx,
        chunk_contextual_key_images,
        m_found_enote_records,
        m_found_spent_key_images,
        m_legacy_key_images_in_sp_selfsends);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMock::end_chunk_handling_session(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids)
{
    m_enote_store.update_with_sp_records_from_ledger(first_new_block,
        alignment_block_id,
        new_block_ids,
        m_found_enote_records,
        m_found_spent_key_images,
        m_legacy_key_images_in_sp_selfsends);

    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
    m_legacy_key_images_in_sp_selfsends.clear();
}
//-------------------------------------------------------------------------------------------------------------------
bool EnoteStoreUpdaterLedgerMock::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    return m_enote_store.try_get_block_id(block_height, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMock::get_refresh_height() const
{
    return m_enote_store.get_refresh_height();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMock::get_top_block_height() const
{
    return m_enote_store.get_top_sp_scanned_block_height();
}
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterNonLedgerMock::EnoteStoreUpdaterNonLedgerMock(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteStoreMockV1 &enote_store) :
        m_wallet_spend_pubkey{wallet_spend_pubkey},
        m_k_view_balance{k_view_balance},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_unlockamounts_key(m_k_view_balance, m_k_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(m_k_view_balance, m_k_find_received);
    jamtis::make_jamtis_generateaddress_secret(m_k_view_balance, m_s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(rct::sk2rct(m_s_cipher_tag));
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterNonLedgerMock::process_and_handle_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images)
{
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> legacy_key_images_in_sp_selfsends;

    process_chunk_full_sp(m_wallet_spend_pubkey,
        m_k_view_balance,
        m_k_unlock_amounts,
        m_k_find_received,
        m_s_generate_address,
        *m_cipher_context,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_basic_records_per_tx,
        chunk_contextual_key_images,
        found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends);

    m_enote_store.update_with_sp_records_from_offchain(found_enote_records,
        found_spent_key_images,
        legacy_key_images_in_sp_selfsends);
}
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterLedgerMockLegacyIntermediate::EnoteStoreUpdaterLedgerMockLegacyIntermediate(
        const rct::key &legacy_base_spend_pubkey,
        const crypto::secret_key &legacy_view_privkey,
        const bool legacy_key_image_recovery_mode,
        SpEnoteStoreMockV1 &enote_store) :
        m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
        m_legacy_view_privkey{legacy_view_privkey},
        m_legacy_key_image_recovery_mode{legacy_key_image_recovery_mode},
        m_enote_store{enote_store}
{}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacyIntermediate::start_chunk_handling_session()
{
    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacyIntermediate::process_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images)
{
    process_chunk_intermediate_legacy(m_legacy_base_spend_pubkey,
        m_legacy_view_privkey,
        [this](const crypto::key_image &key_image) -> bool
        {
            return this->m_enote_store.has_enote_with_key_image(key_image);
        },
        chunk_basic_records_per_tx,
        chunk_contextual_key_images,
        m_found_enote_records,
        m_found_spent_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockLegacyIntermediate::end_chunk_handling_session(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids)
{
    m_enote_store.update_with_intermediate_legacy_records_from_ledger(first_new_block,
        alignment_block_id,
        new_block_ids,
        m_found_enote_records,
        m_found_spent_key_images);

    m_found_enote_records.clear();
    m_found_spent_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
bool EnoteStoreUpdaterLedgerMockLegacyIntermediate::try_get_block_id(const std::uint64_t block_height,
    rct::key &block_id_out) const
{
    return m_enote_store.try_get_block_id(block_height, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockLegacyIntermediate::get_refresh_height() const
{
    return m_enote_store.get_refresh_height();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockLegacyIntermediate::get_top_block_height() const
{
    if (m_legacy_key_image_recovery_mode)
        return m_enote_store.get_top_legacy_fullscanned_block_height();
    else
        return m_enote_store.get_top_legacy_partialscanned_block_height();
}
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterLedgerMockIntermediate::EnoteStoreUpdaterLedgerMockIntermediate(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    SpEnoteStoreMockPaymentValidatorV1 &enote_store) :
        m_wallet_spend_pubkey{wallet_spend_pubkey},
        m_k_unlock_amounts{k_unlock_amounts},
        m_k_find_received{k_find_received},
        m_s_generate_address{s_generate_address},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(rct::sk2rct(m_s_cipher_tag));
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockIntermediate::start_chunk_handling_session()
{
    m_found_enote_records.clear();
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockIntermediate::process_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1>&)
{
    process_chunk_intermediate_sp(m_wallet_spend_pubkey,
        m_k_unlock_amounts,
        m_k_find_received,
        m_s_generate_address,
        *m_cipher_context,
        chunk_basic_records_per_tx,
        m_found_enote_records);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterLedgerMockIntermediate::end_chunk_handling_session(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids)
{
    m_enote_store.update_with_sp_records_from_ledger(first_new_block,
        alignment_block_id,
        m_found_enote_records,
        new_block_ids);

    m_found_enote_records.clear();
}
//-------------------------------------------------------------------------------------------------------------------
bool EnoteStoreUpdaterLedgerMockIntermediate::try_get_block_id(const std::uint64_t block_height,
    rct::key &block_id_out) const
{
    return m_enote_store.try_get_block_id(block_height, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockIntermediate::get_refresh_height() const
{
    return m_enote_store.get_refresh_height();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t EnoteStoreUpdaterLedgerMockIntermediate::get_top_block_height() const
{
    return m_enote_store.get_top_block_height();
}
//-------------------------------------------------------------------------------------------------------------------
EnoteStoreUpdaterNonLedgerMockIntermediate::EnoteStoreUpdaterNonLedgerMockIntermediate(
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    SpEnoteStoreMockPaymentValidatorV1 &enote_store) :
        m_wallet_spend_pubkey{wallet_spend_pubkey},
        m_k_unlock_amounts{k_unlock_amounts},
        m_k_find_received{k_find_received},
        m_s_generate_address{s_generate_address},
        m_enote_store{enote_store}
{
    jamtis::make_jamtis_ciphertag_secret(m_s_generate_address, m_s_cipher_tag);

    m_cipher_context = std::make_unique<jamtis::jamtis_address_tag_cipher_context>(rct::sk2rct(m_s_cipher_tag));
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteStoreUpdaterNonLedgerMockIntermediate::process_and_handle_chunk(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1>&)
{
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> found_enote_records;

    process_chunk_intermediate_sp(m_wallet_spend_pubkey,
        m_k_unlock_amounts,
        m_k_find_received,
        m_s_generate_address,
        *m_cipher_context,
        chunk_basic_records_per_tx,
        found_enote_records);

    m_enote_store.update_with_sp_records_from_offchain(found_enote_records);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
