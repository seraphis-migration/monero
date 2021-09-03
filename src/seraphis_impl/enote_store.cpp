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
#include "enote_store.h"

//local headers
#include "common/container_helpers.h"
#include "misc_log_ex.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_impl/enote_store_event_types.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_utils_legacy.h"

//third party headers

//standard headers
#include <functional>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
SpEnoteStore::SpEnoteStore(const std::uint64_t refresh_index,
    const std::uint64_t first_sp_enabled_block_in_chain,
    const std::uint64_t default_spendable_age,
    const CheckpointCacheConfig &checkpoint_cache_config) :
        m_legacy_block_id_cache    { checkpoint_cache_config, refresh_index                                            },
        m_sp_block_id_cache        { checkpoint_cache_config, std::max(refresh_index, first_sp_enabled_block_in_chain) },
        m_legacy_partialscan_index { refresh_index - 1     },
        m_legacy_fullscan_index    { refresh_index - 1     },
        m_sp_scanned_index         { refresh_index - 1     },
        m_default_spendable_age    { default_spendable_age }
{}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::legacy_refresh_index() const
{
    return m_legacy_block_id_cache.min_checkpoint_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::sp_refresh_index() const
{
    return m_sp_block_id_cache.min_checkpoint_index();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::top_block_index() const
{
    // 1. no blocks
    if (m_legacy_block_id_cache.num_checkpoints() == 0 &&
        m_sp_block_id_cache.num_checkpoints() == 0)
        return this->legacy_refresh_index() - 1;

    // 2. only have legacy blocks
    if (m_sp_block_id_cache.num_checkpoints() == 0)
        return m_legacy_block_id_cache.top_block_index();

    // 3. only have seraphis blocks
    if (m_legacy_block_id_cache.num_checkpoints() == 0)
        return m_sp_block_id_cache.top_block_index();

    // 4. have legacy and seraphis blocks
    return std::max(
            m_legacy_block_id_cache.top_block_index(),
            m_sp_block_id_cache.top_block_index()
        );
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::next_legacy_partialscanned_block_index(const std::uint64_t block_index) const
{
    // 1. get the cached legacy block index > the requested index
    const std::uint64_t next_index{m_legacy_block_id_cache.get_next_block_index(block_index)};

    // 2. assume a block is 'unknown' if its index is above the last legacy partial-scanned block index
    if (next_index + 1 > m_legacy_partialscan_index + 1)
        return -1;

    return next_index;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::next_legacy_fullscanned_block_index(const std::uint64_t block_index) const
{
    // 1. get the cached legacy block index > the requested index
    const std::uint64_t next_index{m_legacy_block_id_cache.get_next_block_index(block_index)};

    // 2. assume a block is 'unknown' if its index is above the last legacy full-scanned block index
    if (block_index + 1 > m_legacy_fullscan_index + 1)
        return -1;

    return next_index;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::next_sp_scanned_block_index(const std::uint64_t block_index) const
{
    // 1. get the cached seraphis block index > the requested index
    const std::uint64_t next_index{m_sp_block_id_cache.get_next_block_index(block_index)};

    // 2. assume a block is 'unknown' if its index is above the last seraphis block index
    if (block_index + 1 > m_sp_scanned_index + 1)
        return -1;

    return next_index;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::nearest_legacy_partialscanned_block_index(const std::uint64_t block_index) const
{
    // get the cached legacy block index <= the requested index
    return m_legacy_block_id_cache.get_nearest_block_index(
            std::min(block_index + 1, m_legacy_partialscan_index + 1) - 1
        );
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::nearest_legacy_fullscanned_block_index(const std::uint64_t block_index) const
{
    // get the cached legacy block index <= the requested index
    return m_legacy_block_id_cache.get_nearest_block_index(
            std::min(block_index + 1, m_legacy_fullscan_index + 1) - 1
        );
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStore::nearest_sp_scanned_block_index(const std::uint64_t block_index) const
{
    // get the cached seraphis block index <= the requested index
    return m_sp_block_id_cache.get_nearest_block_index(
            std::min(block_index + 1, m_sp_scanned_index + 1) - 1
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_block_id_for_legacy_partialscan(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // 1. get the nearest cached legacy block index
    // - we use this indirection to validate edge conditions
    const std::uint64_t nearest_cached_index{this->nearest_legacy_partialscanned_block_index(block_index)};

    // 2. check error states
    if (nearest_cached_index == this->legacy_refresh_index() - 1 ||
        nearest_cached_index != block_index)
        return false;

    // 3. get the block id
    CHECK_AND_ASSERT_THROW_MES(m_legacy_block_id_cache.try_get_block_id(block_index, block_id_out),
        "sp enote store (try get block id legacy partialscan): failed to get cached block id for index that is known.");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_block_id_for_legacy_fullscan(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // 1. get the nearest cached legacy block index
    // - we use this indirection to validate edge conditions
    const std::uint64_t nearest_cached_index{this->nearest_legacy_fullscanned_block_index(block_index)};

    // 2. check error states
    if (nearest_cached_index == this->legacy_refresh_index() - 1 ||
        nearest_cached_index != block_index)
        return false;

    // 3. get the block id
    CHECK_AND_ASSERT_THROW_MES(m_legacy_block_id_cache.try_get_block_id(block_index, block_id_out),
        "sp enote store (try get block id legacy fullscan): failed to get cached block id for index that is known.");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_block_id_for_sp(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // 1. get the nearest cached sp block index
    // - we use this indirection to validate edge conditions
    const std::uint64_t nearest_cached_index{this->nearest_sp_scanned_block_index(block_index)};

    // 2. check error states
    if (nearest_cached_index == this->sp_refresh_index() - 1 ||
        nearest_cached_index != block_index)
        return false;

    // 3. get the block id
    CHECK_AND_ASSERT_THROW_MES(m_sp_block_id_cache.try_get_block_id(block_index, block_id_out),
        "sp enote store (try get block id sp scan): failed to get cached block id for index that is known.");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // try to get the block id from each of the scan types
    return this->try_get_block_id_for_legacy_partialscan(block_index, block_id_out) ||
        this->try_get_block_id_for_legacy_fullscan(block_index, block_id_out) ||
        this->try_get_block_id_for_sp(block_index, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::has_enote_with_key_image(const crypto::key_image &key_image) const
{
    // note: test sp records first since over time that will be the hottest path
    return m_sp_contextual_enote_records.find(key_image) != m_sp_contextual_enote_records.end() ||
        m_legacy_key_images.find(key_image) != m_legacy_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_legacy_enote_record(const crypto::key_image &key_image,
    LegacyContextualEnoteRecordV1 &contextual_record_out) const
{
    // 1. drill into the legacy maps searching for at least one matching legacy enote record
    // a. legacy key images map
    if (m_legacy_key_images.find(key_image) == m_legacy_key_images.end())
        return false;

    // b. tracked legacy duplicates
    const rct::key &onetime_address{m_legacy_key_images.at(key_image)};

    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address) ==
            m_tracked_legacy_onetime_address_duplicates.end())
        return false;

    // c. identifiers associated with this key image's onetime address
    const std::unordered_set<rct::key> &identifiers_of_duplicates{
            m_tracked_legacy_onetime_address_duplicates.at(onetime_address)
        };

    if (identifiers_of_duplicates.size() == 0)
        return false;

    // 2. search for the highest-amount enote among the enotes that have our key image
    rct::key best_identifier{rct::zero()};
    rct::xmr_amount best_amount{0};
    rct::xmr_amount temp_record_amount;

    for (const rct::key &identifier : identifiers_of_duplicates)
    {
        // a. check intermediate records
        if (m_legacy_intermediate_contextual_enote_records.find(identifier) !=
            m_legacy_intermediate_contextual_enote_records.end())
        {
            temp_record_amount = m_legacy_intermediate_contextual_enote_records.at(identifier).record.amount;
        }
        // b. check full records
        else if (m_legacy_contextual_enote_records.find(identifier) !=
            m_legacy_contextual_enote_records.end())
        {
            temp_record_amount = m_legacy_contextual_enote_records.at(identifier).record.amount;
        }
        else
            continue;

        // c. save the highest-amount record
        if (best_amount < temp_record_amount)
        {
            best_identifier = identifier;
            best_amount     = temp_record_amount;
        }
    }

    // 3. if the highest-amount enote is not among the full enote records, then we failed
    if (m_legacy_contextual_enote_records.find(best_identifier) == m_legacy_contextual_enote_records.end())
        return false;

    // 4. save the highest-amount record
    contextual_record_out = m_legacy_contextual_enote_records.at(best_identifier);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_get_sp_enote_record(const crypto::key_image &key_image,
    SpContextualEnoteRecordV1 &contextual_record_out) const
{
    // 1. check if the key image has a record
    if (m_sp_contextual_enote_records.find(key_image) == m_sp_contextual_enote_records.end())
        return false;

    // 2. save the record
    contextual_record_out = m_sp_contextual_enote_records.at(key_image);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStore::try_import_legacy_key_image(const crypto::key_image &legacy_key_image,
    const rct::key &onetime_address,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. fail if there are no enote records for this onetime address
    const auto duplicates_ref = m_tracked_legacy_onetime_address_duplicates.find(onetime_address);
    if (duplicates_ref == m_tracked_legacy_onetime_address_duplicates.end())
        return false;

    // 2. get the spent context if this key image appeared in a seraphis tx
    SpEnoteSpentContextV1 spent_context{};

    if (m_legacy_key_images_in_sp_selfsends.find(legacy_key_image) != m_legacy_key_images_in_sp_selfsends.end())
        spent_context = m_legacy_key_images_in_sp_selfsends.at(legacy_key_image);

    // 3. there may be full legacy enote records with this key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier : duplicates_ref->second)
    {
        // a. skip identifiers not in the full legacy records map
        const auto record_ref = m_legacy_contextual_enote_records.find(legacy_enote_identifier);
        if (record_ref == m_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        if (try_update_enote_spent_context_v1(record_ref->second.spent_context, spent_context))
            events_inout.emplace_back(UpdatedLegacySpentContext{legacy_enote_identifier});
    }

    // 4. promote intermediate enote records with this onetime address to full enote records
    for (const rct::key &legacy_enote_identifier : duplicates_ref->second)
    {
        // a. skip identifiers not in the intermediate records map
        const auto record_ref = m_legacy_intermediate_contextual_enote_records.find(legacy_enote_identifier);
        if (record_ref == m_legacy_intermediate_contextual_enote_records.end())
            continue;

        // b. if this identifier has an intermediate record, it should not have a full record
        CHECK_AND_ASSERT_THROW_MES(m_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
                m_legacy_contextual_enote_records.end(),
            "sp enote store (import legacy key image): intermediate and full legacy maps inconsistent (bug).");

        // c. set the full record
        get_legacy_enote_record(record_ref->second.record,
            legacy_key_image,
            m_legacy_contextual_enote_records[legacy_enote_identifier].record);
        events_inout.emplace_back(NewLegacyRecord{legacy_enote_identifier});

        // d. set the full record's contexts
        update_contextual_enote_record_contexts_v1(
                record_ref->second.origin_context,
                spent_context,
                m_legacy_contextual_enote_records[legacy_enote_identifier].origin_context,
                m_legacy_contextual_enote_records[legacy_enote_identifier].spent_context
            );

        // e. remove the intermediate record
        m_legacy_intermediate_contextual_enote_records.erase(legacy_enote_identifier);
        events_inout.emplace_back(RemovedLegacyIntermediateRecord{legacy_enote_identifier});

        // f. save to the legacy key image set
        m_legacy_key_images[legacy_key_image] = onetime_address;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_legacy_fullscan_index_for_import_cycle(const std::uint64_t saved_index)
{
    // clamp the imported index to the top known block index in case blocks were popped in the middle of an import
    //   cycle and the enote store was refreshed before this function call, thereby reducing the top known block index
    this->set_last_legacy_fullscan_index(std::min(saved_index + 1, m_legacy_block_id_cache.top_block_index() + 1) - 1);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::set_last_legacy_partialscan_index(const std::uint64_t new_index)
{
    // 1. set this scan index (+1 because if no scanning has been done then we are below the refresh index)
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= this->legacy_refresh_index(),
        "sp enote store (set legacy partialscan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= m_legacy_block_id_cache.top_block_index() + 1,
        "sp enote store (set legacy partialscan index): new index is above known block range.");

    m_legacy_partialscan_index = new_index;

    // 2. update legacy full scan index
    // - if the partialscan index is below the fullscan index, assume this means there was a reorg
    m_legacy_fullscan_index = std::min(m_legacy_fullscan_index + 1, m_legacy_partialscan_index + 1) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::set_last_legacy_fullscan_index(const std::uint64_t new_index)
{
    // 1. set this scan index (+1 because if no scanning has been done then we are below the refresh index)
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= this->legacy_refresh_index(),
        "sp enote store (set legacy fullscan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= m_legacy_block_id_cache.top_block_index() + 1,
        "sp enote store (set legacy fullscan index): new index is above known block range.");

    m_legacy_fullscan_index = new_index;

    // 2. update legacy partial scan index
    // - fullscan qualifies as partialscan
    // note: this update intentionally won't fix inaccuracy in the m_legacy_partialscan_index caused by a reorg, because
    //       in manual workflows the legacy partialscan index is often higher than the legacy fullscan index; that is
    //       find because the partialscan index only matters when doing a manual view-only workflow, and any reorg-
    //       induced inaccuracy in that height will be fixed by re-running that workflow
    m_legacy_partialscan_index = std::max(m_legacy_partialscan_index + 1, m_legacy_fullscan_index + 1) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::set_last_sp_scanned_index(const std::uint64_t new_index)
{
    // set this scan index (+1 because if no scanning has been done then we are below the refresh index)
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= this->sp_refresh_index(),
        "sp enote store (set seraphis scan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= m_sp_block_id_cache.top_block_index() + 1,
        "sp enote store (set seraphis scan index): new index is above known block range.");

    m_sp_scanned_index = new_index;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_intermediate_legacy_records_from_nonledger(
    const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_nonledger_update(nonledger_origin_status, found_spent_key_images, events_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 3. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_intermediate_legacy_records_from_ledger(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_legacy_partialscan(alignment_block_id,
        first_new_block,
        new_block_ids,
        events_inout);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images, events_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_intermediate_legacy_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. clean up enote store maps that conflict with the found spent key images (which take precedence)
    this->clean_maps_for_found_spent_legacy_key_images(found_spent_key_images, events_inout);

    // 2. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_nonledger_update(nonledger_origin_status, found_spent_key_images, events_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 3. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_legacy_records_from_ledger(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_legacy_fullscan(alignment_block_id,
        first_new_block,
        new_block_ids,
        events_inout);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images, events_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status, 
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. remove records that will be replaced
    this->clean_maps_for_sp_nonledger_update(nonledger_origin_status, events_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 3. update spent contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);

    // 4. handle legacy key images attached to self-spends
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_sp_records_from_ledger(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_sp(alignment_block_id, first_new_block, new_block_ids, events_inout);

    // 2. remove records that will be replaced
    this->clean_maps_for_sp_ledger_update(first_new_block, events_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, events_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images, events_inout);

    // 5. handle legacy key images attached to self-spends
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_new_blocks_from_ledger_legacy_partialscan(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    LegacyIntermediateBlocksDiff diff{};
    update_checkpoint_cache_with_new_block_ids(alignment_block_id,
        first_new_block,
        new_block_ids,
        m_legacy_block_id_cache,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    events_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be LEGACY_INTERMEDIATE_SCAN)
    this->set_last_legacy_partialscan_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_new_blocks_from_ledger_legacy_fullscan(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    LegacyBlocksDiff diff{};
    update_checkpoint_cache_with_new_block_ids(alignment_block_id,
        first_new_block,
        new_block_ids,
        m_legacy_block_id_cache,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    events_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be LEGACY_FULL)
    // note: we must set the partialscan index here in case a reorg dropped blocks; we don't do it inside the
    //       set_last_legacy_fullscan_index() function because that function needs to be used in manual view-scanning
    //       workflows where the legacy fullscan index will often lag behind the partialscan index
    this->set_last_legacy_partialscan_index(first_new_block + new_block_ids.size() - 1);
    this->set_last_legacy_fullscan_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_with_new_blocks_from_ledger_sp(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    SpBlocksDiff diff{};
    update_checkpoint_cache_with_new_block_ids(alignment_block_id,
        first_new_block,
        new_block_ids,
        m_sp_block_id_cache,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    events_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be SERAPHIS)
    this->set_last_sp_scanned_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_found_spent_legacy_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. if a found legacy key image is in the 'legacy key images from sp txs' map, remove it from that map
    // - a fresh spent context for legacy key images implies seraphis txs were reorged and replaced with legacy txs
    //   spending the same legacy enotes; we want to guarantee that the fresh spent contexts are applied to our
    //   stored enotes, and doing this step achieves that
    // - save the key images removed so we can clear the corresponding spent contexts in the enote records
    std::unordered_map<crypto::key_image, rct::key> spent_contexts_removed_from_sp_selfsends;  //[ KI : tx id ]
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore key images not in the sp selfsend tracker
        const auto tracked_ki_ref = m_legacy_key_images_in_sp_selfsends.find(found_spent_key_image.first);
        if (tracked_ki_ref == m_legacy_key_images_in_sp_selfsends.end())
            continue;

        // b. record [ KI : tx id ] of spent key images found in the sp selfsend tracker
        spent_contexts_removed_from_sp_selfsends[found_spent_key_image.first] = tracked_ki_ref->second.transaction_id;

        // c. remove the entry from the sp selfsend tracker
        m_legacy_key_images_in_sp_selfsends.erase(found_spent_key_image.first);
    }

    // 2. clear spent contexts referencing legacy key images removed from the seraphis legacy key image tracker
    for (const auto &removed_element : spent_contexts_removed_from_sp_selfsends)
    {
        // a. get the identifiers associated with this element's key image
        const auto onetime_address_ref = m_legacy_key_images.find(removed_element.first);
        if (onetime_address_ref == m_legacy_key_images.end())
            continue;
        const auto duplicates_ref = m_tracked_legacy_onetime_address_duplicates.find(onetime_address_ref->second);
        if (duplicates_ref == m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        // b. clean up each of the records
        for (const rct::key &legacy_identifier : duplicates_ref->second)
        {
            // i. ignore records that don't match the removed elements
            auto record_ref = m_legacy_contextual_enote_records.find(legacy_identifier);
            if (record_ref == m_legacy_contextual_enote_records.end())
                continue;
            if (!(record_ref->second.spent_context.transaction_id == removed_element.second))
                continue;

            // ii. clear spent contexts of records whose key images were removed from the seraphis selfsends tracker
            record_ref->second.spent_context = SpEnoteSpentContextV1{};
            events_inout.emplace_back(ClearedLegacySpentContext{legacy_identifier});
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_removed_legacy_enotes(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<rct::key, std::unordered_set<rct::key>> &mapped_identifiers_of_removed_enotes,
    const std::unordered_map<rct::key, crypto::key_image> &mapped_key_images_of_removed_enotes,
    const SpEnoteSpentStatus clearable_spent_status,
    const std::uint64_t first_uncleared_block_index,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. clean maps that conflict with the found spent key images
    this->clean_maps_for_found_spent_legacy_key_images(found_spent_key_images, events_inout);

    // 2. clear spent contexts referencing removed blocks or the unconfirmed cache if the corresponding legacy key image
    //    is not in the seraphis legacy key image tracker
    for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)  //todo: this is O(n)
    {
        // a. ignore legacy key images found in seraphis txs that still exist after cleaning maps for found spent key
        //    images
        if (m_legacy_key_images_in_sp_selfsends.find(mapped_contextual_enote_record.second.record.key_image) !=
                m_legacy_key_images_in_sp_selfsends.end())
            continue;

        // b. ignore spent contexts that aren't clearable according to the caller
        if (mapped_contextual_enote_record.second.spent_context.spent_status != clearable_spent_status)
            continue;
        if (mapped_contextual_enote_record.second.spent_context.block_index + 1 <= first_uncleared_block_index + 1)
            continue;

        // c. clear spent contexts that point to txs that the enote store considers nonexistent
        mapped_contextual_enote_record.second.spent_context = SpEnoteSpentContextV1{};
        events_inout.emplace_back(ClearedLegacySpentContext{mapped_contextual_enote_record.first});
    }

    // 3. clean up legacy trackers
    // a. onetime address duplicate tracker: remove identifiers of removed txs
    for (const auto &mapped_identifiers : mapped_identifiers_of_removed_enotes)
    {
        // a. ignore unknown onetime addresses
        const auto duplicates_ref = m_tracked_legacy_onetime_address_duplicates.find(mapped_identifiers.first);
        if (duplicates_ref == m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        // b. remove identifiers of removed enotes
        for (const rct::key &identifier_of_removed_enote : mapped_identifiers.second)
            duplicates_ref->second.erase(identifier_of_removed_enote);

        // c. clean up empty entries in the duplicate tracker
        if (duplicates_ref->second.size() == 0)
            m_tracked_legacy_onetime_address_duplicates.erase(mapped_identifiers.first);
    }

    // b. legacy key image tracker: remove any key images of removed txs if the corresponding onetime addresses don't
    //    have any identifiers registered in the duplicate tracker
    for (const auto &mapped_key_image : mapped_key_images_of_removed_enotes)
    {
        if (m_tracked_legacy_onetime_address_duplicates.find(mapped_key_image.first) != 
            m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        m_legacy_key_images.erase(mapped_key_image.second);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_legacy_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    CHECK_AND_ASSERT_THROW_MES(nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN ||
            nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED,
        "sp enote store (clean maps for sp nonledger update): invalid origin status.");

    // 1. remove records that will be replaced
    // [ Ko : [ identifier ] ]
    std::unordered_map<rct::key, std::unordered_set<rct::key>> mapped_identifiers_of_removed_enotes;

    auto legacy_contextual_record_is_removable_func =
        [nonledger_origin_status, &mapped_identifiers_of_removed_enotes]
        (const auto &mapped_contextual_enote_record) -> bool
        {
            // a. ignore enotes of unspecified origin
            if (!has_origin_status(mapped_contextual_enote_record.second, nonledger_origin_status))
                return false;

            // b. save identifiers of records to be removed
            mapped_identifiers_of_removed_enotes[
                    onetime_address_ref(mapped_contextual_enote_record.second.record.enote)
                ].insert(mapped_contextual_enote_record.first);

            // c. remove the record
            return true;
        };

    // a. legacy intermediate records
    tools::for_all_in_map_erase_if(m_legacy_intermediate_contextual_enote_records,  //todo: this is O(n)
            [&legacy_contextual_record_is_removable_func, &events_inout]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. record the identifier of the record being removed
                events_inout.emplace_back(RemovedLegacyIntermediateRecord{mapped_contextual_enote_record.first});

                // c. remove the record
                return true;
            }
        );

    // b. legacy full records
    std::unordered_map<rct::key, crypto::key_image> mapped_key_images_of_removed_enotes;  //[ Ko : KI ]

    tools::for_all_in_map_erase_if(m_legacy_contextual_enote_records,  //todo: this is O(n)
            [
                &legacy_contextual_record_is_removable_func,
                &mapped_key_images_of_removed_enotes,
                &events_inout
            ]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. save key images of full records that are to be removed
                mapped_key_images_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.record.enote)
                    ] = key_image_ref(mapped_contextual_enote_record.second);

                // c. record the identifier of the record being removed
                events_inout.emplace_back(RemovedLegacyRecord{mapped_contextual_enote_record.first});

                // d. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_legacy_enotes(found_spent_key_images,
        mapped_identifiers_of_removed_enotes,
        mapped_key_images_of_removed_enotes,
        nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN
            ? SpEnoteSpentStatus::SPENT_OFFCHAIN
            : SpEnoteSpentStatus::SPENT_UNCONFIRMED,
        -1,
        events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_legacy_ledger_update(const std::uint64_t first_new_block,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. remove records that will be replaced
    // [ Ko : [ legacy identifiers ] ]
    std::unordered_map<rct::key, std::unordered_set<rct::key>> mapped_identifiers_of_removed_enotes;

    auto legacy_contextual_record_is_removable_func =
        [first_new_block, &mapped_identifiers_of_removed_enotes](const auto &mapped_contextual_enote_record) -> bool
        {
            // a. ignore off-chain records
            if (!has_origin_status(mapped_contextual_enote_record.second, SpEnoteOriginStatus::ONCHAIN))
                return false;

            // b. ignore onchain enotes outside of range [first_new_block, end of chain]
            if (mapped_contextual_enote_record.second.origin_context.block_index < first_new_block)
                return false;

            // c. record the identifier of the enote being removed
            mapped_identifiers_of_removed_enotes[
                    onetime_address_ref(mapped_contextual_enote_record.second.record.enote)
                ].insert(mapped_contextual_enote_record.first);

            // d. remove the record
            return true;
        };

    // a. legacy intermediate records
    tools::for_all_in_map_erase_if(m_legacy_intermediate_contextual_enote_records,  //todo: this is O(n)
            [&legacy_contextual_record_is_removable_func, &events_inout]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. record the identifier of the record being removed
                events_inout.emplace_back(RemovedLegacyIntermediateRecord{mapped_contextual_enote_record.first});

                // c. remove the record
                return true;
            }
        );

    // b. legacy full records
    std::unordered_map<rct::key, crypto::key_image> mapped_key_images_of_removed_enotes;  //[ Ko : KI ]

    tools::for_all_in_map_erase_if(m_legacy_contextual_enote_records,  //todo: this is O(n)
            [
                &legacy_contextual_record_is_removable_func,
                &mapped_key_images_of_removed_enotes,
                &events_inout
            ]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. save key images of full records that are to be removed
                mapped_key_images_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.record.enote)
                    ] = mapped_contextual_enote_record.second.record.key_image;

                // c. record the identifier of the record being removed
                events_inout.emplace_back(RemovedLegacyRecord{mapped_contextual_enote_record.first});

                // d. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_legacy_enotes(found_spent_key_images,
        mapped_identifiers_of_removed_enotes,
        mapped_key_images_of_removed_enotes,
        SpEnoteSpentStatus::SPENT_ONCHAIN,
        first_new_block - 1,
        events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_removed_sp_enotes(const std::unordered_set<rct::key> &tx_ids_of_removed_selfsend_enotes,
    std::list<EnoteStoreEvent> &events_inout)
{
    // clear spent contexts referencing the txs of removed selfsend enotes
    // - key images only appear at the same time as selfsends, so clearing spent contexts made from the txs of lost
    //   enotes is a reliable way to manage spent contexts

    // 1. seraphis enotes
    for (auto &mapped_contextual_enote_record : m_sp_contextual_enote_records)  //todo: this is O(n)
    {
        if (tx_ids_of_removed_selfsend_enotes.find(mapped_contextual_enote_record.second.spent_context.transaction_id) ==
                tx_ids_of_removed_selfsend_enotes.end())
            continue;

        mapped_contextual_enote_record.second.spent_context = SpEnoteSpentContextV1{};
        events_inout.emplace_back(ClearedSpSpentContext{mapped_contextual_enote_record.first});
    }

    // 2. legacy enotes
    for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)  //todo: this is O(n)
    {
        if (tx_ids_of_removed_selfsend_enotes.find(mapped_contextual_enote_record.second.spent_context.transaction_id) ==
                tx_ids_of_removed_selfsend_enotes.end())
            continue;

        mapped_contextual_enote_record.second.spent_context = SpEnoteSpentContextV1{};
        events_inout.emplace_back(ClearedLegacySpentContext{mapped_contextual_enote_record.first});
    }

    // 3. remove legacy key images found in removed txs
    tools::for_all_in_map_erase_if(m_legacy_key_images_in_sp_selfsends,  //todo: this is O(n)
            [&tx_ids_of_removed_selfsend_enotes](const auto &mapped_legacy_key_image) -> bool
            {
                return tx_ids_of_removed_selfsend_enotes.find(mapped_legacy_key_image.second.transaction_id) !=
                    tx_ids_of_removed_selfsend_enotes.end();
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_sp_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
    std::list<EnoteStoreEvent> &events_inout)
{
    CHECK_AND_ASSERT_THROW_MES(nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN ||
            nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED,
        "sp enote store (clean maps for sp nonledger update): invalid origin status.");

    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_selfsend_enotes;

    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,  //todo: this is O(n)
            [
                nonledger_origin_status,
                &tx_ids_of_removed_selfsend_enotes,
                &events_inout
            ]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. ignore enotes that don't have our specified origin status
                if (!has_origin_status(mapped_contextual_enote_record.second, nonledger_origin_status))
                    return false;

                // b. save the tx id of the record to be removed if it's a selfsend
                if (jamtis::is_jamtis_selfsend_type(mapped_contextual_enote_record.second.record.type))
                {
                    tx_ids_of_removed_selfsend_enotes.insert(
                            mapped_contextual_enote_record.second.origin_context.transaction_id
                        );
                }

                // c. record the onetime address of the record being removed
                events_inout.emplace_back(RemovedSpRecord{mapped_contextual_enote_record.first});

                // d. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_selfsend_enotes, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::clean_maps_for_sp_ledger_update(const std::uint64_t first_new_block,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_selfsend_enotes;

    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,  //todo: this is O(n)
            [
                first_new_block,
                &tx_ids_of_removed_selfsend_enotes,
                &events_inout
            ]
            (const auto &mapped_contextual_enote_record) -> bool
            {
                // a. ignore off-chain records
                if (!has_origin_status(mapped_contextual_enote_record.second, SpEnoteOriginStatus::ONCHAIN))
                    return false;

                // b. ignore onchain enotes outside of range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.origin_context.block_index < first_new_block)
                    return false;

                // c. save tx id of the record to be removed if it's a selfsend
                if (jamtis::is_jamtis_selfsend_type(mapped_contextual_enote_record.second.record.type))
                {
                    tx_ids_of_removed_selfsend_enotes.insert(
                            mapped_contextual_enote_record.second.origin_context.transaction_id
                        );
                }

                // d. record the onetime address of the record being removed
                events_inout.emplace_back(RemovedSpRecord{mapped_contextual_enote_record.first});

                // e. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_selfsend_enotes, events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record,
    std::list<EnoteStoreEvent> &events_inout)
{
    // 1. if key image is known, promote to a full enote record
    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address_ref(new_record.record.enote)) !=
        m_tracked_legacy_onetime_address_duplicates.end())
    {
        const auto &identifiers_of_known_enotes =
            m_tracked_legacy_onetime_address_duplicates.at(onetime_address_ref(new_record.record.enote));

        CHECK_AND_ASSERT_THROW_MES(identifiers_of_known_enotes.size() > 0,
            "sp enote store (add intermediate record): record's onetime address is known, but there are no "
            "identifiers (bug).");

        for (const rct::key &identifier : identifiers_of_known_enotes)
        {
            // key image is known if there is a full record associated with this intermediate record's onetime address
            if (m_legacy_contextual_enote_records.find(identifier) == m_legacy_contextual_enote_records.end())
                continue;

            CHECK_AND_ASSERT_THROW_MES(identifier == *(identifiers_of_known_enotes.begin()),
                "sp enote store (add intermediate record): key image is known but there are intermediate "
                "records with this onetime address (a given onetime address should have only intermediate or only "
                "full legacy records).");

            LegacyContextualEnoteRecordV1 temp_full_record{};

            get_legacy_enote_record(new_record.record,
                m_legacy_contextual_enote_records.at(identifier).record.key_image,
                temp_full_record.record);
            temp_full_record.origin_context = new_record.origin_context;

            this->add_record(temp_full_record, events_inout);
            return;
        }
    }

    // 2. else add the intermediate record or update an existing record's origin context
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.record.enote),
        new_record.record.amount,
        new_record_identifier);

    if (m_legacy_intermediate_contextual_enote_records.find(new_record_identifier) ==
        m_legacy_intermediate_contextual_enote_records.end())
    {
        // add new intermediate record
        m_legacy_intermediate_contextual_enote_records[new_record_identifier] = new_record;
        events_inout.emplace_back(NewLegacyIntermediateRecord{new_record_identifier});
    }
    else
    {
        // update intermediate record's origin context
        if (try_update_enote_origin_context_v1(new_record.origin_context,
                m_legacy_intermediate_contextual_enote_records[new_record_identifier].origin_context))
            events_inout.emplace_back(UpdatedLegacyIntermediateOriginContext{new_record_identifier});
    }

    // 3. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.record.enote)]
        .insert(new_record_identifier);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::add_record(const LegacyContextualEnoteRecordV1 &new_record,
    std::list<EnoteStoreEvent> &events_inout)
{
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.record.enote),
        new_record.record.amount,
        new_record_identifier);

    // 1. add the record or update an existing record's contexts
    if (m_legacy_contextual_enote_records.find(new_record_identifier) == m_legacy_contextual_enote_records.end())
    {
        m_legacy_contextual_enote_records[new_record_identifier] = new_record;
        events_inout.emplace_back(NewLegacyRecord{new_record_identifier});
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record.origin_context,
                new_record.spent_context,
                m_legacy_contextual_enote_records[new_record_identifier].origin_context,
                m_legacy_contextual_enote_records[new_record_identifier].spent_context
            );
        events_inout.emplace_back(UpdatedLegacyOriginContext{new_record_identifier});
        events_inout.emplace_back(UpdatedLegacySpentContext{new_record_identifier});
    }

    // 2. if this enote is located in the legacy key image tracker for seraphis txs, update with the tracker's spent
    //    context
    if (m_legacy_key_images_in_sp_selfsends.find(new_record.record.key_image) !=
        m_legacy_key_images_in_sp_selfsends.end())
    {
        // update the record's spent context
        try_update_enote_spent_context_v1(m_legacy_key_images_in_sp_selfsends.at(new_record.record.key_image),
            m_legacy_contextual_enote_records[new_record_identifier].spent_context);
        //don't add event record: assume it would be redundant

        // note: do not change the tracker's spent context here, the tracker is a helper cache for the scanning process
        //       and should only be mutated by the relevant code
    }

    // 3. if this enote is located in the intermediate enote record map, update the full record with the intermediate
    //    record's origin context
    if (m_legacy_intermediate_contextual_enote_records.find(new_record_identifier) !=
        m_legacy_intermediate_contextual_enote_records.end())
    {
        // update the record's origin context
        try_update_enote_origin_context_v1(
                m_legacy_intermediate_contextual_enote_records.at(new_record_identifier).origin_context,
                m_legacy_contextual_enote_records[new_record_identifier].origin_context
            );
        //don't add event record: assume it would be redundant
    }

    // 4. there may be other full legacy enote records with this record's key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier :
            m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.record.enote)])
    {
        // a. skip identifiers not in the full legacy records map
        if (m_legacy_contextual_enote_records.find(legacy_enote_identifier) == m_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        try_update_enote_spent_context_v1(
            m_legacy_contextual_enote_records.at(legacy_enote_identifier).spent_context,
            m_legacy_contextual_enote_records[new_record_identifier].spent_context);
        //don't add event record: assume it would be redundant
    }

    // 5. remove the intermediate record with this identifier (must do this before importing the key image, since
    //    the key image importer assumes the intermediate and full legacy maps don't have any overlap)
    if (m_legacy_intermediate_contextual_enote_records.erase(new_record_identifier) > 0)
        events_inout.emplace_back(RemovedLegacyIntermediateRecord{new_record_identifier});

    // 6. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.record.enote)]
        .insert(new_record_identifier);

    // 7. save to the legacy key image set
    m_legacy_key_images[new_record.record.key_image] = onetime_address_ref(new_record.record.enote);

    // 8. import this key image to force-promote all intermediate records with different identifiers but the same
    //    onetime address to full records
    this->try_import_legacy_key_image(new_record.record.key_image,
        onetime_address_ref(new_record.record.enote),
        events_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::add_record(const SpContextualEnoteRecordV1 &new_record, std::list<EnoteStoreEvent> &events_inout)
{
    const crypto::key_image &record_key_image{key_image_ref(new_record)};

    // add the record or update an existing record's contexts
    if (m_sp_contextual_enote_records.find(record_key_image) == m_sp_contextual_enote_records.end())
    {
        m_sp_contextual_enote_records[record_key_image] = new_record;
        events_inout.emplace_back(NewSpRecord{record_key_image});
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record, m_sp_contextual_enote_records[record_key_image]);
        events_inout.emplace_back(UpdatedSpOriginContext{record_key_image});
        events_inout.emplace_back(UpdatedSpSpentContext{record_key_image});
    }
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_legacy_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore key images with unknown legacy enotes
        const auto legacy_ki_ref = m_legacy_key_images.find(found_spent_key_image.first);
        if (legacy_ki_ref == m_legacy_key_images.end())
            continue;

        // b. check that legacy key image map and tracked onetime address maps are consistent
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates.find(legacy_ki_ref->second) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "sp enote store (update with legacy enote records): duplicate tracker is missing a onetime address "
            "(bug).");

        // c. update contexts of any enotes associated with this key image
        const auto &identifiers_of_enotes_to_update =
            m_tracked_legacy_onetime_address_duplicates.at(legacy_ki_ref->second);

        for (const rct::key &identifier_of_enote_to_update : identifiers_of_enotes_to_update)
        {
            auto record_ref = m_legacy_contextual_enote_records.find(identifier_of_enote_to_update);
            CHECK_AND_ASSERT_THROW_MES(record_ref != m_legacy_contextual_enote_records.end(),
                "sp enote store (update with legacy enote records): full record map is missing identifier (bug).");
            CHECK_AND_ASSERT_THROW_MES(record_ref->second.record.key_image == found_spent_key_image.first,
                "sp enote store (update with legacy enote records): full record map is inconsistent (bug).");

            update_contextual_enote_record_contexts_v1(
                record_ref->second.origin_context,
                found_spent_key_image.second,
                record_ref->second.origin_context,
                record_ref->second.spent_context);
            events_inout.emplace_back(UpdatedLegacyOriginContext{identifier_of_enote_to_update});
            events_inout.emplace_back(UpdatedLegacySpentContext{identifier_of_enote_to_update});
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::update_sp_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreEvent> &events_inout)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore enotes with unknown key images
        auto record_ref = m_sp_contextual_enote_records.find(found_spent_key_image.first);
        if (record_ref == m_sp_contextual_enote_records.end())
            continue;

        // b. update this enote's contexts
        update_contextual_enote_record_contexts_v1(
            record_ref->second.origin_context,
            found_spent_key_image.second,
            record_ref->second.origin_context,
            record_ref->second.spent_context);
        events_inout.emplace_back(UpdatedSpOriginContext{found_spent_key_image.first});
        events_inout.emplace_back(UpdatedSpSpentContext{found_spent_key_image.first});
    }
}
//-------------------------------------------------------------------------------------------------------------------
// ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStore::handle_legacy_key_images_from_sp_selfsends(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreEvent> &events_inout)
{
    // handle each key image
    for (const auto &legacy_key_image_with_spent_context : legacy_key_images_in_sp_selfsends)
    {
        // 1. save the key image's spent context in the tracker (or update an existing context)
        // note: these are always saved to help with reorg handling
        try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
            m_legacy_key_images_in_sp_selfsends[legacy_key_image_with_spent_context.first]);
        //don't add event record: the m_legacy_key_images_in_sp_selfsends is an internal cache

        // 2. get the identifiers associated with this element's key image
        const auto onetime_address_ref = m_legacy_key_images.find(legacy_key_image_with_spent_context.first);
        if (onetime_address_ref == m_legacy_key_images.end())
            continue;
        const auto duplicates_ref = m_tracked_legacy_onetime_address_duplicates.find(onetime_address_ref->second);
        if (duplicates_ref == m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        // 3. try to update the spent contexts of legacy enotes that have this key image
        for (const rct::key &legacy_identifier : duplicates_ref->second)
        {
            // a. ignore identifiers that aren't in the full legacy map
            auto record_ref = m_legacy_contextual_enote_records.find(legacy_identifier);
            if (record_ref == m_legacy_contextual_enote_records.end())
                continue;

            // b. update the spent context of this legacy enote
            if (try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
                    record_ref->second.spent_context))
                events_inout.emplace_back(UpdatedLegacySpentContext{record_ref->first});
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
