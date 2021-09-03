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

// Enote store that supports full-featured balance recovery by managing enote-related caches.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/checkpoint_cache.h"
#include "seraphis_impl/enote_store_event_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers
#include <unordered_map>
#include <unordered_set>

//forward declarations


namespace sp
{

////
// SpEnoteStore
// - tracks legacy and seraphis enotes
///
class SpEnoteStore final
{
public:
//constructors
    /// normal constructor
    SpEnoteStore(const std::uint64_t refresh_index,
        const std::uint64_t first_sp_enabled_block_in_chain,
        const std::uint64_t default_spendable_age,
        const CheckpointCacheConfig &checkpoint_cache_config =
                CheckpointCacheConfig{
                        .num_unprunable = 50,
                        .max_separation = 100000,
                        .density_factor = 20
                    }
            );

//member functions
    /// config: get index of the first block the enote store cares about
    std::uint64_t legacy_refresh_index() const;
    std::uint64_t sp_refresh_index() const;
    /// config: get default spendable age
    std::uint64_t default_spendable_age() const { return m_default_spendable_age; }

    /// get index of the highest recorded block (legacy refresh index - 1 if no recorded blocks)
    std::uint64_t top_block_index() const;
    /// get index of the highest block that was legacy partialscanned (view-scan only)
    std::uint64_t top_legacy_partialscanned_block_index() const { return m_legacy_partialscan_index; }
    /// get index of the highest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t top_legacy_fullscanned_block_index()    const { return m_legacy_fullscan_index;    }
    /// get index of the highest block that was seraphis view-balance scanned
    std::uint64_t top_sp_scanned_block_index()            const { return m_sp_scanned_index;         }

    /// get the next cached block index > the requested index (-1 on failure)
    std::uint64_t next_legacy_partialscanned_block_index(const std::uint64_t block_index) const;
    std::uint64_t next_legacy_fullscanned_block_index   (const std::uint64_t block_index) const;
    std::uint64_t next_sp_scanned_block_index           (const std::uint64_t block_index) const;
    /// get the nearest cached block index <= the requested index (refresh index - 1 on failure)
    std::uint64_t nearest_legacy_partialscanned_block_index(const std::uint64_t block_index) const;
    std::uint64_t nearest_legacy_fullscanned_block_index   (const std::uint64_t block_index) const;
    std::uint64_t nearest_sp_scanned_block_index           (const std::uint64_t block_index) const;
    /// try to get the cached block id for a given index and specified scan mode
    /// note: during scanning, different scan modes are assumed to 'not see' block ids obtained by a different scan mode;
    ///       this is necessary to reliably recover from reorgs involving multiple scan modes
    bool try_get_block_id_for_legacy_partialscan(const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_legacy_fullscan   (const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_sp                (const std::uint64_t block_index, rct::key &block_id_out) const;
    /// try to get the cached block id for a given index (checks legacy block ids then seraphis block ids)
    bool try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const;
    /// check if any stored enote has a given key image
    bool has_enote_with_key_image(const crypto::key_image &key_image) const;
    /// get the legacy [ legacy identifier : legacy intermediate record ] map
    /// - note: useful for collecting onetime addresses and viewkey extensions for key image recovery
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>& legacy_intermediate_records() const
    { return m_legacy_intermediate_contextual_enote_records; }
    /// get the legacy [ legacy identifier : legacy record ] map
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1>& legacy_records() const
    { return m_legacy_contextual_enote_records; }
    /// get the legacy [ Ko : [ legacy identifier ] ] map
    const std::unordered_map<rct::key, std::unordered_set<rct::key>>& legacy_onetime_address_identifier_map() const
    { return m_tracked_legacy_onetime_address_duplicates; }
    /// get the legacy [ KI : Ko ] map
    const std::unordered_map<crypto::key_image, rct::key>& legacy_key_images() const
    { return m_legacy_key_images; }
    /// get the seraphis [ KI : sp record ] map
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1>& sp_records() const
    { return m_sp_contextual_enote_records; }
    /// try to get the legacy enote with a specified key image
    /// - will only return the highest-amount legacy enote among duplicates, and will return false if the
    ///   highest-amount legacy enote is currently in the intermediate records map
    bool try_get_legacy_enote_record(const crypto::key_image &key_image,
        LegacyContextualEnoteRecordV1 &contextual_record_out) const;
    /// try to get the seraphis enote with a specified key image
    bool try_get_sp_enote_record(const crypto::key_image &key_image,
        SpContextualEnoteRecordV1 &contextual_record_out) const;

    /// try to import a legacy key image
    /// - PRECONDITION1: the legacy key image was computed from/for the input onetime address
    /// - returns false if the onetime address is unknown (e.g. due to a reorg that removed the corresponding record)
    bool try_import_legacy_key_image(const crypto::key_image &legacy_key_image,
        const rct::key &onetime_address,
        std::list<EnoteStoreEvent> &events_inout);
    /// update the legacy fullscan index as part of a legacy key image import cycle
    void update_legacy_fullscan_index_for_import_cycle(const std::uint64_t saved_index);

    /// setters for scan indices
    /// WARNING: misuse of these will mess up the enote store's state (to recover: set index below problem then rescan)
    /// note: to repair the enote store in case of an exception or other error during an update, save all of the last
    ///       scanned indices from before the update, reset the enote store with them (after the failure), and then
    ///       re-scan to repair
    void set_last_legacy_partialscan_index(const std::uint64_t new_index);
    void set_last_legacy_fullscan_index   (const std::uint64_t new_index);
    void set_last_sp_scanned_index        (const std::uint64_t new_index);

    /// update the store with legacy enote records and associated context
    void update_with_intermediate_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_intermediate_legacy_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_intermediate_legacy_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_legacy_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);

    /// update the store with seraphis enote records and associated context
    void update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_sp_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreEvent> &events_inout);

private:
    /// update the store with a set of new block ids from the ledger
    void update_with_new_blocks_from_ledger_legacy_partialscan(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_new_blocks_from_ledger_legacy_fullscan(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_new_blocks_from_ledger_sp(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreEvent> &events_inout);

    /// clean maps based on new legacy found spent key images
    void clean_maps_for_found_spent_legacy_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    /// clean maps based on details of removed legacy enotes
    void clean_maps_for_removed_legacy_enotes(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<rct::key, std::unordered_set<rct::key>> &mapped_identifiers_of_removed_enotes,
        const std::unordered_map<rct::key, crypto::key_image> &mapped_key_images_of_removed_enotes,
        const SpEnoteSpentStatus clearable_spent_status,
        const std::uint64_t first_uncleared_block_index,
        std::list<EnoteStoreEvent> &events_inout);
    /// clean up legacy state to prepare for adding fresh legacy enotes and key images
    void clean_maps_for_legacy_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void clean_maps_for_legacy_ledger_update(const std::uint64_t first_new_block,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);

    /// clean maps based on tx ids of removed seraphis enotes
    void clean_maps_for_removed_sp_enotes(const std::unordered_set<rct::key> &tx_ids_of_removed_enotes,
        std::list<EnoteStoreEvent> &events_inout);
    /// clean up seraphis state to prepare for adding fresh seraphis enotes and key images and legacy key images
    void clean_maps_for_sp_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
        std::list<EnoteStoreEvent> &events_inout);
    void clean_maps_for_sp_ledger_update(const std::uint64_t first_new_block,
        std::list<EnoteStoreEvent> &events_inout);

    /// add a record
    void add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record,
        std::list<EnoteStoreEvent> &events_inout);
    void add_record(const LegacyContextualEnoteRecordV1 &new_record,
        std::list<EnoteStoreEvent> &events_inout);
    void add_record(const SpContextualEnoteRecordV1 &new_record,
        std::list<EnoteStoreEvent> &events_inout);

    /// update legacy state with fresh legacy key images that were found to be spent
    void update_legacy_with_fresh_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    /// update seraphis state with fresh seraphis key images that were found to be spent
    void update_sp_with_fresh_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);

    /// cache legacy key images obtained from seraphis selfsends
    /// - these are the key images of legacy enotes spent by the user in seraphis txs; they are cached because
    ///   the enote store may not have the corresponding legacy enotes' records loaded in yet (or only the intermediate
    ///   records are known)
    void handle_legacy_key_images_from_sp_selfsends(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreEvent> &events_inout);

//member variables
    /// legacy intermediate enotes: [ legacy identifier : legacy intermediate record ]
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>
        m_legacy_intermediate_contextual_enote_records;
    /// legacy enotes: [ legacy identifier : legacy record ]
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> m_legacy_contextual_enote_records;
    /// seraphis enotes: [ seraphis KI : seraphis record ]
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_sp_contextual_enote_records;

    /// saved legacy key images from txs with seraphis selfsends (i.e. from txs we created)
    /// [ legacy KI : spent context ]
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_legacy_key_images_in_sp_selfsends;
    /// legacy duplicate tracker for dealing with enotes that have duplicated key images
    /// note: the user can receive multiple legacy enotes with the same identifier, but those are treated as equivalent,
    ///       which should only cause problems for users if the associated tx memos are different (very unlikely scenario)
    /// [ Ko : [ legacy identifier ] ]
    std::unordered_map<rct::key, std::unordered_set<rct::key>> m_tracked_legacy_onetime_address_duplicates;
    /// legacy onetime addresses attached to known legacy enotes
    /// note: might not include all entries in 'm_legacy_key_images_in_sp_selfsends' if some corresponding enotes are
    //        unknown
    /// [ legacy KI : legacy Ko ]
    std::unordered_map<crypto::key_image, rct::key> m_legacy_key_images;

    /// cached block ids in range: [refresh index, end of known legacy-supporting chain]
    CheckpointCache m_legacy_block_id_cache;
    /// cached block ids in range:
    ///   [max(refresh index, first seraphis-enabled block), end of known seraphis-supporting chain]
    CheckpointCache m_sp_block_id_cache;

    /// highest block that was legacy partialscanned (view-scan only)
    std::uint64_t m_legacy_partialscan_index{static_cast<std::uint64_t>(-1)};
    /// highest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t m_legacy_fullscan_index{static_cast<std::uint64_t>(-1)};
    /// highest block that was seraphis view-balance scanned
    std::uint64_t m_sp_scanned_index{static_cast<std::uint64_t>(-1)};

    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it is
    ///   on-chain and the next block's index is >= 'enote origin index + max(1, default_spendable_age)'; legacy
    ///   enotes also have an unlock_time attribute on top of the default spendable age
    std::uint64_t m_default_spendable_age{0};
};

} //namespace sp
