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
#include "tx_contextual_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <list>
#include <unordered_map>
#include <unordered_set>

//forward declarations


namespace sp
{

enum class EnoteStoreBalanceUpdateExclusions
{
    LEGACY_FULL,
    LEGACY_INTERMEDIATE,
    SERAPHIS,
    ORIGIN_LEDGER_LOCKED
};

////
// SpEnoteStoreMockSimpleV1
///
class SpEnoteStoreMockSimpleV1 final
{
    friend class InputSelectorMockSimpleV1;

public:
    /// add a record
    void add_record(const SpContextualEnoteRecordV1 &new_record);

//member variables
protected:
    /// the enotes
    std::list<SpContextualEnoteRecordV1> m_contextual_enote_records;
};

////
// SpEnoteStoreMockV1
// - tracks legacy and seraphis enotes
///
class SpEnoteStoreMockV1 final
{
    friend class InputSelectorMockV1;

    enum class ScanUpdateMode
    {
        LEGACY_FULL,
        LEGACY_INTERMEDIATE,
        SERAPHIS
    };

public:
//constructors
    /// default constructor
    SpEnoteStoreMockV1() = default;

    /// normal constructor
    SpEnoteStoreMockV1(const std::uint64_t refresh_height,
        const std::uint64_t first_sp_enabled_block_in_chain,
        const std::uint64_t default_spendable_age = 0);

//member functions
    /// setters for scan heights
    /// WARNING: misuse of these will mess up the enote store's state (to recover: set height(s) below problem then rescan)
    void set_last_legacy_fullscan_height(const std::uint64_t new_height);
    void set_last_legacy_partialscan_height(const std::uint64_t new_height);
    void set_last_sp_scanned_height(const std::uint64_t new_height);

    /// add a record
    void add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record);
    void add_record(const LegacyContextualEnoteRecordV1 &new_record);
    void add_record(const SpContextualEnoteRecordV1 &new_record);

    /// import a legacy key image
    /// PRECONDITION1: the legacy key image was computed from/for the input onetime address
    /// PRECONDITION2: the onetime address is already known by the enote store (e.g. from intermediate legacy scanning)
    void import_legacy_key_image(const crypto::key_image &legacy_key_image, const rct::key &onetime_address);

    /// update the store with a set of new block ids from the ledger
    void update_with_new_blocks_from_ledger(const ScanUpdateMode scan_update_mode,
    const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids);

    /// cache legacy key images obtained from seraphis selfsends (i.e. ALL legacy key images spent by user in seraphis txs)
    void handle_legacy_key_images_from_sp_selfsends(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends);

    /// update the store with legacy enote records found in the ledger, with associated context
    void update_with_intermediate_legacy_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images);
    void update_with_legacy_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images);

    /// update the store with enote records found in the ledger, with associated context
    void update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends);

    /// update the store with enote records found off-chain, with associated context
    void update_with_sp_records_from_offchain(
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends);

    /// check if any stored enote has a given key image
    bool has_enote_with_key_image(const crypto::key_image &key_image) const;
    /// try to get the recorded block id for a given height
    bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const;
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>& get_legacy_intermediate_records() const
    { return m_mapped_legacy_intermediate_contextual_enote_records; }

    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const { return m_refresh_height; }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
    std::uint64_t get_top_block_height() const { return m_refresh_height + m_block_ids.size() - 1; }
    /// get height of heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    /// WARNING: if this is used in combination with the height of the last legacy-enabled block to determine whether
    //           legacy scanning is needed, then if a previous legacy scan reached that block height then legacy scanning
    //           won't be executed to heal any reorgs that change the last legacy-enabled block (fix this by
    //           forcing a legacy fullscan)
    std::uint64_t get_top_legacy_fullscanned_block_height() const { return m_legacy_fullscan_height; }
    /// get height of heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t get_top_legacy_partialscanned_block_height() const { return m_legacy_partialscan_height; }
    /// get height of heighest block that was seraphis view-balance scanned
    std::uint64_t get_top_sp_scanned_block_height() const { return m_sp_scanned_height; }
    /// get current balance using specified origin/spent statuses and exclusions
    boost::multiprecision::uint128_t get_balance(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions = {}) const;

private:
    /// clean up legacy state to prepare for adding fresh legacy enotes and key images
    void clean_legacy_maps_for_ledger_update(const std::uint64_t first_new_block,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images);
    /// update legacy state with fresh legacy key images that were found to be spent
    void update_legacy_with_fresh_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images);

//member variables
protected:
    /// intermediate legacy enotes (unknown key images): mapped to H32(Ko, a)
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>
        m_mapped_legacy_intermediate_contextual_enote_records;
    /// legacy enotes: mapped to H32(Ko, a)
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> m_mapped_legacy_contextual_enote_records;
    /// seraphis enotes
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_mapped_sp_contextual_enote_records;

    /// saved legacy key images from txs with seraphis selfsends (i.e. txs we created)
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_legacy_key_images_in_sp_selfsends;
    /// legacy H32(Ko, a) identifiers mapped to onetime addresses, for dealing with enotes that have duplicated key images
    /// note: the user can receive multiple legacy enotes with the same identifier, but those are treated as equivalent,
    ///       which should only cause problems for users if the associated tx memos are different (very unlikely scenario)
    std::unordered_map<rct::key, std::unordered_set<rct::key>> m_tracked_legacy_onetime_address_duplicates;
    /// all legacy onetime addresses attached to known legacy enotes, mapped to key images
    /// note: might not include all entries in 'legacy key images in sp selfsends' if some corresponding enotes are unknown
    std::unordered_map<crypto::key_image, rct::key> m_legacy_key_images;

    /// refresh height
    std::uint64_t m_refresh_height{0};
    /// stored block ids in range [refresh height, end of known chain]
    std::vector<rct::key> m_block_ids;

    /// heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t m_legacy_fullscan_height{static_cast<std::uint64_t>(-1)};
    /// heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t m_legacy_partialscan_height{static_cast<std::uint64_t>(-1)};
    /// heighest block that was seraphis view-balance scanned
    std::uint64_t m_sp_scanned_height{static_cast<std::uint64_t>(-1)};

    /// configuration value: the first ledger block that can contain seraphis txs
    std::uint64_t m_first_sp_enabled_block_in_chain{static_cast<std::uint64_t>(-1)};
    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it's on-chain
    //      and the hext height is >= 'origin height + max(1, default_spendable_age)'; legacy enotes also have an
    //      unlock_time attribute on top of the default spendable age
    std::uint64_t m_default_spendable_age{0};
};

////
// SpEnoteStoreMockPaymentValidatorV1
// - tracks non-self-send seraphis enotes
///
class SpEnoteStoreMockPaymentValidatorV1 final
{
public:
//constructors
    /// default constructor
    SpEnoteStoreMockPaymentValidatorV1() = default;

    /// normal constructor
    SpEnoteStoreMockPaymentValidatorV1(const std::uint64_t refresh_height,
        const std::uint64_t default_spendable_age = 0) :
        m_refresh_height{refresh_height},
        m_default_spendable_age{default_spendable_age}
    {}

//member functions
    /// add a record
    void add_record(const SpContextualIntermediateEnoteRecordV1 &new_record);

    /// update the store with enote records found in the ledger, with associated context
    void update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::vector<rct::key> &new_block_ids);

    /// update the store with enote records found off-chain, with associated context
    void update_with_sp_records_from_offchain(
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records);

    /// try to get the recorded block id for a given height
    bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const;

    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const { return m_refresh_height; }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks) (heighest block PayVal-scanned)
    std::uint64_t get_top_block_height() const { return m_refresh_height + m_block_ids.size() - 1; }
    /// get current total amount received using specified origin statuses
    boost::multiprecision::uint128_t get_received_sum(const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions = {}) const;

//member variables
protected:
    /// seraphis enotes
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> m_mapped_sp_contextual_enote_records;

    /// refresh height
    std::uint64_t m_refresh_height{0};
    /// stored block ids in range [refresh height, end of known chain]
    std::vector<rct::key> m_block_ids;

    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it's on-chain
    //      and the hext height is >= 'origin height + max(1, default_spendable_age)'
    std::uint64_t m_default_spendable_age{0};
};

} //namespace sp
