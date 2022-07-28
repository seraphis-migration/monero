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
    SpEnoteStoreMockV1(const std::uint64_t refresh_height, const std::uint64_t first_sp_enabled_block_in_chain);

//member functions
    /// setters for scan heights
    /// WARNING: misuse of these will mess up the enote store's state (to recover: set height(s) below problem then rescan)
    void set_last_legacy_fullscan_height(const std::uint64_t new_height);
    void set_last_legacy_partialscan_height(const std::uint64_t new_height);
    void set_last_sp_scanned_height(const std::uint64_t new_height);

    /// add a record
    void add_record(const SpContextualEnoteRecordV1 &new_record);

    /// import a legacy key image (TODO)
    /// PRECONDITION: the legacy key image was computed from/for the input onetime address
    void import_legacy_key_image(const crypto::key_image &legacy_key_image, const rct::key &onetime_address);

    /// update the store with a set of new block ids from the ledger
    void update_with_new_blocks_from_ledger(const ScanUpdateMode scan_update_mode,
    const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids);

    /// cache legacy key images obtained from seraphis selfsends (i.e. ALL legacy key images spent by user in seraphis txs)
    void handle_legacy_key_images_from_sp_selfsends(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends);

    /// update the store with legacy enote records found in the ledger, with associated context (TODO)
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

    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const { return m_refresh_height; }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
    std::uint64_t get_top_block_height() const { return m_refresh_height + m_block_ids.size() - 1; }
    /// get height of heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t get_top_legacy_fullscanned_block_height() const { return m_legacy_fullscan_height; }
    /// get height of heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t get_top_legacy_partialscanned_block_height() const { return m_legacy_partialscan_height; }
    /// get height of heighest block that was seraphis view-balance scanned
    std::uint64_t get_top_sp_scanned_block_height() const { return m_sp_scanned_height; }
    /// get current balance using specified origin/spent statuses
    boost::multiprecision::uint128_t get_balance(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses) const;

//member variables
protected:
    /// the enotes
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_mapped_contextual_enote_records;

    /// refresh height
    std::uint64_t m_refresh_height{0};
    /// stored block ids in range [refresh height, end of known chain]
    std::vector<rct::key> m_block_ids;

    /// heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t m_legacy_fullscan_height{0};
    /// heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t m_legacy_partialscan_height{0};
    /// heighest block that was seraphis view-balance scanned
    std::uint64_t m_sp_scanned_height{0};

    /// configuration value: the first ledger block that can contain seraphis txs
    std::uint64_t m_first_sp_enabled_block_in_chain{0};
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
    SpEnoteStoreMockPaymentValidatorV1(const std::uint64_t refresh_height) :
        m_refresh_height{refresh_height}
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
    boost::multiprecision::uint128_t get_received_sum(const std::unordered_set<SpEnoteOriginStatus> &origin_statuses) const;

//member variables
protected:
    /// the enotes
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> m_mapped_contextual_enote_records;

    /// refresh height
    std::uint64_t m_refresh_height{0};
    /// stored block ids in range [refresh height, end of known chain]
    std::vector<rct::key> m_block_ids;
};

} //namespace sp
