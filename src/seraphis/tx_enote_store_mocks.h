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
///
class SpEnoteStoreMockV1 final
{
    friend class InputSelectorMockV1;

public:
//constructors
    /// default constructor
    SpEnoteStoreMockV1() = default;

    /// normal constructor
    SpEnoteStoreMockV1(const std::uint64_t refresh_height) :
        m_refresh_height{refresh_height}
    {}

//member functions
    /// add a record
    void add_record(const SpContextualEnoteRecordV1 &new_record);

    /// update the store with enote records found in the ledger, with associated context
    void update_with_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::vector<rct::key> &new_block_ids);

    /// update the store with enote records found off-chain, with associated context
    void update_with_records_from_offchain(
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images);

    /// check if any stored enote has a given key image
    bool has_enote_with_key_image(const crypto::key_image &key_image) const;
    /// try to get the recorded block id for a given height
    bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const;

    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const { return m_refresh_height; }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
    std::uint64_t get_top_block_height() const { return m_refresh_height + m_block_ids.size() - 1; }
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
};

////
// SpEnoteStoreMockPaymentValidatorV1
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
    void update_with_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::vector<rct::key> &new_block_ids);

    /// update the store with enote records found off-chain, with associated context
    void update_with_records_from_offchain(
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records);

    /// try to get the recorded block id for a given height
    bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const;

    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const { return m_refresh_height; }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
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
