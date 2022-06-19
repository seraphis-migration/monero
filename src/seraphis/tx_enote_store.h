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
#include "ringct/rctTypes.h"
#include "tx_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>

//forward declarations


namespace sp
{

////
// SpEnoteStoreV1
// - enotes owned by a wallet
///
class SpEnoteStoreV1
{
public:
//overloaded operators
    /// disable copy/move (this is a virtual base class)
    SpEnoteStoreV1& operator=(SpEnoteStoreV1&&) = delete;

//member functions
    /// add a record
    virtual void add_record(const SpContextualEnoteRecordV1 &new_record) = 0;

    /// update the store with enote records found in the ledger, with associated context
    virtual void update_with_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::vector<rct::key> &new_block_ids) = 0;
/*
    // WARNING: any offchain information (e.g. offchain spent contexts) cleared here will be lost, so it may be
    //          appropriate to do an offchain refresh after this ledger refresh operation

    // expect alignment_block_id matches m_block_ids[first_new_block - m_refresh_height - 1]
    // if first_new_block > m_refresh_height

    // a. remove onchain enotes in range [first_new_block, end of chain]
    clear_onchain_records_from_height(first_new_block);

    // b. remove all unconfirmed enotes
    clear_records_with_origin_status(SpEnoteOriginContextV1::OriginStatus::UNCONFIRMED);

    // c. clear spent contexts referencing removed enotes
    clear_spent_context_of_records_with_spent_status(SpEnoteSpentContextV1::SpentStatus::SPENT_UNCONFIRMED);
    clear_spent_context_of_records_from_spent_height(first_new_block);

    // d. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        add_record(found_enote_record.second);

    // e. update spent contexts of stored enotes
    for (const auto &found_spent_key_image : found_spent_key_images)
        update_spent_context(found_spent_key_image.first, found_spent_key_image.second);

    // f. set new block ids in range [first_new_block, end of chain)
    set_block_ids_from_height(first_new_block, new_block_ids);
*/

    /// update the store with enote records found off-chain, with associated context
    virtual void update_with_records_from_offchain(
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images) = 0;
/*
    // a. clear existing offchain enotes and erase any spent context referencing an offchain tx
    clear_records_with_origin_status(SpEnoteOriginContextV1::OriginStatus::OFFCHAIN);
    clear_spent_context_of_records_with_spent_status(SpEnoteSpentContextV1::SpentStatus::SPENT_OFFCHAIN);

    // b. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        add_record(found_enote_record.second);

    // c. update spent contexts of stored enotes
    for (const auto &found_spent_key_image : found_spent_key_images)
        update_spent_context(found_spent_key_image.first, found_spent_key_image.second);
*/

    /// check if any stored enote has a given key image
    virtual bool has_enote_with_key_image(const crypto::key_image &key_image) const = 0;
    /// try to get the recorded block id for a given height
    virtual bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const = 0;

    /// get height of first block the enote store cares about
    virtual std::uint64_t get_refresh_height() const = 0;
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
    virtual std::uint64_t get_top_block_height() const = 0;

    /// get current balance using specified origin/spent statuses
    virtual boost::multiprecision::uint128_t get_balance(
        const std::unordered_set<SpEnoteOriginContextV1::OriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentContextV1::SpentStatus> &spent_statuses) const = 0;
};

} //namespace sp
