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

// Utilities for interacting with enote stores.

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_set>
#include <vector>

//forward declarations
namespace sp
{
    class CheckpointCache;
    class SpEnoteStore;
    class SpEnoteStorePaymentValidator;
namespace scanning
{
    struct ContiguityMarker;
}
}

namespace sp
{

////
// BalanceExclusions
// - Enotes that match with a balance exclusion will not be included in a balance calculation.
///
enum class BalanceExclusions
{
    LEGACY_FULL,
    LEGACY_INTERMEDIATE,
    SERAPHIS_INTERMEDIATE,
    SERAPHIS_FULL,
    ORIGIN_LEDGER_LOCKED
};

/**
* brief: update_checkpoint_cache_with_new_block_ids - insert new block ids into a checkpoint cache
* param: alignment_block_id -
* param: first_new_block_index -
* param: new_block_ids -
* inoutparam: cache_inout -
* outparam: old_top_index_out -
* outparam: range_start_index_out -
* outparam: num_blocks_added_out -
*/
void update_checkpoint_cache_with_new_block_ids(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block_index,
    const std::vector<rct::key> &new_block_ids,
    CheckpointCache &cache_inout,
    std::uint64_t &old_top_index_out,
    std::uint64_t &range_start_index_out,
    std::uint64_t &num_blocks_added_out);
/**
* brief: get_next_*_block - get the enote store's next cached block > the test index
*   - marker = {-1, boost::none} on failure
* param: enote_store -
* param: block_index -
* return: marker representing the enote store's next block > the test index
*/
scanning::ContiguityMarker get_next_legacy_partialscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_next_legacy_fullscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_next_sp_scanned_block(const SpEnoteStorePaymentValidator &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_next_sp_scanned_block(const SpEnoteStore &enote_store, const std::uint64_t block_index);
/**
* brief: get_nearest_*_block - get the enote store's nearest cached block <= the test index
*   - marker = {refresh index - 1, boost::none} on failure
* param: enote_store -
* param: block_index -
* return: marker representing the enote store's nearest block <= the test index
*/
scanning::ContiguityMarker get_nearest_legacy_partialscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_nearest_legacy_fullscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_nearest_sp_scanned_block(const SpEnoteStorePaymentValidator &enote_store,
    const std::uint64_t block_index);
scanning::ContiguityMarker get_nearest_sp_scanned_block(const SpEnoteStore &enote_store, const std::uint64_t block_index);
/**
* brief: get_balance - get current balance of an enote store using specified origin/spent statuses and exclusions
* param: enote_store -
* param: origin_statuses -
* param: spent_statuses -
* param: exclusions -
* return: the total balance
*/
boost::multiprecision::uint128_t get_balance(const SpEnoteStore &enote_store,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses = {},
    const std::unordered_set<BalanceExclusions> &exclusions = {});
/**
* brief: get_balance - get current total amount received using specified origin statuses and exclusions
* param: payment_validator -
* param: origin_statuses -
* param: exclusions -
* return: the total amount received
*/
boost::multiprecision::uint128_t get_received_sum(const SpEnoteStorePaymentValidator &payment_validator,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions = {});

} //namespace sp
