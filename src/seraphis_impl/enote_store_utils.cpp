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
#include "enote_store_utils.h"

//local headers
#include "misc_log_ex.h"
#include "seraphis_impl/checkpoint_cache.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_payment_validator.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_main/scan_machine_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <ctime>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t get_balance_intermediate_legacy(
    // [ legacy identifier : legacy intermediate record ]
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &legacy_intermediate_records,
    // [ Ko : legacy identifier ]
    const std::unordered_map<rct::key, std::unordered_set<rct::key>> &legacy_onetime_address_identifier_map,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if excluded
    if (exclusions.find(BalanceExclusions::LEGACY_INTERMEDIATE) != exclusions.end())
        return 0;

    // 2. accumulate balance
    // note: it is unknown if enotes in intermediate records are spent
    for (const auto &mapped_contextual_record : legacy_intermediate_records)
    {
        const LegacyContextualIntermediateEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. ignore this enote if its origin status is not requested
        if (origin_statuses.find(current_contextual_record.origin_context.origin_status) == origin_statuses.end())
            continue;

        // b. ignore locked onchain enotes if they should be excluded
        if (exclusions.find(BalanceExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.origin_context.origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.origin_context.block_index,
                    current_contextual_record.record.unlock_time,
                    top_block_index,
                    default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr))
                ))
            continue;

        // c. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(legacy_onetime_address_identifier_map
                    .find(onetime_address_ref(current_contextual_record.record.enote)) !=
                legacy_onetime_address_identifier_map.end(),
            "get balance intermediate legacy: tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_in_set(mapped_contextual_record.first,
                current_contextual_record.record.amount,
                origin_statuses,
                legacy_onetime_address_identifier_map.at(
                    onetime_address_ref(current_contextual_record.record.enote)
                ),
                [&legacy_intermediate_records](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(legacy_intermediate_records.find(identifier) !=
                            legacy_intermediate_records.end(),
                        "get balance intermediate legacy: tracked legacy duplicates has an entry that "
                        "doesn't line up 1:1 with the legacy intermediate map even though it should (bug).");

                    return legacy_intermediate_records
                        .at(identifier)
                        .origin_context
                        .origin_status;
                },
                [&legacy_intermediate_records](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(legacy_intermediate_records.find(identifier) !=
                            legacy_intermediate_records.end(),
                        "get balance intermediate legacy: tracked legacy duplicates has an entry that "
                        "doesn't line up 1:1 with the legacy intermediate map even though it should (bug).");

                    return legacy_intermediate_records.at(identifier).record.amount;
                }))
            continue;

        // d. update balance
        balance += current_contextual_record.record.amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t get_balance_full_legacy(
    // [ legacy identifier : legacy record ]
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &legacy_records,
    // [ Ko : legacy identifier ]
    const std::unordered_map<rct::key, std::unordered_set<rct::key>> &legacy_onetime_address_identifier_map,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if excluded
    if (exclusions.find(BalanceExclusions::LEGACY_FULL) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : legacy_records)
    {
        const LegacyContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. ignore this enote if its origin status is not requested
        if (origin_statuses.find(current_contextual_record.origin_context.origin_status) == origin_statuses.end())
            continue;

        // b. ignore this enote if its spent status is requested
        if (spent_statuses.find(current_contextual_record.spent_context.spent_status) != spent_statuses.end())
            continue;

        // c. ignore locked onchain enotes if they should be excluded
        if (exclusions.find(BalanceExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.origin_context.origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.origin_context.block_index,
                    current_contextual_record.record.unlock_time,
                    top_block_index,
                    default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr)))
                )
            continue;

        // d. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(legacy_onetime_address_identifier_map
                    .find(onetime_address_ref(current_contextual_record.record.enote)) !=
                legacy_onetime_address_identifier_map.end(),
            "get balance full legacy: tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_in_set(mapped_contextual_record.first,
                current_contextual_record.record.amount,
                origin_statuses,
                legacy_onetime_address_identifier_map.at(
                    onetime_address_ref(current_contextual_record.record.enote)
                ),
                [&legacy_records](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(legacy_records.find(identifier) != legacy_records.end(),
                        "get balance full legacy: tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return legacy_records
                        .at(identifier)
                        .origin_context
                        .origin_status;
                },
                [&legacy_records](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(legacy_records.find(identifier) !=  legacy_records.end(),
                        "get balance full legacy: tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return legacy_records.at(identifier).record.amount;
                }))
            continue;

        // e. update balance
        balance += current_contextual_record.record.amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t get_balance_intermediate_seraphis(
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &sp_intermediate_records,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t received_sum{0};

    // 1. ignore if excluded
    if (exclusions.find(BalanceExclusions::SERAPHIS_INTERMEDIATE) != exclusions.end())
        return 0;

    // 2. accumulate received sum
    // note: it is unknown if enotes in intermediate records are spent
    for (const auto &mapped_contextual_record : sp_intermediate_records)
    {
        const SpContextualIntermediateEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. ignore this enote if its origin status is not requested
        if (origin_statuses.find(current_contextual_record.origin_context.origin_status) == origin_statuses.end())
            continue;

        // b. ignore locked onchain enotes if they should be excluded
        if (exclusions.find(BalanceExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.origin_context.origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    current_contextual_record.origin_context.block_index,
                    top_block_index,
                    default_spendable_age
                ))
            continue;

        // c. update received sum
        received_sum += current_contextual_record.record.amount;
    }

    return received_sum;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static boost::multiprecision::uint128_t get_balance_full_seraphis(
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &sp_records,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if excluded
    if (exclusions.find(BalanceExclusions::SERAPHIS_FULL) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : sp_records)
    {
        const SpContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. ignore this enote if its origin status is not requested
        if (origin_statuses.find(current_contextual_record.origin_context.origin_status) == origin_statuses.end())
            continue;

        // b. ignore this enote if its spent status is requested
        if (spent_statuses.find(current_contextual_record.spent_context.spent_status) != spent_statuses.end())
            continue;

        // c. ignore locked onchain enotes if they should be excluded
        if (exclusions.find(BalanceExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.origin_context.origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    current_contextual_record.origin_context.block_index,
                    top_block_index,
                    default_spendable_age
                ))
            continue;

        // d. update balance
        balance += current_contextual_record.record.amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void update_checkpoint_cache_with_new_block_ids(const rct::key &alignment_block_id,
    const std::uint64_t first_new_block_index,
    const std::vector<rct::key> &new_block_ids,
    CheckpointCache &cache_inout,
    std::uint64_t &old_top_index_out,
    std::uint64_t &range_start_index_out,
    std::uint64_t &num_blocks_added_out)
{
    // 1. check inputs
    const std::uint64_t first_allowed_index{cache_inout.min_checkpoint_index()};

    CHECK_AND_ASSERT_THROW_MES(first_new_block_index >= first_allowed_index,
        "update checkpoint cache with new block ids: first new block is below the refresh index.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block_index - first_allowed_index <=
            cache_inout.top_block_index() - cache_inout.min_checkpoint_index() + 1,
        "update checkpoint cache with new block ids: new blocks don't line up with existing blocks.");
    if (first_new_block_index > first_allowed_index)
    {
        rct::key cached_alignment_block_id;
        CHECK_AND_ASSERT_THROW_MES(cache_inout.try_get_block_id(first_new_block_index - 1, cached_alignment_block_id) &&
                alignment_block_id == cached_alignment_block_id,
            "update checkpoint cache with new block ids: alignment block id doesn't align with cached block ids.");
    }

    // 2. save the diff
    old_top_index_out     = cache_inout.top_block_index();
    range_start_index_out = first_new_block_index;
    num_blocks_added_out  = new_block_ids.size();

    // 3. insert the new block ids
    cache_inout.insert_new_block_ids(first_new_block_index, new_block_ids);
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_next_legacy_partialscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index)
{
    // 1. next block known by enote store > test index
    const std::uint64_t next_index{enote_store.next_legacy_partialscanned_block_index(block_index)};

    // 2. try to get the block index for the next block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_legacy_partialscan(next_index, temp_block_id))
        return scanning::ContiguityMarker{static_cast<std::uint64_t>(-1), boost::none};

    // 3. { next block index, next block id }
    return scanning::ContiguityMarker{next_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_next_legacy_fullscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index)
{
    // 1. next block known by enote store > test index
    const std::uint64_t next_index{enote_store.next_legacy_fullscanned_block_index(block_index)};

    // 2. try to get the block index for the next block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_legacy_fullscan(next_index, temp_block_id))
        return scanning::ContiguityMarker{static_cast<std::uint64_t>(-1), boost::none};

    // 3. { next block index, next block id }
    return scanning::ContiguityMarker{next_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_next_sp_scanned_block(const SpEnoteStorePaymentValidator &enote_store,
    const std::uint64_t block_index)
{
    // 1. next block known by enote store > test index
    const std::uint64_t next_index{enote_store.next_sp_scanned_block_index(block_index)};

    // 2. try to get the block index for the next block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_sp(next_index, temp_block_id))
        return scanning::ContiguityMarker{static_cast<std::uint64_t>(-1), boost::none};

    // 3. { next block index, next block id }
    return scanning::ContiguityMarker{next_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_next_sp_scanned_block(const SpEnoteStore &enote_store, const std::uint64_t block_index)
{
    // 1. next block known by enote store > test index
    const std::uint64_t next_index{enote_store.next_sp_scanned_block_index(block_index)};

    // 2. try to get the block index for the next block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_sp(next_index, temp_block_id))
        return scanning::ContiguityMarker{static_cast<std::uint64_t>(-1), boost::none};

    // 3. { next block index, next block id }
    return scanning::ContiguityMarker{next_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_nearest_legacy_partialscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index)
{
    // 1. nearest block known by enote store <= test index
    const std::uint64_t nearest_index{enote_store.nearest_legacy_partialscanned_block_index(block_index)};

    // 2. try to get the block index for the nearest block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_legacy_partialscan(nearest_index, temp_block_id))
        return scanning::ContiguityMarker{enote_store.legacy_refresh_index() - 1, boost::none};

    // 3. { nearest block index, nearest block id }
    return scanning::ContiguityMarker{nearest_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_nearest_legacy_fullscanned_block(const SpEnoteStore &enote_store,
    const std::uint64_t block_index)
{
    // 1. nearest block known by enote store <= test index
    const std::uint64_t nearest_index{enote_store.nearest_legacy_fullscanned_block_index(block_index)};

    // 2. try to get the block index for the nearest block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_legacy_fullscan(nearest_index, temp_block_id))
        return scanning::ContiguityMarker{enote_store.legacy_refresh_index() - 1, boost::none};

    // 3. { nearest block index, nearest block id }
    return scanning::ContiguityMarker{nearest_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_nearest_sp_scanned_block(const SpEnoteStorePaymentValidator &enote_store,
    const std::uint64_t block_index)
{
    // 1. nearest block known by enote store <= test index
    const std::uint64_t nearest_index{enote_store.nearest_sp_scanned_block_index(block_index)};

    // 2. try to get the block index for the nearest block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_sp(nearest_index, temp_block_id))
        return scanning::ContiguityMarker{enote_store.refresh_index() - 1, boost::none};

    // 3. { nearest block index, nearest block id }
    return scanning::ContiguityMarker{nearest_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
scanning::ContiguityMarker get_nearest_sp_scanned_block(const SpEnoteStore &enote_store, const std::uint64_t block_index)
{
    // 1. nearest block known by enote store <= test index
    const std::uint64_t nearest_index{enote_store.nearest_sp_scanned_block_index(block_index)};

    // 2. try to get the block index for the nearest block
    rct::key temp_block_id;
    if (!enote_store.try_get_block_id_for_sp(nearest_index, temp_block_id))
        return scanning::ContiguityMarker{enote_store.sp_refresh_index() - 1, boost::none};

    // 3. { nearest block index, nearest block id }
    return scanning::ContiguityMarker{nearest_index, temp_block_id};
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t get_balance(const SpEnoteStore &enote_store,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t balance{0};

    // 1. intermediate legacy enotes (it is unknown if these enotes are spent)
    balance += get_balance_intermediate_legacy(enote_store.legacy_intermediate_records(),
        enote_store.legacy_onetime_address_identifier_map(),
        enote_store.top_block_index(),
        enote_store.default_spendable_age(),
        origin_statuses,
        exclusions);

    // 2. full legacy enotes
    balance += get_balance_full_legacy(enote_store.legacy_records(),
        enote_store.legacy_onetime_address_identifier_map(),
        enote_store.top_block_index(),
        enote_store.default_spendable_age(),
        origin_statuses,
        spent_statuses,
        exclusions);

    // 3. seraphis enotes
    balance += get_balance_full_seraphis(enote_store.sp_records(),
        enote_store.top_block_index(),
        enote_store.default_spendable_age(),
        origin_statuses,
        spent_statuses,
        exclusions);

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t get_received_sum(const SpEnoteStorePaymentValidator &payment_validator,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<BalanceExclusions> &exclusions)
{
    boost::multiprecision::uint128_t received_sum{0};

    // 1. intermediate seraphis enotes (received normal enotes only; it is unknown if they are spent)
    received_sum += get_balance_intermediate_seraphis(payment_validator.sp_intermediate_records(),
        payment_validator.top_block_index(),
        payment_validator.default_spendable_age(),
        origin_statuses,
        exclusions);

    return received_sum;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
