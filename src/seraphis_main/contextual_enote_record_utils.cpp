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
#include "contextual_enote_record_utils.h"

//local headers
#include "contextual_enote_record_types.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "ringct/rctTypes.h"
#include "tx_input_selection.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <functional>
#include <set>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool onchain_legacy_enote_is_locked(const std::uint64_t enote_origin_block_index,
    const std::uint64_t enote_unlock_time,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::uint64_t current_time)
{
    // 1. check default spendable age
    // - test: is the next minable block lower than the first block where the enote is spendable?
    // - an enote is not spendable in the block where it originates, so the default spendable age is always at least 1
    if (top_block_index + 1 < enote_origin_block_index + std::max(std::uint64_t{1}, default_spendable_age))
        return true;

    // 2. check unlock time: height encoding
    // - test: is the next minable block's height lower than the block height where the enote is unlocked?
    // note: block height == block index  (there is a lot of confusion around this since it 'seems' like height == chain
    //       size, but that doesn't take into account that the genesis block is at height 0)
    if (enote_unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER &&
        top_block_index + 1 < enote_unlock_time)
        return true;

    // 3. check unlock time: UNIX encoding
    // - test: is the current time lower than the UNIX time when the enote is unlocked?
    if (enote_unlock_time >= CRYPTONOTE_MAX_BLOCK_NUMBER &&
        current_time < enote_unlock_time)
        return true;

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool onchain_sp_enote_is_locked(const std::uint64_t enote_origin_block_index,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age)
{
    // check default spendable age
    // - test: is the next minable block lower than the first block where the enote is spendable?
    // - an enote is not spendable in the block where it originates, so the default spendable age is always at least 1
    return top_block_index + 1 < enote_origin_block_index + std::max(std::uint64_t{1}, default_spendable_age);
}
//-------------------------------------------------------------------------------------------------------------------
bool legacy_enote_has_highest_amount_in_set(const rct::key &specified_enote_identifier,
    const rct::xmr_amount specified_enote_amount,
    const std::unordered_set<SpEnoteOriginStatus> &allowed_origin_statuses,
    const std::unordered_set<rct::key> &enote_identifier_set,
    const std::function<const SpEnoteOriginStatus&(const rct::key&)> &get_record_origin_status_for_identifier_func,
    const std::function<rct::xmr_amount(const rct::key&)> &get_record_amount_for_identifier_func)
{
    // 1. collect enote amounts from the set of enote identifiers
    std::set<rct::xmr_amount> collected_amounts;
    bool found_specified_enote{false};

    for (const rct::key &identifier : enote_identifier_set)
    {
        // a. ignore enotes with unwanted origin statuses
        if (allowed_origin_statuses.find(get_record_origin_status_for_identifier_func(identifier)) ==
                allowed_origin_statuses.end())
            continue;

        // b. record this amount
        const rct::xmr_amount amount{get_record_amount_for_identifier_func(identifier)};
        collected_amounts.insert(amount);

        // c. expect that we got the same amount for our specified enote
        if (identifier == specified_enote_identifier)
        {
            CHECK_AND_ASSERT_THROW_MES(amount == specified_enote_amount,
                "legacy enote highest amount search: mismatch between specified amount and found amount.");
            found_specified_enote = true;
        }
    }

    // 2. expect that we found our specified identifier
    // - do this instead of calling .find() on the identifier set in case the origin status check skips our identifier
    CHECK_AND_ASSERT_THROW_MES(found_specified_enote,
        "legacy enote highest amount search: the specified enote's identifier was not found.");

    // 3. success if the specified amount is the highest in the set
    // - note: it is fine if identifiers in the set have the same amount
    return *(collected_amounts.rbegin()) == specified_enote_amount;
}
//-------------------------------------------------------------------------------------------------------------------
void split_selected_input_set(const input_set_tracker_t &input_set,
    std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_records_out,
    std::vector<SpContextualEnoteRecordV1> &sp_contextual_records_out)
{
    legacy_contextual_records_out.clear();
    sp_contextual_records_out.clear();

    // 1. obtain legacy records
    if (input_set.find(InputSelectionType::LEGACY) != input_set.end())
    {
        legacy_contextual_records_out.reserve(input_set.at(InputSelectionType::LEGACY).size());

        for (const auto &mapped_contextual_enote_record : input_set.at(InputSelectionType::LEGACY))
        {
            CHECK_AND_ASSERT_THROW_MES(mapped_contextual_enote_record.second.is_type<LegacyContextualEnoteRecordV1>(),
                "splitting an input set: record is supposed to be legacy but is not.");

            legacy_contextual_records_out.emplace_back(
                    mapped_contextual_enote_record.second.unwrap<LegacyContextualEnoteRecordV1>()
                );
        }
    }

    // 2. obtain seraphis records
    if (input_set.find(InputSelectionType::SERAPHIS) != input_set.end())
    {
        sp_contextual_records_out.reserve(input_set.at(InputSelectionType::SERAPHIS).size());

        for (const auto &mapped_contextual_enote_record : input_set.at(InputSelectionType::SERAPHIS))
        {
            CHECK_AND_ASSERT_THROW_MES(mapped_contextual_enote_record.second.is_type<SpContextualEnoteRecordV1>(),
                "splitting an input set: record is supposed to be seraphis but is not.");

            sp_contextual_records_out.emplace_back(
                    mapped_contextual_enote_record.second.unwrap<SpContextualEnoteRecordV1>()
                );
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t total_amount(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records)
{
    boost::multiprecision::uint128_t total_amount{0};

    for (const LegacyContextualEnoteRecordV1 &contextual_record : contextual_records)
        total_amount += amount_ref(contextual_record);

    return total_amount;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t total_amount(const std::vector<SpContextualEnoteRecordV1> &contextual_records)
{
    boost::multiprecision::uint128_t total_amount{0};

    for (const SpContextualEnoteRecordV1 &contextual_record : contextual_records)
        total_amount += amount_ref(contextual_record);

    return total_amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_membership_proof_real_reference_mappings(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &enote_ledger_mappings_out)
{
    enote_ledger_mappings_out.clear();
    enote_ledger_mappings_out.reserve(contextual_records.size());

    for (const LegacyContextualEnoteRecordV1 &contextual_record : contextual_records)
    {
        // 1. only onchain enotes have ledger indices
        if (!has_origin_status(contextual_record, SpEnoteOriginStatus::ONCHAIN))
            return false;

        // 2. save the [ KI : enote ledger index ] entry
        enote_ledger_mappings_out[key_image_ref(contextual_record)] =
            contextual_record.origin_context.enote_ledger_index;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_membership_proof_real_reference_mappings(const std::vector<SpContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &enote_ledger_mappings_out)
{
    enote_ledger_mappings_out.clear();
    enote_ledger_mappings_out.reserve(contextual_records.size());

    for (const SpContextualEnoteRecordV1 &contextual_record : contextual_records)
    {
        // 1. only onchain enotes have ledger indices
        if (!has_origin_status(contextual_record, SpEnoteOriginStatus::ONCHAIN))
            return false;

        // 2. save the [ KI : enote ledger index ] entry
        enote_ledger_mappings_out[key_image_ref(contextual_record)] =
            contextual_record.origin_context.enote_ledger_index;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_origin_context_v1(const SpEnoteOriginContextV1 &fresh_origin_context,
    SpEnoteOriginContextV1 &current_origin_context_inout)
{
    // 1. fail if the current context is older than the fresh one
    if (is_older_than(current_origin_context_inout, fresh_origin_context))
        return false;

    // 2. overwrite with the fresh context (do this even if the fresh one seems to have the same age)
    current_origin_context_inout = fresh_origin_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_spent_context_v1(const SpEnoteSpentContextV1 &fresh_spent_context,
    SpEnoteSpentContextV1 &current_spent_context_inout)
{
    // 1. fail if the current context is older than the fresh one
    if (is_older_than(current_spent_context_inout, fresh_spent_context))
        return false;

    // 2. overwrite with the fresh context (do this even if the fresh one seems to have the same age)
    current_spent_context_inout = fresh_spent_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_contextual_enote_record_spent_context_v1(const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpContextualEnoteRecordV1 &contextual_enote_record_inout)
{
    // 1. fail if our record doesn't have a key image in the set
    if (!has_key_image(contextual_key_image_set, key_image_ref(contextual_enote_record_inout)))
        return false;

    // 2. try to update the record's spent context
    if (!try_update_enote_spent_context_v1(contextual_key_image_set.spent_context,
            contextual_enote_record_inout.spent_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteOriginStatus origin_status_from_spent_status_v1(const SpEnoteSpentStatus spent_status)
{
    switch (spent_status)
    {
        case (SpEnoteSpentStatus::UNSPENT) :
        case (SpEnoteSpentStatus::SPENT_OFFCHAIN) :
            return SpEnoteOriginStatus::OFFCHAIN;

        case (SpEnoteSpentStatus::SPENT_UNCONFIRMED) :
            return SpEnoteOriginStatus::UNCONFIRMED;

        case (SpEnoteSpentStatus::SPENT_ONCHAIN) :
            return SpEnoteOriginStatus::ONCHAIN;

        default :
            return SpEnoteOriginStatus::OFFCHAIN;
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_bump_enote_record_origin_status_v1(const SpEnoteSpentStatus spent_status,
    SpEnoteOriginStatus &origin_status_inout)
{
    // 1. get the implied origin status
    const SpEnoteOriginStatus implied_origin_status{origin_status_from_spent_status_v1(spent_status)};

    // 2. check if our existing origin status is older than the new implied one
    if (origin_status_inout > implied_origin_status)
        return false;

    // 3. bump our origin status
    origin_status_inout = implied_origin_status;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpEnoteOriginContextV1 &new_origin_context,
    const SpEnoteSpentContextV1 &new_spent_context,
    SpEnoteOriginContextV1 &origin_context_inout,
    SpEnoteSpentContextV1 &spent_context_inout)
{
    // 1. update the origin context
    try_update_enote_origin_context_v1(new_origin_context, origin_context_inout);

    // 2. update the spent context
    try_update_enote_spent_context_v1(new_spent_context, spent_context_inout);

    // 3. bump the origin status based on the new spent status
    try_bump_enote_record_origin_status_v1(spent_context_inout.spent_status, origin_context_inout.origin_status);
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpContextualEnoteRecordV1 &fresh_record,
    SpContextualEnoteRecordV1 &existing_record_inout)
{
    CHECK_AND_ASSERT_THROW_MES(fresh_record.record.key_image == existing_record_inout.record.key_image,
        "updating a contextual enote record: the fresh record doesn't represent the same enote.");

    update_contextual_enote_record_contexts_v1(fresh_record.origin_context,
        fresh_record.spent_context,
        existing_record_inout.origin_context,
        existing_record_inout.spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
