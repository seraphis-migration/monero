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

// NOT FOR PRODUCTION

//paired header
#include "tx_input_selector_mocks.h"

//local headers
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/tx_input_selection.h"

//third party headers
#include "boost/container/map.hpp"
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool pred_has_match(const boost::container::multimap<rct::xmr_amount, ContextualRecordVariant> &input_set,
    const std::function<bool(const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record)> &predicate)
{
    return std::find_if(input_set.begin(), input_set.end(), predicate) != input_set.end();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool pred_has_match(const input_set_tracker_t &input_set,
    const InputSelectionType input_type,
    const std::function<bool(const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record)> &predicate)
{
    if (input_set.find(input_type) == input_set.end())
        return false;

    return pred_has_match(input_set.at(input_type), predicate);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool InputSelectorMockSimpleV1::try_select_input_candidate_v1(const boost::multiprecision::uint128_t desired_total_amount,
    const input_set_tracker_t &added_inputs,
    const input_set_tracker_t &candidate_inputs,
    ContextualRecordVariant &selected_input_out) const
{
    // 1. try to select a legacy input
    for (const LegacyContextualEnoteRecordV1 &contextual_enote_record : m_enote_store.m_legacy_contextual_enote_records)
    {
        // a. only consider unspent enotes
        if (!has_spent_status(contextual_enote_record, SpEnoteSpentStatus::UNSPENT))
            continue;

        // b. prepare record finder
        auto record_finder =
            [&contextual_enote_record](const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record)
            -> bool
            {
                if (!comparison_record.second.is_type<LegacyContextualEnoteRecordV1>())
                    return false;

                return have_same_destination(
                        contextual_enote_record,
                        comparison_record.second.unwrap<LegacyContextualEnoteRecordV1>()
                    );
            };

        // c. ignore already added legacy inputs
        if (pred_has_match(added_inputs, InputSelectionType::LEGACY, record_finder))
            continue;

        // d. ignore legacy input candidates
        if (pred_has_match(candidate_inputs, InputSelectionType::LEGACY, record_finder))
            continue;

        selected_input_out = contextual_enote_record;
        return true;
    }

    // 2. try to select a seraphis input
    for (const SpContextualEnoteRecordV1 &contextual_enote_record : m_enote_store.m_sp_contextual_enote_records)
    {
        // a. only consider unspent enotes
        if (!has_spent_status(contextual_enote_record, SpEnoteSpentStatus::UNSPENT))
            continue;

        // b. prepare record finder
        auto record_finder =
            [&contextual_enote_record](const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record)
            -> bool
            {
                if (!comparison_record.second.is_type<SpContextualEnoteRecordV1>())
                    return false;

                return have_same_destination(
                        contextual_enote_record,
                        comparison_record.second.unwrap<SpContextualEnoteRecordV1>()
                    );
            };

        // c. ignore already added seraphis inputs
        if (pred_has_match(added_inputs, InputSelectionType::SERAPHIS, record_finder))
            continue;

        // d. ignore already seraphis input candidates
        if (pred_has_match(candidate_inputs, InputSelectionType::SERAPHIS, record_finder))
            continue;

        selected_input_out = contextual_enote_record;
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool InputSelectorMockV1::try_select_input_candidate_v1(const boost::multiprecision::uint128_t desired_total_amount,
    const input_set_tracker_t &added_inputs,
    const input_set_tracker_t &candidate_inputs,
    ContextualRecordVariant &selected_input_out) const
{
    // 1. try to select from legacy enotes
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &mapped_legacy_contextual_enote_records{
            m_enote_store.legacy_records()
        };
    const std::unordered_map<rct::key, std::unordered_set<rct::key>> &legacy_onetime_address_identifier_map{
            m_enote_store.legacy_onetime_address_identifier_map()
        };
    for (const auto &mapped_enote_record : mapped_legacy_contextual_enote_records)
    {
        // a. only consider unspent enotes
        if (!has_spent_status(mapped_enote_record.second, SpEnoteSpentStatus::UNSPENT))
            continue;

        // b. prepare record finder
        auto record_finder =
            [&mapped_enote_record](const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record) -> bool
            {
                if (!comparison_record.second.is_type<LegacyContextualEnoteRecordV1>())
                    return false;

                return have_same_destination(
                        mapped_enote_record.second,
                        comparison_record.second.unwrap<LegacyContextualEnoteRecordV1>()
                    );
            };

        // c. ignore already added legacy inputs
        if (pred_has_match(added_inputs, InputSelectionType::LEGACY, record_finder))
            continue;

        // d. ignore existing legacy input candidates
        if (pred_has_match(candidate_inputs, InputSelectionType::LEGACY, record_finder))
            continue;

        // e. if this legacy enote shares a onetime address with any other legacy enotes, only proceed if this one
        //   has the highest amount
        if (!legacy_enote_has_highest_amount_in_set(mapped_enote_record.first,
                mapped_enote_record.second.record.amount,
                {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED, SpEnoteOriginStatus::ONCHAIN},
                legacy_onetime_address_identifier_map.at(
                    onetime_address_ref(mapped_enote_record.second.record.enote)
                ),
                [&mapped_legacy_contextual_enote_records](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(mapped_legacy_contextual_enote_records.find(identifier) !=
                            mapped_legacy_contextual_enote_records.end(),
                        "input selector (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return mapped_legacy_contextual_enote_records.at(identifier).origin_context.origin_status;
                },
                [&mapped_legacy_contextual_enote_records](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(mapped_legacy_contextual_enote_records.find(identifier) != 
                            mapped_legacy_contextual_enote_records.end(),
                        "input selector (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return mapped_legacy_contextual_enote_records.at(identifier).record.amount;
                }))
            continue;

        selected_input_out = mapped_enote_record.second;
        return true;
    }

    // 2. try to select from seraphis enotes
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &mapped_sp_contextual_enote_records{
            m_enote_store.sp_records()
        };
    for (const auto &mapped_enote_record : mapped_sp_contextual_enote_records)
    {
        // a. only consider unspent enotes
        if (!has_spent_status(mapped_enote_record.second, SpEnoteSpentStatus::UNSPENT))
            continue;

        // b. prepare record finder
        auto record_finder =
            [&mapped_enote_record](const std::pair<rct::xmr_amount, ContextualRecordVariant> &comparison_record) -> bool
            {
                if (!comparison_record.second.is_type<SpContextualEnoteRecordV1>())
                    return false;

                return have_same_destination(
                        mapped_enote_record.second,
                        comparison_record.second.unwrap<SpContextualEnoteRecordV1>()
                    );
            };

        // c. ignore already added seraphis inputs
        if (pred_has_match(added_inputs, InputSelectionType::SERAPHIS, record_finder))
            continue;

        // d. ignore already excluded seraphis inputs
        if (pred_has_match(candidate_inputs, InputSelectionType::SERAPHIS, record_finder))
            continue;

        selected_input_out = mapped_enote_record.second;
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
