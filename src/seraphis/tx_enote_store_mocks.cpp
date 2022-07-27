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

//paired header
#include "tx_enote_store_mocks.h"

//local headers
#include "misc_log_ex.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_contextual_enote_record_utils.h"

//third party headers

//standard headers
#include <functional>
#include <unordered_set>
#include <utility>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename MapT>
static void for_all_in_map_erase_if(MapT &map_inout,
    const std::function<bool(const typename MapT::value_type&)> &predicate)
{
    for (auto map_it = map_inout.begin(); map_it != map_inout.end();)
    {
        if (predicate(*map_it))
            map_it = map_inout.erase(map_it);
        else
            ++map_it;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockSimpleV1::add_record(const SpContextualEnoteRecordV1 &new_record)
{
    m_contextual_enote_records.emplace_back(new_record);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const SpContextualEnoteRecordV1 &new_record)
{
    crypto::key_image record_key_image;
    new_record.get_key_image(record_key_image);

    // add the record or update an existing record's contexts
    if (m_mapped_contextual_enote_records.find(record_key_image) == m_mapped_contextual_enote_records.end())
    {
        m_mapped_contextual_enote_records[record_key_image] = new_record;
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record, m_mapped_contextual_enote_records[record_key_image]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::import_legacy_key_image(const crypto::key_image &legacy_key_image, const rct::key &onetime_address)
{
    //todo
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_intermediate_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::vector<rct::key> &new_block_ids)
{
    //todo
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::vector<rct::key> &new_block_ids)
{
    //todo
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    CHECK_AND_ASSERT_THROW_MES(first_new_block >= m_refresh_height,
        "enote store ledger records update (mock): first new block is below the refresh height.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block - m_refresh_height <= m_block_ids.size(),
        "enote store ledger records update (mock): new blocks don't line up with existing blocks.");
    if (first_new_block > m_refresh_height)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id == m_block_ids[first_new_block - m_refresh_height - 1],
            "enote store ledger records update (mock): alignment block id doesn't align with recorded block ids.");
    }

    m_block_ids.resize(first_new_block - m_refresh_height);  //crop old blocks
    m_block_ids.insert(m_block_ids.end(), new_block_ids.begin(), new_block_ids.end());

    // 2. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_contextual_enote_records,
            [first_new_block](const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &mapped_contextual_enote_record)
                -> bool
            {
                // a. remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_height >= first_new_block)
                {
                    return true;
                }

                // b. remove all unconfirmed enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::UNCONFIRMED)
                    return true;

                return false;
            }
        );

    // 3. clear spent contexts referencing removed enotes
    for (auto &mapped_contextual_enote_record : m_mapped_contextual_enote_records)
    {
        // a. any enote spent onchain in range [first_new_block, end of chain]
        if (mapped_contextual_enote_record.second.m_spent_context.m_spent_status ==
                SpEnoteSpentStatus::SPENT_ONCHAIN &&
            mapped_contextual_enote_record.second.m_spent_context.m_block_height >= first_new_block)
        {
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
        }

        // b. any enote spent in an unconfirmed tx
        if (mapped_contextual_enote_record.second.m_spent_context.m_spent_status ==
                SpEnoteSpentStatus::SPENT_UNCONFIRMED)
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
    }

    // 4. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 5. update contexts of stored enotes with found spent key images
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        if (m_mapped_contextual_enote_records.find(found_spent_key_image.first) !=
                m_mapped_contextual_enote_records.end())
        {
            update_contextual_enote_record_contexts_v1(
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_origin_context,
                found_spent_key_image.second,
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_origin_context,
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_spent_context);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_offchain(
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images)
{
    // 1. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_contextual_enote_records,
            [](const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // remove all offchain enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::OFFCHAIN)
                    return true;

                return false;
            }
        );

    // 2. clear spent contexts referencing removed enotes
    for (auto &mapped_contextual_enote_record : m_mapped_contextual_enote_records)
    {
        // any enote spent in an offchain tx
        if (mapped_contextual_enote_record.second.m_spent_context.m_spent_status ==
                SpEnoteSpentStatus::SPENT_OFFCHAIN)
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
    }

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);

    // 4. update spent contexts of stored enotes with found spent key images
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        if (m_mapped_contextual_enote_records.find(found_spent_key_image.first) !=
                m_mapped_contextual_enote_records.end())
        {
            update_contextual_enote_record_contexts_v1(
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_origin_context,
                found_spent_key_image.second,
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_origin_context,
                m_mapped_contextual_enote_records[found_spent_key_image.first].m_spent_context);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::has_enote_with_key_image(const crypto::key_image &key_image) const
{
    return m_mapped_contextual_enote_records.find(key_image) != m_mapped_contextual_enote_records.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    if (block_height < m_refresh_height ||
        block_height > m_refresh_height + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    block_id_out = m_block_ids[block_height - m_refresh_height];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses) const
{
    boost::multiprecision::uint128_t inflow_sum{0};
    boost::multiprecision::uint128_t outflow_sum{0};

    for (const auto &mapped_contextual_record : m_mapped_contextual_enote_records)
    {
        const SpContextualEnoteRecordV1 &contextual_record{mapped_contextual_record.second};

        if (origin_statuses.find(contextual_record.m_origin_context.m_origin_status) != origin_statuses.end())
            inflow_sum += contextual_record.m_record.m_amount;

        if (spent_statuses.find(contextual_record.m_spent_context.m_spent_status) != spent_statuses.end())
            outflow_sum += contextual_record.m_record.m_amount;
    }

    if (inflow_sum >= outflow_sum)
        return inflow_sum - outflow_sum;
    else
        return 0;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::add_record(const SpContextualIntermediateEnoteRecordV1 &new_record)
{
    rct::key record_onetime_address;
    new_record.get_onetime_address(record_onetime_address);

    // add the record or update an existing record's origin context
    if (m_mapped_contextual_enote_records.find(record_onetime_address) == m_mapped_contextual_enote_records.end())
    {
        m_mapped_contextual_enote_records[record_onetime_address] = new_record;
    }
    else
    {
        try_update_enote_origin_context_v1(new_record.m_origin_context,
            m_mapped_contextual_enote_records[record_onetime_address].m_origin_context);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    CHECK_AND_ASSERT_THROW_MES(first_new_block >= m_refresh_height,
        "enote store ledger records update (mock): first new block is below the refresh height.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block - m_refresh_height <= m_block_ids.size(),
        "enote store ledger records update (mock): new blocks don't line up with existing blocks.");
    if (first_new_block > m_refresh_height)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id == m_block_ids[first_new_block - m_refresh_height - 1],
            "enote store ledger records update (mock): alignment block id doesn't align with recorded block ids.");
    }

    m_block_ids.resize(first_new_block - m_refresh_height);  //crop old blocks
    m_block_ids.insert(m_block_ids.end(), new_block_ids.begin(), new_block_ids.end());

    // 2. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_contextual_enote_records,
            [first_new_block](
                const std::pair<rct::key, SpContextualIntermediateEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // a. remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_height >= first_new_block)
                {
                    return true;
                }

                // b. remove all unconfirmed enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::UNCONFIRMED)
                    return true;

                return false;
            }
        );

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_offchain(
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records)
{
    // 1. remove records that will be replaced
    for_all_in_map_erase_if(m_mapped_contextual_enote_records,
            [](const std::pair<rct::key, SpContextualIntermediateEnoteRecordV1> &mapped_contextual_enote_record) -> bool
            {
                // remove all offchain enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::OFFCHAIN)
                    return true;

                return false;
            }
        );

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockPaymentValidatorV1::try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const
{
    if (block_height < m_refresh_height ||
        block_height > m_refresh_height + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    block_id_out = m_block_ids[block_height - m_refresh_height];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockPaymentValidatorV1::get_received_sum(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses) const
{
    boost::multiprecision::uint128_t inflow_sum{0};

    for (const auto &mapped_contextual_record : m_mapped_contextual_enote_records)
    {
        const SpContextualIntermediateEnoteRecordV1 &contextual_record{mapped_contextual_record.second};

        if (origin_statuses.find(contextual_record.m_origin_context.m_origin_status) != origin_statuses.end())
            inflow_sum += contextual_record.m_record.m_amount;
    }

    return inflow_sum;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
