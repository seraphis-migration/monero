// Copyright (c) 2023, The Monero Project
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
// paired header

#include "seraphis_wallet/show_enotes.h"

// local headers
#include "common/util.h"
#include "ringct/rctTypes.h"

// third party headers

// standard headers

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::string sp_spent_status_to_string(SpEnoteSpentStatus status)
{
    switch (status)
    {
        case sp::SpEnoteSpentStatus::UNSPENT:
            return std::string("Unspent");
        case sp::SpEnoteSpentStatus::SPENT_OFFCHAIN:
            return std::string("Spent offchain");
        case sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED:
            return std::string("Spent - pending");
        case sp::SpEnoteSpentStatus::SPENT_ONCHAIN:
            return std::string("Spent - confirmed");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b)
{
    if (a.spent_context.spent_status != b.spent_context.spent_status)
    {
        if (a.spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT)
            return true;
        else
            return false;
    }
    else
        return a.spent_context.block_timestamp > b.spent_context.block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp_in(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b)
{
    return a.origin_context.block_timestamp > b.origin_context.block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp_out(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b)
{
    return a.spent_context.block_timestamp > b.spent_context.block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_all(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.origin_context.block_index >= range_height.first &&
        (enote.second.spent_context.block_index <= range_height.second || enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT))
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        enote.second.origin_context.origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        enote.second.origin_context.block_index >= range_height.first &&
        enote.second.origin_context.block_index <= range_height.second)
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in_pool(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        enote.second.origin_context.origin_status == sp::SpEnoteOriginStatus::UNCONFIRMED)
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in_offchain(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        enote.second.origin_context.origin_status == sp::SpEnoteOriginStatus::OFFCHAIN)
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::SPENT_ONCHAIN &&
        enote.second.origin_context.origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        enote.second.origin_context.block_index >= range_height.first &&
        enote.second.spent_context.block_index <= range_height.second)
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out_pool(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED &&
        enote.second.origin_context.origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        enote.second.origin_context.block_index >= range_height.first)
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out_offchain(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out)
{
    if (enote.second.spent_context.spent_status == sp::SpEnoteSpentStatus::SPENT_OFFCHAIN &&
        enote.second.origin_context.block_index >= range_height.first )
        vec_out.push_back(enote.second);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
// SHOW ENOTES
//-------------------------------------------------------------------------------------------------------------------
void select_filter_comparator(const SpTxDirectionStatus tx_status,
    const std::pair<uint64_t, uint64_t> range_height,
    FilterEnotes &filter_in_out,
    ComparatorEnotes &comparator_enotes)
{
    switch (tx_status)
    {
        case SpTxDirectionStatus::ALL:
        {
            filter_in_out     = filter_all;
            comparator_enotes = compare_block_timestamp;
            return;
        }
        case SpTxDirectionStatus::IN_ONCHAIN:
        {
            filter_in_out     = filter_in;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::IN_POOL:
        {
            filter_in_out     = filter_in_pool;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::IN_OFFCHAIN:
        {
            filter_in_out     = filter_in_offchain;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::OUT_ONCHAIN:
        {
            filter_in_out     = filter_out;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::OUT_POOL:
        {
            filter_in_out     = filter_out_pool;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::OUT_OFFCHAIN:
        {
            filter_in_out     = filter_out_offchain;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::FAILED:
        {
            return;
        }
        default:
            return;
    }
}

void get_enotes(const SpEnoteStore &sp_enote_store,
    const SpTxDirectionStatus tx_status,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_enote_records_out)
{
    vec_enote_records_out.clear();

    FilterEnotes filter;
    ComparatorEnotes comparator;

    select_filter_comparator(tx_status, range_height, filter, comparator);

    std::for_each(sp_enote_store.sp_records().begin(),
        sp_enote_store.sp_records().end(),
        [&](const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote)
        { filter(enote, range_height, vec_enote_records_out); });

    std::stable_sort(vec_enote_records_out.begin(), vec_enote_records_out.end(), comparator);
}


void show_enotes(const std::vector<SpContextualEnoteRecordV1> &vec_enote_records)
{
    rct::xmr_amount unspent_total{};
    for (int i = vec_enote_records.size() - 1; i >= 0; i--)
    {
        std::cout << "Status: " << sp_spent_status_to_string(vec_enote_records[i].spent_context.spent_status);
        std::cout << "  |   Amount: " << vec_enote_records[i].record.amount;
        if (vec_enote_records[i].spent_context.spent_status == sp::SpEnoteSpentStatus::UNSPENT)
        {
            std::cout << "  |   Timestamp origin: "
                      << tools::get_human_readable_timestamp(vec_enote_records[i].origin_context.block_timestamp);
            std::cout << "  |   Block height origin: " << vec_enote_records[i].origin_context.block_index;
            std::cout << "  |   Tx id origin: " << vec_enote_records[i].origin_context.transaction_id << std::endl;
            unspent_total += vec_enote_records[i].record.amount;
        }
        else
        {
            std::cout << "  |   Timestamp spent: "
                      << tools::get_human_readable_timestamp(vec_enote_records[i].spent_context.block_timestamp);
            std::cout << "  |   Block height spent: " << vec_enote_records[i].spent_context.block_index;
            std::cout << "  |   Tx id spent: " << vec_enote_records[i].spent_context.transaction_id << std::endl;
        }
    }
    std::cout << "Total unspent: " << unspent_total << std::endl;
}

// [in/out/all/pending/failed/pool/coinbase
// if tx_status == in -> spent_status = unspent
// if tx_status == out -> spent_status != unspent
// if tx_status == pending_offchain -> origin_status = offchain
// if tx_status == pending_pool -> origin_status = unconfirmed

// if tx_status == failed -> not in enote_store but in tx_store ?
