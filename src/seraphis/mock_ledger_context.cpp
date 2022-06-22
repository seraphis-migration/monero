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
#include "mock_ledger_context.h"

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "jamtis_enote_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_enote_scanning.h"
#include "txtype_squashed_v1.h"

//third party headers
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::get_chain_height() const
{
    return m_block_ids.size() - 1;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_unconfirmed_v1(const crypto::key_image &key_image) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return key_image_exists_unconfirmed_v1_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_onchain_v1(const crypto::key_image &key_image) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return key_image_exists_onchain_v1_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
    rct::keyV &proof_elements_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    // gets squashed enotes
    proof_elements_out.clear();
    proof_elements_out.reserve(indices.size());

    for (const std::uint64_t index : indices)
    {
        CHECK_AND_ASSERT_THROW_MES(index < m_sp_squashed_enotes.size(), "Tried to get squashed enote that doesn't exist.");
        proof_elements_out.emplace_back(m_sp_squashed_enotes.at(index));
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::min_enote_index() const
{
    return 0;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::max_enote_index() const
{
    return m_sp_squashed_enotes.size() - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const crypto::secret_key &k_find_received,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    get_onchain_chunk_impl(chunk_start_height, chunk_max_size, k_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_get_unconfirmed_chunk(const crypto::secret_key &k_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return try_get_unconfirmed_chunk_impl(k_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_tx_v1(const SpTxSquashedV1 &tx)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return try_add_unconfirmed_tx_v1_impl(tx);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1(const rct::key &mock_coinbase_input_context,
    SpTxSupplementV1 mock_coinbase_tx_supplement,
    std::vector<SpEnoteV1> mock_coinbase_output_enotes)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return commit_unconfirmed_txs_v1_impl(mock_coinbase_input_context,
        std::move(mock_coinbase_tx_supplement),
        std::move(mock_coinbase_output_enotes));
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::remove_tx_from_unconfirmed_cache(const rct::key &tx_id)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    remove_tx_from_unconfirmed_cache_impl(tx_id);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::clear_unconfirmed_cache()
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    clear_unconfirmed_cache_impl();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_chain_at_height(const std::uint64_t pop_height)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return pop_chain_at_height_impl(pop_height);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_blocks(const std::size_t num_blocks)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return pop_blocks_impl(num_blocks);
}
//-------------------------------------------------------------------------------------------------------------------
// internal implementation details
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_unconfirmed_v1_impl(const crypto::key_image &key_image) const
{
    return m_unconfirmed_sp_key_images.find(key_image) != m_unconfirmed_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_onchain_v1_impl(const crypto::key_image &key_image) const
{
    return m_sp_key_images.find(key_image) != m_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk_impl(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const crypto::secret_key &k_find_received,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();
    chunk_out.m_block_ids.clear();

    // 1. failure cases
    if (get_chain_height() + 1 == 0 ||
        chunk_start_height > get_chain_height() ||
        chunk_max_size == 0)
    {
        // set empty chunk info: top of the chain
        chunk_out.m_block_range =
            {
                get_chain_height() + 1,
                get_chain_height()
            };

        if (m_block_ids.size())
        {
            CHECK_AND_ASSERT_THROW_MES(m_block_ids.find(m_block_ids.size() - 1) != m_block_ids.end(),
                "onchain chunk find-received scanning (mock ledger context): block ids map incorrect indexing (bug).");

            chunk_out.m_block_ids.emplace_back(m_block_ids.at(m_block_ids.size() - 1));
        }
        else
            chunk_out.m_block_ids.emplace_back(rct::zero());

        return;
    }

    // 2. set block information

    // a. block range
    chunk_out.m_block_range =
        {
            chunk_start_height,
            std::min(get_chain_height(), chunk_start_height + chunk_max_size - 1)
        };

    CHECK_AND_ASSERT_THROW_MES(
        m_block_ids.find(std::get<0>(chunk_out.m_block_range)) != m_block_ids.end() &&
        m_block_ids.find(std::get<1>(chunk_out.m_block_range)) != m_block_ids.end(),
        "onchain chunk find-received scanning (mock ledger context): block range outside of block ids map (bug).");

    // b. prefix block id
    chunk_out.m_prefix_block_id =
        chunk_start_height > 0
        ? m_block_ids.at(chunk_start_height - 1)
        : rct::zero();

    // c. block ids in the range
    chunk_out.m_block_ids.reserve(std::get<1>(chunk_out.m_block_range) - std::get<0>(chunk_out.m_block_range) + 1);

    std::for_each(
            m_block_ids.find(std::get<0>(chunk_out.m_block_range)),
            m_block_ids.find(std::get<1>(chunk_out.m_block_range) + 1),
            [&](const std::pair<std::uint64_t, rct::key> &mapped_block_id)
            {
                chunk_out.m_block_ids.emplace_back(mapped_block_id.second);
            }
        );

    CHECK_AND_ASSERT_THROW_MES(chunk_out.m_block_ids.size() ==
            std::get<1>(chunk_out.m_block_range) - std::get<0>(chunk_out.m_block_range) + 1,
        "onchain chunk find-received scanning (mock ledger context): invalid number of block ids acquired (bug).");

    // 3. scan blocks in the range
    CHECK_AND_ASSERT_THROW_MES(
        m_blocks_of_tx_output_contents.find(std::get<0>(chunk_out.m_block_range)) !=
        m_blocks_of_tx_output_contents.end(),
        "onchain chunk find-received scanning (mock ledger context): start of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(
        m_blocks_of_tx_output_contents.find(std::get<1>(chunk_out.m_block_range)) !=
        m_blocks_of_tx_output_contents.end(),
        "onchain chunk find-received scanning (mock ledger context): end of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(
        m_blocks_of_tx_key_images.find(std::get<0>(chunk_out.m_block_range)) !=
        m_blocks_of_tx_key_images.end(),
        "onchain chunk find-received scanning (mock ledger context): start of chunk not known in key images map (bug).");
    CHECK_AND_ASSERT_THROW_MES(
        m_blocks_of_tx_key_images.find(std::get<1>(chunk_out.m_block_range)) !=
        m_blocks_of_tx_key_images.end(),
        "onchain chunk find-received scanning (mock ledger context): end of chunk not known in key images map (bug).");

    // a. initialize output count to the total number of enotes in the ledger before the first block to scan
    std::uint64_t total_output_count_before_tx{0};

    if (std::get<0>(chunk_out.m_block_range) > 0)
    {
        CHECK_AND_ASSERT_THROW_MES(
            m_accumulated_output_counts.find(std::get<0>(chunk_out.m_block_range) - 1) !=
            m_accumulated_output_counts.end(),
            "onchain chunk find-received scanning (mock ledger context): output counts missing a block (bug).");

        total_output_count_before_tx = m_accumulated_output_counts.at(std::get<0>(chunk_out.m_block_range) - 1);
    }

    // b. find-received scan each block in the range
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();

    std::for_each(
            m_blocks_of_tx_output_contents.find(std::get<0>(chunk_out.m_block_range)),
            m_blocks_of_tx_output_contents.find(std::get<1>(chunk_out.m_block_range) + 1),
            [&](const auto &block_of_tx_output_contents)
            {
                for (const auto &tx_with_output_contents : block_of_tx_output_contents.second)
                {
                    // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
                    if (try_find_enotes_in_tx(k_find_received,
                        block_of_tx_output_contents.first,
                        sortable2rct(tx_with_output_contents.first),
                        total_output_count_before_tx,
                        std::get<rct::key>(tx_with_output_contents.second),
                        std::get<SpTxSupplementV1>(tx_with_output_contents.second),
                        std::get<std::vector<SpEnoteV1>>(tx_with_output_contents.second),
                        SpEnoteOriginStatus::ONCHAIN,
                        hw::get_device("default"),
                        chunk_out.m_basic_records_per_tx))
                    {
                        CHECK_AND_ASSERT_THROW_MES(
                            m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first).find(tx_with_output_contents.first) !=
                            m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first).end(),
                            "onchain chunk find-received scanning (mock ledger context): key image map missing tx (bug).");

                        collect_key_images_from_tx(block_of_tx_output_contents.first,
                            sortable2rct(tx_with_output_contents.first),
                            m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first)
                                .at(tx_with_output_contents.first),
                            SpEnoteSpentStatus::SPENT_ONCHAIN,
                            chunk_out.m_contextual_key_images);
                    }

                    // add this tx's number of outputs to the total output count
                    total_output_count_before_tx += std::get<std::vector<SpEnoteV1>>(tx_with_output_contents.second).size();
                }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_get_unconfirmed_chunk_impl(const crypto::secret_key &k_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    // find-received scan each tx in the unconfirmed chache
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();

    for (const auto &tx_with_output_contents : m_unconfirmed_tx_output_contents)
    {
        // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
        if (try_find_enotes_in_tx(k_find_received,
            -1,
            sortable2rct(tx_with_output_contents.first),
            0,
            std::get<rct::key>(tx_with_output_contents.second),
            std::get<SpTxSupplementV1>(tx_with_output_contents.second),
            std::get<std::vector<SpEnoteV1>>(tx_with_output_contents.second),
            SpEnoteOriginStatus::UNCONFIRMED,
            hw::get_device("default"),
            chunk_out.m_basic_records_per_tx))
        {
            CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(tx_with_output_contents.first) !=
                    m_unconfirmed_tx_key_images.end(),
                "unconfirmed chunk find-received scanning (mock ledger context): key image map missing tx (bug).");

            collect_key_images_from_tx(-1,
                sortable2rct(tx_with_output_contents.first),
                m_unconfirmed_tx_key_images.at(tx_with_output_contents.first),
                SpEnoteSpentStatus::SPENT_UNCONFIRMED,
                chunk_out.m_contextual_key_images);
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_coinbase_v1_impl(const rct::key &tx_id,
    const rct::key &input_context,
    SpTxSupplementV1 tx_supplement,
    std::vector<SpEnoteV1> output_enotes)
{
    /// check failure modes

    // 1. fail if tx id is duplicated (bug since key image check should prevent this)
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(tx_id) == m_unconfirmed_tx_key_images.end(),
        "mock tx ledger (adding unconfirmed coinbase tx): tx id already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(tx_id) == m_unconfirmed_tx_output_contents.end(),
        "mock tx ledger (adding unconfirmed coinbase tx): tx id already exists in output contents map (bug).");


    /// update state

    // 1. add key images (there are none, but we want an entry in the map)
    m_unconfirmed_tx_key_images[tx_id];

    // 2. add tx outputs
    m_unconfirmed_tx_output_contents[tx_id] = {input_context, std::move(tx_supplement), std::move(output_enotes)};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_tx_v1_impl(const SpTxSquashedV1 &tx)
{
    /// check failure modes

    // 1. fail if new tx overlaps with cached key images: unconfirmed, onchain
    std::vector<crypto::key_image> key_images_collected;

    for (const SpEnoteImageV1 &enote_image : tx.m_input_images)
    {
        if (key_image_exists_unconfirmed_v1_impl(enote_image.m_core.m_key_image) ||
            key_image_exists_onchain_v1_impl(enote_image.m_core.m_key_image))
            return false;

        key_images_collected.emplace_back(enote_image.m_core.m_key_image);
    }

    rct::key input_context;
    jamtis::make_jamtis_input_context_standard(key_images_collected, input_context);

    // 2. fail if tx id is duplicated (bug since key image check should prevent this)
    rct::key tx_id;
    tx.get_hash(tx_id);

    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(tx_id) == m_unconfirmed_tx_key_images.end(),
        "mock tx ledger (adding unconfirmed tx): tx id already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(tx_id) == m_unconfirmed_tx_output_contents.end(),
        "mock tx ledger (adding unconfirmed tx): tx id already exists in output contents map (bug).");


    /// update state

    // 1. add key images
    for (const SpEnoteImageV1 &enote_image : tx.m_input_images)
        m_unconfirmed_sp_key_images.insert(enote_image.m_core.m_key_image);

    m_unconfirmed_tx_key_images[tx_id] = std::move(key_images_collected);

    // 2. add tx outputs
    m_unconfirmed_tx_output_contents[tx_id] = {input_context, tx.m_tx_supplement, tx.m_outputs};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1_impl(const rct::key &mock_coinbase_input_context,
    SpTxSupplementV1 mock_coinbase_tx_supplement,
    std::vector<SpEnoteV1> mock_coinbase_output_enotes)
{
    /// sanity checks: check unconfirmed key images and txids
    for (const auto &tx_key_images : m_unconfirmed_tx_key_images)
    {
        // a. tx ids are present in both unconfirmed data maps
        CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(tx_key_images.first) !=
                m_unconfirmed_tx_output_contents.end(),
            "mock tx ledger (committing unconfirmed txs): tx id not in all unconfirmed data maps (bug).");

        // b. tx ids are not present onchain
        for (const auto &block_tx_key_images : m_blocks_of_tx_key_images)
        {
            CHECK_AND_ASSERT_THROW_MES(block_tx_key_images.second.find(tx_key_images.first) ==
                    block_tx_key_images.second.end(),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx id found in ledger (bug).");
        }

        for (const auto &block_tx_outputs : m_blocks_of_tx_output_contents)
        {
            CHECK_AND_ASSERT_THROW_MES(block_tx_outputs.second.find(tx_key_images.first) == block_tx_outputs.second.end(),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx id found in ledger (bug).");
        }

        // c. key images are not present onchain
        for (const crypto::key_image &key_image : tx_key_images.second)
        {
            CHECK_AND_ASSERT_THROW_MES(!key_image_exists_onchain_v1_impl(key_image),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx key image exists in ledger (bug).");
        }
    }

    // d. unconfirmed maps line up
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.size() == m_unconfirmed_tx_output_contents.size(),
        "mock tx ledger (committing unconfirmed txs): unconfirmed data maps mismatch (bug).");

    // e. accumulated output count is consistent
    const std::uint64_t accumulated_output_count =
        m_accumulated_output_counts.size()
        ? (m_accumulated_output_counts.rbegin())->second  //last block's accumulated output count
        : 0;

    CHECK_AND_ASSERT_THROW_MES(accumulated_output_count == m_sp_squashed_enotes.size(),
        "mock tx ledger (committing unconfirmed txs): inconsistent number of accumulated outputs (bug).");


    /// add mock coinbase tx to unconfirmed cache
    // note: this should not invalidate the result of any of the prior checks
    CHECK_AND_ASSERT_THROW_MES(try_add_unconfirmed_coinbase_v1_impl(rct::pkGen(),
            mock_coinbase_input_context,
            std::move(mock_coinbase_tx_supplement),
            std::move(mock_coinbase_output_enotes)),
        "mock tx ledger (committing unconfirmed txs): unable to add mock coinbase tx to unconfirmed cache (bug).");


    /// update state
    const std::uint64_t new_height{m_blocks_of_tx_key_images.size()};

    // 1. add key images
    m_sp_key_images.insert(m_unconfirmed_sp_key_images.begin(), m_unconfirmed_sp_key_images.end());
    m_blocks_of_tx_key_images[new_height] = std::move(m_unconfirmed_tx_key_images);

    // 2. add tx outputs

    // a. initialize with current total output count
    std::uint64_t total_output_count{m_sp_squashed_enotes.size()};

    // b. insert all squashed enotes to the reference set
    for (const auto &tx_info : m_unconfirmed_tx_output_contents)
    {
        const auto &tx_enotes = std::get<std::vector<SpEnoteV1>>(tx_info.second);
        for (const SpEnoteV1 &enote : tx_enotes)
        {
            make_seraphis_squashed_enote_Q(enote.m_core.m_onetime_address,
                enote.m_core.m_amount_commitment,
                m_sp_squashed_enotes[total_output_count]);

            ++total_output_count;
        }
    }

    // c. add this block's accumulated output count
    m_accumulated_output_counts[new_height] = total_output_count;

    // d. steal the unconfirmed cache's tx output contents
    m_blocks_of_tx_output_contents[new_height] = std::move(m_unconfirmed_tx_output_contents);

    // 3. add block id (random in mockup)
    m_block_ids[new_height] = rct::pkGen();

    // 4. clear unconfirmed chache
    clear_unconfirmed_cache_impl();

    return new_height;
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::remove_tx_from_unconfirmed_cache_impl(const rct::key &tx_id)
{
    // clear key images
    if (m_unconfirmed_tx_key_images.find(tx_id) != m_unconfirmed_tx_key_images.end())
    {
        for (const crypto::key_image &key_image : m_unconfirmed_tx_key_images[tx_id])
            m_unconfirmed_sp_key_images.erase(key_image);

        m_unconfirmed_tx_key_images.erase(tx_id);
    }

    // clear output contents
    m_unconfirmed_tx_output_contents.erase(tx_id);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::clear_unconfirmed_cache_impl()
{
    m_unconfirmed_sp_key_images.clear();
    m_unconfirmed_tx_key_images.clear();
    m_unconfirmed_tx_output_contents.clear();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_chain_at_height_impl(const std::uint64_t pop_height)
{
    if (pop_height > get_chain_height())
        return 0;

    const std::uint64_t num_blocks_to_pop{get_chain_height() - pop_height + 1};

    // 1. remove key images
    if (m_blocks_of_tx_key_images.find(pop_height) != m_blocks_of_tx_key_images.end())
    {
        for (const auto &tx_key_images : m_blocks_of_tx_key_images[pop_height])
        {
            for (const crypto::key_image &key_image : tx_key_images.second)
                m_sp_key_images.erase(key_image);
        }
    }

    // 2. remove squashed enotes
    if (m_accumulated_output_counts.find(pop_height) != m_accumulated_output_counts.end())
    {
        // sanity check
        if (pop_height > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(m_accumulated_output_counts.find(pop_height - 1) !=
                    m_accumulated_output_counts.end(),
                "mock ledger context (popping chain): accumulated output counts has a hole (bug).");
        }

        // remove all outputs starting in the pop_height block
        const std::uint64_t first_output_to_remove =
            pop_height > 0
            ? m_accumulated_output_counts[pop_height - 1]
            : 0;

        m_sp_squashed_enotes.erase(m_sp_squashed_enotes.find(first_output_to_remove), m_sp_squashed_enotes.end());
    }

    // 3. clean up block maps
    m_blocks_of_tx_key_images.erase(m_blocks_of_tx_key_images.find(pop_height), m_blocks_of_tx_key_images.end());
    m_accumulated_output_counts.erase(m_accumulated_output_counts.find(pop_height), m_accumulated_output_counts.end());
    m_blocks_of_tx_output_contents.erase(m_blocks_of_tx_output_contents.find(pop_height),
        m_blocks_of_tx_output_contents.end());
    m_block_ids.erase(m_block_ids.find(pop_height), m_block_ids.end());

    return num_blocks_to_pop;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_blocks_impl(const std::size_t num_blocks)
{
    const std::uint64_t chain_height{get_chain_height()};
    return pop_chain_at_height_impl(chain_height + 1 >= num_blocks ? chain_height + 1 - num_blocks : 0);
}
//-------------------------------------------------------------------------------------------------------------------
// free functions
//-------------------------------------------------------------------------------------------------------------------
bool try_add_tx_to_ledger(const SpTxSquashedV1 &tx_to_add, MockLedgerContext &ledger_context_inout)
{
    if (!ledger_context_inout.try_add_unconfirmed_tx_v1(tx_to_add))
        return false;

    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
