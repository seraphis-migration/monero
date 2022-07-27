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
#include "mock_offchain_context.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_enote_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "tx_component_types.h"
#include "tx_enote_scanning.h"
#include "tx_enote_scanning_utils.h"
#include "txtype_squashed_v1.h"

//third party headers
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::key_image_exists_v1(const crypto::key_image &key_image) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return key_image_exists_v1_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_get_offchain_chunk_sp(const crypto::secret_key &k_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return try_get_offchain_chunk_sp_impl(k_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_partial_tx_v1(const SpPartialTxV1 &partial_tx)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return try_add_partial_tx_v1_impl(partial_tx);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_tx_v1(const SpTxSquashedV1 &tx)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return try_add_tx_v1_impl(tx);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_from_cache(const rct::key &input_context)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    remove_tx_from_cache_impl(input_context);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_with_key_image_from_cache(const crypto::key_image &key_image)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    remove_tx_with_key_image_from_cache_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::clear_cache()
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    clear_cache_impl();
}
//-------------------------------------------------------------------------------------------------------------------
// internal implementation details
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::key_image_exists_v1_impl(const crypto::key_image &key_image) const
{
    return m_sp_key_images.find(key_image) != m_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_get_offchain_chunk_sp_impl(const crypto::secret_key &k_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    // find-received scan each tx in the unconfirmed chache
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();

    for (const auto &tx_with_output_contents : m_output_contents)
    {
        // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
        if (try_find_sp_enotes_in_tx(k_find_received,
            -1,
            -1,
            tx_with_output_contents.first,  //use input context as proxy for tx id
            0,
            tx_with_output_contents.first,
            std::get<SpTxSupplementV1>(tx_with_output_contents.second),
            std::get<std::vector<SpEnoteV1>>(tx_with_output_contents.second),
            SpEnoteOriginStatus::OFFCHAIN,
            hw::get_device("default"),
            chunk_out.m_basic_records_per_tx))
        {
            CHECK_AND_ASSERT_THROW_MES(m_tx_key_images.find(tx_with_output_contents.first) != m_tx_key_images.end(),
                "offchain find-received scanning (mock offchain context): key image map missing input context (bug).");

            collect_key_images_from_tx(-1,
                -1,
                sortable2rct(tx_with_output_contents.first),
                std::vector<crypto::key_image>{},  //legacy key images todo?
                m_tx_key_images.at(tx_with_output_contents.first),  //use input context as proxy for tx id
                SpEnoteSpentStatus::SPENT_OFFCHAIN,
                chunk_out.m_contextual_key_images);
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_v1_impl(const std::vector<SpEnoteImageV1> &input_images,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &output_enotes)
{
    /// check failure modes

    // 1. fail if new tx overlaps with cached key images: offchain, unconfirmed, onchain
    std::vector<crypto::key_image> key_images_collected;

    for (const SpEnoteImageV1 &enote_image : input_images)
    {
        if (key_image_exists_v1_impl(enote_image.m_core.m_key_image))
            return false;

        key_images_collected.emplace_back(enote_image.m_core.m_key_image);
    }

    rct::key input_context;
    jamtis::make_jamtis_input_context_standard(key_images_collected, input_context);

    // 2. fail if input context is duplicated (bug since key image check should prevent this)
    CHECK_AND_ASSERT_THROW_MES(m_tx_key_images.find(input_context) == m_tx_key_images.end(),
        "mock tx ledger (adding offchain tx): input context already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_output_contents.find(input_context) == m_output_contents.end(),
        "mock tx ledger (adding offchain tx): input context already exists in output contents map (bug).");


    /// update state

    // 1. add key images
    for (const SpEnoteImageV1 &enote_image : input_images)
        m_sp_key_images.insert(enote_image.m_core.m_key_image);

    m_tx_key_images[input_context] = std::move(key_images_collected);

    // 2. add tx outputs
    m_output_contents[input_context] = {tx_supplement, output_enotes};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_partial_tx_v1_impl(const SpPartialTxV1 &partial_tx)
{
    return try_add_v1_impl(partial_tx.m_input_images, partial_tx.m_tx_supplement, partial_tx.m_outputs);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_tx_v1_impl(const SpTxSquashedV1 &tx)
{
    return try_add_v1_impl(tx.m_input_images, tx.m_tx_supplement, tx.m_outputs);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_from_cache_impl(const rct::key &input_context)
{
    // clear key images
    if (m_tx_key_images.find(input_context) != m_tx_key_images.end())
    {
        for (const crypto::key_image &key_image : m_tx_key_images[input_context])
            m_sp_key_images.erase(key_image);

        m_tx_key_images.erase(input_context);
    }

    // clear output contents
    m_output_contents.erase(input_context);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_with_key_image_from_cache_impl(const crypto::key_image &key_image)
{
    // early return if key image isn't cached
    if (m_sp_key_images.find(key_image) == m_sp_key_images.end())
        return;

    // remove the tx that has this key image (there should only be one)
    auto tx_key_images_search_it = std::find_if(m_tx_key_images.begin(), m_tx_key_images.end(), 
            [&key_image](const auto &tx_key_images) -> bool
            {
                return std::find(tx_key_images.second.begin(), tx_key_images.second.end(), key_image) !=
                    tx_key_images.second.end();
            }
        );

    if (tx_key_images_search_it != m_tx_key_images.end())
        remove_tx_from_cache_impl(tx_key_images_search_it->first);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::clear_cache_impl()
{
    m_sp_key_images.clear();
    m_output_contents.clear();
    m_tx_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
