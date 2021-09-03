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
#include "mock_offchain_context.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_main/scan_balance_recovery_utils.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::cryptonote_key_image_exists(const crypto::key_image &key_image) const
{
    return m_legacy_key_images.find(key_image) != m_legacy_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::seraphis_key_image_exists(const crypto::key_image &key_image) const
{
    return m_sp_key_images.find(key_image) != m_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_partial_tx_v1(const SpPartialTxV1 &partial_tx)
{
    return this->try_add_v1_impl(partial_tx.legacy_input_images,
        partial_tx.sp_input_images,
        partial_tx.tx_supplement,
        partial_tx.outputs);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_tx_v1(const SpTxSquashedV1 &tx)
{
    return this->try_add_v1_impl(tx.legacy_input_images, tx.sp_input_images, tx.tx_supplement, tx.outputs);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_from_cache(const rct::key &input_context)
{
    // 1. clear key images
    if (m_tx_key_images.find(input_context) != m_tx_key_images.end())
    {
        for (const crypto::key_image &key_image : std::get<0>(m_tx_key_images[input_context]))
            m_legacy_key_images.erase(key_image);
        for (const crypto::key_image &key_image : std::get<1>(m_tx_key_images[input_context]))
            m_sp_key_images.erase(key_image);

        m_tx_key_images.erase(input_context);
    }

    // 2. clear output contents
    m_output_contents.erase(input_context);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::remove_tx_with_key_image_from_cache(const crypto::key_image &key_image)
{
    // 1. early return if key image isn't cached
    if (m_sp_key_images.find(key_image) == m_sp_key_images.end() &&
        m_legacy_key_images.find(key_image) == m_legacy_key_images.end())
        return;

    // 2. remove the tx that has this key image (there should only be one)
    auto tx_key_images_search_it = std::find_if(m_tx_key_images.begin(), m_tx_key_images.end(), 
            [&key_image](const auto &tx_key_images) -> bool
            {
                // check legacy key images
                if (std::find(std::get<0>(tx_key_images.second).begin(),
                            std::get<0>(tx_key_images.second).end(),
                            key_image) !=
                        std::get<0>(tx_key_images.second).end())
                    return true;

                // check seraphis key images
                if (std::find(std::get<1>(tx_key_images.second).begin(),
                            std::get<1>(tx_key_images.second).end(),
                            key_image) !=
                        std::get<1>(tx_key_images.second).end())
                    return true;

                return false;
            }
        );

    if (tx_key_images_search_it != m_tx_key_images.end())
        this->remove_tx_from_cache(tx_key_images_search_it->first);
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::clear_cache()
{
    m_legacy_key_images.clear();
    m_sp_key_images.clear();
    m_output_contents.clear();
    m_tx_key_images.clear();
}
//-------------------------------------------------------------------------------------------------------------------
void MockOffchainContext::get_offchain_chunk_sp(const crypto::x25519_secret_key &xk_find_received,
    scanning::ChunkData &chunk_data_out) const
{
    chunk_data_out.basic_records_per_tx.clear();
    chunk_data_out.contextual_key_images.clear();

    // 1. no chunk if no txs to scan
    if (m_output_contents.size() == 0)
        return;

    // 2. find-received scan each tx in the unconfirmed chache
    std::list<ContextualBasicRecordVariant> collected_records;
    SpContextualKeyImageSetV1 collected_key_images;

    for (const auto &tx_with_output_contents : m_output_contents)
    {
        const rct::key &tx_id{tx_with_output_contents.first};  //use input context as proxy for tx id

        // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
        if (scanning::try_find_sp_enotes_in_tx(xk_find_received,
            -1,
            -1,
            tx_id,
            0,
            tx_with_output_contents.first,
            std::get<SpTxSupplementV1>(tx_with_output_contents.second),
            std::get<std::vector<SpEnoteVariant>>(tx_with_output_contents.second),
            SpEnoteOriginStatus::OFFCHAIN,
            collected_records))
        {
            chunk_data_out.basic_records_per_tx[tx_id]
                .splice(chunk_data_out.basic_records_per_tx[tx_id].end(), collected_records);

            CHECK_AND_ASSERT_THROW_MES(m_tx_key_images.find(tx_with_output_contents.first) != m_tx_key_images.end(),
                "offchain find-received scanning (mock offchain context): key image map missing input context (bug).");

            if (scanning::try_collect_key_images_from_tx(-1,
                    -1,
                    tx_id,
                    std::get<0>(m_tx_key_images.at(tx_with_output_contents.first)),
                    std::get<1>(m_tx_key_images.at(tx_with_output_contents.first)),
                    SpEnoteSpentStatus::SPENT_OFFCHAIN,
                    collected_key_images))
                chunk_data_out.contextual_key_images.emplace_back(std::move(collected_key_images));
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// internal implementation details
//-------------------------------------------------------------------------------------------------------------------
bool MockOffchainContext::try_add_v1_impl(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &output_enotes)
{
    /// check failure modes

    // 1. fail if new tx overlaps with cached key images: offchain
    std::vector<crypto::key_image> legacy_key_images_collected;
    std::vector<crypto::key_image> sp_key_images_collected;

    for (const LegacyEnoteImageV2 &legacy_enote_image : legacy_input_images)
    {
        if (this->cryptonote_key_image_exists(legacy_enote_image.key_image))
            return false;

        legacy_key_images_collected.emplace_back(legacy_enote_image.key_image);
    }

    for (const SpEnoteImageV1 &sp_enote_image : sp_input_images)
    {
        if (this->seraphis_key_image_exists(key_image_ref(sp_enote_image)))
            return false;

        sp_key_images_collected.emplace_back(key_image_ref(sp_enote_image));
    }

    rct::key input_context;
    jamtis::make_jamtis_input_context_standard(legacy_key_images_collected, sp_key_images_collected, input_context);

    // 2. fail if input context is duplicated (bug since key image check should prevent this)
    CHECK_AND_ASSERT_THROW_MES(m_tx_key_images.find(input_context) == m_tx_key_images.end(),
        "mock tx ledger (adding offchain tx): input context already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_output_contents.find(input_context) == m_output_contents.end(),
        "mock tx ledger (adding offchain tx): input context already exists in output contents map (bug).");


    /// update state

    // 1. add key images
    for (const crypto::key_image &legacy_key_image : legacy_key_images_collected)
        m_legacy_key_images.insert(legacy_key_image);

    for (const crypto::key_image &sp_key_image : sp_key_images_collected)
        m_sp_key_images.insert(sp_key_image);

    m_tx_key_images[input_context] = {std::move(legacy_key_images_collected), std::move(sp_key_images_collected)};

    // 2. add tx outputs
    std::vector<SpEnoteVariant> output_enote_variants;
    output_enote_variants.reserve(output_enotes.size());

    for (const SpEnoteV1 &enote : output_enotes)
        output_enote_variants.emplace_back(enote);

    m_output_contents[input_context] = {tx_supplement, output_enote_variants};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
