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
#include "legacy_ki_import_tool.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_event_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers
#include <list>
#include <map>
#include <unordered_map>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_ki_import_checkpoint(const SpEnoteStore &enote_store, LegacyKIImportCheckpoint &checkpoint_out)
{
    // 1. get the enote store's last legacy partialscanned block
    const std::uint64_t partialscan_index_pre_import_cycle{
            enote_store.top_legacy_partialscanned_block_index()
        };

    // 2. get the enote store's last legacy fullscanned block
    const std::uint64_t fullscan_index_pre_import_cycle{
            enote_store.top_legacy_fullscanned_block_index()
        };
    CHECK_AND_ASSERT_THROW_MES(fullscan_index_pre_import_cycle + 1 <= partialscan_index_pre_import_cycle + 1,
        "make legacy ki import checkpoint: fullscanned block is higher than partialscanned block.");

    // 3. get the lowest block that the enote store needs to fullscan
    const std::uint64_t legacy_refresh_index{enote_store.legacy_refresh_index()};
    const std::uint64_t first_new_index_for_fullscan{
            std::max(fullscan_index_pre_import_cycle + 1, legacy_refresh_index)
        };

    // 4. save block id checkpoints within range of partialscanned blocks we are trying to update
    // - range: any block <= the first block to fullscan TO our last partialscanned-only block
    checkpoint_out.block_id_checkpoints.clear();

    for (std::uint64_t block_index{enote_store.nearest_legacy_partialscanned_block_index(first_new_index_for_fullscan)};
        block_index != enote_store.legacy_refresh_index() - 1         &&  //can happen if we never did ANY legacy scanning
            block_index + 1 <= partialscan_index_pre_import_cycle + 1 &&  //shouldn't ever fail; better safe than sorry
            block_index != static_cast<std::uint64_t>(-1);                //end condition
        block_index = enote_store.next_legacy_partialscanned_block_index(block_index))
    {
        CHECK_AND_ASSERT_THROW_MES(enote_store.try_get_block_id_for_legacy_partialscan(block_index,
                checkpoint_out.block_id_checkpoints[block_index]),
            "make legacy ki import checkpoint: failed to get block id for a legacy partialscan checkpoint.");
    }

    // 5. export legacy intermediate records that need key images
    checkpoint_out.legacy_intermediate_records = enote_store.legacy_intermediate_records();
}
//-------------------------------------------------------------------------------------------------------------------
void import_legacy_key_images(const std::unordered_map<rct::key, crypto::key_image> &legacy_key_images,  //[ Ko : KI ]
    SpEnoteStore &enote_store_inout,
    std::list<EnoteStoreEvent> &update_events_out)
{
    // import key images (ignore failures)
    update_events_out.clear();
    for (const auto import_pair : legacy_key_images)
        enote_store_inout.try_import_legacy_key_image(import_pair.second, import_pair.first, update_events_out);
}
//-------------------------------------------------------------------------------------------------------------------
void import_legacy_key_images(const std::unordered_map<crypto::public_key, crypto::key_image> &legacy_key_images,
    SpEnoteStore &enote_store_inout,
    std::list<EnoteStoreEvent> &update_events_out)
{
    // import key images (ignore failures)
    update_events_out.clear();
    for (const auto import_pair : legacy_key_images)
    {
        enote_store_inout.try_import_legacy_key_image(import_pair.second,
            rct::pk2rct(import_pair.first),
            update_events_out);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finish_legacy_ki_import_cycle(const LegacyKIImportCheckpoint &checkpoint, SpEnoteStore &enote_store_inout)
{
    // 1. find the highest aligned checkpoint from when intermediate records were exported
    // - we want to make sure any reorg that replaced blocks below the partial scan index recorded at the beginning of
    //   the cycle won't be ignored by the next partial scan
    std::uint64_t highest_aligned_index_post_import_cycle{enote_store_inout.top_legacy_fullscanned_block_index()};
    rct::key temp_block_id;

    for (const auto &checkpoint : checkpoint.block_id_checkpoints)
    {
        if (!enote_store_inout.try_get_block_id_for_legacy_partialscan(checkpoint.first, temp_block_id))
            continue;
        if (!(temp_block_id == checkpoint.second))
            break;

        highest_aligned_index_post_import_cycle =
            std::max(checkpoint.first + 1, highest_aligned_index_post_import_cycle + 1) - 1;
    }

    // 2. clamp the alignment index below the current enote store's lowest intermediate record
    // - we do this in case not all records collected at the beginning of this import cycle were imported as expected
    for (const auto &intermediate_record : enote_store_inout.legacy_intermediate_records())
    {
        // a. ignore enotes that aren't on-chain
        if (!has_origin_status(intermediate_record.second, SpEnoteOriginStatus::ONCHAIN))
            continue;

        // b. clamp the alignment index to one block below the intermediate record's origin
        highest_aligned_index_post_import_cycle =
            std::min(
                    highest_aligned_index_post_import_cycle + 1,
                    intermediate_record.second.origin_context.block_index
                ) - 1;
    }

    // 3. update the legacy fullscan index
    enote_store_inout.update_legacy_fullscan_index_for_import_cycle(highest_aligned_index_post_import_cycle);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
