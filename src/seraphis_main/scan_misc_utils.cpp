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
#include "scan_misc_utils.h"

//local headers
#include "misc_log_ex.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/scan_misc_utils.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace scanning
{
//-------------------------------------------------------------------------------------------------------------------
std::size_t chunk_size(const ChunkContext &chunk_context)
{
    return chunk_context.block_ids.size();
}
//-------------------------------------------------------------------------------------------------------------------
bool chunk_data_is_empty(const ChunkData &chunk_data)
{
    return chunk_data.basic_records_per_tx.size() == 0 &&
        chunk_data.contextual_key_images.size() == 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool chunk_context_is_empty(const ChunkContext &chunk_context)
{
    return chunk_size(chunk_context) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
void check_chunk_data_semantics(const ChunkData &chunk_data,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status,
    const std::uint64_t allowed_lowest_index,
    const std::uint64_t allowed_highest_index)
{
    // 1. check contextual basic records
    for (const auto &tx_basic_records : chunk_data.basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            CHECK_AND_ASSERT_THROW_MES(origin_status_ref(contextual_basic_record) ==
                    expected_origin_status,
                "scan chunk data semantics check: contextual basic record doesn't have expected origin status.");
            CHECK_AND_ASSERT_THROW_MES(transaction_id_ref(contextual_basic_record) ==
                    tx_basic_records.first,
                "scan chunk data semantics check: contextual basic record doesn't have origin tx id matching mapped id.");
            CHECK_AND_ASSERT_THROW_MES(block_index_ref(contextual_basic_record) ==
                    block_index_ref(*tx_basic_records.second.begin()),
                "scan chunk data semantics check: contextual record tx index doesn't match other records in tx.");

            CHECK_AND_ASSERT_THROW_MES(
                    block_index_ref(contextual_basic_record) >= allowed_lowest_index &&
                    block_index_ref(contextual_basic_record) <= allowed_highest_index,
                "scan chunk data semantics check: contextual record block index is out of the expected range.");
        }
    }

    // 2. check contextual key images
    for (const auto &contextual_key_image_set : chunk_data.contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(contextual_key_image_set.spent_context.spent_status == expected_spent_status,
            "scan chunk data semantics check: contextual key image doesn't have expected spent status.");

        // notes:
        // - in seraphis tx building, tx authors must always put a selfsend output enote in their txs; during balance
        //   recovery, the view tag check will pass for those selfsend enotes; this means to identify if your enotes are
        //   spent, you only need to look at key images in txs with view tag matches
        // - in support of that expectation, we enforce that the key images in a scanning chunk must come from txs
        //   recorded in the 'basic records per tx' map, which will contain only owned enote candidates (in seraphis
        //   scanning, that's all the enotes that passed the view tag check)
        // - if you want to include key images from txs that have no owned enote candidates, then you must add empty
        //   entries to the 'basic records per tx' map for those txs
        //   - when doing legacy scanning, you need to include all key images from the chain since legacy tx construction
        //     does/did not require all txs to have a self-send output
        CHECK_AND_ASSERT_THROW_MES(
                chunk_data.basic_records_per_tx.find(contextual_key_image_set.spent_context.transaction_id) !=
                chunk_data.basic_records_per_tx.end(),
            "scan chunk data semantics check: contextual key image transaction id is not mirrored in basic records map.");

        CHECK_AND_ASSERT_THROW_MES(
                contextual_key_image_set.spent_context.block_index >= allowed_lowest_index &&
                contextual_key_image_set.spent_context.block_index <= allowed_highest_index,
            "scan chunk data semantics check: contextual key image block index is out of the expected range.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_ledger_chunk_semantics(const LedgerChunk &ledger_chunk, const std::uint64_t expected_prefix_index)
{
    // 1. check context semantics
    CHECK_AND_ASSERT_THROW_MES(ledger_chunk.get_context().start_index - 1 == expected_prefix_index,
        "check ledger chunk semantics: chunk range doesn't start at expected prefix index.");

    const std::uint64_t num_blocks_in_chunk{ledger_chunk.get_context().block_ids.size()};
    CHECK_AND_ASSERT_THROW_MES(num_blocks_in_chunk >= 1,
        "check ledger chunk semantics: chunk has no blocks.");    

    // 2. get start and end block indices
    // - start block = prefix block + 1
    const std::uint64_t allowed_lowest_index{ledger_chunk.get_context().start_index};
    // - end block
    const std::uint64_t allowed_highest_index{allowed_lowest_index + num_blocks_in_chunk - 1};

    // 3. check the chunk data semantics for each subconsumer
    for (const rct::key &subconsumer_id : ledger_chunk.subconsumer_ids())
    {
        // a. extract the chunk data
        const ChunkData *chunk_data{ledger_chunk.try_get_data(subconsumer_id)};
        CHECK_AND_ASSERT_THROW_MES(chunk_data,
            "check ledger chunk semantics: could not get chunk data for subconsumer.");

        // b. check the chunk data semantics
        check_chunk_data_semantics(*chunk_data,
            SpEnoteOriginStatus::ONCHAIN,
            SpEnoteSpentStatus::SPENT_ONCHAIN,
            allowed_lowest_index,
            allowed_highest_index);
    }
}
//-------------------------------------------------------------------------------------------------------------------
ScanMachineMetadata initialize_scan_machine_metadata(const ScanMachineConfig &scan_config)
{
    return ScanMachineMetadata{
            .config                = scan_config,
            .partialscan_attempts  = 0,
            .fullscan_attempts     = 0
        };
}
//-------------------------------------------------------------------------------------------------------------------
ScanMachineState initialize_scan_machine_state(const ScanMachineConfig &scan_config)
{
    return ScanMachineNeedFullscan{ .metadata = initialize_scan_machine_metadata(scan_config) };
}
//-------------------------------------------------------------------------------------------------------------------
bool is_terminal_state(const ScanMachineState &state)
{
    return state.is_type<ScanMachineTerminated>();
}
//-------------------------------------------------------------------------------------------------------------------
bool is_success_state(const ScanMachineState &state)
{
    const ScanMachineTerminated *terminated{state.try_unwrap<ScanMachineTerminated>()};
    return terminated && terminated->result == ScanMachineResult::SUCCESS;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace sp
