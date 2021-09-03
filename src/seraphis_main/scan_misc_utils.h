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

// Miscellaneous utilities related to scanning.

#pragma once

//local headers
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_machine_types.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
namespace scanning
{
    struct ChunkData;
    struct ChunkContext;
    class LedgerChunk;
}
}

namespace sp
{
namespace scanning
{

/**
* brief: chunk_size - get number of blocks in chunk
* param: chunk_context -
* return: number of blocks in chunk
*/
std::size_t chunk_size(const ChunkContext &chunk_context);
/**
* brief: chunk_data_is_empty - check if a chunk data is empty (contains no records)
* param: chunk_data -
* return: true if the chunk data is empty
*/
bool chunk_data_is_empty(const ChunkData &chunk_data);
/**
* brief: chunk_is_empty - check if a chunk context is empty (refers to no blocks)
* param: chunk_context -
* return: true if the chunk context is empty
*/
bool chunk_context_is_empty(const ChunkContext &chunk_context);
/**
* brief: check_chunk_data_semantics - check semantics of chunk data
*   - throws on failure
* param: chunk_data -
* param: expected_origin_status -
* param: expected_spent_status -
* param: allowed_lowest_index - lowest block index allowed in chunk data (e.g. origin block, spent block)
* param: allowed_highest_index - highest block index allowed in chunk data (e.g. origin block, spent block)
*/
void check_chunk_data_semantics(const ChunkData &chunk_data,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status,
    const std::uint64_t allowed_lowest_index,
    const std::uint64_t allowed_highest_index);
/**
* brief: check_ledger_chunk_semantics - check semantics of an on-chain chunk
*   - expects the chunk context to be non-empty
*   - throws on failure
* param: ledger_chunk -
* param: expected_prefix_index -
*/
void check_ledger_chunk_semantics(const LedgerChunk &ledger_chunk, const std::uint64_t expected_prefix_index);
/**
* brief: initialize_scan_machine_metadata - initialize scan machine metadata with a specified configuration
* param: scan_config -
* return: initialized metadata
*/
ScanMachineMetadata initialize_scan_machine_metadata(const ScanMachineConfig &scan_config);
/**
* brief: initialize_scan_machine_state - initialize a scan machine state with a specified configuration
*   - initial state: need fullscan
* param: scan_config -
* return: initialized scan machine state
*/
ScanMachineState initialize_scan_machine_state(const ScanMachineConfig &scan_config);
/**
* brief: is_terminal_state - test if a scan machine is in a terminal state
* param: state -
* return: true if state is terminal
*/
bool is_terminal_state(const ScanMachineState &state);
/**
* brief: is_success_state - test if a scan machine is in a successful terminal state
* param: state -
* return: true if state is terminal
*/
bool is_success_state(const ScanMachineState &state);

} //namespace scanning
} //namespace sp
