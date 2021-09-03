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
#include "scan_process_basic.h"

//local headers
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_chunk_consumer.h"
#include "seraphis_main/scan_context.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_machine.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/scan_misc_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool refresh_enote_store_nonledger(const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status,
    scanning::ScanContextNonLedger &scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout)
{
    try
    {
        // 1. get the scan chunk
        scanning::ChunkData nonledger_chunk;
        scan_context_inout.get_nonledger_chunk(nonledger_chunk);

        scanning::check_chunk_data_semantics(nonledger_chunk, expected_origin_status, expected_spent_status, 0, -1);

        // 2. check if the scan context was aborted
        // - don't consume chunk if aborted and chunk is empty (it may not represent the real state of the nonledger
        //   cache)
        // - consume chunk if aborted and chunk is non-empty (it's possible for a scan context to be aborted after
        //   acquiring a chunk)
        if (scanning::chunk_data_is_empty(nonledger_chunk) &&
            scan_context_inout.is_aborted())
            return false;

        // 3. consume the chunk
        chunk_consumer_inout.consume_nonledger_chunk(expected_origin_status, nonledger_chunk);
    }
    catch (...)
    {
        LOG_ERROR("refresh enote store nonledger failed.");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool refresh_enote_store_ledger(const scanning::ScanMachineConfig &scan_machine_config,
    scanning::ScanContextLedger &ledger_scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout)
{
    // 1. prepare metadata
    scanning::ScanMachineState state{scanning::initialize_scan_machine_state(scan_machine_config)};

    // 2. advance the state machine until it terminates or encounters a failure
    while (scanning::try_advance_state_machine(ledger_scan_context_inout, chunk_consumer_inout, state) &&
        !scanning::is_terminal_state(state))
    {}

    // 3. check the result
    if (!scanning::is_success_state(state))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool refresh_enote_store(const scanning::ScanMachineConfig &scan_machine_config,
    scanning::ScanContextNonLedger &nonledger_scan_context_inout,
    scanning::ScanContextLedger &ledger_scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout)
{
    // 1. perform a full scan
    if (!refresh_enote_store_ledger(scan_machine_config, ledger_scan_context_inout, chunk_consumer_inout))
        return false;

    // 2. perform an unconfirmed scan
    if (!refresh_enote_store_nonledger(SpEnoteOriginStatus::UNCONFIRMED,
            SpEnoteSpentStatus::SPENT_UNCONFIRMED,
            nonledger_scan_context_inout,
            chunk_consumer_inout))
        return false;

    // 3. perform a follow-up full scan
    // rationale:
    // - blocks may have been added between the initial on-chain pass and the unconfirmed pass, and those blocks may
    //   contain txs not seen by the unconfirmed pass (i.e. sneaky txs)
    // - we want scan results to be chronologically contiguous (it is better for the unconfirmed scan results to be stale
    //   than the on-chain scan results)
    if (!refresh_enote_store_ledger(scan_machine_config, ledger_scan_context_inout, chunk_consumer_inout))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
