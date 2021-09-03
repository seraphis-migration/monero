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

// Basic API for the seraphis balance recovery framework.

#pragma once

//local headers
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
namespace scanning
{
    struct ScanMachineConfig;
    class ScanContextNonLedger;
    class ScanContextLedger;
    class ChunkConsumer;
}
}

namespace sp
{

/**
* brief: refresh_enote_store_nonledger - perform a non-ledger balance recovery process (e.g. scan the tx pool)
* param: expected_origin_status -
* param: expected_spent_status -
* inoutparam: scan_context_inout -
* inoutparam: chunk_consumer_inout -
* return: false if the refresh was not completely successful
*/
bool refresh_enote_store_nonledger(const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status,
    scanning::ScanContextNonLedger &scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout);
/**
* brief: refresh_enote_store_ledger - perform an on-chain balance recovery process (i.e. scan the ledger)
* param: scan_machine_config -
* inoutparam: ledger_scan_context_inout -
* inoutparam: chunk_consumer_inout -
* return: false if the refresh was not completely successful
*/
bool refresh_enote_store_ledger(const scanning::ScanMachineConfig &scan_machine_config,
    scanning::ScanContextLedger &ledger_scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout);
/**
* brief: refresh_enote_store - perform a complete on-chain + unconfirmed cache balance recovery process
* param: scan_machine_config -
* inoutparam: nonledger_scan_context_inout -
* inoutparam: ledger_scan_context_inout -
* inoutparam: chunk_consumer_inout -
* return: false if the refresh was not completely successful
*/
bool refresh_enote_store(const scanning::ScanMachineConfig &scan_machine_config,
    scanning::ScanContextNonLedger &nonledger_scan_context_inout,
    scanning::ScanContextLedger &ledger_scan_context_inout,
    scanning::ChunkConsumer &chunk_consumer_inout);

} //namespace sp
