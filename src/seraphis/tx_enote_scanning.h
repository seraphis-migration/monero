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

//todo


#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "tx_contextual_enote_record_types.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations
namespace sp
{
    class EnoteScanningContextLedger;
    class EnoteFindingContextOffchain;
    class EnoteStoreUpdaterLedger;
    class EnoteStoreUpdaterNonLedger;
}

namespace sp
{

////
// EnoteScanningChunkLedgerV1
// - contextual basic enote records for owned enote candidates in a chunk of blocks
// - key images from all txs that have owned enote candidates in that chunk
// - chunk range: [start height, end height)
// - prefix block id: id of block that comes before the chunk range, used for contiguity checks
///
struct EnoteScanningChunkLedgerV1 final
{
    /// block range: [start height, end height)
    std::uint64_t m_start_height;
    std::uint64_t m_end_height;
    /// block id at 'start height - 1'  (implicitly ignored if start_height == 0)
    rct::key m_prefix_block_id;
    /// block ids in range [start height, end height)
    std::vector<rct::key> m_block_ids;
    /// owned enote candidates in range [start height, end height) (mapped to tx id)
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> m_basic_records_per_tx;
    /// key images from txs with owned enote candidates in range [start height, end height)
    std::list<SpContextualKeyImageSetV1> m_contextual_key_images;
};

////
// EnoteScanningChunkLedgerV1
// - contextual basic enote records for owned enote candidates in a non-ledger context (at a single point in time)
// - key images from all txs with owned enote candidates
///
struct EnoteScanningChunkNonLedgerV1 final
{
    /// owned enote candidates in a non-ledger context (mapped to tx id)
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> m_basic_records_per_tx;
    /// key images from txs with owned enote candidates in the non-ledger context
    std::list<SpContextualKeyImageSetV1> m_contextual_key_images;
};

struct RefreshLedgerEnoteStoreConfig final
{
    /// number of blocks below highest known contiguous block to start scanning
    std::uint64_t m_reorg_avoidance_depth{10};
    /// max number of blocks per on-chain scanning chunk
    std::uint64_t m_max_chunk_size{100};
    /// maximum number of times to try rescanning if a partial reorg is detected
    std::uint64_t m_max_partialscan_attempts{3};
};

//todo
void check_v1_enote_scan_chunk_ledger_semantics_v1(const EnoteScanningChunkLedgerV1 &onchain_chunk,
    const std::uint64_t expected_prefix_height);
void check_v1_enote_scan_chunk_nonledger_semantics_v1(const EnoteScanningChunkNonLedgerV1 &nonledger_chunk,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status);

//todo: use a EnoteScanChunkProcessingContext to hide details of chunk processing and enote store updating?
void refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_inout);

void refresh_enote_store_offchain(const EnoteFindingContextOffchain &enote_finding_context,
    EnoteStoreUpdaterNonLedger &enote_store_updater_inout);

void refresh_enote_store_full(const RefreshLedgerEnoteStoreConfig &ledger_refresh_config,
    const EnoteFindingContextOffchain &enote_finding_context,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_ledger_inout,
    EnoteStoreUpdaterNonLedger &enote_store_updater_nonledger_inout);

} //namespace sp
