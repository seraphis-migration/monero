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
#include "crypto/crypto.h"
#include "sp_crypto_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_store.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <list>
#include <unordered_map>
#include <utility>
#include <vector>

//forward declarations
namespace sp
{
    class EnoteScanningContextLedger;
    class EnoteFindingContextOffchain;
}

namespace sp
{

////
// EnoteScanningChunkLedgerV1
// - contextual basic enote records for view tag matches in a chunk of blocks
// - key images from all txs that have view tag matches in that chunk
// - chunk range: (prefix height, end height]
//   - prefix height: block that comes before the chunk range, used for contiguity checks
//   - end height: last block of the chunk
///
struct EnoteScanningChunkLedgerV1 final
{
    /// block range: prefix height, end height
    std::pair<std::uint64_t, std::uint64_t> m_block_range;
    /// block ids in range: [prefix height, end height]
    std::vector<rct::key> m_block_ids;
    /// view tag matches in range (prefix height, end height] (mapped to tx id)
    std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> m_basic_records_per_tx;
    /// key images from txs with view tag matches in range (prefix height, end height]
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_contextual_key_images;
};

//todo? EnoteScanningChunkLedgerVariantV1: to encapsulate scanning chunk types

////
// EnoteScanningChunkLedgerV1
// - contextual basic enote records for view tag matches in a non-ledger context (at a single point in time)
// - key images from all txs that have view tag matches
///
struct EnoteScanningChunkNonLedgerV1 final
{
    /// view tag matches in a non-ledger context (mapped to tx id)
    std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> m_basic_records_per_tx;
    /// key images from txs with view tag matches in the non-ledger context
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_contextual_key_images;
};

//todo? EnoteScanningChunkOffchainVariantV1: to encapsulate scanning chunk types

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
    const SpEnoteOriginContextV1::OriginStatus expected_origin_status,
    const SpEnoteSpentContextV1::SpentStatus expected_spent_status);

//todo: use a EnoteScanChunkProcessingContext to hide details of chunk processing and enote store updating?
void refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    EnoteScanningContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout);

void refresh_enote_store_offchain(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    SpEnoteStoreV1 &enote_store_inout);

void refresh_enote_store_full(const RefreshLedgerEnoteStoreConfig &ledger_refresh_config,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    EnoteScanningContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout);

} //namespace sp
