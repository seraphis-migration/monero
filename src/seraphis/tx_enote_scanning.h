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
    /// cumulative enote counts in range: [prefix height, end height]
    std::vector<std::uint64_t> m_accumulated_output_counts;
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

////
// EnoteScanChunkContextLedger
// - manages a source of ledger-based enote scanning chunks (i.e. finding potentially owned enotes)
///
class EnoteScanChunkContextLedger
{
public:
//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteScanChunkContextLedger& operator=(EnoteScanChunkContextLedger&&) = delete;

//member functions
    /// tell the enote finder it can start scanning from a specified block height
    virtual void begin_scanning_from_height(const std::uint64_t initial_prefix_height,
        const std::uint64_t max_chunk_size) = 0;
    /// try to get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    virtual bool try_get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) = 0;
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    virtual bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) = 0;
    /// tell the enote finder to stop its scanning process (should be no-throw no-fail)
    virtual void terminate_scanning() = 0;
};

////
// EnoteFindingContextLedger
// - wraps a ledger context of some kind, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextLedger
{
public:
//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteFindingContextLedger& operator=(EnoteFindingContextLedger&&) = delete;

//member functions
    /// try to get an onchain chunk
    virtual void try_get_onchain_chunk(const std::uint64_t chunk_prefix_height,
        const std::uint64_t chunk_max_size,
        EnoteScanningChunkLedgerV1 &chunk_out) const = 0;
    virtual void try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) const = 0;
};

//EnoteFindingContextLedgerMock: take mock offchain context, find-received key as input

////
// EnoteScanChunkContextLedgerDefault
// - manages an enote finding context for acquiring enote scanning chunks from a ledger context
// - default implementation
// - todo: give optional thread pool to constructor, do multi-threaded chunk collection
///
class EnoteScanChunkContextLedgerDefault final : public EnoteScanChunkContextLedger
{
public:
//constructor
    EnoteScanChunkContextLedgerDefault(const EnoteFindingContextLedger &enote_finding_context) :
        m_enote_finding_context{enote_finding_context}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanChunkContextLedgerDefault& operator=(EnoteScanChunkContextLedgerDefault&&) = delete;

//member functions
    /// start scanning from a specified block height
    void begin_scanning_from_height(const std::uint64_t initial_prefix_height, const std::uint64_t max_chunk_size) override;
    /// try to get the next available onchain chunk (contiguous with the last chunk acquired since starting to scan)
    bool try_get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) override;
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) override;
    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override;

//member variables
private:
    /// finds chunks of enotes that are potentially owned
    const EnoteFindingContextLedger &m_enote_finding_context;

    /// 
    std::uint64_t m_initial_prefix_height{static_cast<std::uint64_t>(-1)};
    /// 
    std::uint64_t m_max_chunk_size{0};
};

//EnoteScanChunkContextLedgerTest: use mock ledger context, define test case that includes reorgs

////
// EnoteFindingContextOffchain
// - wraps an offchain context of some kind, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextOffchain
{
public:
//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteFindingContextOffchain& operator=(EnoteFindingContextOffchain&&) = delete;

//member functions
    /// try to get a fresh offchain chunk
    virtual bool try_get_offchain_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) const = 0;
};

//EnoteFindingContextOffchainMock: take mock offchain context, find-received key as input



////
// EnoteScanChunkProcessLedger
// - raii wrapper on a EnoteScanChunkContextLedger for a specific scanning process (begin ... terminate)
///
class EnoteScanChunkProcessLedger final
{
public:
//constructors
    /// normal constructor
    EnoteScanChunkProcessLedger(const std::uint64_t initial_prefix_height,
        const std::uint64_t max_chunk_size,
        EnoteScanChunkContextLedger &enote_scan_chunk_context) :
        m_enote_scan_chunk_context{enote_scan_chunk_context}
    {
        m_enote_scan_chunk_context.begin_scanning_from_height(initial_prefix_height, max_chunk_size);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanChunkProcessLedger& operator=(EnoteScanChunkProcessLedger&&) = delete;

//destructor
    ~EnoteScanChunkProcessLedger()
    {
        try { m_enote_scan_chunk_context.terminate_scanning(); }
        catch (...) { /* todo: log error */ }
    }

//member functions
    /// try to get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    bool try_get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out)
    {
        return m_enote_scan_chunk_context.try_get_onchain_chunk(chunk_out);
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out)
    {
        return m_enote_scan_chunk_context.try_get_unconfirmed_chunk(chunk_out);
    }

//member variables
private:
    /// reference to an enote finding context
    EnoteScanChunkContextLedger &m_enote_scan_chunk_context;
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

struct ChainContiguityMarker final
{
    /// height of the block
    std::uint64_t m_block_height;
    /// id of the block (optional)
    boost::optional<rct::key> m_block_id;
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
    EnoteScanChunkContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout);

void refresh_enote_store_offchain(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    SpEnoteStoreV1 &enote_store_inout);

void refresh_enote_store_full(const RefreshLedgerEnoteStoreConfig &ledger_refresh_config,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    EnoteScanChunkContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout);

} //namespace sp
