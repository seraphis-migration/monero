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

// Dependency injectors for the find-received step of enote scanning (mock-ups).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "mock_ledger_context.h"
#include "mock_offchain_context.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"

//third party headers

//standard headers
#include <memory>
#include <unordered_map>

//forward declarations


namespace sp
{
namespace mocks
{

/// LegacyScanMode: convenience enum for specifying legacy scan mode ('scan' or 'only process legacy key images')
enum class LegacyScanMode : unsigned char
{
    SCAN,
    KEY_IMAGES_ONLY
};

////
// EnoteFindingContextLedgerMockLegacy
// - wraps a mock ledger context, produces chunks of potentially owned enotes (from legacy view scanning)
// - note: if the legacy_scan_mode is set to KEY_IMAGES_ONLY, then chunks found will contain only key images
///
class EnoteFindingContextLedgerMockLegacy final : public EnoteFindingContextLedger
{
public:
//constructors
    EnoteFindingContextLedgerMockLegacy(const MockLedgerContext &mock_ledger_context,
        const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey,
        const LegacyScanMode legacy_scan_mode) :
            m_mock_ledger_context{mock_ledger_context},
            m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
            m_legacy_subaddress_map{legacy_subaddress_map},
            m_legacy_view_privkey{legacy_view_privkey},
            m_legacy_scan_mode{legacy_scan_mode}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLedgerMockLegacy& operator=(EnoteFindingContextLedgerMockLegacy&&) = delete;

//member functions
    /// get an onchain chunk (or empty chunk representing top of current chain)
    std::unique_ptr<scanning::LedgerChunk> get_onchain_chunk(const std::uint64_t chunk_start_index,
        const std::uint64_t chunk_max_size) const override;

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
    const rct::key &m_legacy_base_spend_pubkey;
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &m_legacy_subaddress_map;
    const crypto::secret_key &m_legacy_view_privkey;
    const LegacyScanMode m_legacy_scan_mode;
};

////
// EnoteFindingContextLedgerMockSp
// - wraps a mock ledger context, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextLedgerMockSp final : public EnoteFindingContextLedger
{
public:
//constructors
    EnoteFindingContextLedgerMockSp(const MockLedgerContext &mock_ledger_context,
        const crypto::x25519_secret_key &xk_find_received) :
            m_mock_ledger_context{mock_ledger_context},
            m_xk_find_received{xk_find_received}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLedgerMockSp& operator=(EnoteFindingContextLedgerMockSp&&) = delete;

//member functions
    /// get an onchain chunk (or empty chunk representing top of current chain)
    std::unique_ptr<scanning::LedgerChunk> get_onchain_chunk(const std::uint64_t chunk_start_index,
        const std::uint64_t chunk_max_size) const override;

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
    const crypto::x25519_secret_key &m_xk_find_received;
};

////
// EnoteFindingContextUnconfirmedMockSp
// - wraps a mock ledger context, produces chunks of potentially owned unconfirmed enotes (from find-received scanning)
///
class EnoteFindingContextUnconfirmedMockSp final : public EnoteFindingContextNonLedger
{
public:
//constructors
    EnoteFindingContextUnconfirmedMockSp(const MockLedgerContext &mock_ledger_context,
        const crypto::x25519_secret_key &xk_find_received) :
            m_mock_ledger_context{mock_ledger_context},
            m_xk_find_received{xk_find_received}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextUnconfirmedMockSp& operator=(EnoteFindingContextUnconfirmedMockSp&&) = delete;

//member functions
    /// get a fresh unconfirmed chunk
    void get_nonledger_chunk(scanning::ChunkData &chunk_out) const override;

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
    const crypto::x25519_secret_key &m_xk_find_received;
};

////
// EnoteFindingContextOffchainMockSp
// - wraps a mock offchain context, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextOffchainMockSp final : public EnoteFindingContextNonLedger
{
public:
//constructors
    EnoteFindingContextOffchainMockSp(const MockOffchainContext &mock_offchain_context,
        const crypto::x25519_secret_key &xk_find_received) :
            m_mock_offchain_context{mock_offchain_context},
            m_xk_find_received{xk_find_received}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextOffchainMockSp& operator=(EnoteFindingContextOffchainMockSp&&) = delete;

//member functions
    /// get a fresh offchain chunk
    void get_nonledger_chunk(scanning::ChunkData &chunk_out) const override;

//member variables
private:
    const MockOffchainContext &m_mock_offchain_context;
    const crypto::x25519_secret_key &m_xk_find_received;
};

} //namespace mocks
} //namespace sp
