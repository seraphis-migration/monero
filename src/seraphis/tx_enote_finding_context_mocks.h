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

// Dependency injectors for the find-received step of enote scanning (mock-ups).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "mock_offchain_context.h"
#include "tx_enote_finding_context.h"
#include "tx_enote_scanning.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// EnoteFindingContextLedgerMock
// - wraps a mock ledger context, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextLedgerMock final : public EnoteFindingContextLedger
{
public:
//constructors
    EnoteFindingContextLedgerMock(const MockLedgerContext &mock_ledger_context, const crypto::secret_key &k_find_received) :
        m_mock_ledger_context{mock_ledger_context},
        m_k_find_received{k_find_received}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLedgerMock& operator=(EnoteFindingContextLedgerMock&&) = delete;

//member functions
    /// try to get an onchain chunk
    bool try_get_onchain_chunk(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        EnoteScanningChunkLedgerV1 &chunk_out) const override;
    /// try to get an unconfirmed chunk
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) const override;

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
    const crypto::secret_key &m_k_find_received;
};

////
// EnoteFindingContextOffchain
// - wraps a mock offchain context, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextOffchainMock final : public EnoteFindingContextOffchain
{
public:
//constructors
    EnoteFindingContextOffchainMock(const MockOffchainContext &mock_offchain_context,
            const crypto::secret_key &k_find_received) :
        m_mock_offchain_context{mock_offchain_context},
        m_k_find_received{k_find_received}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextOffchainMock& operator=(EnoteFindingContextOffchainMock&&) = delete;

//member functions
    /// try to get a fresh offchain chunk
    bool try_get_offchain_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) const override;

//member variables
private:
    const MockOffchainContext &m_mock_offchain_context;
    const crypto::secret_key &m_k_find_received;
};

} //namespace sp
