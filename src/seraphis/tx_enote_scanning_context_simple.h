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

// Simple implementation of a ledger-based enote scanning context.


#pragma once

//local headers
#include "tx_enote_finding_context.h"
#include "tx_enote_scanning.h"
#include "tx_enote_scanning_context.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// EnoteScanningContextLedgerSimple
// - manages an enote finding context for acquiring enote scanning chunks from a ledger context
// - simple implementation: synchronously obtain chunks from an enote finding context
///
class EnoteScanningContextLedgerSimple final : public EnoteScanningContextLedger
{
public:
//constructor
    EnoteScanningContextLedgerSimple(const EnoteFindingContextLedger &enote_finding_context) :
        m_enote_finding_context{enote_finding_context}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanningContextLedgerSimple& operator=(EnoteScanningContextLedgerSimple&&) = delete;

//member functions
    /// start scanning from a specified block height
    void begin_scanning_from_height(const std::uint64_t initial_prefix_height, const std::uint64_t max_chunk_size) override
    {
        m_current_prefix_height = initial_prefix_height;
        m_max_chunk_size = max_chunk_size;
    }
    /// try to get the next available onchain chunk (starting at the end of the last chunk acquired since starting to scan)
    bool try_get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) override
    {
        if (!m_enote_finding_context.try_get_onchain_chunk(m_current_prefix_height, m_max_chunk_size, chunk_out))
            return false;

        m_current_prefix_height = std::get<1>(chunk_out.m_block_range);
        return true;
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) override
    {
        return m_enote_finding_context.try_get_unconfirmed_chunk(chunk_out);
    }
    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override { /* no-op */ }

//member variables
private:
    /// finds chunks of enotes that are potentially owned
    const EnoteFindingContextLedger &m_enote_finding_context;

    std::uint64_t m_current_prefix_height{static_cast<std::uint64_t>(-1);
    std::uint64_t m_max_chunk_size{0};
};

//EnoteScanningContextLedgerTest: use mock ledger context, define test case that includes reorgs

} //namespace sp
