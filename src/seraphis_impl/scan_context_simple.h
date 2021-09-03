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

// Simple implementations of enote scanning contexts.

#pragma once

//local headers
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/scan_context.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"

//third party headers

//standard headers
#include <memory>

//forward declarations


namespace sp
{
namespace scanning
{

////
// ScanContextNonLedgerDummy
// - dummy nonledger scanning context
///
class ScanContextNonLedgerDummy final : public ScanContextNonLedger
{
public:
    void get_nonledger_chunk(ChunkData &chunk_out) override { chunk_out = ChunkData{}; }
    bool is_aborted()                        const override { return false; }
};

////
// ScanContextNonLedgerSimple
// - simple implementation: synchronously obtain chunks from an enote finding context
///
class ScanContextNonLedgerSimple final : public ScanContextNonLedger
{
public:
//constructor
    ScanContextNonLedgerSimple(const EnoteFindingContextNonLedger &enote_finding_context) :
        m_enote_finding_context{enote_finding_context}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ScanContextNonLedgerSimple& operator=(ScanContextNonLedgerSimple&&) = delete;

//member functions
    /// get a scanning chunk for the nonledger txs in the injected context
    void get_nonledger_chunk(ChunkData &chunk_out) override
    {
        m_enote_finding_context.get_nonledger_chunk(chunk_out);
    }
    /// test if scanning has been aborted
    bool is_aborted() const override { return false; }

//member variables
private:
    /// enote finding context: finds chunks of enotes that are potentially owned
    const EnoteFindingContextNonLedger &m_enote_finding_context;
};

////
// ScanContextLedgerSimple
// - simple implementation: synchronously obtain chunks from an enote finding context
///
class ScanContextLedgerSimple final : public ScanContextLedger
{
public:
//constructor
    ScanContextLedgerSimple(const EnoteFindingContextLedger &enote_finding_context) :
        m_enote_finding_context{enote_finding_context}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ScanContextLedgerSimple& operator=(ScanContextLedgerSimple&&) = delete;

//member functions
    /// start scanning from a specified block index
    void begin_scanning_from_index(const std::uint64_t initial_start_index,
        const std::uint64_t max_chunk_size_hint) override
    {
        m_next_start_index = initial_start_index;
        m_max_chunk_size   = max_chunk_size_hint;
    }
    /// get the next available onchain chunk (or empty chunk representing top of current chain)
    /// - start past the end of the last chunk acquired since starting to scan
    std::unique_ptr<LedgerChunk> get_onchain_chunk() override
    {
        // 1. try to get a chunk
        std::unique_ptr<LedgerChunk> chunk{
                m_enote_finding_context.get_onchain_chunk(m_next_start_index, m_max_chunk_size)
            };
        if (!chunk)
            return nullptr;

        // 2. save the next chunk's expected start index
        m_next_start_index = chunk->get_context().start_index + chunk->get_context().block_ids.size();
        return chunk;
    }
    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override { /* no-op */ }
    /// test if scanning has been aborted
    bool is_aborted() const override { return false; }

//member variables
private:
    /// enote finding context: finds chunks of enotes that are potentially owned
    const EnoteFindingContextLedger &m_enote_finding_context;

    std::uint64_t m_next_start_index{static_cast<std::uint64_t>(-1)};
    std::uint64_t m_max_chunk_size{0};
};

} //namespace scanning
} //namespace sp
