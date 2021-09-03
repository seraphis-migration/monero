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

// Dependency injectors for the find-received step of enote scanning. Intended to be stateless.

#pragma once

//local headers
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"

//third party headers

//standard headers
#include <memory>

//forward declarations


namespace sp
{

////
// EnoteFindingContextNonLedger
// - wraps a nonledger context of some kind, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextNonLedger
{
public:
//destructor
    virtual ~EnoteFindingContextNonLedger() = default;

//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteFindingContextNonLedger& operator=(EnoteFindingContextNonLedger&&) = delete;

//member functions
    /// get a fresh nonledger chunk (this is expected to contain all enotes in the nonledger context)
    virtual void get_nonledger_chunk(scanning::ChunkData &chunk_out) const = 0;
};

////
// EnoteFindingContextLedger
// - wraps a ledger context of some kind, produces chunks of potentially owned enotes (from find-received scanning)
///
class EnoteFindingContextLedger
{
public:
//destructor
    virtual ~EnoteFindingContextLedger() = default;

//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteFindingContextLedger& operator=(EnoteFindingContextLedger&&) = delete;

//member functions
    /// get an onchain chunk (or empty chunk representing top of current chain)
    virtual std::unique_ptr<scanning::LedgerChunk> get_onchain_chunk(const std::uint64_t chunk_start_index,
        const std::uint64_t chunk_max_size) const = 0;
};

} //namespace sp
