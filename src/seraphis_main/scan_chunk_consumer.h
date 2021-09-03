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

// Dependency injector for consuming data acquired by the candidacy phase of balance recovery.

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "ringct/rctTypes.h"
#include "scan_ledger_chunk.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace sp
{
namespace scanning
{
    struct ChunkData;
    struct ContiguityMarker;
}
}

namespace sp
{
namespace scanning
{

////
// ChunkConsumer
// - provides an API for consuming chunks of enotes from find-received scanning
///
class ChunkConsumer
{
public:
//destructor
    virtual ~ChunkConsumer() = default;

//overloaded operators
    /// disable copy/move (this is an abstract base class)
    ChunkConsumer& operator=(ChunkConsumer&&) = delete;

//member functions
    /// get index of first block the consumer cares about
    virtual std::uint64_t refresh_index() const = 0;
    /// get index of first block the consumer wants to have scanned
    virtual std::uint64_t desired_first_block() const = 0;
    /// get a marker for the next block > the specified index
    /// ERROR: return { -1, boost::none } if there is no such block
    virtual ContiguityMarker get_next_block(const std::uint64_t block_index) const = 0;
    /// get a marker for the nearest block <= the specified index
    /// ERROR: return { refresh_index - 1, boost::none } if there is no such block
    virtual ContiguityMarker get_nearest_block(const std::uint64_t block_index) const = 0;

    /// consume a chunk of basic enote records and save the results
    virtual void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status, const ChunkData &data) = 0;
    virtual void consume_onchain_chunk(const LedgerChunk &chunk,
        const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids) = 0;
};

} //namespace scanning
} //namespace sp
