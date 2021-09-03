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

// Interface for implementing a ledger chunk.

#pragma once

//local headers
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace sp
{
namespace scanning
{
    struct ChunkData;
    struct ChunkContext;
}
}

namespace sp
{
namespace scanning
{

////
// LedgerChunk
// - interface for implementing a ledger chunk; implementations may store data directly or asynchronously
//
// - chunk context: tracks where this chunk exists on-chain
// - chunk data: data obtained from scanning the chunk (per subconsumer)
//
// - subconsumers: a ledger chunk can store chunk data for multiple subconsumers (so they can share a chunk context)
///
class LedgerChunk
{
public:
    virtual ~LedgerChunk() = default;
    /// chunk context (includes chunk block range, prefix block id, and chunk block ids)
    virtual const ChunkContext& get_context() const = 0;
    /// chunk data (includes owned enote candidates and key image candidates)
    virtual const ChunkData* try_get_data(const rct::key &subconsumer_id) const = 0;
    /// set of subconsumers associated with this ledger chunk
    virtual const std::vector<rct::key>& subconsumer_ids() const = 0;
};

} //namespace scanning
} //namespace sp
