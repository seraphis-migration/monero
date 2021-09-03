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

// Core types for scanning enotes and key images to recover a user's balance.

// PRECONDITIONS:
// 1. chunks must be built from an atomic view of the source cache (ledger, unconfirmed cache, offchain cache)
// 2. chunk data: contextual_key_images must reference a tx recorded in basic_records_per_tx (even if you
//    need to add empty map entries to achieve that)
// 3. any call to get a chunk from a scanning context should produce a chunk that is at least as fresh as any
//    other chunk obtained from that context (atomic ordering)
// 4. any call to consume a chunk in a chunk consumer should resolve all side-effects observable via the consumer's
//    interface by the time the call is complete (e.g. any changes to block ids observable by get_nearest_block() need
//    to be completed during the 'consume chunk' call)

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>

//forward declarations


namespace sp
{
namespace scanning
{

////
// ChunkData
// - contextual basic enote records for owned enote candidates in a set of scanned txs (at a single point in time)
// - key images from each of the txs recorded in the basic records map
//   - add empty entries to that map if you want to include the key images of txs without owned enote candidates, e.g.
//     for legacy scanning where key images can appear in a tx even if none of the tx outputs were sent to you
//   - LEGACY OPTIMIZATION (optional): only key images of rings which include a received enote MUST be collected
//     - if filtering to get those key images is not possible then including all key images works too
///
struct ChunkData final
{
    /// owned enote candidates in a set of scanned txs (mapped to tx id)
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> basic_records_per_tx;
    /// key images from txs with owned enote candidates in the set of scanned txs
    std::list<SpContextualKeyImageSetV1> contextual_key_images;
};

////
// ChunkContext
// - prefix block id: id of block that comes before the chunk range, used for contiguity checks between chunks and with
//   a chunk consumer
// - chunk range (in block indices): [start index, end index)
//   - end index = start index + num blocks
///
struct ChunkContext final
{
    /// block id at 'start index - 1'  (implicitly ignored if start_index == 0)
    rct::key prefix_block_id;
    /// start index
    std::uint64_t start_index;
    /// block ids in range [start index, end index)
    std::vector<rct::key> block_ids;
};

} //namespace scanning
} //namespace sp
