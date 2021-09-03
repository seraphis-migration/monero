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

// Async ledger chunk.
// WARNING: It is potentially UB to pass an async ledger chunk to any thread not associated with the referenced
//          threadpool.

#pragma once

//local headers
#include "async/threadpool.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"

//third party headers

//standard headers
#include <future>
#include <vector>

//forward declarations


namespace sp
{
namespace scanning
{

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

struct PendingChunkContext final
{
    std::promise<void> stop_signal;                  //for canceling the pending context request
    std::shared_future<ChunkContext> chunk_context;  //start index, element ids, prefix id
    async::join_condition_t context_join_condition;  //for waiting on the chunk context
};

struct PendingChunkData final
{
    std::promise<void> stop_signal;              //for canceling the pending data request
    std::shared_future<ChunkData> chunk_data;    //basic enote records and contextual key image sets
    async::join_condition_t data_join_condition; //for waiting on the chunk data
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

class AsyncLedgerChunk final : public LedgerChunk
{
public:
//constructors
    /// normal constructor
    AsyncLedgerChunk(async::Threadpool &threadpool,
        PendingChunkContext &&pending_context,
        std::vector<PendingChunkData> &&pending_data,
        std::vector<rct::key> subconsumer_ids);

//member functions
    /// access the chunk context
    const ChunkContext& get_context() const override;
    /// access the chunk data for a specified subconsumer
    const ChunkData* try_get_data(const rct::key &subconsumer_id) const override;
    /// get the cached subconsumer ids associated with this chunk
    const std::vector<rct::key>& subconsumer_ids() const override;

private:
    /// wait until the pending context is ready
    void wait_for_context() const;
    /// wait until the specified pending data is ready
    void wait_for_data(const std::size_t pending_data_index) const;

//member variables
    async::Threadpool &m_threadpool;
    mutable PendingChunkContext m_pending_context;
    mutable std::vector<PendingChunkData> m_pending_data;
    const std::vector<rct::key> m_subconsumer_ids;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

} //namespace scanning
} //namespace sp
