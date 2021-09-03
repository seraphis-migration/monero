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

// Simple ledger chunk types.

#pragma once

//local headers
#include "misc_log_ex.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"
#include "seraphis_main/scan_misc_utils.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace scanning
{

////
// LedgerChunkEmpty
// - empty chunks only
///
class LedgerChunkEmpty final : public LedgerChunk
{
public:
    LedgerChunkEmpty(ChunkContext context) :
        m_context{std::move(context)},
        m_data{},
        m_subconsumer_ids{rct::zero()}  //we need at least one subconsumer to satisfy ledger chunk semantics checks
    {
        CHECK_AND_ASSERT_THROW_MES(chunk_context_is_empty(context), "empty ledger chunk: chunk is not empty.");
    }

    const ChunkContext& get_context()              const override { return m_context;         }
    const ChunkData* try_get_data(const rct::key&) const override { return &m_data;           }
    const std::vector<rct::key>& subconsumer_ids() const override { return m_subconsumer_ids; }

private:
    ChunkContext m_context;
    ChunkData m_data;
    std::vector<rct::key> m_subconsumer_ids;
};

////
// LedgerChunkStandard
// - store data directly
///
class LedgerChunkStandard final : public LedgerChunk
{
public:
    LedgerChunkStandard(ChunkContext context, std::vector<ChunkData> data, std::vector<rct::key> subconsumer_ids) :
        m_context{std::move(context)},
        m_data{std::move(data)},
        m_subconsumer_ids{std::move(subconsumer_ids)}
    {
        CHECK_AND_ASSERT_THROW_MES(m_data.size() == m_subconsumer_ids.size(),
            "standard ledger chunk: mismatch between data and subconsumer ids.");
    }

    const ChunkContext& get_context() const override { return m_context; }
    const ChunkData* try_get_data(const rct::key &subconsumer_id) const override
    {
        auto id_it = std::find(m_subconsumer_ids.begin(), m_subconsumer_ids.end(), subconsumer_id);
        if (id_it == m_subconsumer_ids.end()) return nullptr;
        return &(m_data[std::distance(m_subconsumer_ids.begin(), id_it)]);
    }
    const std::vector<rct::key>& subconsumer_ids() const override { return m_subconsumer_ids; }

private:
    ChunkContext m_context;
    std::vector<ChunkData> m_data;
    std::vector<rct::key> m_subconsumer_ids;
};

} //namespace scanning
} //namespace sp
