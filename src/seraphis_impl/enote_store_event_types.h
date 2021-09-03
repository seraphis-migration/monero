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

// Events that can happen when updating an enote store.

#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

/// blocks added from a legacy intermediate scan update
struct LegacyIntermediateBlocksDiff final
{
    /// old index of top legacy intermediate scanned block
    std::uint64_t old_top_index;

    /// range of new blocks added
    std::uint64_t range_start_index;
    std::uint64_t num_blocks_added;
};

/// blocks added from a legacy full scan update
struct LegacyBlocksDiff final
{
    /// old index of top legacy full scanned block
    std::uint64_t old_top_index;

    /// range of new blocks added
    std::uint64_t range_start_index;
    std::uint64_t num_blocks_added;
};

/// blocks added from a seraphis intermediate scan update
struct SpIntermediateBlocksDiff final
{
    /// old index of top seraphis intermediate scanned block
    std::uint64_t old_top_index;

    /// range of new blocks added
    std::uint64_t range_start_index;
    std::uint64_t num_blocks_added;
};

/// blocks added from a seraphis scan update
struct SpBlocksDiff final
{
    /// old index of top seraphis scanned block
    std::uint64_t old_top_index;

    /// range of new blocks added
    std::uint64_t range_start_index;
    std::uint64_t num_blocks_added;
};

/// a legacy record's spent context was cleared
struct ClearedLegacySpentContext final
{
    rct::key identifier;
};

/// a seraphis record's spent context was cleared
struct ClearedSpSpentContext final
{
    crypto::key_image key_image;
};

/// a legacy record's spent context was updated
struct UpdatedLegacySpentContext final
{
    rct::key identifier;
};

/// a seraphis record's spent context was updated
struct UpdatedSpSpentContext final
{
    crypto::key_image key_image;
};

/// a legacy intermediate record's origin context was updated
struct UpdatedLegacyIntermediateOriginContext final
{
    rct::key identifier;
};

/// a legacy record's origin context was updated
struct UpdatedLegacyOriginContext final
{
    rct::key identifier;
};

/// a seraphis intermediate record's origin context was updated
struct UpdatedSpIntermediateOriginContext final
{
    rct::key onetime_address;
};

/// a seraphis record's origin context was updated
struct UpdatedSpOriginContext final
{
    crypto::key_image key_image;
};

/// a legacy intermediate record was removed
struct RemovedLegacyIntermediateRecord final
{
    rct::key identifier;
};

/// a legacy record was removed
struct RemovedLegacyRecord final
{
    rct::key identifier;
};

/// a seraphis intermediate record was removed
struct RemovedSpIntermediateRecord final
{
    rct::key onetime_address;
};

/// a seraphis record was removed
struct RemovedSpRecord final
{
    crypto::key_image key_image;
};

/// a legacy intermediate record was added
struct NewLegacyIntermediateRecord final
{
    rct::key identifier;
};

/// a legacy record was added
struct NewLegacyRecord final
{
    rct::key identifier;
};

/// a seraphis intermediate record was added
struct NewSpIntermediateRecord final
{
    rct::key onetime_address;
};

/// a seraphis record was added
struct NewSpRecord final
{
    crypto::key_image key_image;
};

/// an event in a seraphis payment validator enote store
using PaymentValidatorStoreEvent =
    tools::variant<
        SpIntermediateBlocksDiff,
        UpdatedSpIntermediateOriginContext,
        RemovedSpIntermediateRecord,
        NewSpIntermediateRecord
    >;

/// an event in a generic enote store
using EnoteStoreEvent = 
    tools::variant<
        LegacyIntermediateBlocksDiff,
        LegacyBlocksDiff,
        SpBlocksDiff,
        ClearedLegacySpentContext,
        ClearedSpSpentContext,
        UpdatedLegacySpentContext,
        UpdatedSpSpentContext,
        UpdatedLegacyOriginContext,
        UpdatedLegacyIntermediateOriginContext,
        UpdatedSpOriginContext,
        RemovedLegacyIntermediateRecord,
        RemovedLegacyRecord,
        RemovedSpRecord,
        NewLegacyIntermediateRecord,
        NewLegacyRecord,
        NewSpRecord
    >;

} //namespace sp
