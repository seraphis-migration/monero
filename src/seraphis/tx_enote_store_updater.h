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

//todo


#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <vector>

//forward declarations


namespace sp
{

////
// EnoteStoreUpdaterLedger
// - provides an API for updating an enote store with chunks of enotes from find-received scanning (from a ledger)
///
class EnoteStoreUpdaterLedger
{
public:
//overloaded operators
    /// disable copy/move (this is an abstract base class)
    EnoteStoreUpdaterLedger& operator=(EnoteStoreUpdaterLedger&&) = delete;

//member functions
    /// start a chunk-handling session (if previous session wasn't ended, discard it)
    virtual void start_chunk_handling_session() = 0;
    /// process a chunk of basic enote records and save the results
    virtual void process_chunk(
        const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images) = 0;
    /// end the current chunk-handling session
    virtual void end_chunk_handling_session(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids) = 0;

    /// try to get the internal recorded block id for a given height
    virtual bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const = 0;
    /// get height of first block the internal enote store cares about
    virtual std::uint64_t get_refresh_height() const = 0;
    /// get height of heighest internal recorded block (refresh height - 1 if no recorded blocks)
    virtual std::uint64_t get_top_block_height() const = 0;
};

////
// EnoteStoreUpdaterNonLedger
// - provides an API for updating an enote store with chunks of enotes from find-received scanning(from an offchain context)
///
class EnoteStoreUpdaterNonLedger
{
public:
//overloaded operators
    /// disable copy/move (this is an abstract base class)
    EnoteStoreUpdaterNonLedger& operator=(EnoteStoreUpdaterNonLedger&&) = delete;

//member functions
    /// process a chunk of basic enote records and handle the results
    virtual void process_and_handle_chunk(
        const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images) = 0;
};

} //namespace sp
