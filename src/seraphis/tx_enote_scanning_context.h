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

// Dependency injector for managing the find-received step of enote scanning.


#pragma once

//local headers
#include "tx_enote_scanning.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// EnoteScanningContextLedger
// - manages a source of ledger-based enote scanning chunks (i.e. finding potentially owned enotes)
///
class EnoteScanningContextLedger
{
public:
//overloaded operators
    /// disable copy/move (this is a virtual base class)
    EnoteScanningContextLedger& operator=(EnoteScanningContextLedger&&) = delete;

//member functions
    /// tell the enote finder it can start scanning from a specified block height
    virtual void begin_scanning_from_height(const std::uint64_t initial_start_height,
        const std::uint64_t max_chunk_size) = 0;
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: if chunk is empty, chunk represents top of current chain
    virtual void get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) = 0;
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    virtual bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) = 0;
    /// tell the enote finder to stop its scanning process (should be no-throw no-fail)
    virtual void terminate_scanning() = 0;
};

} //namespace sp
