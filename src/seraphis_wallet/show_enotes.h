// Copyright (c) 2023, The Monero Project
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

#pragma once

// local headers
#include "common/util.h"
#include "crypto/crypto.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"

// third party headers

// standard headers


using namespace sp;

typedef void (*FilterEnotes)(const std::pair<crypto::key_image, SpContextualEnoteRecordV1> &enote,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_out);

typedef bool (*ComparatorEnotes)(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b);

///
enum class SpTxDirectionStatus : unsigned char
{
    // get all (in,out,offchain,pool) except failed
    ALL,
    // 'incoming txs' where enotes are unspent and onchain
    IN_ONCHAIN,
    // 'incoming txs' where enotes are on the mining pool
    IN_POOL,
    // 'incoming txs' where enotes are offchain
    IN_OFFCHAIN,
    // 'outgoing txs' where enotes are spent and onchain
    OUT_ONCHAIN,
    // 'outgoing txs' where enotes are on the mining pool
    OUT_POOL,
    // 'outgoing txs' where enotes are spent offchain
    OUT_OFFCHAIN,
    // 'outgoing txs' that failed to be broadcasted
    FAILED,
};

void get_enotes(const SpEnoteStore &sp_enote_store,
    const SpTxDirectionStatus tx_status,
    const std::pair<uint64_t, uint64_t> range_height,
    std::vector<SpContextualEnoteRecordV1> &vec_enote_records_out);

void show_enotes(const std::vector<SpContextualEnoteRecordV1> &vec_enote_records);
