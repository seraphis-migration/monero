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

// Enote store for a seraphis 'payment validator' that can read the amounts and destinations of incoming normal enotes.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "seraphis_impl/checkpoint_cache.h"
#include "seraphis_impl/enote_store_event_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>

//forward declarations


namespace sp
{

////
// SpEnoteStorePaymentValidator
// - tracks amounts and destinations of normal seraphis owned enotes (selfsends are not tracked)
///
class SpEnoteStorePaymentValidator final
{
public:
//constructors
    /// normal constructor
    SpEnoteStorePaymentValidator(const std::uint64_t refresh_index,
        const std::uint64_t default_spendable_age,
        const CheckpointCacheConfig &checkpoint_cache_config =
                CheckpointCacheConfig{
                        .num_unprunable = 50,
                        .max_separation = 100000,
                        .density_factor = 20
                    }
            );

//member functions
    /// get index of the first block the enote store cares about
    std::uint64_t refresh_index() const { return m_sp_block_id_cache.min_checkpoint_index(); }
    /// get index of the highest cached block (refresh index - 1 if no cached blocks)
    std::uint64_t top_block_index() const { return m_sp_block_id_cache.top_block_index(); }
    /// get the default spendable age (config value)
    std::uint64_t default_spendable_age() const { return m_default_spendable_age; }
    /// get the next cached block index > the requested index (-1 on failure)
    std::uint64_t next_sp_scanned_block_index(const std::uint64_t block_index) const;
    /// get the nearest cached block index <= the requested index (refresh index - 1 on failure)
    std::uint64_t nearest_sp_scanned_block_index(const std::uint64_t block_index) const;
    /// try to get the cached block id for a given index
    bool try_get_block_id_for_sp(const std::uint64_t block_index, rct::key &block_id_out) const;

    /// get the seraphis intermediate records: [ Ko : sp intermediate records ]
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1>& sp_intermediate_records() const
    { return m_sp_contextual_enote_records; }

    /// update the store with enote records, with associated context
    void update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
        std::list<PaymentValidatorStoreEvent> &events_inout);
    void update_with_sp_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
        std::list<PaymentValidatorStoreEvent> &events_inout);

private:
    /// add a record
    void add_record(const SpContextualIntermediateEnoteRecordV1 &new_record,
        std::list<PaymentValidatorStoreEvent> &events_inout);

//member variables
    /// seraphis enotes
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> m_sp_contextual_enote_records;

    /// cached block ids in range [refresh index, end of known chain]
    CheckpointCache m_sp_block_id_cache;

    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it is
    ///   on-chain and the next block's index is >= 'enote origin index + max(1, default_spendable_age)'
    const std::uint64_t m_default_spendable_age;
};

} //namespace sp
