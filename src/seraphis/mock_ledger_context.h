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

// Mock ledger context: for testing
// note: In a real ledger, new enotes and new linking tags from a tx must be committed in ONE atomic operation. Otherwise,
//       the order of linking tags and enotes may be misaligned.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <map>
#include <mutex>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

//forward declarations
namespace sp
{
    struct SpEnoteV1;
    struct SpTxSquashedV1;
}


namespace sp
{

class MockLedgerContext final
{
public:
    /**
    * brief: key_image_exists_v1 - checks if a Seraphis linking tag (key image) exists in the ledger
    * param: key_image -
    * return: true/false on check result
    */
    bool key_image_exists_v1(const crypto::key_image &key_image) const;
    /**
    * brief: get_reference_set_proof_elements_v1 - gets Seraphis squashed enotes stored in the ledger
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const;
    /**
    * brief: min_enote_index - lowest index of an enote in the ledger
    *   TODO: version this somehow?
    * param: tx_to_add -
    * return: lowest enote index (defaults to 0 if no enotes)
    */
    std::uint64_t min_enote_index() const;
    /**
    * brief: max_enote_index - highest index of an enote in the ledger
    *   TODO: version this somehow?
    * return: highest enote index (defaults to std::uint64_t::max if no enotes)
    */
    std::uint64_t max_enote_index() const;
    /**
    * brief: num_enotes - number of enotes in the ledger
    *   TODO: version this somehow?
    * return: number of enotes in the ledger
    */
    std::uint64_t num_enotes() const { return max_enote_index() - min_enote_index() + 1; }
    /**
    * brief: try_add_transaction_sp_squashed_v1 - try to add a SpTxSquashedV1 transaction to the ledger
    * param: tx_to_add -
    * return: true if adding tx succeeded
    */
    bool try_add_transaction_sp_squashed_v1(const SpTxSquashedV1 &tx_to_add);
    /**
    * brief: try_add_key_image_v1 - add a Seraphis key image (linking tag) to the ledger
    * param: key_image -
    * return: false if linking tag can't be added (duplicate)
    */
    bool try_add_key_image_v1(const crypto::key_image &key_image);
    /**
    * brief: add_enote_v1 - add a Seraphis v1 enote to the ledger (and store the squashed enote)
    * param: enote -
    * return: index in the ledger of the enote just added
    */
    std::uint64_t add_enote_v1(const SpEnoteV1 &enote);

private:
    /// implementations of the above, without internally locking the ledger mutex (all expected to be no-fail)
    bool key_image_exists_v1_impl(const crypto::key_image &key_image) const;
    void add_key_image_v1_impl(const crypto::key_image &key_image);
    std::uint64_t add_enote_v1_impl(const SpEnoteV1 &enote);

    /// Ledger mutex (mutable for use in const member functions)
    mutable std::mutex m_ledger_mutex;

/*
    //// OFF-CHAIN/OFFLINE FULL/PARTIAL TXs

    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_offchain_sp_key_images;
    /// map of tx outputs
    std::map<
        rct::key,         // input context
        std::tuple<       // tx output contents
            SpTxSupplementV1,        // tx supplement
            std::vector<SpEnoteV1>   // output enotes
        >
    > m_offchain_output_contents;
    /// map of tx key images
    std::map<
        rct::key,   // input context
        std::vector<crypto::key_image>  // key images in tx
    > m_offchain_tx_key_images;


    //// UNCONFIRMED TXs

    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_unconfirmed_sp_key_images;
    /// map of tx outputs
    std::map<
        rct::key,         // tx id
        std::tuple<       // tx output contents
            rct::key,                // input context
            SpTxSupplementV1,        // tx supplement
            std::vector<SpEnoteV1>   // output enotes
        >
    > m_unconfirmed_tx_output_contents;
    /// map of tx key images
    std::map<
        rct::key,   // tx id
        std::vector<crypto::key_image>  // key images in tx
    > m_unconfirmed_tx_key_images;


    //// ON-CHAIN BLOCKS & TXs
*/
    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_sp_key_images;
    /// Seraphis v1 enotes (mapped to output index)
    std::unordered_map<std::uint64_t, SpEnoteV1> m_sp_enotes;
    /// Seraphis squashed enotes (mapped to output index)
    std::unordered_map<std::uint64_t, rct::key> m_sp_squashed_enotes;
/*
    /// map of tx outputs
    std::map<
        std::uint64_t,        // block height
        std::map<
            rct::key,         // tx id
            std::tuple<       // tx output contents
                rct::key,                // input context
                SpTxSupplementV1,        // tx supplement
                std::vector<SpEnoteV1>   // output enotes
            >
        >
    > m_blocks_of_tx_output_contents;
    /// map of accumulated output counts
    std::map<
        std::uint64_t,  // block height
        std::uint64_t   // total number of enotes including those in this block
    > m_accumulated_output_counts;
    /// map of tx key images
    std::map<
        std::uint64_t,  // block height
        std::map<
            rct::key,   // tx id
            std::vector<crypto::key_image>  // key images in tx
        >
    > m_blocks_of_tx_key_images;
    /// map of block IDs
    std::map<
        std::uint64_t,  // block height
        rct::key        // block ID
    > m_block_ids;
*/
};

template<typename TxType>
bool try_add_tx_to_ledger(const TxType &tx_to_add, MockLedgerContext &ledger_context_inout);

template<>
inline bool try_add_tx_to_ledger<SpTxSquashedV1>(const SpTxSquashedV1 &tx_to_add,
    MockLedgerContext &ledger_context_inout)
{
    return ledger_context_inout.try_add_transaction_sp_squashed_v1(tx_to_add);
}

} //namespace sp
