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
// note: txs added to the mock ledger aren't validated (aside from key image checks)


#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "legacy_enote_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"

//third party headers
#include <boost/optional/optional.hpp>
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <map>
#include <tuple>
#include <unordered_set>
#include <vector>

//forward declarations
namespace sp
{
    struct SpEnoteV1;
    struct SpTxSquashedV1;
    struct EnoteScanningChunkLedgerV1;
    struct EnoteScanningChunkNonLedgerV1;
}


namespace sp
{

class MockLedgerContext final
{
public:
//constructors
    /// define tx era ranges (legacy: [0, first seraphis only); seraphis: [first seraphis allowed,) )
    /// note: blocks with mock legacy coinbase txs are only allowed before the first seraphis-only block
    MockLedgerContext(const std::uint64_t first_seraphis_allowed_block, const std::uint64_t first_seraphis_only_block);

//member functions
    /**
    * brief: get_chain_height - get current chain height
    *   - returns uint64{-1} if there are no blocks
    * return: current chain height (num blocks - 1)
    */
    std::uint64_t get_chain_height() const;
    /**
    * brief: key_image_exists_onchain_v1 - checks if a Seraphis linking tag (key image) exists in the ledger
    * param: key_image -
    * return: true/false on check result
    */
    bool key_image_exists_offchain_v1(const crypto::key_image &key_image) const;
    bool key_image_exists_unconfirmed_v1(const crypto::key_image &key_image) const;
    bool key_image_exists_onchain_v1(const crypto::key_image &key_image) const;
    /**
    * brief: get_reference_set_proof_elements_v1 - get legacy enotes stored in the ledger (for a membership proof)
    * param: indices -
    * outparam: proof_elements_out - {KI, C}
    */
    void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        std::vector<std::pair<rct::key, rct::key>> &proof_elements_out) const;
    /**
    * brief: get_reference_set_proof_elements_v2 - get Seraphis squashed enotes stored in the ledger
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    void get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const;
    /**
    * brief: max_legacy_enote_index - highest index of a legacy enote in the ledger
    *   TODO: version this somehow?
    * return: highest legacy enote index (defaults to std::uint64_t::max if no enotes)
    */
    std::uint64_t max_legacy_enote_index() const;
    /**
    * brief: max_sp_enote_index - highest index of a seraphis enote in the ledger
    *   TODO: version this somehow?
    * return: highest seraphis enote index (defaults to std::uint64_t::max if no enotes)
    */
    std::uint64_t max_sp_enote_index() const;
    /**
    * brief: num_legacy_enotes - number of legacy enotes in the ledger
    * return: number of legacy enotes in the ledger
    */
    std::uint64_t num_legacy_enotes() const { return max_legacy_enote_index() + 1; }
    /**
    * brief: num_sp_enotes - number of seraphis enotes in the ledger
    * return: number of seraphis enotes in the ledger
    */
    std::uint64_t num_sp_enotes() const { return max_sp_enote_index() + 1; }
    /**
    * brief: get_onchain_chunk_legacy - legacy view scan a chunk of blocks
    * param: chunk_start_height -
    * param: chunk_max_size -
    * param: legacy_base_spend_pubkey -
    * param: legacy_subaddress_map -
    * param: legacy_view_privkey -
    * outparam: chunk_out - chunk of scanned blocks (or empty chunk representing top of current chain)
    */
    void get_onchain_chunk_legacy(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const boost::optional<crypto::secret_key> &legacy_view_privkey,
        EnoteScanningChunkLedgerV1 &chunk_out) const;
    /**
    * brief: get_onchain_chunk_sp - find-received scan a chunk of blocks
    * param: chunk_start_height -
    * param: chunk_max_size -
    * param: k_find_received -
    * outparam: chunk_out - chunk of scanned blocks (or empty chunk representing top of current chain)
    */
    void get_onchain_chunk_sp(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        const crypto::secret_key &k_find_received,
        EnoteScanningChunkLedgerV1 &chunk_out) const;
    /**
    * brief: try_get_unconfirmed_chunk_sp - try to find-received scan the unconfirmed tx cache
    * param: k_find_received -
    * outparam: chunk_out -
    * return: true if chunk is not empty
    */
    bool try_get_unconfirmed_chunk_sp(const crypto::secret_key &k_find_received,
        EnoteScanningChunkNonLedgerV1 &chunk_out) const;
    /**
    * brief: add_legacy_coinbase - make a block with a mock legacy coinbase tx (containing legacy key images)
    * param: tx_id -
    * param: unlock_time -
    * param: memo -
    * param: legacy_key_images_for_block -
    * param: output_enotes -
    * return: block height of newly added block
    */
    std::uint64_t add_legacy_coinbase(const rct::key &tx_id,
        const std::uint64_t unlock_time,
        TxExtra memo,
        std::vector<crypto::key_image> legacy_key_images_for_block,
        std::vector<LegacyEnoteVariant> output_enotes);
    /**
    * brief: try_add_unconfirmed_tx_v1 - try to add a full transaction to the 'unconfirmed' tx cache
    *   - fails if there are key image duplicates with: unconfirmed, onchain
    *   - auto-removes any offchain entries that have overlapping key images with this tx
    * param: tx -
    * return: true if adding succeeded
    */
    bool try_add_unconfirmed_tx_v1(const SpTxSquashedV1 &tx);
    /**
    * brief: commit_unconfirmed_cache_v1 - move all unconfirmed txs onto the chain in a new block, with new mock coinbase tx
    *   - clears the unconfirmed tx cache
    *   - note: currently does NOT validate if coinbase enotes are sorted properly
    *   - todo: use a real coinbase tx instead, with height that is expected to match the next block height (try commit)
    * param: mock_coinbase_input_context -
    * param: mock_coinbase_tx_supplement -
    * param: mock_coinbase_output_enotes -
    * return: block height of newly added block
    */
    std::uint64_t commit_unconfirmed_txs_v1(const rct::key &mock_coinbase_input_context,
        SpTxSupplementV1 mock_coinbase_tx_supplement,
        std::vector<SpEnoteV1> mock_coinbase_output_enotes);
    /**
    * brief: remove_tx_from_unconfirmed_cache - remove a tx from the unconfirmed cache
    * param: tx_id - tx id of tx to remove
    */
    void remove_tx_from_unconfirmed_cache(const rct::key &tx_id);
    /**
    * brief: clear_unconfirmed_cache - remove all data stored in unconfirmed cache
    */
    void clear_unconfirmed_cache();
    /**
    * brief: pop_chain_at_height - remove all blocks >= the specified block height from the chain
    * param: pop_height - first block to pop from the chain
    * return: number of blocks popped
    */
    std::uint64_t pop_chain_at_height(const std::uint64_t pop_height);
    /**
    * brief: pop_blocks - remove a specified number of blocks from the chain
    * param: num_blocks - number of blocks to remove
    * return: number of blocks popped
    */
    std::uint64_t pop_blocks(const std::size_t num_blocks);

private:
    /// implementations of the above, without internally locking the ledger mutex (all expected to be no-fail)
    bool key_image_exists_unconfirmed_v1_impl(const crypto::key_image &key_image) const;
    bool key_image_exists_onchain_v1_impl(const crypto::key_image &key_image) const;
    void get_onchain_chunk_legacy_impl(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const boost::optional<crypto::secret_key> &legacy_view_privkey,
        EnoteScanningChunkLedgerV1 &chunk_out) const;
    void get_onchain_chunk_sp_impl(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        const crypto::secret_key &k_find_received,
        EnoteScanningChunkLedgerV1 &chunk_out) const;
    bool try_get_unconfirmed_chunk_sp_impl(const crypto::secret_key &k_find_received,
        EnoteScanningChunkNonLedgerV1 &chunk_out) const;
    std::uint64_t add_legacy_coinbase_impl(const rct::key &tx_id,
        const std::uint64_t unlock_time,
        TxExtra memo,
        std::vector<crypto::key_image> legacy_key_images_for_block,
        std::vector<LegacyEnoteVariant> output_enotes);
    bool try_add_unconfirmed_coinbase_v1_impl(const rct::key &tx_id,
        const rct::key &input_context,
        SpTxSupplementV1 tx_supplement,
        std::vector<SpEnoteV1> output_enotes);
    bool try_add_unconfirmed_tx_v1_impl(const SpTxSquashedV1 &tx);
    std::uint64_t commit_unconfirmed_txs_v1_impl(const rct::key &mock_coinbase_input_context,
        SpTxSupplementV1 mock_coinbase_tx_supplement,
        std::vector<SpEnoteV1> mock_coinbase_output_enotes);
    void remove_tx_from_unconfirmed_cache_impl(const rct::key &tx_id);
    void clear_unconfirmed_cache_impl();
    std::uint64_t pop_chain_at_height_impl(const std::uint64_t pop_height);
    std::uint64_t pop_blocks_impl(const std::size_t num_blocks);

    /// context mutex (mutable for use in const member functions)
    mutable boost::shared_mutex m_context_mutex;

    /// first block where a seraphis tx is allowed (this block and all following must have seraphis coinbase tx)
    std::uint64_t m_first_seraphis_allowed_block;
    /// first block where only seraphis txs are allowed
    std::uint64_t m_first_seraphis_only_block;


    //// UNCONFIRMED TXs

    /// Cryptonote key images (legacy)
    std::unordered_set<crypto::key_image> m_unconfirmed_legacy_key_images;
    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_unconfirmed_sp_key_images;
    /// map of tx key images
    std::map<
        sortable_key,     // tx id
        std::pair<
            std::vector<crypto::key_image>,  // legacy key images in tx
            std::vector<crypto::key_image>   // seraphis key images in tx
        >
    > m_unconfirmed_tx_key_images;
    /// map of Seraphis tx outputs
    std::map<
        sortable_key,     // tx id
        std::tuple<       // tx output contents
            rct::key,                // input context
            SpTxSupplementV1,        // tx supplement
            std::vector<SpEnoteV1>   // output enotes
        >
    > m_unconfirmed_tx_output_contents;


    //// ON-CHAIN BLOCKS & TXs

    /// Cryptonote key images (legacy)
    std::unordered_set<crypto::key_image> m_legacy_key_images;
    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_sp_key_images;
    /// map of tx key images
    std::map<
        std::uint64_t,      // block height
        std::map<
            sortable_key,   // tx id
            std::pair<
                std::vector<crypto::key_image>,  // legacy key images in tx
                std::vector<crypto::key_image>   // seraphis key images in tx
            >
        >
    > m_blocks_of_tx_key_images;
    /// legacy enote references {KI, C} (mapped to output index)
    std::map<std::uint64_t, std::pair<rct::key, rct::key>> m_legacy_enote_references;
    /// Seraphis squashed enotes (mapped to output index)
    std::map<std::uint64_t, rct::key> m_sp_squashed_enotes;
    /// map of accumulated output counts (legacy)
    std::map<
        std::uint64_t,  // block height
        std::uint64_t   // total number of legacy enotes including those in this block
    > m_accumulated_legacy_output_counts;
    /// map of accumulated output counts (Seraphis)
    std::map<
        std::uint64_t,  // block height
        std::uint64_t   // total number of seraphis enotes including those in this block
    > m_accumulated_sp_output_counts;
    /// map of legacy tx outputs
    std::map<
        std::uint64_t,        // block height
        std::map<
            sortable_key,     // tx id
            std::tuple<       // tx output contents
                std::uint64_t,                    // unlock time (only height representation supported here)
                TxExtra,                          // tx memo
                std::vector<LegacyEnoteVariant>   // output enotes
            >
        >
    > m_blocks_of_legacy_tx_output_contents;
    /// map of Seraphis tx outputs
    std::map<
        std::uint64_t,        // block height
        std::map<
            sortable_key,     // tx id
            std::tuple<       // tx output contents
                rct::key,                // input context
                SpTxSupplementV1,        // tx supplement
                std::vector<SpEnoteV1>   // output enotes
            >
        >
    > m_blocks_of_sp_tx_output_contents;
    /// map of block info
    std::map<
        std::uint64_t,  // block height
        std::tuple<
            rct::key,       // block ID
            std::uint64_t   // block timestamp
        >
    > m_block_infos;
};

bool try_add_tx_to_ledger(const SpTxSquashedV1 &tx_to_add, MockLedgerContext &ledger_context_inout);

} //namespace sp
