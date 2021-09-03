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

// NOT FOR PRODUCTION

// Mock offchain context.
// note: the input context is used as a proxy for tx id in the maps, because the tx id is not known for partial txs

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"

//third party headers

//standard headers
#include <map>
#include <tuple>
#include <unordered_set>
#include <vector>

//forward declarations
namespace sp
{
    struct SpPartialTxV1;
    struct SpTxSquashedV1;
namespace scanning
{
    struct ChunkData;
}
}

namespace sp
{
namespace mocks
{

class MockOffchainContext final
{
public:
    /**
    * brief: cryptonote_key_image_exists - checks if a cryptonote key image exists in the offchain context
    * param: key_image -
    * return: true/false on check result
    */
    bool cryptonote_key_image_exists(const crypto::key_image &key_image) const;
    /**
    * brief: seraphis_key_image_exists - checks if a seraphis key image exists in the offchain context
    * param: key_image -
    * return: true/false on check result
    */
    bool seraphis_key_image_exists(const crypto::key_image &key_image) const;
    /**
    * brief: try_add_partial_tx_v1 - try to add a partial transaction to the offchain tx cache
    *   - fails if there are key image duplicates with: offchain
    * param: partial_tx -
    * return: true if adding succeeded
    */
    bool try_add_partial_tx_v1(const SpPartialTxV1 &partial_tx);
    /**
    * brief: try_add_tx_v1 - try to add a full transaction to the offchain tx cache
    *   - fails if there are key image duplicates with: offchain
    * param: tx -
    * return: true if adding succeeded
    */
    bool try_add_tx_v1(const SpTxSquashedV1 &tx);
    /**
    * brief: remove_tx_from_cache - remove a tx or partial tx from the offchain cache
    * param: input_context - input context of tx/partial tx to remove
    */
    void remove_tx_from_cache(const rct::key &input_context);
    /**
    * brief: remove_tx_with_key_image_from_cache - remove the tx with a specified key image from the offchain cache
    * param: key_image - key image in tx/partial tx to remove
    */
    void remove_tx_with_key_image_from_cache(const crypto::key_image &key_image);
    /**
    * brief: clear_cache - remove all data stored in offchain cache
    */
    void clear_cache();
    /**
    * brief: get_offchain_chunk_sp - find-received scan the offchain tx cache
    * param: xk_find_received -
    * outparam: chunk_data_out -
    * return: true if chunk is not empty
    */
    void get_offchain_chunk_sp(const crypto::x25519_secret_key &xk_find_received,
        scanning::ChunkData &chunk_data_out) const;

private:
    bool try_add_v1_impl(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
        const std::vector<SpEnoteImageV1> &sp_input_images,
        const SpTxSupplementV1 &tx_supplement,
        const std::vector<SpEnoteV1> &output_enotes);

    /// legacy key images
    std::unordered_set<crypto::key_image> m_legacy_key_images;
    /// Seraphis key images
    std::unordered_set<crypto::key_image> m_sp_key_images;
    /// map of tx outputs
    std::unordered_map<
        rct::key,     // input context
        std::tuple<       // tx output contents
            SpTxSupplementV1,             // tx supplement
            std::vector<SpEnoteVariant>   // output enotes
        >
    > m_output_contents;
    /// map of tx key images
    std::unordered_map<
        rct::key,     // input context
        std::pair<
            std::vector<crypto::key_image>,  // legacy key images in tx
            std::vector<crypto::key_image>   // seraphis key images in tx
        >
    > m_tx_key_images;
};

} //namespace mocks
} //namespace sp
