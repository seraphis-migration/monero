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
#include "crypto/crypto.h"
#include "jamtis_address_tag_utils.h"
#include "ringct/rctTypes.h"
#include "tx_enote_record_types.h"
#include "tx_enote_store_mocks.h"
#include "tx_enote_store_updater.h"

//third party headers

//standard headers
#include <list>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

//forward declarations


namespace sp
{

class EnoteStoreUpdaterLedgerMock final : public EnoteStoreUpdaterLedger
{
public:
//constructors
    /// normal constructor
    EnoteStoreUpdaterLedgerMock(const rct::key &wallet_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpEnoteStoreMockV1 &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteStoreUpdaterLedgerMock& operator=(EnoteStoreUpdaterLedgerMock&&) = delete;

//member functions
    /// start a chunk-handling session (if previous session wasn't ended, discard it)
    void start_chunk_handling_session() override
    {
        m_found_enote_records.clear();
        m_found_spent_key_images.clear();
    }

    /// process a chunk of basic enote records and save the results
    void process_chunk(
        const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images) override;

    /// end the current chunk-handling session (no-op if no session in progress)
    void end_chunk_handling_session(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids) override;

    /// try to get the recorded block id for a given height
    bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const override
    {
        return m_enote_store.try_get_block_id(block_height, block_id_out);
    }
    /// get height of first block the enote store cares about
    std::uint64_t get_refresh_height() const override
    {
        return m_enote_store.get_refresh_height();
    }
    /// get height of heighest recorded block (refresh height - 1 if no recorded blocks)
    std::uint64_t get_top_block_height() const override
    {
        return m_enote_store.get_top_block_height();
    }

//member variables
private:
    /// static data
    const rct::key &m_wallet_spend_pubkey;
    const crypto::secret_key &m_k_view_balance;
    SpEnoteStoreMockV1 &m_enote_store;

    crypto::secret_key m_k_unlock_amounts;
    crypto::secret_key m_k_find_received;
    crypto::secret_key m_s_generate_address;
    crypto::secret_key m_s_cipher_tag;
    std::unique_ptr<jamtis::jamtis_address_tag_cipher_context> m_cipher_context;

    /// session data
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_found_spent_key_images;
};

class EnoteStoreUpdaterNonLedgerMock final : public EnoteStoreUpdaterNonLedger
{
public:
//constructors
    /// normal constructor
    EnoteStoreUpdaterNonLedgerMock(const rct::key &wallet_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpEnoteStoreMockV1 &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteStoreUpdaterNonLedgerMock& operator=(EnoteStoreUpdaterNonLedgerMock&&) = delete;

//member functions
    /// process a chunk of basic enote records and handle the results
    void process_and_handle_chunk(
        const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images) override;

//member variables
private:
    /// static data
    const rct::key &m_wallet_spend_pubkey;
    const crypto::secret_key &m_k_view_balance;
    SpEnoteStoreMockV1 &m_enote_store;

    crypto::secret_key m_k_unlock_amounts;
    crypto::secret_key m_k_find_received;
    crypto::secret_key m_s_generate_address;
    crypto::secret_key m_s_cipher_tag;
    std::unique_ptr<jamtis::jamtis_address_tag_cipher_context> m_cipher_context;
};

} //namespace sp
