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

// Chunk consumers for these enote scanning workflows:
// - legacy view-only (view-scan or key image collection)
// - legacy full-scan
// - seraphis payment validator scan
// - seraphis full-scan

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "enote_finding_context_mocks.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_payment_validator.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/scan_chunk_consumer.h"
#include "seraphis_main/scan_machine_types.h"

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
namespace mocks
{

class ChunkConsumerMockLegacyIntermediate final : public scanning::ChunkConsumer
{
public:
//constructors
    /// normal constructor
    ChunkConsumerMockLegacyIntermediate(const rct::key &legacy_base_spend_pubkey,
        const crypto::secret_key &legacy_view_privkey,
        const LegacyScanMode legacy_scan_mode,
        SpEnoteStore &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ChunkConsumerMockLegacyIntermediate& operator=(ChunkConsumerMockLegacyIntermediate&&) = delete;

//member functions
    /// get index of first block the enote store cares about
    std::uint64_t refresh_index() const override;
    /// get index of first block the updater wants to have scanned
    std::uint64_t desired_first_block() const override;
    /// get a marker for the next block > the specified index
    scanning::ContiguityMarker get_next_block(const std::uint64_t block_index) const override;
    /// get a marker for the nearest block <= the specified index
    scanning::ContiguityMarker get_nearest_block(const std::uint64_t block_index) const override;

    /// consume a chunk of basic enote records and save the results
    void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
        const scanning::ChunkData &chunk_data) override;
    void consume_onchain_chunk(const scanning::LedgerChunk &chunk,
        const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids) override;

//member variables
private:
    /// If this is set to KEY_IMAGES_ONLY, then desired_first_block() will be defined from the last block that was legacy
    /// view-scanned AND where legacy key images were fully handled (i.e. the last fullscanned index). Otherwise, it will
    /// be defined from the last block that was only legacy view-scanned.
    /// - Goal: when scanning for legacy key images, expect the enote scanner to return key images for all blocks that
    ///   were legacy view-scanned but that didn't have key images handled (i.e. because key images weren't available
    ///   during a previous scan).
    const LegacyScanMode m_legacy_scan_mode;

    const rct::key &m_legacy_base_spend_pubkey;
    const crypto::secret_key &m_legacy_view_privkey;
    SpEnoteStore &m_enote_store;
};

class ChunkConsumerMockLegacy final : public scanning::ChunkConsumer
{
public:
//constructors
    /// normal constructor
    ChunkConsumerMockLegacy(const rct::key &legacy_base_spend_pubkey,
        const crypto::secret_key &legacy_spend_privkey,
        const crypto::secret_key &legacy_view_privkey,
        SpEnoteStore &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ChunkConsumerMockLegacy& operator=(ChunkConsumerMockLegacy&&) = delete;

//member functions
    /// get index of first block the enote store cares about
    std::uint64_t refresh_index() const override;
    /// get index of first block the updater wants to have scanned
    std::uint64_t desired_first_block() const override;
    /// get a marker for the next block > the specified index
    scanning::ContiguityMarker get_next_block(const std::uint64_t block_index) const override;
    /// get a marker for the nearest block <= the specified index
    scanning::ContiguityMarker get_nearest_block(const std::uint64_t block_index) const override;

    /// consume a chunk of basic enote records and save the results
    void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
        const scanning::ChunkData &chunk_data) override;
    void consume_onchain_chunk(const scanning::LedgerChunk &chunk,
        const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids) override;

//member variables
private:
    const rct::key &m_legacy_base_spend_pubkey;
    const crypto::secret_key &m_legacy_spend_privkey;
    const crypto::secret_key &m_legacy_view_privkey;

    SpEnoteStore &m_enote_store;
};

class ChunkConsumerMockSpIntermediate final : public scanning::ChunkConsumer
{
public:
//constructors
    /// normal constructor
    ChunkConsumerMockSpIntermediate(const rct::key &jamtis_spend_pubkey,
        const crypto::x25519_secret_key &xk_unlock_amounts,
        const crypto::x25519_secret_key &xk_find_received,
        const crypto::secret_key &s_generate_address,
        SpEnoteStorePaymentValidator &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ChunkConsumerMockSpIntermediate& operator=(ChunkConsumerMockSpIntermediate&&) = delete;

//member functions
    /// get index of first block the enote store cares about
    std::uint64_t refresh_index() const override;
    /// get index of first block the updater wants to have scanned
    std::uint64_t desired_first_block() const override;
    /// get a marker for the next block > the specified index
    scanning::ContiguityMarker get_next_block(const std::uint64_t block_index) const override;
    /// get a marker for the nearest block <= the specified index
    scanning::ContiguityMarker get_nearest_block(const std::uint64_t block_index) const override;

    /// consume a chunk of basic enote records and save the results
    void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
        const scanning::ChunkData &chunk_data) override;
    void consume_onchain_chunk(const scanning::LedgerChunk &chunk,
        const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids) override;

//member variables
private:
    const rct::key &m_jamtis_spend_pubkey;
    const crypto::x25519_secret_key &m_xk_unlock_amounts;
    const crypto::x25519_secret_key &m_xk_find_received;
    const crypto::secret_key &m_s_generate_address;
    SpEnoteStorePaymentValidator &m_enote_store;

    crypto::secret_key m_s_cipher_tag;
    std::unique_ptr<jamtis::jamtis_address_tag_cipher_context> m_cipher_context;
};

class ChunkConsumerMockSp final : public scanning::ChunkConsumer
{
public:
//constructors
    /// normal constructor
    ChunkConsumerMockSp(const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpEnoteStore &enote_store);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    ChunkConsumerMockSp& operator=(ChunkConsumerMockSp&&) = delete;

//member functions
    /// get index of first block the enote store cares about
    std::uint64_t refresh_index() const override;
    /// get index of first block the updater wants to have scanned
    std::uint64_t desired_first_block() const override;
    /// get a marker for the next block > the specified index
    scanning::ContiguityMarker get_next_block(const std::uint64_t block_index) const override;
    /// get a marker for the nearest block <= the specified index
    scanning::ContiguityMarker get_nearest_block(const std::uint64_t block_index) const override;

    /// consume a chunk of basic enote records and save the results
    void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
        const scanning::ChunkData &chunk_data) override;
    void consume_onchain_chunk(const scanning::LedgerChunk &chunk,
        const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids) override;

//member variables
private:
    const rct::key &m_jamtis_spend_pubkey;
    const crypto::secret_key &m_k_view_balance;
    SpEnoteStore &m_enote_store;

    crypto::x25519_secret_key m_xk_unlock_amounts;
    crypto::x25519_secret_key m_xk_find_received;
    crypto::secret_key m_s_generate_address;
    crypto::secret_key m_s_cipher_tag;
    std::unique_ptr<jamtis::jamtis_address_tag_cipher_context> m_cipher_context;
};

} //namespace mocks
} //namespace sp
