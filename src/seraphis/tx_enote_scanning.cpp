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

//paired header
#include "tx_enote_scanning.h"

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "jamtis_core_utils.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_enote_finding_context.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_enote_scanning_context.h"
#include "tx_enote_store.h"

//third party headers

//standard headers
#include <algorithm>
#include <list>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

////
// EnoteScanProcessLedger
// - raii wrapper on a EnoteScanningContextLedger for a specific scanning process (begin ... terminate)
///
class EnoteScanProcessLedger final
{
public:
//constructors
    /// normal constructor
    EnoteScanProcessLedger(const std::uint64_t initial_start_height,
        const std::uint64_t max_chunk_size,
        EnoteScanningContextLedger &enote_scan_context) :
        m_enote_scan_context{enote_scan_context}
    {
        m_enote_scan_context.begin_scanning_from_height(initial_start_height, max_chunk_size);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanProcessLedger& operator=(EnoteScanProcessLedger&&) = delete;

//destructor
    ~EnoteScanProcessLedger()
    {
        try { m_enote_scan_context.terminate_scanning(); }
        catch (...) { /* todo: log error */ }
    }

//member functions
    /// try to get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    bool try_get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out)
    {
        return m_enote_scan_context.try_get_onchain_chunk(chunk_out);
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out)
    {
        return m_enote_scan_context.try_get_unconfirmed_chunk(chunk_out);
    }

//member variables
private:
    /// reference to an enote finding context
    EnoteScanningContextLedger &m_enote_scan_context;
};

enum class ScanStatus
{
    NEED_FULLSCAN,
    NEED_PARTIALSCAN,
    DONE,
    FAIL
};

struct ChainContiguityMarker final
{
    /// height of the block
    std::uint64_t m_block_height;
    /// id of the block (optional)
    boost::optional<rct::key> m_block_id;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_enote_scan_chunk_map_semantics_v1(
    const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    const SpEnoteOriginContextV1::OriginStatus expected_origin_status,
    const SpEnoteSpentContextV1::SpentStatus expected_spent_status)
{
    // 1. contextual key images
    for (const auto &contextual_key_image_set : chunk_contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(contextual_key_image_set.m_spent_context.m_spent_status == expected_spent_status,
            "enote chunk semantics check: contextual key image doesn't have expected spent status.");

        // notes:
        // - a scan chunk is expected to contain basic enote records mapped to txs, along with all the key images for each
        //   of those txs
        // - basic enote records are view tag matches, so only txs with view tag matches will normally be represented
        // - the standard tx-building convention puts a self-send in all txs so the enote scanning process will pick up
        //   all key images of the user in scan chunks (assuming chunks only have key images for txs with view tag matches)
        // - if someone makes a tx with no self-sends, then chunk scanning won't reliably pick up that tx's key images
        //   unless the chunk builder returns an empty basic records list for any tx that has no view tag matches (i.e. so
        //   the chunk builder will return key images from ALL txs)
        //   - this is not supported by default for efficiency and simplicity
        CHECK_AND_ASSERT_THROW_MES(
                chunk_basic_records_per_tx.find(contextual_key_image_set.m_spent_context.m_transaction_id) !=
                chunk_basic_records_per_tx.end(),
            "enote chunk semantics check: contextual key image transaction id is not mirrored in basic records map.");
    }

    // 2. contextual basic records
    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record : tx_basic_records.second)
        {
            CHECK_AND_ASSERT_THROW_MES(contextual_basic_record.m_origin_context.m_origin_status == expected_origin_status,
                "enote chunk semantics check: contextual basic record doesn't have expected origin status.");
            CHECK_AND_ASSERT_THROW_MES(contextual_basic_record.m_origin_context.m_transaction_id == tx_basic_records.first,
                "enote chunk semantics check: contextual basic record doesn't have origin tx id matching mapped id.");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool contiguity_check(const ChainContiguityMarker &marker_A, const ChainContiguityMarker &marker_B)
{
    if (marker_A.m_block_height != marker_B.m_block_height)
        return false;

    if (marker_A.m_block_id &&
        marker_B.m_block_id &&
        marker_A.m_block_id != marker_B.m_block_id)
        return false;

    // note: optional:false contiguitity block ids can match with any block id

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_alignment_marker(const SpEnoteStoreV1 &enote_store,
    const std::uint64_t chunk_start_height,
    const std::vector<rct::key> &chunk_block_ids,
    ChainContiguityMarker &alignment_marker_inout)
{
    // trace through the chunk's block ids to find the heighest one that matches with the enote store's recorded block ids
    rct::key next_block_id;
    for (std::size_t block_index{0}; block_index < chunk_block_ids.size(); ++block_index)
    {
        if (!enote_store.try_get_block_id(chunk_start_height + block_index, next_block_id))
            return;

        if (!(next_block_id == chunk_block_ids[block_index]))
            return;

        alignment_marker_inout.m_block_height = chunk_start_height + block_index;
        alignment_marker_inout.m_block_id = next_block_id;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_record_update(const SpEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_set<rct::key> &txs_have_spent_enotes_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const crypto::key_image new_record_key_image{new_enote_record.m_key_image};

    found_enote_records_inout[new_record_key_image].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    SpEnoteSpentContextV1 spent_context_update{};

    auto record_is_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.has_key_image(new_record_key_image);
            }
        );

    if (record_is_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(record_is_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];

        // d. save the tx id of the tx where this enote was spent
        txs_have_spent_enotes_inout.insert(spent_context_update.m_transaction_id);
    }

    // 3. update the contextual enote record's contexts
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_key_image]);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const SpEnoteStoreV1 &enote_store,
    const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    std::unordered_set<rct::key> txs_have_spent_enotes;

    // 1. check if any owned enotes have been spent in this chunk (key image matches)
    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.m_key_images)
        {
            // a. check enote store
            // b. check enote records found before this chunk (but not updated in enote store)
            if (enote_store.has_enote_with_key_image(key_image) ||
                found_enote_records_inout.find(key_image) != found_enote_records_inout.end())
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(contextual_key_image_set.m_spent_context,
                    found_spent_key_images_inout[key_image]);

                // record tx id of tx that contains one of our key images (i.e. the tx spent one of our known enotes)
                txs_have_spent_enotes.insert(contextual_key_image_set.m_spent_context.m_transaction_id);
            }
        }
    }

    // 2. check for owned enotes in this chunk (non-self-send pass)
    SpEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record : tx_basic_records.second)
        {
            if (try_get_enote_record_v1_plain(contextual_basic_record.m_record,
                wallet_spend_pubkey,
                k_view_balance,
                k_unlock_amounts,
                k_find_received,
                s_generate_address,
                cipher_context,
                new_enote_record))
            {
                process_chunk_new_record_update(new_enote_record,
                    contextual_basic_record.m_origin_context,
                    chunk_contextual_key_images,
                    found_enote_records_inout,
                    found_spent_key_images_inout,
                    txs_have_spent_enotes);
            }
        }
    }

    // 3. check for owned enotes in this chunk (self-send passes)
    // - for each tx in this chunk that spends one of our enotes, check if any of the basic records attached to that
    //   tx contains a self-send enote owned by us
    // - loop in case any self-send enotes acquired in this chunk are also spent in this chunk
    std::unordered_set<rct::key> txs_have_spent_enotes_selfsend_passthrough;

    while (txs_have_spent_enotes.size() > 0)
    {
        for (const rct::key &tx_with_spent_enotes : txs_have_spent_enotes)
        {
            // note: this should never throw since it should be caught in the chunk semantics check
            CHECK_AND_ASSERT_THROW_MES(chunk_basic_records_per_tx.find(tx_with_spent_enotes) !=
                    chunk_basic_records_per_tx.end(),
                "enote scan process chunk (self-send passthroughs): tx with spent enotes not found in records map (bug).");

            for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record :
                chunk_basic_records_per_tx.at(tx_with_spent_enotes))
            {
                if (try_get_enote_record_v1_selfsend(contextual_basic_record.m_record.m_enote,
                    contextual_basic_record.m_record.m_enote_ephemeral_pubkey,
                    contextual_basic_record.m_record.m_input_context,
                    wallet_spend_pubkey,
                    k_view_balance,
                    s_generate_address,
                    new_enote_record))
                {
                    process_chunk_new_record_update(new_enote_record,
                        contextual_basic_record.m_origin_context,
                        chunk_contextual_key_images,
                        found_enote_records_inout,
                        found_spent_key_images_inout,
                        txs_have_spent_enotes_selfsend_passthrough);
                }
            }
        }

        txs_have_spent_enotes = std::move(txs_have_spent_enotes_selfsend_passthrough);
        txs_have_spent_enotes_selfsend_passthrough.clear();
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh_onchain_pass(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const SpEnoteStoreV1 &enote_store,
    const std::uint64_t first_contiguity_height,
    EnoteScanProcessLedger &scan_process_inout,
    ChainContiguityMarker &contiguity_marker_inout,
    ChainContiguityMarker &alignment_marker_inout,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::vector<rct::key> &scanned_block_ids_inout)
{
    EnoteScanningChunkLedgerV1 new_onchain_chunk;

    while (scan_process_inout.try_get_onchain_chunk(new_onchain_chunk))
    {
        // validate chunk semantics (this should check all array bounds to prevent out-of-range accesses below)
        check_v1_enote_scan_chunk_ledger_semantics_v1(new_onchain_chunk, contiguity_marker_inout.m_block_height);

        // check if this chunk is contiguous with the contiguity marker
        if (contiguity_check(contiguity_marker_inout,
            ChainContiguityMarker{std::get<0>(new_onchain_chunk.m_block_range) - 1, new_onchain_chunk.m_prefix_block_id}))
        {
            // update alignment marker if we are aligned with the end of the previous chunk
            if (contiguity_check(alignment_marker_inout, contiguity_marker_inout))
            {
                update_alignment_marker(enote_store,
                    std::get<0>(new_onchain_chunk.m_block_range),
                    new_onchain_chunk.m_block_ids,
                    alignment_marker_inout);
            }
        }
        else
        {
            // if not contiguous, then there must have been a reorg, so we need to rescan
            // note: check the contiguity marker here NOT alignment marker, because we could be aligned only
            //       at the very first marker but contiguous to farther up the chain
            if (contiguity_marker_inout.m_block_height <= first_contiguity_height)
                // a reorg deeper than our first expected point of contiguity
                return ScanStatus::NEED_FULLSCAN;
            else
                // a reorg between chunks obtained in this loop
                return ScanStatus::NEED_PARTIALSCAN;
        }

        // update contiguity marker (last block of chunk)
        contiguity_marker_inout.m_block_height = std::get<1>(new_onchain_chunk.m_block_range);
        contiguity_marker_inout.m_block_id = new_onchain_chunk.m_block_ids.back();

        // process the chunk (update found enote records and spent key images)
        process_chunk(wallet_spend_pubkey,
            k_view_balance,
            k_unlock_amounts,
            k_find_received,
            s_generate_address,
            cipher_context,
            enote_store,
            new_onchain_chunk.m_basic_records_per_tx,
            new_onchain_chunk.m_contextual_key_images,
            found_enote_records_inout,
            found_spent_key_images_inout);

        // add new block ids
        scanned_block_ids_inout.insert(scanned_block_ids_inout.end(),
            new_onchain_chunk.m_block_ids.begin(),
            new_onchain_chunk.m_block_ids.end());
    }

    return ScanStatus::DONE;
}
//-------------------------------------------------------------------------------------------------------------------
// IMPORTANT: chunk processing can't be parallelized since key image checks are sequential/cumulative
// - the scan_process can internally collect chunks in parallel
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::uint64_t max_chunk_size,
    const SpEnoteStoreV1 &enote_store,
    EnoteScanningContextLedger &scanning_context_inout,
    ChainContiguityMarker &contiguity_marker_inout,
    ChainContiguityMarker &alignment_marker_inout,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out,
    std::vector<rct::key> &scanned_block_ids_out)
{
    found_enote_records_out.clear();
    found_spent_key_images_out.clear();
    scanned_block_ids_out.clear();

    // prepare for chunk processing
    crypto::secret_key k_unlock_amounts;
    crypto::secret_key k_find_received;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_unlockamounts_key(k_view_balance, k_unlock_amounts);
    jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

    // set
    const std::uint64_t first_contiguity_height{contiguity_marker_inout.m_block_height};

    // create the scan process
    EnoteScanProcessLedger scan_process{first_contiguity_height + 1, max_chunk_size, scanning_context_inout};

    // on-chain main loop
    const ScanStatus scan_status_first_onchain_pass{
        process_ledger_for_full_refresh_onchain_pass(wallet_spend_pubkey,
            k_view_balance,
            k_unlock_amounts,
            k_find_received,
            s_generate_address,
            cipher_context,
            enote_store,
            first_contiguity_height,
            scan_process,
            contiguity_marker_inout,
            alignment_marker_inout,
            found_enote_records_out,
            found_spent_key_images_out,
            scanned_block_ids_out)
        };

    if (scan_status_first_onchain_pass != ScanStatus::DONE)
        return scan_status_first_onchain_pass;

    // unconfirmed txs
    EnoteScanningChunkNonLedgerV1 unconfirmed_chunk;

    if (scan_process.try_get_unconfirmed_chunk(unconfirmed_chunk))
    {
        // process the chunk (update found enote records and spent key images)
        process_chunk(wallet_spend_pubkey,
            k_view_balance,
            k_unlock_amounts,
            k_find_received,
            s_generate_address,
            cipher_context,
            enote_store,
            unconfirmed_chunk.m_basic_records_per_tx,
            unconfirmed_chunk.m_contextual_key_images,
            found_enote_records_out,
            found_spent_key_images_out);
    }

    // on-chain follow-up pass
    // rationale:
    // - just in case blocks were added between the last chunk and the unconfirmed txs scan, and those blocks contain
    //   txs not seen when scanning unconfirmed txs (sneaky txs)
    // - want scanned enotes to be chronologically contiguous (better for the unconfirmed enotes to be stale
    //   than on-chain enotes)
    return process_ledger_for_full_refresh_onchain_pass(wallet_spend_pubkey,
        k_view_balance,
        k_unlock_amounts,
        k_find_received,
        s_generate_address,
        cipher_context,
        enote_store,
        first_contiguity_height,
        scan_process,
        contiguity_marker_inout,
        alignment_marker_inout,
        found_enote_records_out,
        found_spent_key_images_out,
        scanned_block_ids_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_enote_scan_chunk_ledger_semantics_v1(const EnoteScanningChunkLedgerV1 &onchain_chunk,
    const std::uint64_t expected_prefix_height)
{
    // misc. checks
    CHECK_AND_ASSERT_THROW_MES(std::get<0>(onchain_chunk.m_block_range) - 1 == expected_prefix_height,
        "enote scan chunk semantics check (ledger): chunk range doesn't start at expected prefix height.");

    const std::uint64_t num_blocks_in_chunk{
            std::get<1>(onchain_chunk.m_block_range) - std::get<0>(onchain_chunk.m_block_range) + 1
        };
    CHECK_AND_ASSERT_THROW_MES(num_blocks_in_chunk >= 1,
        "enote scan chunk semantics check (ledger): chunk has no blocks.");    
    CHECK_AND_ASSERT_THROW_MES(onchain_chunk.m_block_ids.size() == num_blocks_in_chunk,
        "enote scan chunk semantics check (ledger): unexpected number of block ids.");

    check_enote_scan_chunk_map_semantics_v1(onchain_chunk.m_basic_records_per_tx,
        onchain_chunk.m_contextual_key_images,
        SpEnoteOriginContextV1::OriginStatus::ONCHAIN,
        SpEnoteSpentContextV1::SpentStatus::SPENT_ONCHAIN);

    // start block = prefix block + 1
    const std::uint64_t allowed_lowest_height{std::get<0>(onchain_chunk.m_block_range)};
    // end block
    const std::uint64_t allowed_heighest_height{std::get<1>(onchain_chunk.m_block_range)};

    // contextual key images: height checks
    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : onchain_chunk.m_contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(contextual_key_image_set.m_spent_context.m_block_height >=
                    allowed_lowest_height &&
                contextual_key_image_set.m_spent_context.m_block_height <= allowed_heighest_height,
            "enote chunk semantics check (ledger): contextual key image block height is out of the expected range.");
    }

    // contextual basic records: height checks
    for (const auto &tx_basic_records : onchain_chunk.m_basic_records_per_tx)
    {
        for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record : tx_basic_records.second)
        {
            CHECK_AND_ASSERT_THROW_MES(
                    contextual_basic_record.m_origin_context.m_block_height ==
                        tx_basic_records.second.begin()->m_origin_context.m_block_height,
                "enote chunk semantics check (ledger): contextual record tx height doesn't match other records in tx.");

            CHECK_AND_ASSERT_THROW_MES(
                    contextual_basic_record.m_origin_context.m_block_height >= allowed_lowest_height &&
                    contextual_basic_record.m_origin_context.m_block_height <= allowed_heighest_height,
                "enote chunk semantics check (ledger): contextual key image block height is out of the expected range.");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_enote_scan_chunk_nonledger_semantics_v1(const EnoteScanningChunkNonLedgerV1 &nonledger_chunk,
    const SpEnoteOriginContextV1::OriginStatus expected_origin_status,
    const SpEnoteSpentContextV1::SpentStatus expected_spent_status)
{
    check_enote_scan_chunk_map_semantics_v1(nonledger_chunk.m_basic_records_per_tx,
        nonledger_chunk.m_contextual_key_images,
        expected_origin_status,
        expected_spent_status);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_find_enotes_in_tx(const crypto::secret_key &k_find_received,
    const std::uint64_t block_height,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &enotes_in_tx,
    const SpEnoteOriginContextV1::OriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &basic_records_per_tx_inout)
{
    if (tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::key_derivation temp_DH_derivation;
    std::list<SpContextualBasicEnoteRecordV1> temp_contextual_record;
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // there can be fewer ephemeral pubkeys than enotes
        // - when we get to the end, keep using the last one
        if (enote_index < tx_supplement.m_output_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            hwdev.generate_key_derivation(
                rct::rct2pk(tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index]),
                k_find_received,
                temp_DH_derivation);
        }

        // prepare record shuttle
        if (temp_contextual_record.size() == 0)
            temp_contextual_record.emplace_back();

        // find-receive scan the enote
        if (try_get_basic_enote_record_v1(enotes_in_tx[enote_index],
            tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
            input_context,
            temp_DH_derivation,
            temp_contextual_record.back().m_record))
        {
            temp_contextual_record.back().m_origin_context =
                SpEnoteOriginContextV1{
                        .m_block_height = block_height,
                        .m_transaction_id = transaction_id,
                        .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                        .m_origin_status = origin_status,
                        .m_memo = tx_supplement.m_tx_extra
                    };

            // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
            //       upstream caller will be able to handle that case without problems
            auto &basic_records_for_tx = basic_records_per_tx_inout[transaction_id];
            basic_records_for_tx.splice(basic_records_for_tx.end(),
                temp_contextual_record,
                temp_contextual_record.begin());

            found_an_enote = true;
        }
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
void collect_key_images_from_tx(const std::uint64_t block_height,
    const rct::key &transaction_id,
    const std::vector<crypto::key_image> &key_images_in_tx,
    const SpEnoteSpentContextV1::SpentStatus spent_status,
    std::list<SpContextualKeyImageSetV1> &contextual_key_images_inout)
{
    contextual_key_images_inout.emplace_back(
            SpContextualKeyImageSetV1{
                .m_key_images = key_images_in_tx,
                .m_spent_context =
                    SpEnoteSpentContextV1{
                        .m_block_height = block_height,
                        .m_transaction_id = transaction_id,
                        .m_spent_status = spent_status
                    }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    EnoteScanningContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout)
{
    // we want to scan the first block after the last block that we scanned
    std::uint64_t desired_first_block{enote_store_inout.get_top_block_height() + 1};

    // scan attempts
    ScanStatus scan_status{ScanStatus::NEED_FULLSCAN};
    std::size_t partialscan_attempts{0};
    std::size_t fullscan_attempts{0};

    while (scan_status == ScanStatus::NEED_PARTIALSCAN ||
        scan_status == ScanStatus::NEED_FULLSCAN)
    {
        /// initialization based on scan status

        // 1. update scan attempt
        if (scan_status == ScanStatus::NEED_PARTIALSCAN)
            ++partialscan_attempts;
        else if (scan_status == ScanStatus::NEED_FULLSCAN)
            ++fullscan_attempts;

        // 2. fail if we have exceeded the number of partial scanning attempts (i.e. for partial reorgs)
        if (partialscan_attempts > config.m_max_partialscan_attempts)
        {
            scan_status = ScanStatus::FAIL;
            break;
        }

        // 3. set reorg avoidance
        // note: we use an exponential back-off as a function of fullscan attempts because if a fullscan fails then
        //       the true location of alignment divergence is unknown; moreover, the distance between the first
        //       desired start height and the enote store's minimum height may be very large; if a fixed back-off were used,
        //       then it could take many fullscan attempts to find the point of divergence
        const std::uint64_t reorg_avoidance_depth =
            fullscan_attempts > 0
            ? static_cast<uint64_t>(std::pow(10, fullscan_attempts - 1) * config.m_reorg_avoidance_depth)
            : config.m_reorg_avoidance_depth;

        // 4. initial block to scan = max(desired first block - reorg depth, enote store's min scan height)
        std::uint64_t initial_refresh_height;

        if (desired_first_block >= reorg_avoidance_depth + enote_store_inout.get_refresh_height())
            initial_refresh_height = desired_first_block - reorg_avoidance_depth;
        else
            initial_refresh_height = enote_store_inout.get_refresh_height();

        // 5. set initial contiguity marker (highest block known to be contiguous with the prefix of the first block to scan)
        ChainContiguityMarker contiguity_marker;
        contiguity_marker.m_block_height = initial_refresh_height - 1;

        if (contiguity_marker.m_block_height != enote_store_inout.get_refresh_height() - 1)
        {
            // getting a block id should always succeed if we are starting past the prefix block of the enote store
            contiguity_marker.m_block_id = rct::zero();
            CHECK_AND_ASSERT_THROW_MES(enote_store_inout.try_get_block_id(initial_refresh_height - 1,
                    *(contiguity_marker.m_block_id)),
                "refresh ledger for enote store: could not get block id for start of scanning but a block id was "
                "expected (bug).");
        }

        // 6. set initial alignment marker (the heighest scanned block that matches with our current enote store's recorded
        //   block ids)
        ChainContiguityMarker alignment_marker{contiguity_marker};


        /// scan
        // 1. process the ledger
        std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> found_enote_records;
        std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

        std::vector<rct::key> scanned_block_ids;

        scan_status = process_ledger_for_full_refresh(wallet_spend_pubkey,
            k_view_balance,
            config.m_max_chunk_size,
            enote_store_inout,
            scanning_context_inout,
            contiguity_marker,
            alignment_marker,
            found_enote_records,
            found_spent_key_images,
            scanned_block_ids);

        // 2. update desired start height for if there needs to be another scan attempt
        desired_first_block = contiguity_marker.m_block_height + 1;


        /// check scan status
        // 1. give up if scanning failed
        if (scan_status == ScanStatus::FAIL)
            break;

        // 2. if we need to do a full scan, go back to the top immediately
        if (scan_status == ScanStatus::NEED_FULLSCAN)
        {
            // . bug: if we need to fullscan and the initial refresh height of this scan was at the enote store's min height
            // note: this is a bug because when starting at the min block height, the initial contiguity marker should be
            //       optional:false, which permits contiguity with any value of the first chunk's prefix block (so there
            //       should not be a full-scan-inducing contiguity failure)
            CHECK_AND_ASSERT_THROW_MES(initial_refresh_height > enote_store_inout.get_refresh_height(),
                "refresh ledger for enote store: need to fullscan but previous scan exceeded enote store's range (bug).");

            continue;
        }


        /// refresh the enote store with new ledger context

        // 1. sanity checks
        CHECK_AND_ASSERT_THROW_MES(initial_refresh_height <= alignment_marker.m_block_height + 1,
            "refresh ledger for enote store: initial refresh height exceeds the post-alignment block (bug).");
        CHECK_AND_ASSERT_THROW_MES(alignment_marker.m_block_height + 1 - initial_refresh_height <=
                scanned_block_ids.size(),
            "refresh ledger for enote store: contiguous block ids have fewer blocks than the alignment range (bug).");

        // 2. crop block ids we don't care about
        const std::vector<rct::key> scanned_block_ids_cropped{
                scanned_block_ids.data() + alignment_marker.m_block_height + 1 - initial_refresh_height,
                scanned_block_ids.data() + scanned_block_ids.size()
            };

        // 3. update the enote store
        enote_store_inout.update_with_records_from_ledger(alignment_marker.m_block_height + 1,
            alignment_marker.m_block_id ? *(alignment_marker.m_block_id) : rct::zero(),
            found_enote_records,
            found_spent_key_images,
            scanned_block_ids_cropped);
    }

    CHECK_AND_ASSERT_THROW_MES(scan_status == ScanStatus::DONE, "refresh ledger for enote store: refreshing failed!");
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_offchain(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    SpEnoteStoreV1 &enote_store_inout)
{
    // 1. get a scan chunk and process it
    EnoteScanningChunkNonLedgerV1 offchain_chunk;
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> found_enote_records;
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> found_spent_key_images;

    if (enote_finding_context.try_get_offchain_chunk(offchain_chunk))
    {
        // validate chunk semantics (consistent vector sizes, block heights in contexts are within range)
        check_v1_enote_scan_chunk_nonledger_semantics_v1(offchain_chunk,
            SpEnoteOriginContextV1::OriginStatus::OFFCHAIN,
            SpEnoteSpentContextV1::SpentStatus::SPENT_OFFCHAIN);

        // prepare for chunk processing
        crypto::secret_key k_unlock_amounts;
        crypto::secret_key k_find_received;
        crypto::secret_key s_generate_address;
        crypto::secret_key s_cipher_tag;
        jamtis::make_jamtis_unlockamounts_key(k_view_balance, k_unlock_amounts);
        jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);
        jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
        jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

        const jamtis::jamtis_address_tag_cipher_context cipher_context{rct::sk2rct(s_cipher_tag)};

        // process the chunk
        process_chunk(wallet_spend_pubkey,
            k_view_balance,
            k_unlock_amounts,
            k_find_received,
            s_generate_address,
            cipher_context,
            enote_store_inout,
            offchain_chunk.m_basic_records_per_tx,
            offchain_chunk.m_contextual_key_images,
            found_enote_records,
            found_spent_key_images);
    }

    // 2. refresh the enote store with new offchain context
    enote_store_inout.update_with_records_from_offchain(found_enote_records, found_spent_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_full(const RefreshLedgerEnoteStoreConfig &ledger_refresh_config,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const EnoteFindingContextOffchain &enote_finding_context,
    EnoteScanningContextLedger &scanning_context_inout,
    SpEnoteStoreV1 &enote_store_inout)
{
    refresh_enote_store_ledger(ledger_refresh_config,
        wallet_spend_pubkey,
        k_view_balance,
        scanning_context_inout,
        enote_store_inout);
    refresh_enote_store_offchain(wallet_spend_pubkey, k_view_balance, enote_finding_context, enote_store_inout);
}
//-------------------------------------------------------------------------------------------------------------------

/*
- scanning
    - EnoteScanChunkProcessingContext: manages user keys + enote store context + processed chunks
        - encapsulate processing to facilitate full-view wallet vs payment validator distinction
*/

} //namespace sp
