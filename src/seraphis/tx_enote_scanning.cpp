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
#include "ringct/rctTypes.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_enote_finding_context.h"
#include "tx_enote_scanning_context.h"
#include "tx_enote_store_updater.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

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
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: if chunk is empty, chunk represents top of current chain
    void get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out)
    {
        m_enote_scan_context.get_onchain_chunk(chunk_out);
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
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status)
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
    // 1. optional:false markers are contiguous with all blocks <= its height
    if (!marker_A.m_block_id &&
        marker_A.m_block_height + 1 >= marker_B.m_block_height + 1)
        return true;

    if (!marker_B.m_block_id &&
        marker_B.m_block_height + 1 >= marker_A.m_block_height + 1)
        return true;

    // 2. if both markers are optional:true, then heights must match
    if (marker_A.m_block_height != marker_B.m_block_height)
        return false;

    // 3. if both markers are optional:true, then block ids must match
    if (marker_A.m_block_id &&
        marker_B.m_block_id &&
        marker_A.m_block_id != marker_B.m_block_id)
        return false;

    // 4. if either marker is optional:false, its block id can match with any block id in the other marker
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_alignment_marker(const EnoteStoreUpdaterLedger &enote_store_updater,
    const std::uint64_t chunk_start_height,
    const std::vector<rct::key> &chunk_block_ids,
    ChainContiguityMarker &alignment_marker_inout)
{
    // trace through the chunk's block ids to find the heighest one that matches with the enote store's recorded block ids
    rct::key next_block_id;
    for (std::size_t block_index{0}; block_index < chunk_block_ids.size(); ++block_index)
    {
        if (!enote_store_updater.try_get_block_id(chunk_start_height + block_index, next_block_id))
            return;

        if (!(next_block_id == chunk_block_ids[block_index]))
            return;

        alignment_marker_inout.m_block_height = chunk_start_height + block_index;
        alignment_marker_inout.m_block_id = next_block_id;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh_onchain_pass(const std::uint64_t first_contiguity_height,
    EnoteScanProcessLedger &scan_process_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_inout,
    ChainContiguityMarker &contiguity_marker_inout,
    ChainContiguityMarker &alignment_marker_inout,
    std::vector<rct::key> &scanned_block_ids_inout)
{
    EnoteScanningChunkLedgerV1 new_onchain_chunk;
    scan_process_inout.get_onchain_chunk(new_onchain_chunk);

    while (new_onchain_chunk.m_end_height > new_onchain_chunk.m_start_height)
    {
        // validate chunk semantics (this should check all array bounds to prevent out-of-range accesses below)
        check_v1_enote_scan_chunk_ledger_semantics_v1(new_onchain_chunk, contiguity_marker_inout.m_block_height);

        // check if this chunk is contiguous with the contiguity marker
        if (contiguity_check(contiguity_marker_inout,
            ChainContiguityMarker{new_onchain_chunk.m_start_height - 1, new_onchain_chunk.m_prefix_block_id}))
        {
            // update alignment marker if we are aligned with the end of the previous chunk
            if (contiguity_check(alignment_marker_inout, contiguity_marker_inout))
            {
                update_alignment_marker(enote_store_updater_inout,
                    new_onchain_chunk.m_start_height,
                    new_onchain_chunk.m_block_ids,
                    alignment_marker_inout);
            }
        }
        else
        {
            // if not contiguous, then there must have been a reorg, so we need to rescan

            // note: +1 in case either height == -1
            if (contiguity_marker_inout.m_block_height + 1 <= first_contiguity_height + 1)
            {
                // a reorg that affects our first expected point of contiguity
                return ScanStatus::NEED_FULLSCAN;
            }
            else
            {
                // a reorg between chunks obtained in this loop
                return ScanStatus::NEED_PARTIALSCAN;
            }
        }

        // update contiguity marker (last block of chunk)
        contiguity_marker_inout.m_block_height = new_onchain_chunk.m_end_height - 1;
        contiguity_marker_inout.m_block_id = new_onchain_chunk.m_block_ids.back();

        // process the chunk
        enote_store_updater_inout.process_chunk(new_onchain_chunk.m_basic_records_per_tx,
            new_onchain_chunk.m_contextual_key_images);

        // add new block ids
        scanned_block_ids_inout.insert(scanned_block_ids_inout.end(),
            new_onchain_chunk.m_block_ids.begin(),
            new_onchain_chunk.m_block_ids.end());

        // get next chunk
        scan_process_inout.get_onchain_chunk(new_onchain_chunk);
    }

    // verify that the last chunk obtained, which represents the top of the current chain, matches our contiguity marker
    CHECK_AND_ASSERT_THROW_MES(new_onchain_chunk.m_block_ids.size() == 0,
        "process ledger for onchain pass: final chunk does not have zero block ids as expected.");

    // check if a reorg dropped below our contiguity marker without replacing the dropped blocks
    // note: this branch won't execute if the chain height is below our contiguity marker when our contiguity marker is
    //       optional:false, because we don't care if the chain height is lower than our scanning 'backstop' (i.e.
    //       lowest point in our enote store)
    if (!contiguity_check(contiguity_marker_inout,
        ChainContiguityMarker{new_onchain_chunk.m_end_height - 1, new_onchain_chunk.m_prefix_block_id}))
    {
        // note: +1 in case first contiguity height == -1
        if (new_onchain_chunk.m_end_height <= first_contiguity_height + 1)
        {
            // a reorg that affects our first expected point of contiguity
            return ScanStatus::NEED_FULLSCAN;
        }
        else
        {
            // a reorg between chunks obtained in this loop
            return ScanStatus::NEED_PARTIALSCAN;
        }
    }

    return ScanStatus::DONE;
}
//-------------------------------------------------------------------------------------------------------------------
// IMPORTANT: chunk processing can't be parallelized since key image checks are sequential/cumulative
// - the scan_process can internally collect chunks in parallel
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh(const std::uint64_t max_chunk_size,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_inout,
    ChainContiguityMarker &contiguity_marker_inout,
    ChainContiguityMarker &alignment_marker_inout,
    std::vector<rct::key> &scanned_block_ids_out)
{
    scanned_block_ids_out.clear();

    // set
    const std::uint64_t first_contiguity_height{contiguity_marker_inout.m_block_height};

    // create the scan process
    EnoteScanProcessLedger scan_process{first_contiguity_height + 1, max_chunk_size, scanning_context_inout};

    // on-chain main loop
    const ScanStatus scan_status_first_onchain_pass{
        process_ledger_for_full_refresh_onchain_pass(first_contiguity_height,
            scan_process,
            enote_store_updater_inout,
            contiguity_marker_inout,
            alignment_marker_inout,
            scanned_block_ids_out)
        };

    // leave early if first onchain loop didn't succeed
    if (scan_status_first_onchain_pass != ScanStatus::DONE)
        return scan_status_first_onchain_pass;

    // unconfirmed txs
    EnoteScanningChunkNonLedgerV1 unconfirmed_chunk;

    if (scan_process.try_get_unconfirmed_chunk(unconfirmed_chunk))
    {
        // process the chunk
        enote_store_updater_inout.process_chunk(unconfirmed_chunk.m_basic_records_per_tx,
            unconfirmed_chunk.m_contextual_key_images);
    }

    // on-chain follow-up pass
    // rationale:
    // - just in case blocks were added between the last chunk and the unconfirmed txs scan, and those blocks contain
    //   txs not seen when scanning unconfirmed txs (sneaky txs)
    // - want scanned enotes to be chronologically contiguous (better for the unconfirmed enotes to be stale
    //   than on-chain enotes)
    return process_ledger_for_full_refresh_onchain_pass(first_contiguity_height,
        scan_process,
        enote_store_updater_inout,
        contiguity_marker_inout,
        alignment_marker_inout,
        scanned_block_ids_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_enote_scan_chunk_ledger_semantics_v1(const EnoteScanningChunkLedgerV1 &onchain_chunk,
    const std::uint64_t expected_prefix_height)
{
    // misc. checks
    CHECK_AND_ASSERT_THROW_MES(onchain_chunk.m_start_height - 1 == expected_prefix_height,
        "enote scan chunk semantics check (ledger): chunk range doesn't start at expected prefix height.");

    const std::uint64_t num_blocks_in_chunk{onchain_chunk.m_end_height - onchain_chunk.m_start_height};
    CHECK_AND_ASSERT_THROW_MES(num_blocks_in_chunk >= 1,
        "enote scan chunk semantics check (ledger): chunk has no blocks.");    
    CHECK_AND_ASSERT_THROW_MES(onchain_chunk.m_block_ids.size() == num_blocks_in_chunk,
        "enote scan chunk semantics check (ledger): unexpected number of block ids.");

    check_enote_scan_chunk_map_semantics_v1(onchain_chunk.m_basic_records_per_tx,
        onchain_chunk.m_contextual_key_images,
        SpEnoteOriginStatus::ONCHAIN,
        SpEnoteSpentStatus::SPENT_ONCHAIN);

    // start block = prefix block + 1
    const std::uint64_t allowed_lowest_height{onchain_chunk.m_start_height};
    // end block
    const std::uint64_t allowed_heighest_height{onchain_chunk.m_end_height - 1};

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
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status)
{
    check_enote_scan_chunk_map_semantics_v1(nonledger_chunk.m_basic_records_per_tx,
        nonledger_chunk.m_contextual_key_images,
        expected_origin_status,
        expected_spent_status);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_inout)
{
    // we want to scan the first block after the last block that we scanned
    std::uint64_t desired_first_block{enote_store_updater_inout.get_top_block_height() + 1};

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

        CHECK_AND_ASSERT_THROW_MES(fullscan_attempts < 50,
            "refresh ledger for enote store: fullscan attempts exceeded 50 (sanity check fail).");

        // 2. fail if we have exceeded the number of partial scanning attempts (i.e. for handling partial reorgs)
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
            [&]() -> std::uint64_t
            {
                // test '> 1' to support unit tests with reorg avoidance depth == 0 (e.g. for exercising partial scans)
                if (fullscan_attempts > 1)
                {
                    CHECK_AND_ASSERT_THROW_MES(config.m_reorg_avoidance_depth > 0,
                        "refresh ledger for enote store: tried more than one fullscan with zero reorg avoidance depth.");
                    return static_cast<uint64_t>(std::pow(10, fullscan_attempts - 1) * config.m_reorg_avoidance_depth);
                }

                return config.m_reorg_avoidance_depth;
            }();

        // 4. initial block to scan = max(desired first block - reorg depth, enote store's min scan height)
        std::uint64_t initial_refresh_height;

        if (desired_first_block >= reorg_avoidance_depth + enote_store_updater_inout.get_refresh_height())
            initial_refresh_height = desired_first_block - reorg_avoidance_depth;
        else
            initial_refresh_height = enote_store_updater_inout.get_refresh_height();

        // 5. set initial contiguity marker (highest block known to be contiguous with the prefix of the first block to scan)
        ChainContiguityMarker contiguity_marker;
        contiguity_marker.m_block_height = initial_refresh_height - 1;

        if (contiguity_marker.m_block_height != enote_store_updater_inout.get_refresh_height() - 1)
        {
            // getting a block id should always succeed if we are starting past the prefix block of the enote store
            contiguity_marker.m_block_id = rct::zero();
            CHECK_AND_ASSERT_THROW_MES(enote_store_updater_inout.try_get_block_id(initial_refresh_height - 1,
                    *(contiguity_marker.m_block_id)),
                "refresh ledger for enote store: could not get block id for start of scanning but a block id was "
                "expected (bug).");
        }

        // 6. set initial alignment marker (the heighest scanned block that matches with our current enote store's recorded
        //   block ids)
        ChainContiguityMarker alignment_marker{contiguity_marker};


        /// scan
        // 1. process the ledger
        enote_store_updater_inout.start_chunk_handling_session();
        std::vector<rct::key> scanned_block_ids;

        scan_status = process_ledger_for_full_refresh(config.m_max_chunk_size,
            scanning_context_inout,
            enote_store_updater_inout,
            contiguity_marker,
            alignment_marker,
            scanned_block_ids);

        // 2. update desired start height for if there needs to be another scan attempt
        desired_first_block = contiguity_marker.m_block_height + 1;


        /// check scan status
        // 1. give up if scanning failed
        if (scan_status == ScanStatus::FAIL)
            break;

        // 2. if we must do a full scan, go back to the top immediately (all data from this loop will be overwritten)
        if (scan_status == ScanStatus::NEED_FULLSCAN)
            continue;


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
        enote_store_updater_inout.end_chunk_handling_session(alignment_marker.m_block_height + 1,
            alignment_marker.m_block_id ? *(alignment_marker.m_block_id) : rct::zero(),
            scanned_block_ids_cropped);
    }

    CHECK_AND_ASSERT_THROW_MES(scan_status == ScanStatus::DONE, "refresh ledger for enote store: refreshing failed!");
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_offchain(const EnoteFindingContextOffchain &enote_finding_context,
    EnoteStoreUpdaterNonLedger &enote_store_updater_inout)
{
    // get a scan chunk and process it
    EnoteScanningChunkNonLedgerV1 offchain_chunk;

    if (enote_finding_context.try_get_offchain_chunk(offchain_chunk))
    {
        // validate chunk semantics (consistent vector sizes, block heights in contexts are within range)
        check_v1_enote_scan_chunk_nonledger_semantics_v1(offchain_chunk,
            SpEnoteOriginStatus::OFFCHAIN,
            SpEnoteSpentStatus::SPENT_OFFCHAIN);

        // process and handle the chunk
        enote_store_updater_inout.process_and_handle_chunk(offchain_chunk.m_basic_records_per_tx,
            offchain_chunk.m_contextual_key_images);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_full(const RefreshLedgerEnoteStoreConfig &ledger_refresh_config,
    const EnoteFindingContextOffchain &enote_finding_context,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdaterLedger &enote_store_updater_ledger_inout,
    EnoteStoreUpdaterNonLedger &enote_store_updater_nonledger_inout)
{
    refresh_enote_store_ledger(ledger_refresh_config,
        scanning_context_inout,
        enote_store_updater_ledger_inout);
    refresh_enote_store_offchain(enote_finding_context, enote_store_updater_nonledger_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
