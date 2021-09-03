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

// Tool for supporting a legacy key image import cycle.
// PROCESS:
// 1. update your enote store with a legacy intermediate view scan in SCAN MODE
// 2. TOOL: make an import cycle checkpoint with an atomic read-lock on your enote store
// 3. obtain key images for the intermediate records stored in the checkpoint
//    - no invariants will be broken if only some of the key images are obtained, however that may cause the enote
//      store to have an intermediate legacy balance that is higher than expected after the cycle
// 4. TOOL: import the key images to your enote store
// 5. update your enote store with a legacy intermediate view scan in KEY IMAGES ONLY MODE
//    - this is needed to see if any of the imported key images exist on-chain
// 6. TOOL: finish the import cycle with an atomic write-lock on your enote store
//    - do this AFTER the key-images-only scan, otherwise subsequent import cycles will waste time re-doing the blocks
//      from this import cycle
// WARNING: this process will be less efficient if you do step 2, wait a while, do step 1 again, then finish 3-6; the
//    reason is alignment tracking relies on block id checkpoints, and step 1 will 'thin out' older block id checkpoints
//    in the enote store, making it possible for bad alignment checks when finalizing an import cycle; the end effect
//    will be the next import cycle will redo some blocks from the previous cycle

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_event_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers

//forward declarations
#include <list>
#include <map>
#include <unordered_map>

namespace sp
{

////
// LegacyKIImportCheckpoint
// - A snapshot of an enote store for use in a legacy key image import cycle.
///
struct LegacyKIImportCheckpoint final
{
    /// [ block index : block id ] in the range of blocks subject to this import cycle
    std::map<std::uint64_t, rct::key> block_id_checkpoints;
    /// [ legacy identifier : legacy intermediate records ] for legacy enotes subject to this import cycle
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> legacy_intermediate_records;
};

/**
* brief: make_legacy_ki_import_checkpoint - make a legacy key image import cycle checkpoint
* param: enote_store -
* outparam: checkpoint_out -
*/
void make_legacy_ki_import_checkpoint(const SpEnoteStore &enote_store, LegacyKIImportCheckpoint &checkpoint_out);
/**
* brief: import_legacy_key_images - import legacy key images to an enote store
* param: legacy_key_images - [ Ko : KI ]
* inoutparam: enote_store_inout -
*/
void import_legacy_key_images(const std::unordered_map<rct::key, crypto::key_image> &legacy_key_images,
    SpEnoteStore &enote_store_inout,
    std::list<EnoteStoreEvent> &update_events_out);
void import_legacy_key_images(const std::unordered_map<crypto::public_key, crypto::key_image> &legacy_key_images,
    SpEnoteStore &enote_store_inout,
    std::list<EnoteStoreEvent> &update_events_out);
/**
* brief: finish_legacy_ki_import_cycle - finish a legacy key image import cycle by updating the enote store's
*    cached fullscan index
* param: checkpoint -
* inoutparam: enote_store_inout -
*/
void finish_legacy_ki_import_cycle(const LegacyKIImportCheckpoint &checkpoint, SpEnoteStore &enote_store_inout);

} //namespace sp
