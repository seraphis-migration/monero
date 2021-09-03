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

// Helper types for the scan state machine.

#pragma once

//local headers
#include "common/variant.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers

//forward declarations


namespace sp
{
namespace scanning
{

////
// ContiguityMarker
// - marks the end of a contiguous chain of blocks
// - if the contiguous chain is empty, then the block id will be unspecified and the block index will equal the chain's
//   initial index minus one
// - a 'contiguous chain' does not have to start at 'block 0', it can start at any predefined block index where you
//   want to start tracking contiguity
// - example: if your refresh index is 'block 101' and you haven't loaded/scanned any blocks, then your initial
//   contiguity marker will start at 'block 100' with an unspecified block id; if you scanned blocks [101, 120], then
//   your contiguity marker will be at block 120 with that block's block id
///
struct ContiguityMarker final
{
    /// index of the block
    std::uint64_t block_index;
    /// id of the block (optional)
    boost::optional<rct::key> block_id;
};

////
// ScanMachineConfig
// - configuration details for the scan state machine
///
struct ScanMachineConfig final
{
    /// increment for avoiding reorgs
    /// - each fullscan attempt looks (10^attempts * increment) blocks below the requested start index
    std::uint64_t reorg_avoidance_increment{10};
    /// max number of blocks per ledger chunk
    /// - this is only a hint, the downstream scanning context is free to ignore it
    std::uint64_t max_chunk_size_hint{100};
    /// maximum number of times to try rescanning if a partial reorg is detected
    std::uint64_t max_partialscan_attempts{3};
};

////
// ScanMachineMetadata
// - metadata for the scan state machine
///
struct ScanMachineMetadata final
{
    /// config details for the machine
    ScanMachineConfig config;

    /// attempt counters: track history of the machine
    std::size_t partialscan_attempts;
    std::size_t fullscan_attempts;
};

////
// ScanMachineResult
///
enum class ScanMachineResult : unsigned char
{
    FAIL,
    ABORTED,
    SUCCESS
};

////
// ScanMachineNeedFullscan
// - the machine needs to perform a full scan
///
struct ScanMachineNeedFullscan final
{
    /// metadata for the machine
    ScanMachineMetadata metadata;
};

////
// ScanMachineNeedPartialscan
// - the machine needs to perform a partial scan
///
struct ScanMachineNeedPartialscan final
{
    /// metadata for the machine
    ScanMachineMetadata metadata;
};

////
// ScanMachineStartScan
// - the machine needs to initialize a scan process
///
struct ScanMachineStartScan final
{
    /// metadata for the machine
    ScanMachineMetadata metadata;

     /// contiguity marker: keeps track of where in the ledger the machine is pointing to right now
    ContiguityMarker contiguity_marker;
};

////
// ScanMachineDoScan
// - the machine needs to scan one new chunk
///
struct ScanMachineDoScan final
{
    /// metadata for the machine
    ScanMachineMetadata metadata;

    /// contiguity context: keeps track of where in the ledger the machine is pointing to right now
    ContiguityMarker contiguity_marker;
    std::uint64_t first_contiguity_index;
};

////
// ScanMachineTerminated
// - the machine has nothing more it can do
///
struct ScanMachineTerminated final
{
    ScanMachineResult result;
};

/// variant of scan machine states
using ScanMachineState =
    tools::variant<
        ScanMachineNeedFullscan,
        ScanMachineNeedPartialscan,
        ScanMachineStartScan,
        ScanMachineDoScan,
        ScanMachineTerminated
    >;

} //namespace scanning
} //namespace sp
