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

// A reference set using deterministic bins.

#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <cstdint>
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

/// WARNING: changing this is not backward compatible! (struct sizes will change)
using ref_set_bin_dimension_v1_t = std::uint16_t;

////
// SpBinnedReferenceSetConfigV1
///
struct SpBinnedReferenceSetConfigV1 final
{
    /// bin radius (defines the range of elements that a bin covers in the parent set)
    ref_set_bin_dimension_v1_t bin_radius;
    /// number of elements referenced by a bin
    ref_set_bin_dimension_v1_t num_bin_members;
};
inline const boost::string_ref container_name(const SpBinnedReferenceSetConfigV1&) { return "SpBinnedReferenceSetConfigV1"; }
void append_to_transcript(const SpBinnedReferenceSetConfigV1 &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
std::size_t sp_binned_ref_set_config_v1_size_bytes();

////
// SpBinnedReferenceSetV1
// - reference set: a set of elements that are selected from a larger set; all elements except one are decoys (random)
// - binned: the reference set is split into subsets of elements that are located in 'bins'
// - bin: a specific range of elements in a larger set
// - bin locus: the center of the bin range, as an index into that larger set; the range is
//   [bin_locus - bin_radius, bin_locus + bin-radius]
// - rotation factor: reference set elements are deterministically selected from bins; the rotation factor rotates all
//   bin members within their bins so that one bin member in one of the bins lines up with a pre-selected non-decoy element
///
struct SpBinnedReferenceSetV1 final
{
    /// bin configuration details (shared by all bins)
    SpBinnedReferenceSetConfigV1 bin_config;
    /// bin generator seed (shared by all bins)
    rct::key bin_generator_seed;
    /// rotation factor (shared by all bins)
    ref_set_bin_dimension_v1_t bin_rotation_factor;
    /// bin loci
    std::vector<std::uint64_t> bin_loci;
};
inline const boost::string_ref container_name(const SpBinnedReferenceSetV1&) { return "SpBinnedReferenceSetV1"; }
void append_to_transcript(const SpBinnedReferenceSetV1 &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
/// - compact version does not include: config, seed
std::size_t sp_binned_ref_set_v1_size_bytes(const std::size_t num_bins);
std::size_t sp_binned_ref_set_v1_size_bytes_compact(const std::size_t num_bins);
std::size_t sp_binned_ref_set_v1_size_bytes(const SpBinnedReferenceSetV1 &reference_set);
std::size_t sp_binned_ref_set_v1_size_bytes_compact(const SpBinnedReferenceSetV1 &reference_set);

/// equivalence operators for equality checks
bool operator==(const SpBinnedReferenceSetConfigV1 &a, const SpBinnedReferenceSetConfigV1 &b);
bool operator!=(const SpBinnedReferenceSetConfigV1 &a, const SpBinnedReferenceSetConfigV1 &b);

/// compute the reference set size of a binned reference set
std::uint64_t reference_set_size(const SpBinnedReferenceSetV1 &reference_set);

} //namespace sp
