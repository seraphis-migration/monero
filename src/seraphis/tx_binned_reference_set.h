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

// A reference set using deterministic bins.


#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <cstdint>
#include <vector>

//forward declarations


namespace sp
{

using ref_set_bin_dimension_v1_t = std::uint16_t;  //warning: changing this is not backward compatible! (struct sizes will change)

////
// SpBinnedReferenceSetConfigV1
///
struct SpBinnedReferenceSetConfigV1 final
{
    /// bin radius (defines the range of elements that a bin covers in the parent set)
    ref_set_bin_dimension_v1_t m_bin_radius;
    /// number of elements referenced by a bin
    ref_set_bin_dimension_v1_t m_num_bin_members;

    /// equals operator for equality checks
    bool operator==(const SpBinnedReferenceSetConfigV1 &other_config) const
    {
        return m_bin_radius == other_config.m_bin_radius &&
            m_num_bin_members == other_config.m_num_bin_members;
    }
    bool operator!=(const SpBinnedReferenceSetConfigV1 &other_config) const { return !(*this == other_config); }

    /// convert to a string and append to existing string (for proof transcripts)
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return sizeof(m_bin_radius) + sizeof(m_num_bin_members); }
};

////
// SpReferenceBinV1
// - bin: a selection of elements from a range of elements in a larger set
// - bin locus: the center of the bin range, as an index into that larger set
///
struct SpReferenceBinV1 final
{
    /// bin locus (index into original set)
    std::uint64_t m_bin_locus;

    /// less-than operator for sorting
    bool operator<(const SpReferenceBinV1 &other_bin) const
    {
        return m_bin_locus < other_bin.m_bin_locus;
    }

    /// convert to a string and append to existing string (for proof transcripts)
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return sizeof(m_bin_locus); }
};

////
// SpBinnedReferenceSetV1
// - reference set: a set of elements that are in a larger set
// - binned: the reference set is split into 'bins'
// - rotation factor: rotates deterministically-generated bin members within each bin, so that a pre-selected
//                    member of the larger set becomes a member of one of the bins
///
struct SpBinnedReferenceSetV1 final
{
    /// bin configuration details (shared by all bins)
    SpBinnedReferenceSetConfigV1 m_bin_config;
    /// bin generator seed (shared by all bins)
    rct::key m_bin_generator_seed;
    /// rotation factor (shared by all bins)
    ref_set_bin_dimension_v1_t m_bin_rotation_factor;
    /// bins
    std::vector<SpReferenceBinV1> m_bins;

    /// compute the reference set size
    std::uint64_t reference_set_size() const { return m_bin_config.m_num_bin_members * m_bins.size(); }

    /// convert to a string and append to existing string (for proof transcripts)
    void append_to_string(std::string &str_inout) const;

    /// size of the binned reference set (does not include the config)
    static std::size_t get_size_bytes(const std::size_t num_bins, const bool include_seed = false);
    std::size_t get_size_bytes(const bool include_seed = false) const;
};

} //namespace sp
