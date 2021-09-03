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

//paired header
#include "binned_reference_set.h"

//local headers
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpBinnedReferenceSetConfigV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("bin_radius", container.bin_radius);
    transcript_inout.append("num_bin_members", container.num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_binned_ref_set_config_v1_size_bytes()
{
    return sizeof(SpBinnedReferenceSetConfigV1::bin_radius) + sizeof(SpBinnedReferenceSetConfigV1::num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpBinnedReferenceSetV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("bin_config", container.bin_config);
    transcript_inout.append("bin_generator_seed", container.bin_generator_seed);
    transcript_inout.append("bin_rotation_factor", container.bin_rotation_factor);
    transcript_inout.append("bin_loci", container.bin_loci);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_binned_ref_set_v1_size_bytes(const std::size_t num_bins)
{
    return sp_binned_ref_set_config_v1_size_bytes() +
        sizeof(SpBinnedReferenceSetV1::bin_generator_seed) +
        sizeof(ref_set_bin_dimension_v1_t) +
        num_bins * 8;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_binned_ref_set_v1_size_bytes_compact(const std::size_t num_bins)
{
    return sizeof(ref_set_bin_dimension_v1_t) + num_bins * 8;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_binned_ref_set_v1_size_bytes(const SpBinnedReferenceSetV1 &reference_set)
{
    return sp_binned_ref_set_v1_size_bytes(reference_set.bin_loci.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_binned_ref_set_v1_size_bytes_compact(const SpBinnedReferenceSetV1 &reference_set)
{
    return sp_binned_ref_set_v1_size_bytes_compact(reference_set.bin_loci.size());
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpBinnedReferenceSetConfigV1 &a, const SpBinnedReferenceSetConfigV1 &b)
{
    return a.bin_radius      == b.bin_radius &&
           a.num_bin_members == b.num_bin_members;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator!=(const SpBinnedReferenceSetConfigV1 &a, const SpBinnedReferenceSetConfigV1 &b)
{
    return !(a == b);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t reference_set_size(const SpBinnedReferenceSetV1 &reference_set)
{
    return reference_set.bin_config.num_bin_members * reference_set.bin_loci.size();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
