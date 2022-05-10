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
#include "tx_binned_reference_set.h"

//local headers
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpBinnedReferenceSetConfigV1::append_to_string(std::string &str_inout) const
{
    // str || bin radius || number of bin members
    append_uint_to_string(m_bin_radius, str_inout);
    append_uint_to_string(m_num_bin_members, str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpReferenceBinV1::append_to_string(std::string &str_inout) const
{
    // str || bin locus
    append_uint_to_string(m_bin_locus, str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpBinnedReferenceSetV1::append_to_string(std::string &str_inout) const
{
    // str || bin config || bin generator seed || bin rotation factor || {bins}
    str_inout.reserve(str_inout.size() + this->get_size_bytes(true) + SpBinnedReferenceSetConfigV1::get_size_bytes());

    // bin config
    m_bin_config.append_to_string(str_inout);

    // bin generator seed
    str_inout.append(reinterpret_cast<const char*>(m_bin_generator_seed.bytes), sizeof(m_bin_generator_seed));

    // bin rotation factor
    append_uint_to_string(m_bin_rotation_factor, str_inout);

    // bins
    for (const SpReferenceBinV1 &bin : m_bins)
        bin.append_to_string(str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBinnedReferenceSetV1::get_size_bytes(const std::size_t num_bins, const bool include_seed /*= false*/)
{
    return num_bins * SpReferenceBinV1::get_size_bytes() +
        sizeof(ref_set_bin_dimension_v1_t) +
        (include_seed ? sizeof(m_bin_generator_seed) : 0);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBinnedReferenceSetV1::get_size_bytes(const bool include_seed /*= false*/) const
{
    return SpBinnedReferenceSetV1::get_size_bytes(m_bins.size(), include_seed);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
