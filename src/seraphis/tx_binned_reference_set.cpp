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
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <limits>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//// validate reference set configurations (must update with each new config version)
template <typename BinDim>
constexpr bool check_bin_config(const std::uint64_t bin_width,
    const std::uint64_t num_bin_members,
    const std::uint16_t grootle_n,
    const std::uint16_t grootle_m)
{
    // bin width outside bin dimension
    if (bin_width > std::numeric_limits<BinDim>::max())
        return false;
    // too many bin members
    if (num_bin_members > std::numeric_limits<BinDim>::max())
        return false;
    // can't fit bin members in bin
    if (num_bin_members > bin_width)
        return false;

    // reference set can't be perfectly divided into bins
    std::uint16_t ref_set_size = ref_set_size_from_decomp(grootle_n, grootle_m);
    return num_bin_members*(ref_set_size/num_bin_members) == ref_set_size;
}

/// reference set V1: size defined by grootle decomposition -> referenced with bins of a specified size
static_assert(check_bin_config<ref_set_bin_dimension_v1_t>(config::SP_REF_SET_BIN_WIDTH_V1,
    config::SP_REF_SET_NUM_BIN_MEMBERS_V1,
    config::SP_GROOTLE_N_V1,
    config::SP_GROOTLE_M_V1), "");

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------    
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
