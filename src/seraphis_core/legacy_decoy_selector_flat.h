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

// Implementation of legacy decoy selector: select unique decoys uniformly from the set of available legacy enote indices.

#pragma once

//local headers
#include "legacy_decoy_selector.h"

//third party headers

//standard headers
#include <cstdint>
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyDecoySelectorFlat
// - get a set of unique legacy ring members, selected from a flat distribution across the range of available enotes
///
class LegacyDecoySelectorFlat final : public LegacyDecoySelector
{
public:
//constructors
    /// default constructor: disabled
    /// normal constructor
    LegacyDecoySelectorFlat(const std::uint64_t min_index, const std::uint64_t max_index);

//destructor: default

//member functions
    /// request a set of ring members from range [min_index, max_index]
    void get_ring_members(const std::uint64_t real_ring_member_index,
        const std::uint64_t num_ring_members,
        std::vector<std::uint64_t> &ring_members_out,
        std::uint64_t &real_ring_member_index_in_ref_set_out) const override;

//member variables
private:
    std::uint64_t m_min_index;
    std::uint64_t m_max_index;
};

} //namespace sp
