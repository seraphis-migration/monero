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
#include "legacy_decoy_selector_flat.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
LegacyDecoySelectorFlat::LegacyDecoySelectorFlat(const std::uint64_t min_index, const std::uint64_t max_index) :
    m_min_index{min_index},
    m_max_index{max_index}
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(m_max_index >= m_min_index, "legacy decoy selector (flat): invalid element range.");
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyDecoySelectorFlat::get_ring_members(const std::uint64_t real_ring_member_index,
        const std::uint64_t num_ring_members,
        std::vector<std::uint64_t> &ring_members_out,
        std::uint64_t &real_ring_member_index_in_ref_set_out) const
{
    CHECK_AND_ASSERT_THROW_MES(real_ring_member_index >= m_min_index,
        "legacy decoy selector (flat): real ring member index below available index range.");
    CHECK_AND_ASSERT_THROW_MES(real_ring_member_index <= m_max_index,
        "legacy decoy selector (flat): real ring member index above available index range.");
    CHECK_AND_ASSERT_THROW_MES(num_ring_members <= m_max_index - m_min_index + 1,
        "legacy decoy selector (flat): insufficient available legacy enotes to have unique ring members.");

    // fill in ring members
    ring_members_out.clear();
    ring_members_out.reserve(num_ring_members);
    ring_members_out.emplace_back(real_ring_member_index);

    while (ring_members_out.size() < num_ring_members)
    {
        // select a new ring member from indices in the specified range that aren't used yet (only unique ring members
        //   are allowed)
        std::uint64_t new_ring_member;
        do { new_ring_member = crypto::rand_range<std::uint64_t>(m_min_index, m_max_index); }
        while (std::find(ring_members_out.begin(), ring_members_out.end(), new_ring_member) != ring_members_out.end());

        ring_members_out.emplace_back(new_ring_member);
    }

    // sort reference set
    std::sort(ring_members_out.begin(), ring_members_out.end());

    // find location in reference set where the real reference sits
    // note: the reference set does not contain duplicates, so we don't have to handle the case of multiple real references
    real_ring_member_index_in_ref_set_out = 0;

    for (const std::uint64_t reference : ring_members_out)
    {
        if (reference == real_ring_member_index)
            return;

        ++real_ring_member_index_in_ref_set_out;
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
