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
#include "sp_ref_set_index_mapper_flat.h"

//local headers
#include "misc_log_ex.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <limits>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// project element 'a' from range [a_min, a_max] into range [b_min, b_max]
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t project_between_ranges(const std::uint64_t a,
    const std::uint64_t a_min,
    const std::uint64_t a_max,
    const std::uint64_t b_min,
    const std::uint64_t b_max)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(
            a     >= a_min &&
            a     <= a_max &&
            a_min <= a_max &&
            b_min <= b_max,
        "ref set index mapper (flat) projecting between ranges: invalid inputs.");

    // (a - a_min)/(a_max - a_min + 1) = (b - b_min)/(b_max - b_min + 1)
    // b = (a - a_min)*(b_max - b_min + 1)/(a_max - a_min + 1) + b_min
    using boost::multiprecision::uint128_t;

    // numerator: (a - a_min)*(b_max - b_min + 1)
    uint128_t result{a - a_min};
    result *= (uint128_t{b_max} - b_min + 1);

    // denominator: (a_max - a_min + 1)
    result /= (uint128_t{a_max} - a_min + 1);

    // + b_min
    return static_cast<std::uint64_t>(result) + b_min;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpRefSetIndexMapperFlat::SpRefSetIndexMapperFlat(const std::uint64_t distribution_min_index,
    const std::uint64_t distribution_max_index) :
        m_distribution_min_index{distribution_min_index},
        m_distribution_max_index{distribution_max_index}
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(m_distribution_max_index >= m_distribution_min_index,
        "ref set index mapper (flat): invalid element range.");
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpRefSetIndexMapperFlat::element_index_to_uniform_index(const std::uint64_t element_index) const
{
    // [min, max] --(projection)-> [0, 2^64 - 1]
    CHECK_AND_ASSERT_THROW_MES(element_index >= m_distribution_min_index,
        "ref set index manager (flat): element index below distribution range.");
    CHECK_AND_ASSERT_THROW_MES(element_index <= m_distribution_max_index,
        "ref set index manager (flat): element index above distribution range.");

    // (element_index - min)/(max - min + 1) = (uniform_index - 0)/([2^64 - 1] - 0 + 1)
    return project_between_ranges(element_index,
        m_distribution_min_index,
        m_distribution_max_index,
        0,
        std::numeric_limits<std::uint64_t>::max());
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpRefSetIndexMapperFlat::uniform_index_to_element_index(const std::uint64_t uniform_index) const
{
    // [min, max] <-(projection)-- [0, 2^64 - 1]

    // (uniform_index - 0)/([2^64 - 1] - 0 + 1) = (element_index - min)/(max - min + 1)
    return project_between_ranges(uniform_index,
        0,
        std::numeric_limits<std::uint64_t>::max(),
        m_distribution_min_index,
        m_distribution_max_index);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
