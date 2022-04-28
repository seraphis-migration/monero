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

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "tx_ref_set_index_mapper.h"

//third party headers

//standard headers
#include <cstdint>
#include <vector>

//forward declarations


namespace sp
{

////
// SpRefSetIndexMapperFlat
// - implementation of SpRefSetIndexMapper
// - linear mapping function (i.e. project the element range onto the uniform space)
///
class SpRefSetIndexMapperFlat final : public SpRefSetIndexMapper
{
public:
//constructors
    /// default constructor
    SpRefSetIndexMapperFlat() = default;

    /// normal constructor
    SpRefSetIndexMapperFlat(const std::uint64_t distribution_min_index,
        const std::uint64_t distribution_max_index);

//destructor: default

//getters
    std::uint64_t get_distribution_min_index() const override { return m_distribution_min_index; }
    std::uint64_t get_distribution_max_index() const override { return m_distribution_max_index; }

//member functions
    /// [min, max] --(projection)-> [0, 2^64 - 1]
    std::uint64_t element_index_to_uniform_index(const std::uint64_t element_index) const override;
    /// [min, max] <-(projection)-- [0, 2^64 - 1]
    std::uint64_t uniform_index_to_element_index(const std::uint64_t uniform_index) const override;

//member variables
private:
    std::uint64_t m_distribution_min_index{1};  //use an invalid range by default so default objects will throw errors
    std::uint64_t m_distribution_max_index{0};
};

} //namespace sp
