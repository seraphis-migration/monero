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

// Interface for mapping reference set indices to and from a custom distribution.


#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>
#include <vector>

//forward declarations


namespace sp
{

////
// SpRefSetIndexMapper
// - interface for mapping reference set indices between a custom distribution (e.g. uniform over [a, b], a gamma distribution,
//   etc.) and a uniform space (the range [0, 2^64 - 1])
// - the original element set (from which the reference set will be selected) exists as a range of indices ([min, max]),
//   so the mapping function exists as a filter between element-space and uniform space
// - mapping: [min, max] <-(func)-> [0, 2^64 - 1]
///
class SpRefSetIndexMapper
{
public:
//constructors: default
//destructor
    virtual ~SpRefSetIndexMapper() = default;

//overloaded operators
    /// disable copy/move (this is a pure virtual base class)
    SpRefSetIndexMapper& operator=(SpRefSetIndexMapper&&) = delete;

//getters
    virtual std::uint64_t get_distribution_min_index() const = 0;
    virtual std::uint64_t get_distribution_max_index() const = 0;

//member functions
    /// [min, max] --(func)-> [0, 2^64 - 1]
    virtual std::uint64_t element_index_to_uniform_index(const std::uint64_t element_index) const = 0;
    /// [min, max] <-(func)-- [0, 2^64 - 1]
    virtual std::uint64_t uniform_index_to_element_index(const std::uint64_t uniform_index) const = 0;
};

} //namespace sp
