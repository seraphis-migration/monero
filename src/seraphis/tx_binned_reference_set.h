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

// A reference set using deterministic bins

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
// - rotation factor: rotates deterministically-generated bin members within the bin, so that a pre-selected
//                    member of the larger set becomes a member of the bin
///
struct SpReferenceBinV1 final
{
    /// bin locus (index into original set)
    std::uint64_t m_bin_locus;
    /// rotation factor
    ref_set_bin_dimension_v1_t m_rotation_factor;

    /// less-than operator for sorting
    /// - only use bin locus for sorting, since the rotation factor is not always independent of ordering (the real
    //    reference's bin's rotation factor depends on the generator seed hashed with the bin index)
    bool operator<(const SpReferenceBinV1 &other_bin) const
    {
        return m_bin_locus < other_bin.m_bin_locus;
    }

    /// convert to a string and append to existing string (for proof transcripts)
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return sizeof(m_bin_locus) + sizeof(m_rotation_factor); }
};

////
// SpBinnedReferenceSetV1
// - reference set: a set of elements that are in a larger set
// - binned: the reference set is split into 'bins'
///
struct SpBinnedReferenceSetV1 final
{
    /// bin configuration details (shared by all bins)
    SpBinnedReferenceSetConfigV1 m_bin_config;
    /// bin generator seed (shared by all bins)
    rct::key m_bin_generator_seed;
    /// bins
    std::vector<SpReferenceBinV1> m_bins;

    /// compute the reference set size
    std::uint64_t reference_set_size() const { return m_bin_config.m_num_bin_members * m_bins.size(); }

    /// convert to a string and append to existing string (for proof transcripts)
    void append_to_string(std::string &str_inout) const;

    /// size of the binned reference set (does not include the config)
    static std::size_t get_size_bytes(const std::size_t num_bins, const bool include_seed = false)
    {
        return num_bins * SpReferenceBinV1::get_size_bytes() + (include_seed ? sizeof(m_bin_generator_seed) : 0);
    }
    std::size_t get_size_bytes(const bool include_seed = false) const
    {
        return SpBinnedReferenceSetV1::get_size_bytes(m_bins.size(), include_seed);
    }
};

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

//getters
    virtual std::uint64_t get_distribution_min_index() const = 0;
    virtual std::uint64_t get_distribution_max_index() const = 0;

//member functions
    /// [min, max] --(func)-> [0, 2^64 - 1]
    virtual std::uint64_t element_index_to_uniform_index(const std::uint64_t element_index) const = 0;
    /// [min, max] <-(func)-- [0, 2^64 - 1]
    virtual std::uint64_t uniform_index_to_element_index(const std::uint64_t uniform_index) const = 0;
};

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

//todo
bool check_bin_config_v1(const std::uint64_t reference_set_size, const SpBinnedReferenceSetConfigV1 &bin_config);

//todo
void generate_bin_loci(const SpRefSetIndexMapper &index_mapper,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    std::vector<std::uint64_t> &bin_loci_out,
    std::uint64_t &bin_index_with_real_out);

//todo
//todo: consider making reference sets deterministic from some input secret so repeat reference sets for the same element
//      can produce the same real bin (given the same generator seed, secret, and index mapper)
void make_binned_reference_set_v1(const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::uint64_t real_reference_index,
    const std::vector<std::uint64_t> &bin_loci,
    const std::uint64_t bin_index_with_real,  //index into bin_loci
    SpBinnedReferenceSetV1 &binned_reference_set_out);
void make_binned_reference_set_v1(const SpRefSetIndexMapper &index_mapper,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    SpBinnedReferenceSetV1 &binned_reference_set_out);

//todo
bool try_get_reference_indices_from_binned_reference_set_v1(const SpBinnedReferenceSetV1 &binned_reference_set,
    std::vector<std::uint64_t> &reference_indices_out);

} //namespace sp
