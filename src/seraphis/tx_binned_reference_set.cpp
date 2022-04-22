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
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "misc_log_ex.h"
#include "seraphis_config_temp.h"
#include "tx_misc_utils.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <limits>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t compute_bin_width(const std::uint64_t bin_radius)
{
    return 2*bin_radius + 1;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename BinDim>
static bool check_bin_config(const std::uint64_t reference_set_size,
    const SpBinnedReferenceSetConfigV1 &bin_config)
{
    // bin width outside bin dimension
    if (bin_config.m_bin_radius > (std::numeric_limits<BinDim>::max() - 1)/2)
        return false;
    // too many bin members
    if (bin_config.m_num_bin_members > std::numeric_limits<BinDim>::max())
        return false;
    // can't fit bin members in bin (note: bin can't contain more than std::uint64_t::max members)
    if (bin_config.m_num_bin_members > compute_bin_width(bin_config.m_bin_radius))
        return false;
    // no bin members
    if (bin_config.m_num_bin_members < 1)
        return false;

    // reference set can't be perfectly divided into bins
    return bin_config.m_num_bin_members * (reference_set_size / bin_config.m_num_bin_members) == reference_set_size;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t clamp(const std::uint64_t a, const std::uint64_t min, const std::uint64_t max)
{
    // clamp 'a' to range [min, max]
    if (a < min)
        return min;
    else if (a > max)
        return max;
    else
        return a;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t saturating_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t min)
{
    if (a < min)
        return min;

    return a - min >= b
        ? a - b
        : min;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t saturating_add(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max)
{
    if (a > max)
        return max;

    return max - a >= b
        ? a + b
        : max;
}
//-------------------------------------------------------------------------------------------------------------------
// special case: n = 0 means n = std::uint64_t::max + 1
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod(const std::uint64_t a, const std::uint64_t n)
{
    // a mod n
    return n > 0 ? a % n : a;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_negate(const std::uint64_t a, const std::uint64_t n)
{
    // -a mod n = n - (a mod n)
    return n - mod(a, n);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_add(std::uint64_t a, std::uint64_t b, const std::uint64_t n)
{
    // a + b mod n
    a = mod(a, n);
    b = mod(b, n);

    // if adding doesn't overflow the modulus, then add directly, otherwise overflow the modulus
    return (n - a > b) ? a + b : b - (n - a);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t n)
{
    // a - b mod n
    return mod_add(a, mod_negate(b, n), n);
}
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
    CHECK_AND_ASSERT_THROW_MES(a >= a_min &&
            a     <= a_max &&
            a_min <= a_max &&
            b_min <= b_max,
        "projecting between ranges: invalid inputs.");

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
// deterministically generate unique members of a bin
//-------------------------------------------------------------------------------------------------------------------
static void make_normalized_bin_members(const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &bin_generator_seed,
    const std::uint64_t bin_locus,
    const std::uint64_t bin_index_in_set,
    std::vector<std::uint64_t> &members_of_bin_out)
{
    // checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.m_bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(bin_config.m_num_bin_members > 0,
        "making normalized bin members: zero bin members were requested (at least one expected).");

    // make this bin's member generator
    // g = H("..", bin_generator_seed, bin_locus, bin_index_in_set)
    static const std::string domain_separator{config::HASH_KEY_BINNED_REF_SET_MEMBER};

    std::string data;
    data.reserve(domain_separator.size() + sizeof(bin_generator_seed) + sizeof(bin_locus) + sizeof(bin_index_in_set));
    data = domain_separator;
    data.append(reinterpret_cast<const char*>(bin_generator_seed.bytes), sizeof(bin_generator_seed));
    append_int_to_string(bin_locus, data);
    append_int_to_string(bin_index_in_set, data);
    crypto::hash member_generator{crypto::cn_fast_hash(data.data(), data.size())};

    // set clip allowed max to be a large multiple of the bin width (minus 1 since we are zero-basis),
    //   to avoid bias in the bin members
    // example 1:
    //   max = 15  (e.g. 4 bits)
    //   width = 4
    //   15 = 15 - ((15 mod 4) + 1 mod 4)
    //   15 = 15 - ((3) + 1 mod 4)
    //   15 = 15 - 0
    //   perfect partitioning: [0..3][4..7][8..11][12..15]
    // example 2:
    //   max = 15  (e.g. 4 bits)
    //   width = 6
    //   11 = 15 - ((15 mod 6) + 1 mod 6)
    //   11 = 15 - ((3) + 1 mod 6)
    //   11 = 15 - 4
    //   perfect partitioning: [0..5][6..11]
    const std::uint64_t clip_allowed_max{
            std::numeric_limits<std::uint64_t>::max() -
                mod(mod(std::numeric_limits<std::uint64_t>::max(), bin_width) + 1, bin_width)
        };

    // make each bin member (as unique indices within the bin)
    std::uint64_t generator_clip;
    std::uint64_t member_candidate;
    members_of_bin_out.clear();
    members_of_bin_out.reserve(bin_config.m_num_bin_members);

    for (std::size_t bin_member_index{0}; bin_member_index < bin_config.m_num_bin_members; ++bin_member_index)
    {
        // look for a unique bin member to add
        do
        {
            // update the generator (find a generator that is within the allowed max)
            do
            {
                crypto::cn_fast_hash(member_generator.data, sizeof(member_generator), member_generator);
                memcpy(&generator_clip, member_generator.data, sizeof(generator_clip));
                generator_clip = SWAP64LE(generator_clip);
            } while (generator_clip > clip_allowed_max);

            // compute the bin member: slice_8_bytes(generator) mod bin_width
            member_candidate = mod(generator_clip, bin_width);
        } while (std::find(members_of_bin_out.begin(), members_of_bin_out.end(), member_candidate) != members_of_bin_out.end());

        members_of_bin_out.emplace_back(member_candidate);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void rotate_elements(const std::uint64_t range_limit,
    const std::uint64_t rotation_factor,
    std::vector<std::uint64_t> &elements_inout)
{
    // rotate a group of elements by a rotation factor
    for (std::uint64_t &element : elements_inout)
        element = mod_add(element, rotation_factor, range_limit);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void denormalize_elements(const std::uint64_t normalization_factor, std::vector<std::uint64_t> &elements_inout)
{
    // de-normalize elements
    for (std::uint64_t &element : elements_inout)
        element += normalization_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SpBinnedReferenceSetConfigV1::append_to_string(std::string &str_inout) const
{
    // str || bin radius || number of bin members
    append_int_to_string(m_bin_radius, str_inout);
    append_int_to_string(m_num_bin_members, str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpReferenceBinV1::append_to_string(std::string &str_inout) const
{
    // str || bin locus || bin rotation factor
    append_int_to_string(m_bin_locus, str_inout);
    append_int_to_string(m_rotation_factor, str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpBinnedReferenceSetV1::append_to_string(std::string &str_inout) const
{
    // str || bin config || bin generator seed || {bins}
    str_inout.reserve(str_inout.size() + this->get_size_bytes(true) + SpBinnedReferenceSetConfigV1::get_size_bytes());

    // bin config
    m_bin_config.append_to_string(str_inout);

    // bin generator seed
    str_inout.append(reinterpret_cast<const char*>(m_bin_generator_seed.bytes), sizeof(m_bin_generator_seed));

    // bins
    for (const SpReferenceBinV1 &bin : m_bins)
        bin.append_to_string(str_inout);
}
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
void generate_bin_loci(const SpRefSetIndexMapper &index_mapper,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    std::vector<std::uint64_t> &bin_loci_out,
    std::uint64_t &bin_index_with_real_out)
{
    /// checks and initialization
    const std::uint64_t distribution_min_index{index_mapper.get_distribution_min_index()};
    const std::uint64_t distribution_max_index{index_mapper.get_distribution_max_index()};

    CHECK_AND_ASSERT_THROW_MES(real_reference_index >= distribution_min_index &&
            real_reference_index <= distribution_max_index,
        "generating bin loci: real element reference is not within the element distribution.");
    CHECK_AND_ASSERT_THROW_MES(reference_set_size >= 1,
        "generating bin loci: reference set size too small (needs to be >= 1).");
    CHECK_AND_ASSERT_THROW_MES(distribution_min_index <= distribution_max_index,
        "generating bin loci: invalid distribution range.");
    CHECK_AND_ASSERT_THROW_MES(distribution_max_index - distribution_min_index >= 
            compute_bin_width(bin_config.m_bin_radius) - 1,
        "generating bin loci: bin width is too large for the distribution range.");
    CHECK_AND_ASSERT_THROW_MES(check_bin_config<ref_set_bin_dimension_v1_t>(reference_set_size, bin_config),
        "generating bin loci: invalid config.");

    const std::uint64_t num_bins{reference_set_size/bin_config.m_num_bin_members};
    const std::uint64_t distribution_width{distribution_max_index - distribution_min_index + 1};


    /// pick a locus for the real reference's bin

    // 1) define range where the locus may reside (clamp bounds to element distribution range)
    const std::uint64_t real_locus_min{
            saturating_sub(real_reference_index, bin_config.m_bin_radius, distribution_min_index)
        };
    const std::uint64_t real_locus_max{
            saturating_add(real_reference_index, bin_config.m_bin_radius, distribution_max_index)
        };

    // 2) generate the bin locus within the element distribution
    const std::uint64_t real_locus{crypto::rand_range<std::uint64_t>(real_locus_min, real_locus_max)};

    // 3) translate the real locus to uniform space (uniform distribution across [0, 2^64 - 1])
    const std::uint64_t real_locus_flattened{index_mapper.element_index_to_uniform_index(real_locus)};


    /// randomly generate a set of bin loci in uniform space
    std::vector<std::uint64_t> bin_loci;
    bin_loci.resize(num_bins);

    for (std::uint64_t &bin_locus : bin_loci)
        bin_locus = crypto::rand_range<std::uint64_t>(0, std::numeric_limits<std::uint64_t>::max());


    /// rotate the randomly generated bins so a random bin lines up with the real bin locus (in uniform space)

    // 1) randomly select one of the bins
    const std::uint64_t designated_real_bin{crypto::rand_range<std::uint64_t>(0, num_bins - 1)};

    // 2) compute rotation factor
    const std::uint64_t bin_loci_rotation_factor{mod_sub(real_locus_flattened, bin_loci[designated_real_bin], 0)};

    // 3) rotate all the bin loci
    rotate_elements(0, bin_loci_rotation_factor, bin_loci);


    /// get bin loci into the element distribution space

    // 1) map the bin loci into the distribution space
    for (std::uint64_t &bin_locus : bin_loci)
        bin_locus = index_mapper.uniform_index_to_element_index(bin_locus);

    // 2) find the bin locus closest to the real locus (the index mapper might have precision loss)
    std::uint64_t locus_closest_to_real{0};
    std::uint64_t locus_gap{distribution_width - 1};  //all gaps will be <= the range of locus values
    std::uint64_t smallest_gap;

    for (std::size_t bin_loci_index{0}; bin_loci_index < bin_loci.size(); ++bin_loci_index)
    {
        // test for gaps above and below the locus
        smallest_gap = std::min(
                mod_sub(real_locus, bin_loci[bin_loci_index], distribution_width),  //gap below
                mod_sub(bin_loci[bin_loci_index], real_locus, distribution_width)   //gap above
            );

        if (smallest_gap < locus_gap)
        {
            locus_gap = smallest_gap;
            locus_closest_to_real = bin_loci_index;
        }
    }

    // 3) reset the bin locus closest to the real locus
    bin_loci[locus_closest_to_real] = real_locus;


    /// prepare outputs

    // 1) sort bin loci
    std::sort(bin_loci.begin(), bin_loci.end());

    // 2) shift bin loci so their entire widths are within the element distribution
    for (std::uint64_t &bin_locus : bin_loci)
    {
        bin_locus = clamp(bin_locus,
            distribution_min_index + bin_config.m_bin_radius,
            distribution_max_index - bin_config.m_bin_radius);
    }

    const std::uint64_t real_locus_shifted{
            clamp(real_locus,
                distribution_min_index + bin_config.m_bin_radius,
                distribution_max_index - bin_config.m_bin_radius)
        };

    // 3) select the real reference's locus (if multiple loci equal the real locus, pick one randomly)
    std::uint64_t last_locus_equal_to_real{0};
    std::uint64_t num_loci_equal_to_real{0};

    for (std::size_t bin_loci_index{0}; bin_loci_index < bin_loci.size(); ++bin_loci_index)
    {
        if (bin_loci[bin_loci_index] == real_locus_shifted)
        {
            last_locus_equal_to_real = bin_loci_index;
            ++num_loci_equal_to_real;
        }
    }

    bin_index_with_real_out =
        crypto::rand_range<std::uint64_t>(last_locus_equal_to_real - num_loci_equal_to_real + 1, last_locus_equal_to_real);

    // 4) set bin loci output
    bin_loci_out = std::move(bin_loci);
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_reference_set_v1(const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::uint64_t real_reference_index,
    const std::vector<std::uint64_t> &bin_loci,
    const std::uint64_t bin_index_with_real,  //index into bin_loci
    SpBinnedReferenceSetV1 &binned_reference_set_out)
{
    // make binned reference set

    /// checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.m_bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(check_bin_config<ref_set_bin_dimension_v1_t>(bin_config.m_num_bin_members * bin_loci.size(),
            bin_config),
        "binned reference set: invalid bin config.");

    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(bin_loci.begin(), bin_loci.end()),
        "binned reference set: bin loci aren't sorted.");
    for (const std::uint64_t bin_locus : bin_loci)
    {
        CHECK_AND_ASSERT_THROW_MES(bin_locus >= bin_config.m_bin_radius,
            "binned reference set: the bottom of a proposed bin hangs below 0.");        
        CHECK_AND_ASSERT_THROW_MES(bin_locus <= std::numeric_limits<std::uint64_t>::max() - bin_config.m_bin_radius,
            "binned reference set: the top of a proposed bin extends above uint64::max().");        
    }

    CHECK_AND_ASSERT_THROW_MES(bin_index_with_real < bin_loci.size(),
        "binned reference set: real element's bin isn't in the bins proposed.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index >= bin_loci[bin_index_with_real] - bin_config.m_bin_radius,
        "binned reference set: real element is below its proposed bin.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index <= bin_loci[bin_index_with_real] + bin_config.m_bin_radius,
        "binned reference set: real element is above its proposed bin.");


    /// make bins
    std::vector<SpReferenceBinV1> bins;
    bins.resize(bin_loci.size());

    for (std::size_t bin_index{0}; bin_index < bin_loci.size(); ++bin_index)
    {
        bins[bin_index].m_bin_locus = bin_loci[bin_index];
        bins[bin_index].m_rotation_factor =
            static_cast<ref_set_bin_dimension_v1_t>(crypto::rand_range<std::uint64_t>(0, bin_width - 1));
    }


    /// set real reference's bin rotation factor

    // 1) generate the bin members' element set indices (normalized and not rotated)
    std::vector<std::uint64_t> members_of_real_bin;
    make_normalized_bin_members(bin_config,
        generator_seed,
        bin_loci[bin_index_with_real],
        bin_index_with_real,
        members_of_real_bin);
    CHECK_AND_ASSERT_THROW_MES(members_of_real_bin.size() == bin_config.m_num_bin_members,
        "binned reference set: getting normalized bin members failed (bug).");

    // 2) select a random bin member to land on the real reference
    const std::uint64_t designated_real_bin_member{crypto::rand_range<std::uint64_t>(0, bin_config.m_num_bin_members - 1)};

    // 3) normalize the real reference within its bin (subtract the bottom of the bin)
    const std::uint64_t normalized_real_reference{
            real_reference_index - (bin_loci[bin_index_with_real] - bin_config.m_bin_radius)
        };

    // 4) compute rotation factor
    bins[bin_index_with_real].m_rotation_factor = static_cast<ref_set_bin_dimension_v1_t>(
        mod_sub(normalized_real_reference, members_of_real_bin[designated_real_bin_member], bin_width));


    /// set output reference set
    binned_reference_set_out.m_bin_config = bin_config;
    binned_reference_set_out.m_bin_generator_seed = generator_seed;
    binned_reference_set_out.m_bins = std::move(bins);
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_reference_set_v1(const SpRefSetIndexMapper &index_mapper,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    SpBinnedReferenceSetV1 &binned_reference_set_out)
{
    // make binned reference set with loci generator

    // generate bin loci
    std::vector<std::uint64_t> bin_loci;
    std::uint64_t bin_index_with_real;
    generate_bin_loci(index_mapper, bin_config, reference_set_size, real_reference_index, bin_loci, bin_index_with_real);

    // make the reference set
    make_binned_reference_set_v1(bin_config,
        generator_seed,
        real_reference_index,
        bin_loci,
        bin_index_with_real,
        binned_reference_set_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_reference_indices_from_binned_reference_set_v1(const SpBinnedReferenceSetV1 &binned_reference_set,
    std::vector<std::uint64_t> &reference_indices_out)
{
    // initialization
    const std::uint64_t bin_width{compute_bin_width(binned_reference_set.m_bin_config.m_bin_radius)};
    const std::uint64_t reference_set_size{
            binned_reference_set.m_bins.size() * binned_reference_set.m_bin_config.m_num_bin_members
        };

    // sanity check the bin config
    if (!check_bin_config<ref_set_bin_dimension_v1_t>(reference_set_size, binned_reference_set.m_bin_config))
        return false;

    // validate bins
    for (const SpReferenceBinV1 &bin : binned_reference_set.m_bins)
    {
        // bins must all fit in the range [0, 2^64 - 1]
        if (bin.m_bin_locus < binned_reference_set.m_bin_config.m_bin_radius)
            return false;
        if (bin.m_bin_locus > std::numeric_limits<std::uint64_t>::max() - binned_reference_set.m_bin_config.m_bin_radius)
            return false;

        // rotation factor must be within the bin (normalized)
        if (bin.m_rotation_factor >= bin_width)
            return false;
    }

    // add all the bin members
    reference_indices_out.clear();
    reference_indices_out.reserve(reference_set_size);

    std::vector<std::uint64_t> bin_members;

    for (std::size_t bin_index{0}; bin_index < binned_reference_set.m_bins.size(); ++bin_index)
    {
        // 1) make normalized bin members
        make_normalized_bin_members(binned_reference_set.m_bin_config,
            binned_reference_set.m_bin_generator_seed,
            binned_reference_set.m_bins[bin_index].m_bin_locus,
            bin_index,
            bin_members);

        // 2) rotate the bin members by the rotation factor
        rotate_elements(bin_width, binned_reference_set.m_bins[bin_index].m_rotation_factor, bin_members);

        // 3) de-normalize the bin members
        denormalize_elements(
            binned_reference_set.m_bins[bin_index].m_bin_locus - binned_reference_set.m_bin_config.m_bin_radius,
            bin_members);

        // 4) save the bin members
        reference_indices_out.insert(reference_indices_out.end(), bin_members.begin(), bin_members.end());
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
