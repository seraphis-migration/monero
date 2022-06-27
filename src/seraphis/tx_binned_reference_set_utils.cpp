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
#include "tx_binned_reference_set_utils.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_binned_reference_set.h"
#include "tx_misc_utils.h"
#include "tx_ref_set_index_mapper.h"

//third party headers

//standard headers
#include <algorithm>
#include <limits>
#include <string>
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

    // prepare for making this bin's member generators
    // g = H_64(bin_generator_seed, bin_locus, bin_index_in_set)
    SpTranscript transcript{
            config::HASH_KEY_BINNED_REF_SET_MEMBER,
            sizeof(bin_generator_seed) + sizeof(bin_locus) + sizeof(bin_index_in_set) + 200 * bin_config.m_num_bin_members
        };
    transcript.append("seed", bin_generator_seed);
    transcript.append("length", bin_locus);
    transcript.append("bin_index", bin_index_in_set);

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
    // - make 64-byte blobs via hashing, then use each 8-byte block to try to generate a bin member
    //   - this minimizes the amount of time spent in the hash function by calling it fewer times
    unsigned char member_generator[64];
    std::size_t member_generator_offset_blocks{0};
    std::uint64_t generator_clip{};
    std::uint64_t member_candidate{};
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
                if (member_generator_offset_blocks*8 >= sizeof(member_generator))
                    member_generator_offset_blocks = 0;

                if (member_generator_offset_blocks == 0)
                    sp_hash_to_64(transcript, member_generator);

                memcpy(&generator_clip, member_generator + 8*member_generator_offset_blocks, 8);
                generator_clip = SWAP64LE(generator_clip);
                ++member_generator_offset_blocks;
            } while (generator_clip > clip_allowed_max);

            // compute the bin member: slice_8_bytes(generator) mod bin_width
            member_candidate = mod(generator_clip, bin_width);
        } while (std::find(members_of_bin_out.begin(), members_of_bin_out.end(), member_candidate) !=
            members_of_bin_out.end());

        members_of_bin_out.emplace_back(member_candidate);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// make bin loci for a reference set (one of which will be the locus for the bin with the real reference)
//-------------------------------------------------------------------------------------------------------------------
static void generate_bin_loci(const SpRefSetIndexMapper &index_mapper,
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
    CHECK_AND_ASSERT_THROW_MES(check_bin_config_v1(reference_set_size, bin_config), "generating bin loci: invalid config.");

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
//-------------------------------------------------------------------------------------------------------------------
bool check_bin_config_v1(const std::uint64_t reference_set_size, const SpBinnedReferenceSetConfigV1 &bin_config)
{
    // bin width outside bin dimension
    if (bin_config.m_bin_radius > (std::numeric_limits<ref_set_bin_dimension_v1_t>::max() - 1)/2)
        return false;
    // too many bin members
    if (bin_config.m_num_bin_members > std::numeric_limits<ref_set_bin_dimension_v1_t>::max())
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
void make_binned_reference_set_v1(const SpRefSetIndexMapper &index_mapper,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    SpBinnedReferenceSetV1 &binned_reference_set_out)
{
    // make binned reference set

    /// generate bin loci
    std::vector<std::uint64_t> bin_loci;
    std::uint64_t bin_index_with_real;
    generate_bin_loci(index_mapper, bin_config, reference_set_size, real_reference_index, bin_loci, bin_index_with_real);


    /// checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.m_bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(check_bin_config_v1(bin_config.m_num_bin_members * bin_loci.size(), bin_config),
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
    binned_reference_set_out.m_bin_rotation_factor = static_cast<ref_set_bin_dimension_v1_t>(
        mod_sub(normalized_real_reference, members_of_real_bin[designated_real_bin_member], bin_width));


    /// set remaining pieces of the output reference set
    binned_reference_set_out.m_bin_config = bin_config;
    binned_reference_set_out.m_bin_generator_seed = generator_seed;
    binned_reference_set_out.m_bin_loci = std::move(bin_loci);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_reference_indices_from_binned_reference_set_v1(const SpBinnedReferenceSetV1 &binned_reference_set,
    std::vector<std::uint64_t> &reference_indices_out)
{
    // initialization
    const std::uint64_t bin_width{compute_bin_width(binned_reference_set.m_bin_config.m_bin_radius)};
    const std::uint64_t reference_set_size{
            binned_reference_set.m_bin_loci.size() * binned_reference_set.m_bin_config.m_num_bin_members
        };

    // sanity check the bin config
    if (!check_bin_config_v1(reference_set_size, binned_reference_set.m_bin_config))
        return false;

    // rotation factor must be within the bins (normalized)
    if (binned_reference_set.m_bin_rotation_factor >= bin_width)
        return false;

    // validate bins
    for (const std::uint64_t &bin_locus : binned_reference_set.m_bin_loci)
    {
        // bins must all fit in the range [0, 2^64 - 1]
        if (bin_locus < binned_reference_set.m_bin_config.m_bin_radius)
            return false;
        if (bin_locus > std::numeric_limits<std::uint64_t>::max() - binned_reference_set.m_bin_config.m_bin_radius)
            return false;
    }

    // add all the bin members
    reference_indices_out.clear();
    reference_indices_out.reserve(reference_set_size);

    std::vector<std::uint64_t> bin_members;

    for (std::size_t bin_index{0}; bin_index < binned_reference_set.m_bin_loci.size(); ++bin_index)
    {
        // 1) make normalized bin members
        make_normalized_bin_members(binned_reference_set.m_bin_config,
            binned_reference_set.m_bin_generator_seed,
            binned_reference_set.m_bin_loci[bin_index],
            bin_index,
            bin_members);

        // 2) rotate the bin members by the rotation factor
        rotate_elements(bin_width, binned_reference_set.m_bin_rotation_factor, bin_members);

        // 3) de-normalize the bin members
        denormalize_elements(
            binned_reference_set.m_bin_loci[bin_index] - binned_reference_set.m_bin_config.m_bin_radius,
            bin_members);

        // 4) save the bin members
        reference_indices_out.insert(reference_indices_out.end(), bin_members.begin(), bin_members.end());
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
