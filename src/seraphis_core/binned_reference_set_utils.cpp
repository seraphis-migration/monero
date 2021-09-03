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
#include "binned_reference_set_utils.h"

//local headers
#include "binned_reference_set.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_ref_set_index_mapper.h"

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
static void rotate_elements(const std::uint64_t range_limit,
    const std::uint64_t rotation_factor,
    std::vector<std::uint64_t> &elements_inout)
{
    // rotate a group of elements by a rotation factor
    for (std::uint64_t &element : elements_inout)
        element = math::mod_add(element, rotation_factor, range_limit);
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
// deterministically generate unique members of a bin (return indices within the bin)
//-------------------------------------------------------------------------------------------------------------------
static void make_normalized_bin_members(const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &bin_generator_seed,
    const std::uint64_t bin_locus,
    const std::uint64_t bin_index_in_set,
    std::vector<std::uint64_t> &members_of_bin_out)
{
    // checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(bin_config.num_bin_members > 0,
        "making normalized bin members: zero bin members were requested (at least one expected).");
    CHECK_AND_ASSERT_THROW_MES(bin_config.num_bin_members <= bin_width,
        "making normalized bin members: too many bin members were requested (cannot exceed bin width).");

    // early return case
    if (bin_width == 1)
    {
        members_of_bin_out.clear();
        members_of_bin_out.resize(bin_config.num_bin_members, 0);
        return;
    }

    // we will discard randomly generated bin members that don't land in a multiple of the bin width
    // - set clip allowed max to be a large multiple of the bin width (minus 1 since we are zero-basis),
    //   to avoid bias in the bin members
    // example 1:
    //   max = 15  (e.g. 4 bits instead of uint64_t)
    //   bin width = 4
    //   15 = 15 - ((15 mod 4) + 1 mod 4)
    //   15 = 15 - ((3) + 1 mod 4)
    //   15 = 15 - 0
    //   perfect partitioning: [0..3][4..7][8..11][12..15]
    // example 2:
    //   max = 15  (e.g. 4 bits)
    //   bin width = 6
    //   11 = 15 - ((15 mod 6) + 1 mod 6)
    //   11 = 15 - ((3) + 1 mod 6)
    //   11 = 15 - 4
    //   perfect partitioning: [0..5][6..11]
    const std::uint64_t clip_allowed_max{
            std::numeric_limits<std::uint64_t>::max() -
                math::mod(math::mod(std::numeric_limits<std::uint64_t>::max(), bin_width) + 1, bin_width)
        };

    // generate each bin member (as a unique index within the bin)
    // - make 64-byte blobs via hashing, then use each 8-byte block to try to generate a bin member
    //   - getting 8 blocks at a time reduces calls to the hash function
    unsigned char member_generator[64];
    std::size_t member_generator_offset_blocks{0};
    std::uint64_t generator_clip{};
    std::uint64_t member_candidate{};
    std::size_t num_generator_refreshes{0};
    members_of_bin_out.clear();
    members_of_bin_out.reserve(bin_config.num_bin_members);

    for (std::size_t bin_member_index{0}; bin_member_index < bin_config.num_bin_members; ++bin_member_index)
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
                {
                    // make a bin member generator
                    // g = H_64(bin_generator_seed, bin_locus, bin_index_in_set, num_generator_refreshes)
                    SpKDFTranscript transcript{
                            config::HASH_KEY_BINNED_REF_SET_MEMBER,
                            sizeof(bin_generator_seed) + sizeof(bin_locus) + sizeof(bin_index_in_set) + 4
                        };
                    transcript.append("seed", bin_generator_seed);
                    transcript.append("length", bin_locus);
                    transcript.append("bin_index", bin_index_in_set);
                    transcript.append("num_generator_refreshes", num_generator_refreshes);
                    sp_hash_to_64(transcript.data(), transcript.size(), member_generator);
                    ++num_generator_refreshes;
                }

                memcpy(&generator_clip, member_generator + 8*member_generator_offset_blocks, 8);
                generator_clip = SWAP64LE(generator_clip);
                ++member_generator_offset_blocks;
            } while (generator_clip > clip_allowed_max);

            // compute the candidate bin member: generator mod bin_width
            member_candidate = math::mod(generator_clip, bin_width);
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
    const std::uint64_t distribution_min_index{index_mapper.distribution_min_index()};
    const std::uint64_t distribution_max_index{index_mapper.distribution_max_index()};

    CHECK_AND_ASSERT_THROW_MES(real_reference_index >= distribution_min_index &&
            real_reference_index <= distribution_max_index,
        "generating bin loci: real element reference is not within the element distribution.");
    CHECK_AND_ASSERT_THROW_MES(reference_set_size >= 1,
        "generating bin loci: reference set size too small (needs to be >= 1).");
    CHECK_AND_ASSERT_THROW_MES(distribution_min_index <= distribution_max_index,
        "generating bin loci: invalid distribution range.");
    CHECK_AND_ASSERT_THROW_MES(distribution_max_index - distribution_min_index >= 
            compute_bin_width(bin_config.bin_radius) - 1,  //note: range may span uint64_t
        "generating bin loci: bin width is too large for the distribution range.");
    CHECK_AND_ASSERT_THROW_MES(validate_bin_config_v1(reference_set_size, bin_config),
        "generating bin loci: invalid config.");

    const std::uint64_t num_bins{reference_set_size/bin_config.num_bin_members};
    const std::uint64_t distribution_width{distribution_max_index - distribution_min_index + 1};


    /// pick a locus for the real reference's bin

    // 1) define range where the locus may reside (clamp bounds to element distribution range)
    const std::uint64_t real_locus_min{
            math::saturating_sub(real_reference_index, bin_config.bin_radius, distribution_min_index)
        };
    const std::uint64_t real_locus_max{
            math::saturating_add(real_reference_index, bin_config.bin_radius, distribution_max_index)
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
    const std::uint64_t bin_loci_rotation_factor{math::mod_sub(real_locus_flattened, bin_loci[designated_real_bin], 0)};

    // 3) rotate all the bin loci
    rotate_elements(0, bin_loci_rotation_factor, bin_loci);


    /// get bin loci into the element distribution space

    // 1) map the bin loci into the distribution space
    for (std::uint64_t &bin_locus : bin_loci)
        bin_locus = index_mapper.uniform_index_to_element_index(bin_locus);

    // 2) find the bin locus closest to the real locus (the index mapper might have precision loss)
    // WARNING: all possible values in the element distribution space should map to values in uniform space,
    //   otherwise decoy bin loci could be 'ruled out'
    std::uint64_t locus_closest_to_real{0};
    std::uint64_t locus_gap{distribution_width - 1};  //all gaps will be <= the range of locus values
    std::uint64_t smallest_gap;

    for (std::size_t bin_loci_index{0}; bin_loci_index < bin_loci.size(); ++bin_loci_index)
    {
        // test for gaps above and below the locus
        smallest_gap = std::min(
                math::mod_sub(real_locus, bin_loci[bin_loci_index], distribution_width),  //gap below
                math::mod_sub(bin_loci[bin_loci_index], real_locus, distribution_width)   //gap above
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
        bin_locus = math::clamp(bin_locus,
            distribution_min_index + bin_config.bin_radius,
            distribution_max_index - bin_config.bin_radius);
    }

    const std::uint64_t real_locus_shifted{
            math::clamp(real_locus,
                distribution_min_index + bin_config.bin_radius,
                distribution_max_index - bin_config.bin_radius)
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
std::uint64_t compute_bin_width(const std::uint64_t bin_radius)
{
    return 2*bin_radius + 1;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_bin_config_v1(const std::uint64_t reference_set_size, const SpBinnedReferenceSetConfigV1 &bin_config)
{
    // bin width outside bin dimension
    if (bin_config.bin_radius > (std::numeric_limits<ref_set_bin_dimension_v1_t>::max() - 1)/2)
        return false;
    // too many bin members
    if (bin_config.num_bin_members > std::numeric_limits<ref_set_bin_dimension_v1_t>::max())
        return false;
    // can't fit bin members uniquely in bin (note: bin can't contain more than std::uint64_t::max members)
    if (bin_config.num_bin_members > compute_bin_width(bin_config.bin_radius))
        return false;
    // no bin members
    if (bin_config.num_bin_members < 1)
        return false;
    // reference set can't be perfectly divided into bins
    if (bin_config.num_bin_members * (reference_set_size / bin_config.num_bin_members) != reference_set_size)
        return false;

    return true;
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
    const std::uint64_t bin_width{compute_bin_width(bin_config.bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(validate_bin_config_v1(bin_loci.size() * bin_config.num_bin_members, bin_config),
        "binned reference set: invalid bin config.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(bin_loci.begin(), bin_loci.end()),
        "binned reference set: bin loci aren't sorted.");

    for (const std::uint64_t bin_locus : bin_loci)
    {
        CHECK_AND_ASSERT_THROW_MES(bin_locus >= bin_config.bin_radius,
            "binned reference set: the bottom of a proposed bin hangs below 0.");        
        CHECK_AND_ASSERT_THROW_MES(bin_locus <= std::numeric_limits<std::uint64_t>::max() - bin_config.bin_radius,
            "binned reference set: the top of a proposed bin extends above uint64::max().");        
    }

    CHECK_AND_ASSERT_THROW_MES(bin_index_with_real < bin_loci.size(),
        "binned reference set: real element's bin isn't in the bins proposed.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index >= bin_loci[bin_index_with_real] - bin_config.bin_radius,
        "binned reference set: real element is below its proposed bin.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index <= bin_loci[bin_index_with_real] + bin_config.bin_radius,
        "binned reference set: real element is above its proposed bin.");


    /// set real reference's bin rotation factor

    // 1) generate the real bin's bin members' element set indices (normalized and not rotated)
    std::vector<std::uint64_t> members_of_real_bin;
    make_normalized_bin_members(bin_config,
        generator_seed,
        bin_loci[bin_index_with_real],
        bin_index_with_real,
        members_of_real_bin);
    CHECK_AND_ASSERT_THROW_MES(members_of_real_bin.size() == bin_config.num_bin_members,
        "binned reference set: getting normalized bin members failed (bug).");

    // 2) select a random bin member to land on the real reference
    const std::uint64_t designated_real_bin_member{crypto::rand_range<std::uint64_t>(0, bin_config.num_bin_members - 1)};

    // 3) normalize the real reference within its bin (subtract the bottom of the bin)
    const std::uint64_t normalized_real_reference{
            real_reference_index - (bin_loci[bin_index_with_real] - bin_config.bin_radius)
        };

    // 4) compute rotation factor
    binned_reference_set_out.bin_rotation_factor = static_cast<ref_set_bin_dimension_v1_t>(
            math::mod_sub(normalized_real_reference, members_of_real_bin[designated_real_bin_member], bin_width)
        );


    /// set remaining pieces of the output reference set
    binned_reference_set_out.bin_config = bin_config;
    binned_reference_set_out.bin_generator_seed = generator_seed;
    binned_reference_set_out.bin_loci = std::move(bin_loci);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_reference_indices_from_binned_reference_set_v1(const SpBinnedReferenceSetV1 &binned_reference_set,
    std::vector<std::uint64_t> &reference_indices_out)
{
    // initialization
    const std::uint64_t bin_width{compute_bin_width(binned_reference_set.bin_config.bin_radius)};
    const std::uint64_t reference_set_size{
            binned_reference_set.bin_loci.size() * binned_reference_set.bin_config.num_bin_members
        };

    // sanity check the bin config
    if (!validate_bin_config_v1(reference_set_size, binned_reference_set.bin_config))
        return false;

    // rotation factor must be within the bins (normalized)
    if (binned_reference_set.bin_rotation_factor >= bin_width)
        return false;

    // validate bins
    for (const std::uint64_t bin_locus : binned_reference_set.bin_loci)
    {
        // bins must all fit in the range [0, 2^64 - 1]
        if (bin_locus < binned_reference_set.bin_config.bin_radius)
            return false;
        if (bin_locus > std::numeric_limits<std::uint64_t>::max() - binned_reference_set.bin_config.bin_radius)
            return false;
    }

    // add all the bin members
    reference_indices_out.clear();
    reference_indices_out.reserve(reference_set_size);

    std::vector<std::uint64_t> bin_members_temp;

    for (std::size_t bin_index{0}; bin_index < binned_reference_set.bin_loci.size(); ++bin_index)
    {
        // 1) make normalized bin members
        make_normalized_bin_members(binned_reference_set.bin_config,
            binned_reference_set.bin_generator_seed,
            binned_reference_set.bin_loci[bin_index],
            bin_index,
            bin_members_temp);

        // 2) rotate the bin members by the rotation factor
        rotate_elements(bin_width, binned_reference_set.bin_rotation_factor, bin_members_temp);

        // 3) de-normalize the bin members
        denormalize_elements(
            binned_reference_set.bin_loci[bin_index] - binned_reference_set.bin_config.bin_radius,
            bin_members_temp);

        // 4) save the bin members
        reference_indices_out.insert(reference_indices_out.end(), bin_members_temp.begin(), bin_members_temp.end());
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
