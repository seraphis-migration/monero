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

//paired header
#include "multisig_signer_set_filter.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "seraphis_crypto/math_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <cstdint>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool check_multisig_config_for_filter(const std::uint32_t threshold, const std::uint32_t num_signers)
{
    if (num_signers > 8*sizeof(signer_set_filter))
        return false;
    if (threshold > num_signers)
        return false;

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static signer_set_filter right_shift_filter(const signer_set_filter filter, const std::uint32_t num_bits)
{
    // note: it is UB to bitshift 32-bit and 64-bit uints by more than 'bitlength(T) - 1'
    return num_bits < 8*sizeof(signer_set_filter)
        ? filter >> num_bits
        : 0;
}
//----------------------------------------------------------------------------------------------------------------------
// get filter with least significant 'num_bits' flags set
//----------------------------------------------------------------------------------------------------------------------
static signer_set_filter get_squashed_full_filter(const std::uint32_t num_bits)
{
    return right_shift_filter(static_cast<signer_set_filter>(-1), 8*sizeof(signer_set_filter) - num_bits);
}
//----------------------------------------------------------------------------------------------------------------------
// map a filter mask onto the set bits of an aggregate filter (ignore all unset bits in the aggregate filter)
// - ex: mask=[1010], agg=[00110110] -> ret=[00100100]
//----------------------------------------------------------------------------------------------------------------------
static signer_set_filter apply_mask_to_filter(signer_set_filter filter_mask, signer_set_filter aggregate_filter)
{
    signer_set_filter temp_filter{0};
    std::uint32_t agg_filter_position{0};

    // find the first set bit in the aggregate filter
    while (aggregate_filter && !(aggregate_filter & 1))
    {
        aggregate_filter >>= 1;
        ++agg_filter_position;
    }

    while (filter_mask && aggregate_filter)
    {
        // set the return filter's flag at the aggregate filter position if the reference filter's top flag is set
        temp_filter |= ((filter_mask & 1) << agg_filter_position);

        // find the next set bit in the aggregate filter
        do
        {
            aggregate_filter >>= 1;
            ++agg_filter_position;
        } while (aggregate_filter && !(aggregate_filter & 1));

        // remove the reference filter's last flag
        filter_mask >>= 1;
    }

    return temp_filter;
}
//----------------------------------------------------------------------------------------------------------------------
// - assumes input signer is a member of the list
//----------------------------------------------------------------------------------------------------------------------
static std::size_t signer_index_in_list(const crypto::public_key &signer,
    const std::vector<crypto::public_key> &signer_list)
{
    std::size_t signer_index{0};
    for (const crypto::public_key &other_signer : signer_list)
    {
        if (signer == other_signer)
            break;
        ++signer_index;
    }

    return signer_index;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
std::uint32_t get_num_flags_set(signer_set_filter filter)
{
    // note: will compile to 'popcnt' on supporting architectures (std::popcount needs C++20)
    std::uint32_t set_flags_count{0};
    for (; filter != 0; filter &= filter - 1)
        ++set_flags_count;

    return set_flags_count;
}
//----------------------------------------------------------------------------------------------------------------------
bool validate_multisig_signer_set_filter(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter filter)
{
    // the filter should only have flags set for possible signers
    if (!check_multisig_config_for_filter(threshold, num_signers))
        return false;
    if (right_shift_filter(filter, num_signers) != 0)
        return false;

    // the filter should only have 'threshold' number of flags set
    if (get_num_flags_set(filter) != threshold)
        return false;

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
bool validate_multisig_signer_set_filters(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<signer_set_filter> &filters)
{
    for (const signer_set_filter filter : filters)
    {
        if (!validate_multisig_signer_set_filter(threshold, num_signers, filter))
            return false;
    }

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
bool validate_aggregate_multisig_signer_set_filter(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter aggregate_filter)
{
    const std::uint32_t num_signers_requested{get_num_flags_set(aggregate_filter)};

    return (num_signers_requested >= threshold) &&
        validate_multisig_signer_set_filter(num_signers_requested, num_signers, aggregate_filter);
}
//----------------------------------------------------------------------------------------------------------------------
void aggregate_multisig_signer_set_filter_to_permutations(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter aggregate_filter,
    std::vector<signer_set_filter> &filter_permutations_out)
{
    CHECK_AND_ASSERT_THROW_MES(check_multisig_config_for_filter(threshold, num_signers),
        "Invalid multisig config when getting filter permutations.");

    const std::uint32_t num_flags_set{get_num_flags_set(aggregate_filter)};

    CHECK_AND_ASSERT_THROW_MES(num_flags_set <= num_signers &&
            num_flags_set >= threshold,
        "Invalid aggregate multisig signer set filter when getting filter permutations.");

    const std::uint32_t expected_num_permutations(sp::math::n_choose_k(num_flags_set, threshold));
    filter_permutations_out.clear();
    filter_permutations_out.reserve(expected_num_permutations);

    // start getting permutations with the filter where the first 'threshold' signers in the aggregate filter are set
    signer_set_filter filter_mask{get_squashed_full_filter(threshold)};

    // apply all masks where 'threshold' flags are set
    do
    {
        // if found a useful bit pattern, map it onto the aggregate filter and save that permutation
        if (get_num_flags_set(filter_mask) == threshold)
        {
            filter_permutations_out.emplace_back(apply_mask_to_filter(filter_mask, aggregate_filter));

            CHECK_AND_ASSERT_THROW_MES(validate_multisig_signer_set_filter(threshold,
                    num_signers,
                    filter_permutations_out.back()),
                "Invalid multisig set filter extracted from aggregate filter.");
        }
    //note: post-increment the reference filter so the filter 'just used' is tested
    //note2: do-while pattern lets us use == to exit the loop, which supports the case where we need to exit after the
    //       mask equals the max value of a filter (i.e. when all the flags are set)
    } while (filter_mask++ < get_squashed_full_filter(num_flags_set));

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(filter_permutations_out.size() == expected_num_permutations,
        "Invalid number of permutations when disaggregating a signer set filter. (bug)");
}
//----------------------------------------------------------------------------------------------------------------------
void multisig_signers_to_filter(const std::vector<crypto::public_key> &allowed_signers,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out)
{
    CHECK_AND_ASSERT_THROW_MES(check_multisig_config_for_filter(0, signer_list.size()),
        "Invalid multisig config when making multisig signer filters.");
    CHECK_AND_ASSERT_THROW_MES(allowed_signers.size() <= signer_list.size(),
        "Invalid number of allowed signers when making multisig signer filters.");

    for (const crypto::public_key &allowed_signer : allowed_signers)
    {
        CHECK_AND_ASSERT_THROW_MES(std::find(signer_list.begin(), signer_list.end(), allowed_signer) != signer_list.end(),
            "Unknown allowed signer when making multisig signer filters.");
    }

    // make aggregate filter from all allowed signers
    aggregate_filter_out = 0;

    for (const crypto::public_key &allowed_signer : allowed_signers)
        aggregate_filter_out |= signer_set_filter{1} << signer_index_in_list(allowed_signer, signer_list);
}
//----------------------------------------------------------------------------------------------------------------------
void multisig_signers_to_filter(const std::unordered_set<crypto::public_key> &allowed_signers,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out)
{
    // convert: unordered_set -> vector
    std::vector<crypto::public_key> allowed_signers_temp;
    allowed_signers_temp.reserve(allowed_signers.size());
    for (const crypto::public_key &allowed_signer : allowed_signers)
        allowed_signers_temp.emplace_back(allowed_signer);

    multisig_signers_to_filter(allowed_signers_temp, signer_list, aggregate_filter_out);
}
//----------------------------------------------------------------------------------------------------------------------
void multisig_signer_to_filter(const crypto::public_key &allowed_signer,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out)
{
    multisig_signers_to_filter(std::vector<crypto::public_key>{allowed_signer}, signer_list, aggregate_filter_out);
}
//----------------------------------------------------------------------------------------------------------------------
void get_filtered_multisig_signers(const signer_set_filter filter,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &signer_list,
    std::vector<crypto::public_key> &filtered_signers_out)
{
    CHECK_AND_ASSERT_THROW_MES(validate_multisig_signer_set_filter(threshold, signer_list.size(), filter),
        "Invalid signer set filter when filtering a list of multisig signers.");

    filtered_signers_out.clear();
    filtered_signers_out.reserve(threshold);

    // filter the signer list
    for (std::size_t signer_index{0}; signer_index < signer_list.size(); ++signer_index)
    {
        if ((filter >> signer_index) & 1)
            filtered_signers_out.emplace_back(signer_list[signer_index]);
    }
}
//----------------------------------------------------------------------------------------------------------------------
bool signer_is_in_filter(const crypto::public_key &signer,
    const std::vector<crypto::public_key> &signer_list,
    const signer_set_filter test_filter)
{
    signer_set_filter temp_filter;
    multisig_signer_to_filter(signer, signer_list, temp_filter);
    return temp_filter & test_filter;
}
//----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
