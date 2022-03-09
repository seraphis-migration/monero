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

#include "multisig_signer_set_filter.h"

#include "misc_log_ex.h"
#include "ringct/rctTypes.h"

#include <boost/math/special_functions/binomial.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  static bool check_multisig_config(const std::uint32_t num_signers,
    const std::uint32_t threshold)
  {
    if (num_signers > 8*sizeof(signer_set_filter))
      return false;
    if (threshold > num_signers)
      return false;

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // TODO: move to a 'math' library, with unit tests
  //----------------------------------------------------------------------------------------------------------------------
  static std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
  {
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
      "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
      return 0;

    double fp_result = boost::math::binomial_coefficient<double>(n, k);

    if (fp_result < 0)
      return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
      return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  static std::uint32_t get_num_flags_set(signer_set_filter filter)
  {
    // note: will compile to 'popcnt' on supporting architectures (std::popcount needs C++20)
    std::uint32_t set_flags_count{0};
    for (; filter != 0; filter &= filter - 1)
      ++set_flags_count;

    return set_flags_count;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // get filter with least significant 'num_bits' flags set
  //----------------------------------------------------------------------------------------------------------------------
  static signer_set_filter get_squashed_full_filter(const std::uint32_t num_bits)
  {
    return static_cast<signer_set_filter>(-1) >> (8*sizeof(signer_set_filter) - num_bits);
  }
  //----------------------------------------------------------------------------------------------------------------------
  // map a reference filter onto the set bits of an aggregate filter
  // - ex: ref=[1010], agg=[00110111] -> ret=[00100100]
  //----------------------------------------------------------------------------------------------------------------------
  static signer_set_filter reference_filter_to_filter(signer_set_filter reference_filter,
    signer_set_filter aggregate_filter)
  {
    signer_set_filter temp_filter{0};
    std::uint32_t agg_filter_position{0};

    while (reference_filter)
    {
      // find the next set bit in the aggregate filter
      while (aggregate_filter && !(aggregate_filter & 1))
      {
        aggregate_filter >>= 1;
        ++agg_filter_position;
      }

      // set the return filter's flag at the aggregate filter position if the reference filter's top flag is set
      temp_filter |= ((reference_filter & 1) << agg_filter_position);

      // remove the reference filter's last flag
      reference_filter >>= 1;
    }

    return temp_filter;
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  bool validate_multisig_signer_set_filter(const std::uint32_t num_signers,
    const std::uint32_t threshold,
    const signer_set_filter filter)
  {
    // the filter should only have flags set for possible signers
    if (!check_multisig_config(num_signers, threshold))
      return false;
    if ((filter >> num_signers) != 0)
      return false;

    // the filter should only have 'threshold' number of flags set
    if (get_num_flags_set(filter) != threshold)
      return false;

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  bool validate_multisig_signer_set_filters(const std::uint32_t num_signers,
    const std::uint32_t threshold,
    const std::vector<signer_set_filter> &filters)
  {
    for (const signer_set_filter filter : filters)
    {
      if (!validate_multisig_signer_set_filter(num_signers, threshold, filter))
        return false;
    }

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  void aggregate_multisig_signer_set_filter_to_permutations(const std::uint32_t num_signers,
    const std::uint32_t threshold,
    const signer_set_filter aggregate_filter,
    std::vector<signer_set_filter> &filter_permutations_out)
  {
    CHECK_AND_ASSERT_THROW_MES(check_multisig_config(num_signers, threshold),
      "Invalid multisig config when getting filter permutations");

    const std::uint32_t num_flags_set{get_num_flags_set(aggregate_filter)};

    CHECK_AND_ASSERT_THROW_MES(num_flags_set <= num_signers &&
      num_flags_set >= threshold,
      "Invalid aggregate multisig signer set filter when getting filter permutations.");

    filter_permutations_out.clear();
    filter_permutations_out.reserve(n_choose_k(num_flags_set, threshold));

    // start the permutation search at the filter where the first 'threshold' signers in the aggregate filter are set
    signer_set_filter reference_filter{get_squashed_full_filter(threshold)};

    // look through all possible 'squashed' bit sequences for sequences where 'threshold' flags are set
    while (reference_filter != get_squashed_full_filter(num_flags_set) + 1)
    {
      // if found a match, map the bit pattern onto the aggregate filter
      if (get_num_flags_set(reference_filter) == threshold)
        filter_permutations_out.emplace_back(reference_filter_to_filter(reference_filter, aggregate_filter));

      ++reference_filter;
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
  void get_filtered_multisig_signers(const std::vector<rct::key> &signer_list,
    const std::uint32_t threshold,
    const signer_set_filter filter,
    std::vector<rct::key> &filtered_signers_out)
  {
    CHECK_AND_ASSERT_THROW_MES(validate_multisig_signer_set_filter(signer_list.size(), threshold, filter),
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
  void allowed_multisig_signers_to_aggregate_filter(const std::vector<rct::key> &signer_list,
    const std::vector<rct::key> &allowed_signers,
    const std::uint32_t threshold,
    signer_set_filter &aggregate_filter_out)
  {
    CHECK_AND_ASSERT_THROW_MES(check_multisig_config(signer_list.size(), threshold),
      "Invalid multisig config when making multisig signer filters.");
    CHECK_AND_ASSERT_THROW_MES(allowed_signers.size() <= signer_list.size() &&
      allowed_signers.size() >= threshold,
      "Invalid number of allowed signers when making multisig signer filters.");

    for (const rct::key &allowed_signer : allowed_signers)
    {
      CHECK_AND_ASSERT_THROW_MES(std::find(signer_list.begin(), signer_list.end(), allowed_signer) != signer_list.end(),
        "Unknown allowed signer when making multisig signer filters.");
    }

    // make aggregate filter from all allowed signers
    aggregate_filter_out = 0;

    for (std::size_t signer_index{0}; signer_index < signer_list.size(); ++signer_index)
    {
      if (std::find(allowed_signers.begin(), allowed_signers.end(), signer_list[signer_index]) != allowed_signers.end())
        aggregate_filter_out |= signer_set_filter{1} << signer_index;
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
