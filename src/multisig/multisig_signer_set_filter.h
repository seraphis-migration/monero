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

#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"

//third party headers

//standard headers
#include <cstdint>
#include <unordered_set>
#include <vector>

//forward declarations


namespace multisig
{

/**
* multisig signer set filter
* - a set of multisig signers, represented as bit flags that correspond 1:1 with a list of sorted signer ids
*/
using signer_set_filter = std::uint64_t;
static_assert(8*sizeof(signer_set_filter) >= config::MULTISIG_MAX_SIGNERS, "");

/**
* brief: get_num_flags_set - count how many flags are set in a filter
* param: filter - a set of signer flags
* return: number of flags set in the filter
*/
std::uint32_t get_num_flags_set(signer_set_filter filter);
/**
* brief: validate_multisig_signer_set_filter - check that a signer set is valid
*   - check: only possible signers are flagged
*   - check: only 'threshold' number of signers are flagged
* param: threshold - threshold of multisig (M)
* param: num_signers - number of participants in multisig (N)
* param: filter - a filter representation of multisig signers to validate
* return: true/false on validation result
*/
bool validate_multisig_signer_set_filter(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter filter);
bool validate_multisig_signer_set_filters(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<signer_set_filter> &filters);
/**
* brief: validate_aggregate_multisig_signer_set_filter - check that an aggregate signer set is valid
*   - check: only possible signers are flagged
*   - check: at least 'threshold' number of signers are flagged (more than threshold are allowed)
* param: threshold - threshold of multisig (M)
* param: num_signers - number of participants in multisig (N)
* param: aggregate_filter - an aggregate set of multisig signers to validate
* return: true/false on validation result
*/
bool validate_aggregate_multisig_signer_set_filter(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter aggregate_filter);
/**
* brief: aggregate_multisig_signer_set_filter_to_permutations - extract filters from an aggregate filter
*   - An aggregate filter is bitwise-or between all contained filters.
*   - Every permutation of 'threshold' number of signers from the aggregate set is a separate signer set that can
*     collaborate on a multisig signature. Dis-aggregating the aggregate filter provides filters corresponding
*     to each of those sets.
* param: threshold - number of signers a filter can represent
* param: num_signers - total number of signers the filter acts on
* param: aggregate_filter - signer set filter that can represent multiple filters each representing threshold signers
* outparam: filter_permutations_out - all the filters that can be extracted from the aggregate filter
*/
void aggregate_multisig_signer_set_filter_to_permutations(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const signer_set_filter aggregate_filter,
    std::vector<signer_set_filter> &filter_permutations_out);
/**
* brief: multisig_signers_to_filter - represent a set of multisig signers as an aggregate filter
* param: allowed_signers - the signers from the signer list that should be represented in the filter
* param: signer_list - list of signer ids (should be sorted)
* outparam: aggregate_filter_out - an aggregate filter that maps the allowed signer list to the signer list
*/
void multisig_signers_to_filter(const std::vector<crypto::public_key> &allowed_signers,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out);
void multisig_signers_to_filter(const std::unordered_set<crypto::public_key> &allowed_signers,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out);
void multisig_signer_to_filter(const crypto::public_key &allowed_signer,
    const std::vector<crypto::public_key> &signer_list,
    signer_set_filter &aggregate_filter_out);
/**
* brief: get_filtered_multisig_signers - filter a signer list using a signer_set_filter
* param: filter - signer set filter
* param: threshold - number of signers the filter is expected to represent
* param: signer_list - list of signer ids (should be sorted)
* outparam: filtered_signers_out - a filtered set of multisig signer ids
*/
void get_filtered_multisig_signers(const signer_set_filter filter,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &signer_list,
    std::vector<crypto::public_key> &filtered_signers_out);
/**
* brief: signer_is_in_filter - check if a signer is in a filter
* param: signer - signer to check
* param: signer_list - list of signer ids to look for the signer in (should be sorted)
* param: test_filter - filter to apply to the signer list
*/
bool signer_is_in_filter(const crypto::public_key &signer,
    const std::vector<crypto::public_key> &signer_list,
    const signer_set_filter test_filter);

} //namespace multisig
