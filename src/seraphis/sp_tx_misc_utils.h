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

// misc. utility functions for seraphis transactions
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <utility>
#include <vector>

//forward declarations


namespace sp
{

/**
* TODO: move this to a better file
* 
* brief: rearrange_vector - rearrange a vector given set of old indices
*    - at index 'i', place element 'vec_inout[old_indices[i]]'
*    - requires each 'i' is unique and maps into vec_inout
* param: old_indices - vector of indices into vec_inout
* param: vec_inout - vector to rearrange
* return: false if a bounds check fails
*/
template <typename T>
bool rearrange_vector(const std::vector<std::size_t> &old_indices, std::vector<T> &vec_inout)
{
    // check: vectors are aligned
    if (old_indices.size() != vec_inout.size())
        return false;

    // check: only unique old indices allowed
    for (auto old_indices_it{old_indices.begin()}; old_indices_it != old_indices.end(); ++old_indices_it)
    {
        if (std::find(old_indices.begin(), old_indices_it, *old_indices_it) != old_indices_it)
            return false;
    }

    std::vector<T> temp_vec;
    temp_vec.reserve(vec_inout.size());

    for (std::size_t i{0}; i < old_indices.size(); ++i)
    {
        // check: all old indices are within vec_inout
        if (old_indices[i] >= old_indices.size())
            return false;

        temp_vec.emplace_back(std::move(vec_inout[old_indices[i]]));
    }

    vec_inout = std::move(temp_vec);

    return true;
}
/**
* brief: ref_set_size_from_decomp - compute n^m from decomposition of a reference set
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* return: n^m
* 
* note: use this instead of std::pow() for better control over error states
*/
std::size_t ref_set_size_from_decomp(const std::size_t ref_set_decomp_n, const std::size_t ref_set_decomp_m);
/**
* brief: compute_rangeproof_grouping_size - compute max number of amounts to aggregate in one range proof at a time
*   - given a number of amounts, split them into power-of-2 groups up to 'max num splits' times; e.g. ...
*     n = 7, split = 1: [4, 3]
*     n = 7, split = 2: [2, 2, 2, 1]
*     n = 11, split = 1: [8, 3]
*     n = 11, split = 2: [4, 4, 3]
* param: num_amounts -
* param: max_num_splits -
* return: max number of amounts to aggregate in one range proof
*/
std::size_t compute_rangeproof_grouping_size(const std::size_t num_amounts, const std::size_t max_num_splits);
/**
* brief: make_bpp_rangeproofs - make BP+ range proofs
* param: amounts -
* param: amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: range_proofs_out - set of amount commitments with range proofs
*/
void make_bpp_rangeproofs(const std::vector<rct::xmr_amount> &amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::vector<rct::BulletproofPlus> &range_proofs_out);
/**
* brief: balance_check_equality - balance check between two commitment sets using an equality test
*   - i.e. sum(inputs) ?= sum(outputs)
* param: commitment_set1 -
* param: commitment_set2 -
* return: true/false on balance check result
*/
bool balance_check_equality(const rct::keyV &commitment_set1, const rct::keyV &commitment_set2);
/**
* brief: balance_check_in_out_amnts - balance check between two sets of amounts
*   - i.e. sum(inputs) ?= sum(outputs)
* param: input_amounts -
* param: output_amounts -
* return: true/false on balance check result
*/
bool balance_check_in_out_amnts(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts);

} //namespace sp
