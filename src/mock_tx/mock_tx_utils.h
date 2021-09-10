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

// Mock tx interface
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace crypto
{
// type conversions for easier calls to sc_add(), sc_sub()
static inline unsigned char *operator &(crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<unsigned char &>(scalar);
}
static inline const unsigned char *operator &(const crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<const unsigned char &>(scalar);
}
} //namespace crypto


namespace mock_tx
{

/**
* brief: ref_set_size_from_decomp - compute n^m from decomposition of a reference set
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* return: n^m
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
* return: set of amount commitments with range proofs
*/
std::vector<rct::BulletproofPlus> make_bpp_rangeproofs(const std::vector<rct::xmr_amount> &amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits);
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

} //namespace mock_tx








