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

// Miscellaneous utility functions for making Seraphis transactions.


#pragma once

//local headers
#include "bulletproofs_plus2.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <string>
#include <utility>
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }


namespace sp
{

/// use operator< to get operator==
/// WARNING: use with caution, since equality is not always implied by operator<, depending on implementation
struct equals_from_less final
{
    template <typename T>
    bool operator()(const T &a, const T &b)
    {
        return !(a < b) && !(b < a);
    }
};

/**
* brief: ref_set_size_from_decomp - compute n^m from decomposition of a reference set
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* return: n^m
* 
* note: use this instead of std::pow() for better control over error states
*/
constexpr std::size_t ref_set_size_from_decomp(const std::size_t ref_set_decomp_n, const std::size_t ref_set_decomp_m)
{
    // ref set size = n^m
    std::size_t ref_set_size{ref_set_decomp_n};

    if (ref_set_decomp_n == 0 || ref_set_decomp_m == 0)
        ref_set_size = 1;
    else
    {
        for (std::size_t mul{1}; mul < ref_set_decomp_m; ++mul)
        {
            if (ref_set_size*ref_set_decomp_n < ref_set_size)  //overflow
                return -1;
            else
                ref_set_size *= ref_set_decomp_n;
        }
    }

    return ref_set_size;
}
/**
* brief: keys_are_unique - check if keys in a vector are unique
* param: keys -
* return: true if keys are unique
*/
bool keys_are_unique(const std::vector<rct::key> &keys);
/**
* brief: round_up_to_power_of_2 - next power of 2 >= the input number
*   TODO: move to better file?
* param: num -
* return: the next power of 2 >= the input num
*/
std::size_t round_up_to_power_of_2(const std::size_t num);
/**
* brief: highest_bit_position - equivalent to floor(log2(num))
*   TODO: move to better file?
* param: num -
* return: floor(log2(num))
*/
std::size_t highest_bit_position(const std::size_t num);
/**
* brief: make_bpp2_rangeproofs - make a BP+ v2 proof that aggregates several range proofs
* param: amounts -
* param: amount_commitment_blinding_factors -
* outparam: range_proofs_out - aggregate set of amount commitments with range proofs
*/
void make_bpp2_rangeproofs(const std::vector<rct::xmr_amount> &amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    BulletproofPlus2 &range_proofs_out);
/**
* brief: append_bpp2_to_transcript - append BP+ v2 proof to a transcript
*   transcript += {V} || A || A1 || B || r1 || s1 || d1 || {L} || {R}
* param: bpp_proof -
* inoutparam: transcript_inout - contents appended to a transcript
*/
void append_bpp2_to_transcript(const BulletproofPlus2 &bpp_proof, SpTranscriptBuilder &transcript_inout);
/**
* brief: bpp_size_bytes - get the size of a BP+ proof in bytes
*   - BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
* param: num_range_proofs -
* param: include_commitments -
* return: the BP+ proof's size in bytes
*/
std::size_t bpp_size_bytes(const std::size_t num_range_proofs, const bool include_commitments);
/**
* brief: bpp_weight - get the 'weight' of a BP+ proof
*   - Verifying a BP+ is linear in the number of aggregated range proofs, but the proof size is logarithmic,
*     so the cost of verifying a BP+ isn't proportional to the proof size. To get that proportionality, we 'claw back'
*     some of the 'aggregated' proof's size.
*   - An aggregate BP+ has 'step-wise' verification costs. It contains 'dummy range proofs' so that the number of
*     actual aggregated proofs equals the next power of 2 >= the number of range proofs desired.
*   - To 'price in' the additional verification costs from batching range proofs, we add a 'clawback' to the proof size,
*     which gives us the proof 'weight'. The clawback is the additional proof size if all the range proofs and dummy
*     range proofs were split into 2-aggregate BP+ proofs (with a 20% discount as 'reward' for using an aggregate proof).
* 
*   weight = size(proof) + clawback
*   clawback = 0.8 * [(num range proofs + num dummy range proofs)*size(BP+ proof with 2 range proofs) - size(proof)]
* param: num_range_proofs -
* param: include_commitments -
* return: the BP+ proof's weight
*/
std::size_t bpp_weight(const std::size_t num_range_proofs, const bool include_commitments);
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
*   - i.e. sum(inputs) ?= sum(outputs) + transaction_fee
* param: input_amounts -
* param: output_amounts -
* param: transaction_fee -
* return: true/false on balance check result
*/
bool balance_check_in_out_amnts(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee);

} //namespace sp
