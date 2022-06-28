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
#include "tx_misc_utils.h"

//local headers
#include "misc_log_ex.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_transcript.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool keys_are_unique(const std::vector<rct::key> &keys)
{
    for (auto key_it = keys.begin(); key_it != keys.end(); ++key_it)
    {
        if (std::find(keys.begin(), key_it, *key_it) != key_it)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t round_up_to_power_of_2(const std::size_t num)
{
    // next power of 2 >= num
    std::size_t result{1};
    while (result < num)
        result <<= 1;

    return result;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t highest_bit_position(std::size_t num)
{
    // floor(log2(num))
    std::size_t bit_position{static_cast<std::size_t>(-1)};
    while (num > 0)
    {
        ++bit_position;
        num >>= 1;
    }

    return bit_position;
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_equality(const rct::keyV &commitment_set1, const rct::keyV &commitment_set2)
{
    // balance check method chosen from perf test: tests/performance_tests/balance_check.h
    return rct::equalKeys(rct::addKeys(commitment_set1), rct::addKeys(commitment_set2));
}
//-------------------------------------------------------------------------------------------------------------------
void make_bpp_rangeproofs(const std::vector<rct::xmr_amount> &amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    rct::BulletproofPlus &range_proofs_out)
{
    /// range proofs
    // - for output amount commitments
    CHECK_AND_ASSERT_THROW_MES(amounts.size() == amount_commitment_blinding_factors.size(),
        "Mismatching amounts and blinding factors.");

    // make the range proofs
    range_proofs_out = rct::bulletproof_plus_PROVE(amounts, amount_commitment_blinding_factors);
}
//-------------------------------------------------------------------------------------------------------------------
void append_bpp_to_transcript(const rct::BulletproofPlus &bpp_proof, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("V", bpp_proof.V);
    transcript_inout.append("A", bpp_proof.A);
    transcript_inout.append("A1", bpp_proof.A1);
    transcript_inout.append("B", bpp_proof.B);
    transcript_inout.append("r1", bpp_proof.r1);
    transcript_inout.append("s1", bpp_proof.s1);
    transcript_inout.append("d1", bpp_proof.d1);
    transcript_inout.append("L", bpp_proof.L);
    transcript_inout.append("R", bpp_proof.R);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_size_bytes(const std::size_t num_range_proofs, const bool include_commitments)
{
    // BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
    std::size_t proof_size{32 * (2 * highest_bit_position(round_up_to_power_of_2(64 * num_range_proofs)) + 6)};

    // size of commitments that are range proofed (if requested)
    if (include_commitments)
        proof_size += 32 * num_range_proofs;

    return proof_size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_weight(const std::size_t num_range_proofs, const bool include_commitments)
{
    // BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
    // BP+ size (2 range proofs): 32 * 20
    // weight = size(proof) + 0.8 * (32*20*(num range proofs + num dummy range proofs)/2) - size(proof))
    // note: the weight can optionally include the commitments that are range proofed

    // two aggregate range proofs: BP+ size
    const std::size_t size_two_agg_proof{32 * 20};

    // (number of range proofs + dummy range proofs) / 2
    const std::size_t num_two_agg_groups{round_up_to_power_of_2(num_range_proofs) / 2};

    // proof size
    const std::size_t proof_size{bpp_size_bytes(num_range_proofs, false)};  //don't include commitments here

    // size of commitments that are range proofed (if requested)
    const std::size_t commitments_size{
            include_commitments
            ? 32 * num_range_proofs
            : 0
        };

    // return the weight
    return (2 * proof_size + 8 * size_two_agg_proof * num_two_agg_groups) / 10 + commitments_size;
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee)
{
    using boost::multiprecision::uint128_t;
    uint128_t input_sum{0};
    uint128_t output_sum{0};

    for (const auto amnt : input_amounts)
        input_sum += amnt;

    for (const auto amnt : output_amounts)
        output_sum += amnt;
    output_sum += transaction_fee;

    return input_sum == output_sum;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
