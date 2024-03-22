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
#include "sp_legacy_proof_helpers.h"

//local headers
#include "bulletproofs_plus2.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t round_up_to_power_of_2(const std::size_t num)
{
    // error case: can't round up
    if (num > ~(static_cast<std::size_t>(-1) >> 1))
        return -1;

    // next power of 2 >= num
    std::size_t result{1};
    while (result < num)
        result <<= 1;

    return result;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t highest_bit_position(std::size_t num)
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
//-------------------------------------------------------------------------------------------------------------------
void append_clsag_to_transcript(const rct::clsag &clsag_proof, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("s", clsag_proof.s);
    transcript_inout.append("c1", clsag_proof.c1);
    transcript_inout.append("I", clsag_proof.I);
    transcript_inout.append("D", clsag_proof.D);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t clsag_size_bytes(const std::size_t ring_size)
{
    return 32 * (ring_size + 2);  //does not include 'I', which is treated as a cached value here
}
//-------------------------------------------------------------------------------------------------------------------
void make_bpp2_rangeproofs(const std::vector<rct::xmr_amount> &amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    BulletproofPlus2 &range_proofs_out)
{
    /// range proofs
    // - for output amount commitments
    CHECK_AND_ASSERT_THROW_MES(amounts.size() == amount_commitment_blinding_factors.size(),
        "make bp+2 rangeproofs: mismatching amounts and blinding factors.");

    // make the range proofs
    range_proofs_out = bulletproof_plus2_PROVE(amounts, amount_commitment_blinding_factors);
}
//-------------------------------------------------------------------------------------------------------------------
void append_bpp2_proof_to_transcript(const BulletproofPlus2Proof &bpp2_proof, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("A", bpp2_proof.A);
    transcript_inout.append("A1", bpp2_proof.A1);
    transcript_inout.append("B", bpp2_proof.B);
    transcript_inout.append("r1", bpp2_proof.r1);
    transcript_inout.append("s1", bpp2_proof.s1);
    transcript_inout.append("d1", bpp2_proof.d1);
    transcript_inout.append("L", bpp2_proof.L);
    transcript_inout.append("R", bpp2_proof.R);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_lr_length(const std::size_t num_range_proofs)
{
    // L/R length: ceil(log2(64 * num range proofs)
    return highest_bit_position(round_up_to_power_of_2(64 * num_range_proofs));
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_size_bytes_lr(const std::size_t lr_length)
{
    // BP+ size: 32 * (2 * LR vec size) + 6)
    return 32 * (2 * lr_length + 6);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_size_bytes(const std::size_t num_range_proofs)
{
    // BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
    return bpp_size_bytes_lr(bpp_lr_length(num_range_proofs));
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_weight_lr(const std::size_t lr_length)
{
    CHECK_AND_ASSERT_THROW_MES(lr_length >= 6, "L/R length can not be less than 6: " << lr_length);

    // BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
    // BP+ size (2 range proofs): 32 * 20
    // weight = size(proof) + 0.8 * (32*20*(num range proofs + num dummy range proofs)/2) - size(proof))
    // explanation: 'claw back' 80% of the size of this BP+ if it were split into proofs of pairs of range proofs

    // BP+ size of an aggregate proof with two range proofs
    const std::size_t size_two_agg_proof{32 * 20};

    // number of BP+ proofs if this BP+ were split into proofs of pairs of range proofs
    // num = (range proofs + dummy range proofs) / 2
    const std::size_t num_two_agg_groups = (1 << (lr_length - 6)) >> 1;

    // the proof size
    const std::size_t proof_size{bpp_size_bytes_lr(lr_length)};

    // return the weight
    return (2 * proof_size + 8 * size_two_agg_proof * num_two_agg_groups) / 10;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t bpp_weight(const std::size_t num_range_proofs)
{
    return bpp_weight_lr(bpp_lr_length(num_range_proofs));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
