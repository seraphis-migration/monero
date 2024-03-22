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

// Miscellaneous utility functions.

#pragma once

//local headers
#include "bulletproofs_plus2.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

/**
* brief: append_clsag_to_transcript - append CLSAG proof to a transcript
*   transcript += {s} || c1 || I || D
* param: clsag_proof -
* inoutparam: transcript_inout - contents appended to a transcript
*/
void append_clsag_to_transcript(const rct::clsag &clsag_proof, SpTranscriptBuilder &transcript_inout);
/**
* brief: clsag_size_bytes - get the size of a CLSAG proof in bytes
*   - CLSAG size: 32 * (ring size + 2)
*   note: the main key image 'I' is not included (it is assumed to be a cached value)
* param: ring_size -
* return: the CLSAG proof's size in bytes
*/
std::size_t clsag_size_bytes(const std::size_t ring_size);
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
*   transcript += A || A1 || B || r1 || s1 || d1 || {L} || {R}
* param: bpp_proof -
* inoutparam: transcript_inout - contents appended to a transcript
*/
void append_bpp2_proof_to_transcript(const BulletproofPlus2Proof &bpp_proof,
    SpTranscriptBuilder &transcript_inout);
/**
 * brief: bpp_lr_length - get the length of the BP+ L/R vectors, given the number of range proofs
 *   - L/R length: ceil(log2(64 * num range proofs)
*/
std::size_t bpp_lr_length(const std::size_t num_range_proofs);
/**
* brief: bpp_size_bytes - get the size of a BP+ proof in bytes (excluding commitments)
*   - BP+ size: 32 * (2*ceil(log2(64 * num range proofs)) + 6)
* param: num_range_proofs -
* param: lr_length - length of the L/R proof vectors
* return: the BP+ proof's size in bytes
*/
std::size_t bpp_size_bytes(const std::size_t num_range_proofs);
std::size_t bpp_size_bytes_lr(const std::size_t lr_length);
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
* param: lr_length - length of the L/R proof vectors
* return: the BP+ proof's weight
*/
std::size_t bpp_weight(const std::size_t num_range_proofs);
std::size_t bpp_weight_lr(const std::size_t lr_length);

} //namespace sp
