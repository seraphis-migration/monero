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

////
// Concise Grootle proof: Groth/Bootle parallel one-of-many proof of commitments with a concise construction
// - given a set of equal-sized tuples of EC points S
// - given a same-sized tuple of EC points (offsets) O
// - prove DL knowledge with respect to G of the commitment to zero tuple {S_pi - O} for an index \pi
//   in the set that is unknown to verifiers
// - uses 'aggregation coefficients', a size reduction technique used in CLSAG/Triptych/Lelantus-Spark-CP-proofs
//
// note: to prove DL of a point in S with respect to G directly, set its offset equal to the identity element I
//
// References:
// - One-out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin (Groth): https://eprint.iacr.org/2014/764
// - Short Accountable Ring Signatures Based on DDH (Bootle): https://eprint.iacr.org/2015/643
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
// - Lelantus-Spark (Aram Jivanyan, Aaron Feickert [Sarang Noether]): https://eprint.iacr.org/2021/1173
///


#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/// Maximum matrix entries
constexpr std::size_t GROOTLE_MAX_MN{128};


////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Types ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// concise Grootle proof (using the aggregation coefficients described in Triptych)
///
struct ConciseGrootleProof
{
    rct::key A, B, C, D;
    rct::keyM f;
    rct::keyV X;
    rct::key zA, zC, z;
};


////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////// Handle Proofs /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: concise_grootle_prove - create a concise grootle proof
* param: M - [vec<tuple of commitments>]
* param: l - secret index into {{M}}
* param: C_offsets - offsets for commitment to zero at index l
* param: privkeys - privkeys of commitments to zero in 'M[l] - C_offsets'
* param: n - decomp input set: n^m
* param: m - ...
* param: message - message to insert in Fiat-Shamir transform hash
* return: Grootle proof
*/
ConciseGrootleProof concise_grootle_prove(const rct::keyM &M,
    const std::size_t l,
    const rct::keyV &C_offsets,
    const std::vector<crypto::secret_key> &privkeys,
    const std::size_t n,
    const std::size_t m,
    const rct::key &message);
/**
* brief: concise_grootle_verify - verify a batch of concise grootle proofs that share a reference set
* param: proofs - batch of proofs to verify
* param: M - (shared) [vec<tuple of commitments>]
* param: proof_offsets - (per-proof) offsets for commitments to zero at unknown indices in each proof
* param: n - decomp input set: n^m
* param: m - ...
* param: message - (per-proof) message to insert in Fiat-Shamir transform hash
* return: true/false on verification result
*/
bool concise_grootle_verify(const std::vector<const ConciseGrootleProof*> &proofs,
    const rct::keyM &M,
    const rct::keyM &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages);

} //namespace sp
