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

////
// Grootle proof: Groth/Bootle parallel one-of-many proof of commitments
// - given a set of equal-sized tuples of EC points S
// - given a same-sized tuple of EC points (offsets) O
// - prove DL knowledge with respect to G of the commitment to zero tuple {S_pi - O} for an index \pi
//   in the set that is unknown to verifiers
//
// References:
// - Short Accountable Ring Signatures Based on DDH (Bootle): https://eprint.iacr.org/2015/643
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
// - Lelantus Spark (Aram Jivanyan, Aaron Feickert [Sarang Noether]): https://eprint.iacr.org/2021/1173
///


#pragma once

//local headers
#include "rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

/// Maximum matrix entries
constexpr std::size_t GROOTLE_MAX_MN{128};


/// concise Grootle proof (using the consise approach described in Triptych)
struct ConciseGrootleProof
{
    rct::key J;
    rct::key K;
    rct::key A,B,C,D;
    rct::keyV X,Y;
    rct::keyM f;
    rct::key zA,zC,z;
};

/// create a concise grootle proof
ConciseGrootleProof concise_grootle_prove(const rct::keyV &M,
    const rct::keyV &P,
    const rct::key &C_offset,
    const std::size_t l,
    const rct::key &r,
    const rct::key &s,
    const std::size_t n,
    const std::size_t m,
    const rct::key &message);

/// verify a set of concise grootle proofs that share a reference set
bool concise_grootle_verify(const std::vector<const ConciseGrootleProof*> &proofs,
    const rct::keyV &M,     // shared
    const rct::keyV &P,     // shared
    const rct::keyV &C_offsets, // per-proof
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages); //per-proof

} //namespace sp
