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

////
// Grootle proof: Groth/Bootle one-of-many proof of a commitment to zero
// - given a set of EC points S
// - given an EC point (the offset) O
// - prove DL knowledge with respect to G of the commitment to zero {S_l - O} for an index l
//   in the set that is unknown to verifiers
// - allows proof batching (around (2*n*m)/(n^m + 2*n*m) amortization speedup possible)
//   - limitations: assumes each proof uses a different reference set (proofs with the same ref set could be MUCH
//     faster), can only batch proofs with the same decomposition (n^m)
//
// note: to prove DL of a point in S with respect to G directly, set the offset equal to the identity element I
//
// References:
// - One-out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin (Groth): https://eprint.iacr.org/2014/764
// - Short Accountable Ring Signatures Based on DDH (Bootle): https://eprint.iacr.org/2015/643
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
// - Lelantus-Spark (Aram Jivanyan, Aaron Feickert [Sarang Noether]): https://eprint.iacr.org/2021/1173
// - MatRiCT (Esgin et. al; section 1.3 for A/B optimization): https://eprint.iacr.org/2019/1287.pdf
///

#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <list>
#include <vector>

//forward declarations
namespace sp
{
    class SpTranscriptBuilder;
    class SpMultiexpBuilder;
}

namespace sp
{

/// Maximum matrix entries
constexpr std::size_t GROOTLE_MAX_MN{128};  //2^64, 3^42, etc.

////
// Grootle proof: Groth/Bootle proof using the A/B optimization from MatRiCT
///
struct GrootleProof
{
    rct::key A;
    rct::key B;
    rct::keyM f;
    rct::keyV X;
    rct::key zA;
    rct::key z;
};
inline const boost::string_ref container_name(const GrootleProof&) { return "GrootleProof"; }
void append_to_transcript(const GrootleProof &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
std::size_t grootle_size_bytes(const std::size_t n, const std::size_t m);
std::size_t grootle_size_bytes(const GrootleProof &proof);

/**
* brief: make_grootle_proof - create a grootle proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: S - referenced commitments
* param: l - secret index into {S}
* param: C_offset - offset for commitment to zero at index l
* param: privkey - privkey of commitment to zero 'S[l] - C_offset' (proof signing key)
* param: n - decomposition of the reference set size: n^m
* param: m - ...
* outparam: proof_out - Grootle proof
*/
void make_grootle_proof(const rct::key &message,
    const rct::keyV &S,
    const std::size_t l,
    const rct::key &C_offset,
    const crypto::secret_key &privkey,
    const std::size_t n,
    const std::size_t m,
    GrootleProof &proof_out);
/**
* brief: verify_grootle_proofs - verify a batch of grootle proofs
* param: proofs - batch of proofs to verify
* param: message - (per-proof) message to insert in Fiat-Shamir transform hash
* param: S - (per-proof) referenced commitments
* param: proof_offsets - (per-proof) offset for commitment to zero at unknown indices in each proof
* param: n - decomposition of the reference set size: n^m
* param: m - ...
* return: true/false on verification result
*/
void get_grootle_verification_data(const std::vector<const GrootleProof*> &proofs,
    const rct::keyV &messages,
    const std::vector<rct::keyV> &S,
    const rct::keyV &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    std::list<SpMultiexpBuilder> &verification_data_out);
bool verify_grootle_proofs(const std::vector<const GrootleProof*> &proofs,
    const rct::keyV &messages,
    const std::vector<rct::keyV> &M,
    const rct::keyV &proof_offsets,
    const std::size_t n,
    const std::size_t m);

} //namespace sp
