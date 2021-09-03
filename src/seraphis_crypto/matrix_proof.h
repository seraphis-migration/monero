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
// Schnorr-like matrix proof between a vector of base keys and vector of private keys.
// - base keys: {B} = {B1, B2, ..., Bn}
// - private keys: {k} = {k1, k2, ..., kn}
// - public keys per base key: V1 = {k1 B1, k2 B1, ..., kn B1}
// - all public keys: M = {{V}} = {V1, V2, ... Vn}
// - 1. demonstrates knowledge of all {k}
// - 2. demonstrates that members of each public key set in {V1, V2, ... Vn} have a 1:1 discrete-log equivalence with the
//      members of the other public key sets across the base keys {B}
// - 3. guarantees that {{V}} contain canonical prime-order subgroup group elements (pubkeys are stored multiplied by
//      (1/8) then multiplied by 8 before verification)
// NOTE: does not allow signing with different private keys on different base keys (e.g. the pair {k1 G1, k2 G2}), this
//       proof is designed mainly for showing discrete log equivalence across multiple bases (with the bonus of being
//       efficient when you have multiple such proofs to construct in parallel)
// NOTE2: at one base key this proof degenerates into a simple Schnorr signature, which can be useful for making signatures
//        across arbitrary base keys
//
// proof outline
// 0. preliminaries
//    H_32(...) = blake2b(...) -> 32 bytes   hash to 32 bytes (domain separated)
//    H_n(...)  = H_64(...) mod l            hash to ed25519 scalar (domain separated)
//    {B}: assumed to be ed25519 keys
// 1. proof nonce and challenge
//    given: m, {B}, {k}
//    {{V}} = {k} * {B}
//    mu = H_n(m, {B}, {{V}})       aggregation coefficient
//    cm = H(mu)                    challenge message
//    a = rand()                    prover nonce
//    c = H_n(cm, [a*B1], [a*B2], ..., [a*Bn])
// 2. aggregate response
//    r = a - c * sum_i(mu^i * k_i)
// 3. proof: {m, c, r, {{V}}}
//
// verification
// 1. mu, cm = ...
// 2. c' = H_n(cm, [r*B1 + c*sum_i(mu^i*V_1[i])], [r*B2 + c*sum_i(mu^i*V_2[i])], ...)
// 3. if (c' == c) then the proof is valid
//
// note: proofs are 'concise' using the powers-of-aggregation coefficient approach from Triptych
//
// References:
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
// - Zero to Monero 2 (koe, Kurt Alonso, Sarang Noether): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
//   - informational reference: Sections 3.1 and 3.2
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

struct MatrixProof
{
    // message
    rct::key m;
    // challenge
    rct::key c;
    // response
    rct::key r;
    // pubkeys matrix (stored multiplied by (1/8)); each inner vector uses a different base key
    std::vector<std::vector<crypto::public_key>> M;
};
inline const boost::string_ref container_name(const MatrixProof&) { return "MatrixProof"; }
void append_to_transcript(const MatrixProof &container, SpTranscriptBuilder &transcript_inout);

/**
* brief: make_matrix_proof - create a matrix proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: B - base keys B1, B2, ...
* param: privkeys - secret keys k1, k2, ...
* outparam: proof_out - the proof
*/
void make_matrix_proof(const rct::key &message,
    const std::vector<crypto::public_key> &B,
    const std::vector<crypto::secret_key> &privkeys,
    MatrixProof &proof_out);
/**
* brief: verify_matrix_proof - verify a matrix proof
* param: proof - proof to verify
* param: B - base keys B1, B2, ...
* return: true/false on verification result
*/
bool verify_matrix_proof(const MatrixProof &proof, const std::vector<crypto::public_key> &B);

} //namespace sp
