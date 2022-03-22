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
// Schnorr-like dual-base proof for a pair of vectors: V_1 = {k_1 G1, k_2 G1, ...}, V_2 = {k_1 G2, k_2 G2, ...}
// - demonstrates knowledge of all k_1, k_2, k_3, ...
// - demonstrates that members of V_1 have a 1:1 discrete-log equivalence with the members of V_2, across generators G1, G2
//
// note: uses 'concise' technique for smaller proofs, with the powers-of-aggregation coefficient approach from Triptych
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

//standard headers
#include <vector>

//forward declarations


namespace crypto
{

struct DualBaseVectorProof
{
    // challenge
    rct::key c;
    // response
    rct::key r;
    // pubkeys
    rct::keyV V_1;
    rct::keyV V_2;
    // message
    rct::key m;
};

/**
* brief: dual_base_vector_prove - create a dual base vector proof
* param: G_1 - generator of first vector
* param: G_2 - generator of second
* param: k - secret keys k_1, k_2, ...
* param: message - message to insert in Fiat-Shamir transform hash
* return: proof
*/
DualBaseVectorProof dual_base_vector_prove(const rct::key &G_1,
    const rct::key &G_2,
    const std::vector<crypto::secret_key> &k,
    const rct::key &message);
/**
* brief: dual_base_vector_verify - verify a dual base vector proof
* param: proof - proof to verify
* param: G_1 - generator of first vector
* param: G_2 - generator of second vector
* return: true/false on verification result
*/
bool dual_base_vector_verify(const DualBaseVectorProof &proof,
    const rct::key &G_1,
    const rct::key &G_2);

} //namespace crypto
