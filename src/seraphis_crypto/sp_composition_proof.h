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
// Schnorr-like composition proof for a key of the form K = x*G + y*X + z*U
// - demonstrates knowledge of secrets x, y, z
//   - x, y, z > 0
// - shows that key image KI = (z/y)*U
//
// proof outline
// 0. preliminaries
//    hash to 32 bytes (domain separated):       H_32(...) = blake2b(...) -> 32 bytes
//    hash to ed25519 scalar (domain separated): H_n(...)  = H_64(...) mod l
//    ed25519 generators: G, X, U
// 1. pubkeys
//    K    = x*G + y*X + z*U
//    K_t1 = (x/y)*G + X + (z/y)*U = (1/y)*K
//    K_t2 = (x/y)*G               = K_t1 - X - KI
//    KI   = (z/y)*U
// 2. proof nonces and challenge
//    cm = H_32(X, U, m, K, KI, K_t1)             challenge message
//    a_t1, a_t2, a_ki = rand()                   prover nonces
//    c = H_n(cm, [a_t1 K], [a_t2 G], [a_ki U])   challenge
// 3. responses
//    r_t1 = a_t1 - c*(1/y)
//    r_t2 = a_t2 - c*(x/y)
//    r_ki = a_ki - c*(z/y)
// 4. proof: {m, c, r_t1, r_t2, r_ki, K, K_t1, KI}
//
// verification
// 1. K_t2 = K_t1 - X - KI, cm = ...
// 2. c' = H_n(cm, [r_t1*K + c*K_t1], [r_t2*G + c*K_t2], [r_ki*U + c*KI])
// 3. if (c' == c) then the proof is valid
//
// proof explanation
// 1. prove transform: K_t1 = (1/y)*K  (invert X component to create key image inside K_t1)
// 2. prove DL on G: (x/y)*G = K_t2 = K_t1 - X - KI  (peel X and KI out of K_t1, show only G component remains; removing
//    X here proves that step 1 correctly inverted the X component)
// 3. prove DL on U: KI = (z/y) U  (key image has DL on only U)
//
// note: G_0 = G, G_1 = X, G_2 = U (for Seraphis paper notation)
// note: in practice, K is a masked address from a Seraphis enote image, and KI is the corresponding 'linking tag'
// note: assume key image KI is in the prime subgroup (canonical bytes) and non-identity
//   - WARNING: the caller must validate KI (and check non-identity); either...
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
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

////
// Seraphis composition proof
///
struct SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1;
    rct::key r_t2;
    rct::key r_ki;
    // intermediate proof key (stored as (1/8)*K_t1)
    rct::key K_t1;

    // message m: not stored with proof
    // main proof key K: not stored with proof
    // key image KI: not stored with proof
};
inline const boost::string_ref container_name(const SpCompositionProof&) { return "SpCompositionProof"; }
void append_to_transcript(const SpCompositionProof &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_composition_size_bytes() { return 32*5; }

/**
* brief: make_sp_composition_proof - create a seraphis composition proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: x - secret key
* param: y - secret key
* param: z - secret key
* outparam: proof_out - seraphis composition proof
*/
void make_sp_composition_proof(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    SpCompositionProof &proof_out);
/**
* brief: verify_sp_composition_proof - verify a seraphis composition proof
*   - PRECONDITION: KI is not identity and contains no torsion elements (the caller must perform those tests)
* param: proof - proof to verify
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: KI - proof key image = (z/y) U
* return: true/false on verification result
*/
bool verify_sp_composition_proof(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI);


////
// detail namespace for internal proof computations
// - these are needed for e.g. multisig
///
namespace composition_proof_detail
{

rct::key compute_challenge_message(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    const rct::key &K_t1);
rct::key compute_challenge(const rct::key &challenge_message,
    const rct::key &K_t1_proofkey,
    const rct::key &K_t2_proofkey,
    const rct::key &KI_proofkey);
void compute_responses(const rct::key &challenge,
    const rct::key &alpha_t1,
    const rct::key &alpha_t2,
    const rct::key &alpha_ki,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    rct::key &r_t1_out,
    rct::key &r_t2_out,
    rct::key &r_ki_out);
void compute_K_t1_for_proof(const crypto::secret_key &y, const rct::key &K, rct::key &K_t1_out);

} //namespace composition_proof_detail
} //namespace sp
