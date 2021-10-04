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
// Schnorr-like composition proof for a set of keys of the form K_i = x_i*G + y_i*X + z_i*U
// - demonstrates knowledge of all x_i, y_i, z_i
//   - x_i >= 0
//   - y_i, z_i > 0
// - shows that key images KI_i = (z_i/y_i)*U
// 
// note: uses 'concise' technique for smaller proofs, with the powers-of-aggregation coefficient approach from Triptych
// note2: G_0 = G, G_1 = X, G_2 = U (for Seraphis paper notation)
// note3: in practice, K_i are masked addresses from Seraphis e-note-images, and KI_i are the corresponding linking tags
// note4: assume key images KI are in the prime subgroup (canonical bytes)
//   - WARNING: the caller must validate KI
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// multisig notation: alpha_{e,b}
// - e: multisig signer index
// - b: indicates which part of the proof this is for
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Types ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// Seraphis composition proof
///
struct SpCompositionProof
{
    // challenge
    rct::key c;
    // condensed responses
    rct::key r_a, r_b;
    // un-condensible responses
    rct::keyV r_i;
    // intermediate proof keys
    rct::keyV K_t1;
    // key images KI: not stored with proof
    // main proof keys K: not stored with proof
    // message m: not stored with proof
};

////
// Multisig signature proposal
// - all parts required to make signature, other than part (KI component) split between multisig participants
//
// WARNING: must only use a 'proposal' to make ONE 'signature',
//          after that the opening privkeys should be deleted immediately
///
struct SpCompositionProofMultisigProposal
{
    // key images KI
    rct::keyV KI;
    // main proof keys K
    rct::keyV K;
    // message
    rct::key message;

    // signature opening privkey: alpha_{e,a}
    rct::key signature_opening_K_t2_priv;
    // signature opening privkeys: alpha_{e,i}
    rct::keyV signature_opening_K_t1_privs;
};

////
// Multisig prep struct
// - store signature opening for KI component
//   - multisig assumes only proof component KI is subject to multisig signing (keys z_i split between signers)
// 
// WARNING: must only use a 'prep' to make ONE 'partial signature',
//          after that the opening privkey should be deleted immediately
// WARNING2: the privkey is for local storage, only the pubkey should be transmitted to other multisig participants
///
struct SpCompositionProofMultisigPrep
{
    // signature opening privkey: alpha_{e,b}
    rct::key signature_opening_KI_priv;
    // signature opening pubkey: alpha_{e,b}*U
    rct::key signature_opening_KI_pub;
};

////
// Multisig partially signed composition proof
// - multisig assumes only proof component KI is subject to multisig signing (keys z_i split between signers)
// - store signature opening for KI component (response r_b)
///
struct SpCompositionProofMultisigPartial
{
    // challenge
    rct::key c;
    // condensed response r_a
    rct::key r_a;
    // un-condensible responses
    rct::keyV r_i;
    // intermediate proof keys
    rct::keyV K_t1;
    // key images KI
    rct::keyV KI;
    // main proof keys K
    rct::keyV K;
    // message
    rct::key message;

    // partial response for r_b (from one multisig participant)
    rct::key r_b_partial;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Main /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_prove - create a Seraphis composition proof
* param: K - main proof keys
* param: x - secret keys (x_i)
* param: y - secret keys (y_i)
* param: z - secret keys (z_i)
* param: message - message to insert in Fiat-Shamir transform hash
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove(const rct::keyV &K,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z,
    const rct::key &message);
/**
* brief: sp_composition_verify - verify a Seraphis composition proof
* param: proof - proof to verify
* param: K - main proof keys
* param: KI - proof key images
* param: message - message to insert in Fiat-Shamir transform hash
* return: true/false on verification result
*/
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::keyV &K,
    const rct::keyV &KI,
    const rct::key &message);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Multisig ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_multisig_proposal - propose to make a multisig Seraphis composition proof
* param: KI - key images KI
* param: K - main proof keys K
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* return: Seraphis composition proof multisig proposal
*/
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::keyV &KI,
    const rct::keyV &K,
    const rct::key &message);
/**
* brief: sp_composition_multisig_init - prepare for making a multisig Seraphis composition proof
* return: multisig participant's prep work for a Seraphis composition proof
*/
SpCompositionProofMultisigPrep sp_composition_multisig_init();
/**
* brief: sp_composition_multisig_response - make local multisig signer's partial signature for a Seraphis composition proof
*   - caller must validate 'proposal'
*       - are key images well-made?
*       - are main keys legitimate?
*       - is message correct?
* param: proposal - proof proposal to construct proof partial signature from
* param: x - secret keys (x_i)
* param: y - secret keys (y_i)
* param: z_e - secret keys of multisig signer (z_{e,i})
* param: signer_openings - signature opening pubkeys alpha_{e,b}*U from all signers
* param: local_opening_priv - alpha_{e,b} for local signer
* param: message - message to insert in Fiat-Shamir transform hash
* return: partially signed Seraphis composition proof
*/
SpCompositionProofMultisigPartial sp_composition_multisig_response(const SpCompositionProofMultisigProposal &proposal,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z_e,
    const rct::keyV &signer_openings,
    const rct::key &local_opening_priv,
    const rct::key &message);
/**
* brief: sp_composition_prove_multisig_final - create a Seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs);

} //namespace sp
