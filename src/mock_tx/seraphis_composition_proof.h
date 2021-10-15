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
//   - WARNING: the caller must validate KI; either...
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// multisig notation: alpha_{b,n,e}
// - b: indicates which part of the proof this is for
// - n: for Frost-style bi-nonce signing, alpha_{b,1,e} is nonce 'D', alpha_{b,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
//
// Multisig references:
// - FROST (Komlo): https://eprint.iacr.org/2020/852.pdf
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375.pdf
// - MRL-0009 (Brandon Goodell and Sarang Noether): https://web.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
// - Zero to Monero: 2nd Edition Chapter 9 (UkoeHB): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
///


#pragma once

//local headers
#include "crypto/crypto.h"
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
    // intermediate proof keys (stored as (1/8)*KI)
    rct::keyV K_t1;
    // key images KI: not stored with proof
    // main proof keys K: not stored with proof
    // message m: not stored with proof
};

////
// Multisig signature proposal
// - all parts required to make signature, other than the (KI component) split between multisig participants
//
// WARNING: must only use a 'proposal' to make ONE 'signature',
//          after that the opening privkeys should be deleted immediately
///
struct SpCompositionProofMultisigProposal
{
    // key images KI
    std::vector<crypto::key_image> KI;
    // main proof keys K
    rct::keyV K;
    // message
    rct::key message;

    // signature opening: alpha_{e,a}
    rct::key signature_opening_K_t2;
    // signature openings: alpha_{e,i}
    rct::keyV signature_openings_K_t1;
};

////
// Multisig prep struct
// - store multisig participant's FROST-style signature opening nonces for KI component
//   - multisig assumes only proof component KI is subject to multisig signing (keys z_i split between signers)
//
// WARNING: must only use a 'prep' to make ONE 'partial signature',
//          after that the opening privkey should be deleted immediately
// WARNING2: the privkey is for local storage, only the pubkey should be transmitted to other multisig participants
///
struct SpCompositionProofMultisigPrep
{
    // signature opening privkey: alpha_{b,1,e}
    crypto::secret_key signature_opening_1_KI_priv;
    // signature opening pubkey: alpha_{b,1,e}*U
    rct::key signature_opening_1_KI_pub;
    // signature opening privkey: alpha_{b,2,e}
    crypto::secret_key signature_opening_2_KI_priv;
    // signature opening pubkey: alpha_{b,2,e}*U
    rct::key signature_opening_2_KI_pub;
};

////
// Multisig partially signed composition proof (from one multisig participant)
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
    std::vector<crypto::key_image> KI;
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
    const std::vector<crypto::secret_key> &x,
    const std::vector<crypto::secret_key> &y,
    const std::vector<crypto::secret_key> &z,
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
    const std::vector<crypto::key_image> &KI,
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
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const std::vector<crypto::key_image> &KI,
    const rct::keyV &K,
    const rct::key &message);
/**
* brief: sp_composition_multisig_init - prepare for making a multisig Seraphis composition proof
* return: multisig participant's prep work for a Seraphis composition proof
*/
SpCompositionProofMultisigPrep sp_composition_multisig_init();
/**
* brief: sp_composition_multisig_partial_sig - make local multisig signer's partial signature for a Seraphis composition
*        proof
*   - caller must validate 'proposal'
*       - are key images well-made?
*       - are main keys legitimate?
*       - is message correct?
* param: proposal - proof proposal to construct proof partial signature from
* param: x - secret keys (x_i)
* param: y - secret keys (y_i)
* param: z_e - secret keys of multisig signer (z_{e,i})
* param: signer_openings_1 - signature opening pubkeys alpha_{b,1,e}*U from all signers (including local signer)
* param: signer_openings_2 - signature opening pubkeys alpha_{b,2,e}*U from all signers (including local signer)
* param: local_opening_1_priv - alpha_{b,1,e} for local signer
* param: local_opening_2_priv - alpha_{b,2,e} for local signer
* return: partially signed Seraphis composition proof
*/
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const std::vector<crypto::secret_key> &x,
    const std::vector<crypto::secret_key> &y,
    const std::vector<crypto::secret_key> &z_e,
    const rct::keyV &signer_openings_1,
    const rct::keyV &signer_openings_2,
    const crypto::secret_key &local_opening_1_priv,
    const crypto::secret_key &local_opening_2_priv);
/**
* brief: sp_composition_prove_multisig_final - create a Seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs);

} //namespace sp
