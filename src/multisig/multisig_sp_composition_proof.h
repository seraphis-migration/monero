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
// Multisig utilities for the seraphis composition proof.
//
// multisig notation: alpha_{ki,n,e}
// - ki: indicates that multisig signing is on the key image part of the proof
// - n: for MuSig2-style bi-nonce signing, alpha_{ki,1,e} is nonce 'D', alpha_{ki,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index in the signer group
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_nonce_cache.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_composition_proof.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace multisig
{

////
// Multisig signature proposal for seraphis composition proofs
//
// WARNING: must only use a proposal to make ONE signature, after that the shared signature nonces stored here
//          should be deleted immediately
///
struct SpCompositionProofMultisigProposal final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // signature nonce (shared component): alpha_t1
    crypto::secret_key signature_nonce_K_t1;
    // signature nonce (shared component): alpha_t2
    crypto::secret_key signature_nonce_K_t2;
};

////
// Multisig partially signed composition proof (from one multisig signer)
// - only proof component KI is subject to multisig signing (proof privkey z is split between signers)
// - r_ki is the partial response from this multisig signer
///
struct SpCompositionProofMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // challenge
    rct::key c;
    // responses r_t1, r_t2
    rct::key r_t1;
    rct::key r_t2;
    // intermediate proof key K_t1
    rct::key K_t1;

    // partial response for r_ki (from one multisig signer)
    rct::key r_ki_partial;
};

/**
* brief: make_sp_composition_multisig_proposal - propose to make a multisig seraphis composition proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: K - main proof key
* param: KI - key image
* outparam: proposal_out - proposal
*/
void make_sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    SpCompositionProofMultisigProposal &proposal_out);
/**
* brief: make_sp_composition_multisig_partial_sig - make local multisig signer's partial signature for a seraphis
*        composition proof
*   - caller must validate the multisig proposal
*       - is the key image well-made and canonical?
*       - is the main key legitimate?
*       - is the message correct?
* param: proposal - proof proposal to use when constructing the partial signature
* param: x - secret key
* param: y - secret key
* param: z_e - secret key of multisig signer e
* param: signer_pub_nonces - signature nonce pubkeys (1/8) * {alpha_{ki,1,e}*U,  alpha_{ki,2,e}*U} from all signers
*                            (including local signer)
* param: local_nonce_1_priv - alpha_{ki,1,e} for local signer
* param: local_nonce_2_priv - alpha_{ki,2,e} for local signer
* outparam: partial_sig_out - partially signed seraphis composition proof
*/
void make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: try_make_sp_composition_multisig_partial_sig - make a partial signature using a nonce record (nonce safety
*        guarantee)
*   - caller must validate the multisig proposal
* param: ...(see make_sp_composition_multisig_partial_sig())
* param: filter - filter representing the multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for making partial signatures; used nonces will be cleared here
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_make_sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: finalize_sp_composition_multisig_proof - create a seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig signers to complete a full proof
* outparam: proof_out - seraphis composition proof
*/
void finalize_sp_composition_multisig_proof(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs,
    sp::SpCompositionProof &proof_out);

} //namespace multisig
