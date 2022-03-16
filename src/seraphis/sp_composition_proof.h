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
// Schnorr-like composition proof for a se key of the form K = x*G + y*X + z*U
// - demonstrates knowledge of x, y, z
//   - x >= 0
//   - y, z > 0
// - shows that key image KI = (z/y)*U
//
// note: G_0 = G, G_1 = X, G_2 = U (for Seraphis paper notation)
// note: in practice, K is a masked address from a Seraphis e-note-image, and KI is the corresponding linking tag
// note: assume key image KI is in the prime subgroup (canonical bytes) and non-identity
//   - WARNING: the caller must validate KI (and check non-identity); either...
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// multisig notation: alpha_{a,n,e}
// - a: indicates which part of the proof this is for
// - n: for MuSig2-style bi-nonce signing, alpha_{b,1,e} is nonce 'D', alpha_{b,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
// - MRL-0009 (Brandon Goodell and Sarang Noether): https://web.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
// - Zero to Monero: 2nd Edition Chapter 9 (UkoeHB): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
// - (Technical Note) Multisig - Defeating Drijvers with Bi-Nonce Signing (UkoeHB):
//     https://github.com/UkoeHB/drijvers-multisig-tech-note
///


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>
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
struct SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1, r_t2, r_ki;
    // intermediate proof key (stored as (1/8)*K_t1)
    rct::key K_t1;
    // key image KI: not stored with proof
    // main proof key K: not stored with proof
    // message m: not stored with proof
};

////
// Multisig signature proposal
// - all parts required to make signature, other than the (KI component) split between multisig participants
//
// WARNING: must only use a 'proposal' to make ONE 'signature' (or signature attempt),
//          after that the opening privkeys should be deleted immediately
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
// Multisig prep struct
// - store multisig participant's MuSig2-style signature opening nonces for KI component
//   - multisig assumes only proof component KI is subject to multisig signing (key z is split between signers)
//
// WARNING: must only use a 'prep' to make ONE 'partial signature',
//          after that the opening nonce privkeys should be deleted immediately
// WARNING2: the nonce privkeys are for local storage, only the pubkeys should be transmitted to other multisig participants
///
struct SpCompositionProofMultisigPrep final
{
    // signature nonce privkey: alpha_{ki,1,e}
    crypto::secret_key signature_nonce_1_KI_priv;
    // signature nonce pubkey: alpha_{ki,1,e}*U
    rct::key signature_nonce_1_KI_pub;
    // signature nonce privkey: alpha_{ki,2,e}
    crypto::secret_key signature_nonce_2_KI_priv;
    // signature nonce pubkey: alpha_{ki,2,e}*U
    rct::key signature_nonce_2_KI_pub;
};

////
// Multisig nonce record
// - store a multisig participant's nonces for multiple signing attempts
//   - multiple messages to sign
//   - multiple signer groups per message
///
class SpCompositionProofMultisigNonceRecord final
{
public:
//constructors: default
//member functions
    /// true if there is a record
    bool has_record(const rct::key &message,
        const multisig::signer_set_filter &filter) const;
    /// true if successfully added nonces
    bool try_add_nonces(const rct::key &message,
        const multisig::signer_set_filter &filter,
        const SpCompositionProofMultisigPrep &prep);
    /// true if found privkeys
    bool try_get_recorded_nonce_privkeys(const rct::key &message,
        const multisig::signer_set_filter &filter,
        crypto::secret_key &nonce_privkey_1_out,
        crypto::secret_key &nonce_privkey_2_out) const;
    /// true if found pubkeys
    bool try_get_recorded_nonce_pubkeys(const rct::key &message,
        const multisig::signer_set_filter &filter,
        rct::key &nonce_pubkey_1_out,
        rct::key &nonce_pubkey_2_out) const;
    /// true if removed a record
    bool try_remove_record(const rct::key &message,
        const multisig::signer_set_filter &filter);

//member variables
private:
    // [message : [filter, nonces]]
    std::unordered_map<
            rct::key,                                //message
            std::unordered_map<
                    multisig::signer_set_filter,      //filter representing a signer group
                    SpCompositionProofMultisigPrep   //nonces
                >
        > m_record;
};

////
// Multisig partially signed composition proof (from one multisig participant)
// - multisig assumes only proof component KI is subject to multisig signing (key z is split between signers)
// - store signature opening for KI component (response r_ki)
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
    rct::key r_t1, r_t2;
    // intermediate proof key K_t1
    rct::key K_t1;

    // partial response for r_ki (from one multisig participant)
    rct::key r_ki_partial;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Main /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_prove - create a Seraphis composition proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: x - secret key
* param: y - secret key
* param: z - secret key
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z);
/**
* brief: sp_composition_verify - verify a Seraphis composition proof
* param: proof - proof to verify
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: KI - proof key image = (z/y) U
* return: true/false on verification result
*/
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Multisig ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_multisig_proposal - propose to make a multisig Seraphis composition proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: K - main proof key
* param: KI - key image
* return: Seraphis composition proof multisig proposal
*/
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI);
/**
* brief: sp_composition_multisig_init - prepare for making a multisig Seraphis composition proof
* return: multisig participant's prep work for a Seraphis composition proof
*/
SpCompositionProofMultisigPrep sp_composition_multisig_init();
/**
* brief: sp_composition_multisig_partial_sig - make local multisig signer's partial signature for a Seraphis composition
*        proof
*   - caller must validate 'proposal'
*       - is the key image well-made?
*       - is the main key legitimate?
*       - is the message correct?
* param: proposal - proof proposal to construct proof partial signature from
* param: x - secret key
* param: y - secret key
* param: z_e - secret key of multisig signer e
* param: signer_nonces_pub_1 - signature nonce pubkeys alpha_{ki,1,e}*U from all signers (including local signer)
* param: signer_nonces_pub_2 - signature nonce pubkeys alpha_{ki,2,e}*U from all signers (including local signer)
* param: local_nonce_1_priv - alpha_{ki,1,e} for local signer
* param: local_nonce_2_priv - alpha_{ki,2,e} for local signer
* return: partially signed Seraphis composition proof
*/
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const rct::keyV &signer_nonces_pub_1,
    const rct::keyV &signer_nonces_pub_2,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv);
/**
* brief: try_get_sp_composition_multisig_partial_sig - make a partial signature using a nonce record (nonce safety guarantee)
*        proof
*   - caller must validate 'proposal'
*       - is the key image well-made?
*       - is the main key legitimate?
*       - is the message correct?
* param: ...(see sp_composition_multisig_partial_sig())
* param: filter - filter representing a multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for makeing partial signatures; used nonces will be cleared
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_get_sp_composition_multisig_partial_sig(
    const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const rct::keyV &signer_nonces_pub_1,
    const rct::keyV &signer_nonces_pub_2,
    const multisig::signer_set_filter filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: sp_composition_prove_multisig_final - create a Seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs);

} //namespace sp
