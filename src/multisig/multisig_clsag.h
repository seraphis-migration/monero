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
// Multisig utilities for CLSAG proofs.
//
// multisig notation: alpha_{n,e}
// - n: for MuSig2-style bi-nonce signing, alpha_{1,e} is nonce 'D', alpha_{2,e} is nonce 'E' (in their notation)
// - e: multisig signer index in the signer group
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
// - MRL-0009 (Brandon Goodell and Sarang Noether): https://web.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_nonce_cache.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace multisig
{

////
// Multisig signature proposal for CLSAG proofs
//
// WARNING: must only use a proposal to make ONE signature, after that the shared decoy responses stored here
//          should be deleted immediately
///
struct CLSAGMultisigProposal final
{
    // message to be signed
    rct::key message;
    // ring of proof keys {main keys, auxilliary keys (Pedersen commitments)}
    rct::ctkeyV ring_members;
    // masked Pedersen commitment at index l (commitment to zero: ring_members[l].mask - masked_C = z G)
    rct::key masked_C;
    // main key image KI
    // note: KI = k * Hp(ring_members[l].dest)
    crypto::key_image KI;
    // ancillary key image D (note: D is stored as '1/8 * D' in the rct::clsag struct, but is stored unmultiplied here)
    // note: D = z * Hp(ring_members[l].dest)
    crypto::key_image D;
    // decoy responses for each {proof key, ancillary proof key} pair (the decoy at index l will be replaced by
    //    the real multisig aggregate response in the final proof)
    rct::keyV decoy_responses;

    // signing key pair's index in the ring
    std::uint32_t l;
};

/// range-checked access to the signing main proof pubkey
const rct::key& main_proof_key_ref(const CLSAGMultisigProposal &proposal);
/// range-checked access to the signing auxilliary proof pubkey
const rct::key& auxilliary_proof_key_ref(const CLSAGMultisigProposal &proposal);

////
// Multisig partially signed CLSAG (from one multisig participant)
// - stores multisig partial response for proof position at index l
// note: does not store ring members because those are not included in the final rct::clsag; ring members are hashed
//       into c_0, so checking that c_0 is consistent between partial sigs is sufficient to ensure partial sigs
//       are combinable
///
struct CLSAGMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key main_proof_key_K;
    // signing key pair's index in the ring
    std::uint32_t l;

    // responses for each {proof key, ancillary proof key} pair 
    // - the response at index l is this multisig partial signature's partial response
    rct::keyV responses;
    // challenge
    rct::key c_0;
    // key image KI
    crypto::key_image KI;
    // ancillary key image D
    crypto::key_image D;
};

/**
* brief: make_clsag_multisig_proposal - propose to make a multisig CLSAG proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: ring_members - ring of proof keys {main key, auxiliary key (Pedersen commitments)}
* param: masked_C - masked auxilliary proof key at index l
*                   commitment to zero: ring_members[l].mask - masked_C = z G
* param: KI - main key image
* param: D - auxilliary key image
* param: l - index of the signing keys in the key ring
* outparam: proposal_out - CLSAG multisig proposal
*/
void make_clsag_multisig_proposal(const rct::key &message,
    rct::ctkeyV ring_members,
    const rct::key &masked_C,
    const crypto::key_image &KI,
    const crypto::key_image &D,
    const std::uint32_t l,
    CLSAGMultisigProposal &proposal_out);
/**
* brief: make_clsag_multisig_partial_sig - make local multisig signer's partial signature for a CLSAG proof
*   - caller must validate the CLSAG multisig proposal
*       - are the key images well-made?
*       - are the main key, ancillary key, and masked key legitimate?
*       - is the message correct?
*       - are all the decoy ring members valid?
* param: proposal - proof proposal to use when constructing the partial signature
* param: k_e - secret key of multisig signer e for main proof key at position l
* param: z_e - secret key of multisig signer e for commitment to zero at position l (for the auxilliary component)
* param: signer_pub_nonces_G - signature nonce pubkeys (1/8) * {alpha_{1,e}*G,  alpha_{2,e}*G} from all signers
*                              (including local signer)
* param: signer_pub_nonces_Hp - signature nonce pubkeys (1/8) * {alpha_{1,e}*Hp(K[l]),  alpha_{2,e}*Hp(K[l])} from all
*                              signers (including local signer)
* param: local_nonce_1_priv - alpha_{1,e} for local signer
* param: local_nonce_2_priv - alpha_{2,e} for local signer
* outparam: partial_sig_out - partially signed CLSAG
*/
void make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    CLSAGMultisigPartial &partial_sig_out);
/**
* brief: try_make_clsag_multisig_partial_sig - make a partial signature using a nonce record (nonce safety guarantee)
*   - caller must validate the CLSAG multisig proposal
* param: ...(see make_clsag_multisig_partial_sig())
* param: filter - filter representing the multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for making partial signatures; used nonces will be cleared
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout,
    CLSAGMultisigPartial &partial_sig_out);
/**
* brief: finalize_clsag_multisig_proof - create a CLSAG proof from multisig partial signatures
* param: partial_sigs - partial signatures from the multisig subgroup that collaborated on this proof
* param: ring_members - ring member keys used by the proof (for validating the assembled proof)
* param: masked_commitment - masked commitment used by the proof (for validating the assembled proof)
* outparam: proof_out - CLSAG
*/
void finalize_clsag_multisig_proof(const std::vector<CLSAGMultisigPartial> &partial_sigs,
    const rct::ctkeyV &ring_members,
    const rct::key &masked_commitment,
    rct::clsag &proof_out);

} //namespace multisig
