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

// Tool for making multisig partial signatures in a type-agnostic way for a range of signature schemes.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_clsag.h"
#include "multisig_signer_set_filter.h"
#include "multisig_signing_helper_types.h"
#include "multisig_sp_composition_proof.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations
namespace multisig { class MultisigNonceCache; }

namespace multisig
{

////
// MultisigPartialSigMaker
// - interface for producing multisig partial signatures, agnostic to the signature scheme (it must be Schnorr-like
//   and use musig2-style multisig via MultisigNonceCache)
// - must support wrapping multiple multisig signature proposals, which are accessed via the primary proof key
///
class MultisigPartialSigMaker
{
public:
//destructor
    virtual ~MultisigPartialSigMaker() = default;

//overloaded operators
    /// disable copy/move (this is a virtual base class)
    MultisigPartialSigMaker& operator=(MultisigPartialSigMaker&&) = delete;

//member functions
    /**
    * brief: attempt_make_partial_sig - attempt to make a partial multisig signature (i.e. partially sign using the local
    *        multisig signer's private key)
    *   - throws on failure
    * param: proof_message - proof message to make a signature for
    * param: proof_key - proof key of one of the multisig proposals stored in this signature maker
    * param: signer_group_filter - filter representing the subgroup of multisig signers who are expected to participate
    *        in making this partial signature (i.e. their public nonces will be used)
    * param: signer_group_pub_nonces - the public nonces the signers who are participating in this signature attempt;
    *        the main vector lines up with the nonce base keys used in the proof (e.g. G and Hp(proof key) for CLSAG, and
    *        U for sp composition proofs); the internal vector lines up with the signers participating in this signature
    *        attempt
    * param: local_multisig_signing_key - the local multisig signer's multisig signing key for the multisig subgroup
    *        represented by 'signer_group_filter'
    * inoutparam: nonce_record_inout - the nonce record from which the local signer's nonce private keys for this
    *             signing attempt will be extracted
    * outparam: partial_sig_out - partial signature created by the local signer for the specified signature proposal and
    *           signing group
    */
    virtual void attempt_make_partial_sig(const rct::key &proof_message,
        const rct::key &proof_key,
        const signer_set_filter signer_group_filter,
        const std::vector<std::vector<MultisigPubNonces>> &signer_group_pub_nonces,
        const crypto::secret_key &local_multisig_signing_key,
        MultisigNonceCache &nonce_record_inout,
        MultisigPartialSigVariant &partial_sig_out) const = 0;
};

////
// MultisigPartialSigMakerCLSAG: make CLSAG multisig partial signatures
///
class MultisigPartialSigMakerCLSAG final : public MultisigPartialSigMaker
{
public:
//constructors
    /// normal constructor: data to wrap
    MultisigPartialSigMakerCLSAG(const std::uint32_t threshold,
        const std::vector<CLSAGMultisigProposal> &proof_proposals,
        const std::vector<crypto::secret_key> &proof_privkeys_k_offset,
        const std::vector<crypto::secret_key> &proof_privkeys_z);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    MultisigPartialSigMakerCLSAG& operator=(MultisigPartialSigMakerCLSAG&&) = delete;

//member functions
    void attempt_make_partial_sig(const rct::key &proof_message,
        const rct::key &proof_key,
        const signer_set_filter signer_group_filter,
        const std::vector<std::vector<MultisigPubNonces>> &signer_group_pub_nonces,
        const crypto::secret_key &local_multisig_signing_key,
        MultisigNonceCache &nonce_record_inout,
        MultisigPartialSigVariant &partial_sig_out) const override;

//member variables
private:
    const rct::key m_inv_threshold;  // 1/threshold
    const std::vector<CLSAGMultisigProposal> &m_proof_proposals;
    const std::vector<crypto::secret_key> &m_proof_privkeys_k_offset;
    const std::vector<crypto::secret_key> &m_proof_privkeys_z;

    // cached proof keys mapped to indices in the set of proof proposals
    std::unordered_map<rct::key, std::size_t> m_cached_proof_keys;
};

////
// MultisigPartialSigMakerSpCompositionProof: make seraphis composition proof multisig partial signatures
///
class MultisigPartialSigMakerSpCompositionProof final : public MultisigPartialSigMaker
{
public:
//constructors
    /// normal constructor: data to wrap
    MultisigPartialSigMakerSpCompositionProof(const std::uint32_t threshold,
        const std::vector<SpCompositionProofMultisigProposal> &proof_proposals,
        const std::vector<crypto::secret_key> &proof_privkeys_x,
        const std::vector<crypto::secret_key> &proof_privkeys_y,
        const std::vector<crypto::secret_key> &proof_privkeys_z_offset,
        const std::vector<crypto::secret_key> &proof_privkeys_z_multiplier);

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    MultisigPartialSigMakerSpCompositionProof& operator=(MultisigPartialSigMakerSpCompositionProof&&) = delete;

//member functions
    void attempt_make_partial_sig(const rct::key &proof_message,
        const rct::key &proof_key,
        const signer_set_filter signer_group_filter,
        const std::vector<std::vector<MultisigPubNonces>> &signer_group_pub_nonces,
        const crypto::secret_key &local_multisig_signing_key,
        MultisigNonceCache &nonce_record_inout,
        MultisigPartialSigVariant &partial_sig_out) const override;

//member variables
private:
    const rct::key m_inv_threshold;  // 1/threshold
    const std::vector<SpCompositionProofMultisigProposal> &m_proof_proposals;
    const std::vector<crypto::secret_key> &m_proof_privkeys_x;
    const std::vector<crypto::secret_key> &m_proof_privkeys_y;
    const std::vector<crypto::secret_key> &m_proof_privkeys_z_offset;
    const std::vector<crypto::secret_key> &m_proof_privkeys_z_multiplier;

    // cached proof keys mapped to indices in the set of proof proposals
    std::unordered_map<rct::key, std::size_t> m_cached_proof_keys;
};

} //namespace multisig
