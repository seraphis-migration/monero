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

// Seraphis transaction-builder helper types

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_payment_proposal.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

////
// SpMultisigPublicInputProposalV1
// - propose a tx input to be signed with multisig (for sending to other multisig participants)
///
struct SpMultisigPublicInputProposalV1 final
{
    /// enote to spend
    SpEnoteV1 m_enote;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;
};

////
// SpMultisigInputProposalV1
// - proposed tx input to be signed with multisig (convenience struct, for internal use)
///
struct SpMultisigInputProposalV1 final
{
    /// enote proposed as a tx input
    SpMultisigPublicInputProposalV1 m_core;

    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey;
    /// a: input amount
    rct::xmr_amount m_input_amount;
    /// x: input amount commitment's blinding factor
    crypto::secret_key m_input_amount_blinding_factor;

    /// less-than operator for sorting (VERY SLOW: USE WITH CAUTION)
    bool operator<(const SpMultisigInputProposalV1 &other_proposal) const;

    /**
    * brief: get_key_image - get this input's key image
    * outparam: key_image_out - KI
    */
    void get_key_image(crypto::key_image &key_image_out) const;

    /**
    * brief: get_enote_core - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_core(SpEnote &enote_out) const;

    /**
    * brief: get_enote_image - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image(SpEnoteImage &image_out) const;
};

//temp
void check_v1_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &input_proposal);
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    SpMultisigInputProposalV1 &proposal_out);

////
// SpMultisigTxProposalV1
// - propose to fund a set of outputs with multisig inputs
// - total input amount can be less than total output amount (additional inputs should be provided from elsewhere)
///
struct SpMultisigTxProposalV1 final
{
    /// tx outputs with known addresses
    std::vector<jamtis::JamtisPaymentProposalV1> m_explicit_payments;
    /// tx outputs with unknown addresses (may include self-sends and dummy outputs)
    std::vector<SpOutputProposalV1> m_opaque_payments;
    /// miscellaneous memo elements to add to the tx memo
    TxExtra m_partial_memo;
    /// tx inputs to sign with multisig
    std::vector<SpMultisigInputProposalV1> m_input_proposals;
    /// composition proof proposals for each input proposal
    std::vector<SpCompositionProofMultisigProposal> m_input_proof_proposals;
    /// all multisig signers who should participate in signing this proposal
    /// - the set may be larger than 'threshold', in which case every permutation of 'threshold' signers will attempt to sign
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    //todo: convert to plain tx proposal
    void get_v1_tx_proposal_v1(SpTxProposalV1 &tx_proposal_out) const;
};

//temp
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &version_string);
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    const std::string &version_string,
    std::vector<SpMultisigInputProposalV1> input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out);

////
// SpMultisigInputInitV1
// - initialize a seraphis composition proof for an enote image
// - has proof nonce pairs for multiple sets of multisig signers (represented by an aggregate filter)
// - only signer sets that include 'signer_id' will be initialized
///
struct SpMultisigInputInitV1 final
{
    /// id of signer who made this input initializer
    crypto::public_key m_signer_id;
    /// proposal prefix (represents the set of destinations and memos; will be signed by this input's image proof)
    rct::key m_proposal_prefix;
    /// key image of the enote image this initializer corresponds to (for tracking)
    crypto::key_image m_key_image;

    /// all multisig signers who should participate in attempting to make this composition proof
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    /// signature nonce pubkeys for each signer set that includes the specified signer id
    /// - all permutations of the aggregate filter that don't include the signer id are ignored
    // alpha_{ki,1,e}*U
    std::vector<rct::key> signature_nonce_1_KI_pub;
    // alpha_{ki,2,e}*U
    std::vector<rct::key> signature_nonce_2_KI_pub;
};

//temp
void make_v1_multisig_input_init_v1(const crypto::public_key &signer_id,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::uint32_t threshold,
    const rct::key &proposal_prefix,
    const crypto::key_image &key_image,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitV1 &input_init_out);
void make_v1_multisig_input_inits_v1(const crypto::public_key &signer_id,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::uint32_t threshold,
    const SpMultisigTxProposalV1 &tx_proposal,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputInitV1> &input_inits_out);

////
// SpMultisigInputPartialSigV1
// - partially signed input; combine partial signatures to complete the image proof for a partial input
///
struct SpMultisigInputPartialSigV1 final
{
    /// proposal prefix (represents the set of destinations and memos; signed by this composition proof)
    rct::key m_proposal_prefix;
    /// key image of the enote image this partial response corresponds to
    crypto::key_image m_key_image;

    /// partial signature for the enote image's composition proof
    SpCompositionProofMultisigPartial m_partial_signature;

    /// set of multisig signers this partial signature corresponds to
    multisig::signer_set_filter m_signer_set_filter;
};

//static std::unordered_map<crypto::key_image, std::vector<SpMultisigInputInitV1>> organize_by_key_image(
//    std::vector<SpMultisigInputInitV1> input_inits);

//temp
// - should be 'loose': make as many responses as possible, ignore signer sets that don't have nonces in the record
//   (in case earlier responses removed nonces from the record)
void make_v1_multisig_input_partial_sig_v1(const multisig::multisig_account &signer_account,
    const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,
    const rct::key &proposal_prefix,
    const multisig::signer_set_filter signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputPartialSigV1 &input_partial_sig_out);
void make_v1_multisig_input_partial_sigs_single_input_v1(const multisig::multisig_account &signer_account,
    const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,
    const std::vector<SpMultisigInputInitV1> &input_inits,  //including from self
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigV1> &input_partial_sigs_out);
void make_v1_multisig_input_partial_sigs_multiple_inputs_v1(const multisig::multisig_account &signer_account,
    const std::vector<SpMultisigInputProposalV1> &input_proposals,
    const std::unordered_map<crypto::key_image, crypto::secret_key> &input_enote_view_privkeys,
    const std::vector<SpMultisigInputInitV1> &input_inits,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::unordered_map<crypto::key_image, std::vector<SpMultisigInputPartialSigV1>> &input_partial_sigs_out);

void make_v1_partial_input_v1(const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,  //use to verify that key images match for 'correct by construction'
    const std::vector<SpMultisigInputPartialSigV1> &input_partial_sigs,
    SpPartialInputV1 &partial_input_out);

} //namespace sp
