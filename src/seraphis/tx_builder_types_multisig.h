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
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpMultisigInputProposalV1
// - propose a tx input to be signed with multisig
///
struct SpMultisigInputProposalV1 final
{
    /// enote to spend
    SpEnoteV1 m_enote;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /// less-than operator for sorting (VERY SLOW: USE WITH CAUTION)
    bool operator<(const SpInputProposal &other_proposal) const;

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
    * brief: get_enote_image_v1 - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image_v1(SpEnoteImageV1 &image_out) const;

    /// less-than operator for sorting
    bool operator<(const SpMultisigInputProposalV1 &other_proposal) const
    {
        //return m_core < other_proposal.m_core;
    }

    /**
    * brief: gen - generate random enote keys
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// SpMultisigTxProposalV1
// - propose to fund a set of outputs with multisig inputs
// - total input amount can be less than total output amount (additional inputs should be provided from elsewhere)
///
struct SpMultisigTxProposalV1 final
{
    /// tx outputs with known addresses
    std::vector<JamtisPaymentProposalV1> m_explicit_payments;
    /// tx outputs with unknown addresses (may include self-sends and dummy outputs)
    std::vector<SpOutputProposalV1> m_opaque_payments;
    /// miscellaneous memo elements to add to the tx memo
    TxExtra m_partial_memo;
    /// tx inputs to sign with multisig
    std::vector<SpMultisigInputProposalV1> m_input_proposals;
    /// multisig composition proof proposals for the proposed inputs
    std::vector<SpCompositionProofMultisigProposal> m_multisig_input_proof_proposals;
    /// all multisig signers who should participate in signing this proposal
    /// - the set may be larger than 'threshold', in which case every permutation of 'threshold' signers will attempt to sign
    multisig::signer_set_filter m_aggregate_signer_set_filter;
};

////
// SpMultisigInputInitV1
// - initialize a seraphis composition proof for an enote image
// - has multiple initializers for different sets of multisig signers
///
struct SpMultisigInputInitV1 final
{
    /// proposal prefix (represents the set of destinations and memos; will be signed by this input's image proof)
    rct::key m_proposal_prefix;
    /// key image of the enote image this initializer corresponds to (for tracking)
    crypto::key_image m_key_image;

    /// sets of multisig signers this initializer lines up with (an aggregate representation)
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    /// signature nonce pubkeys for each signer set
    // alpha_{ki,1,e}*U
    std::vector<rct::key> signature_nonce_1_KI_pub;
    // alpha_{ki,2,e}*U
    std::vector<rct::key> signature_nonce_2_KI_pub;
};

////
// SpMultisigInputResponseV1
// - partially signed input; combine partial signatures to complete the image proof for a partial input
///
struct SpMultisigInputResponseV1 final
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

} //namespace sp
