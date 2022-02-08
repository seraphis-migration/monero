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

// Seraphis transaction-builder helper types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpInputProposalV1
///
struct SpInputProposalV1 final
{
    /// core of the proposal
    SpInputProposal m_core;

     /// less-than operator for sorting
    bool operator<(const SpInputProposalV1 &other_proposal) const
    {
        return m_core < other_proposal.m_core;
    }

    /**
    * brief: get_enote_image_v1 - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image_v1(SpEnoteImageV1 &image_out) const
    {
        return m_core.get_enote_image_squashed_base(image_out.m_core);
    }

    /// generate a v1 input (all random; does not support info recovery)
    void gen(const rct::xmr_amount amount) { m_core.gen(amount); }
};

////
// SpOutputProposalV1
///
struct SpOutputProposalV1 final
{
    /// core of the proposal
    SpOutputProposal m_core;

    /// K_e: enote ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// enc_a
    rct::xmr_amount m_encoded_amount;
    /// view_tag
    jamtis::view_tag_t m_view_tag;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t m_addr_tag_enc;

    ///TODO: misc memo suggestion (fields to add to memo)

    /// less-than operator for sorting
    bool operator<(const SpOutputProposalV1 &other_proposal) const
    {
        return m_core < other_proposal.m_core;
    }

    /// convert this destination into a v1 enote
    void get_enote_v1(SpEnoteV1 &enote_out) const;

    /**
    * brief: gen - generate a V1 Destination (random)
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// SpMembershipReferenceSetV1 - Records info about a membership reference set, for producing a membership proof
///
struct SpMembershipReferenceSetV1 final
{
    /// ref set size = n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
    /// locations in the ledger of the referenced enotes; only enotes in the ledger can have a membership proof
    ///TODO: deterministic references instead of indices
    std::vector<std::size_t> m_ledger_enote_indices;
    /// the referenced enotes
    std::vector<SpEnote> m_referenced_enotes;
    /// the index in the referenced enotes vector of the enote who will be proven a member of the ref set (via its image)
    std::size_t m_real_spend_index_in_set;
};

////
// SpMembershipProofAlignableV1 - Alignable Membership Proof V1
// - the masked address can be used to match this membership proof with its input image
//   - note: matching can fail if a masked address is reused in a tx, but that is almost definitely an implementation error!
///
struct SpMembershipProofAlignableV1 final
{
    /// masked address used in the membership proof (for matching with actual input image)
    rct::key m_masked_address;
    /// the membership proof
    SpMembershipProofV1 m_membership_proof;
};

////
// SpTxProposalV1: set of destinations (and miscellaneous memos)
///
struct SpTxProposalV1 final
{
//constructors
    /// default constructor
    SpTxProposalV1() = default;

    /// normal constructor: make a deterministic tx proposal from output proposals
    SpTxProposalV1(std::vector<SpOutputProposalV1> output_proposals);

//member functions
    /// message to be signed by input spend proofs
    rct::key get_proposal_prefix(const std::string &version_string) const;

//member variables
    /// proposed outputs (created from the destinations)
    std::vector<SpEnoteV1> m_outputs;
    /// proposed tx supplement
    SpTxSupplementV1 m_tx_supplement;
    /// output amounts and blinding factors (for future balance proofs)
    std::vector<rct::xmr_amount> m_output_amounts;
    std::vector<crypto::secret_key> m_output_amount_commitment_blinding_factors;
};

////
// SpTxPartialInputV1
// - enote spent
// - cached amount and amount blinding factor, image masks (for balance and membership proofs)
// - spend proof for input (and proof the input's key image is properly constructed)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct SpTxPartialInputV1 final
{
//constructors
    /// default constructor
    SpTxPartialInputV1() = default;

    /// normal constructor: normal input
    SpTxPartialInputV1(const SpInputProposalV1 &input_proposal, const rct::key &proposal_prefix);

//destructor: default

    /// less-than operator for sorting
    bool operator<(const SpTxPartialInputV1 &other_input) const
    {
        return m_input_image < other_input.m_input_image;
    }

//member functions

//member variables
    /// input's image
    SpEnoteImageV1 m_input_image;
    /// input image's proof (demonstrates ownership of the underlying enote, and that the key image is correct)
    SpImageProofV1 m_image_proof;
    /// image masks
    crypto::secret_key m_image_address_mask;
    crypto::secret_key m_image_commitment_mask;

    /// proposal prefix (represents the set of destinations and memos; signed by this partial input's image proof)
    rct::key m_proposal_prefix;

    /// the input enote's core; used for making a membership proof
    SpEnote m_input_enote_core;
    /// input amount
    rct::xmr_amount m_input_amount;
    /// input amount commitment's blinding factor; used for making the balance proof
    crypto::secret_key m_input_amount_blinding_factor;
};

////
// SpTxPartialV1: everything needed for a tx except input membership proofs
//
// TODO: from multisig - multisigproposal.txproposal, multisig inputs + extra inputs, balance proof
///
struct SpTxPartialV1 final
{
//constructors
    /// default constructor
    SpTxPartialV1() = default;

    /// normal constructor: standard assembly
    SpTxPartialV1(const SpTxProposalV1 &proposal,
        std::vector<SpTxPartialInputV1> inputs,
        const std::string &version_string);

    /// normal constructor (TODO): assembly from multisig pieces

//destructor: default

//member variables
    /// tx input images  (spent e-notes)
    std::vector<SpEnoteImageV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<SpEnoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<const SpBalanceProofV1> m_balance_proof;
    /// composition proofs: ownership/unspentness for each input
    std::vector<SpImageProofV1> m_image_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 m_tx_supplement;

    /// input enotes
    std::vector<SpEnote> m_input_enotes;
    /// image masks for creating input membership proofs
    std::vector<crypto::secret_key> m_image_address_masks;
    std::vector<crypto::secret_key> m_image_commitment_masks;
};

} //namespace sp
