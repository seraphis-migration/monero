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

// Seraphis transaction-builder helper types (multisig).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "enote_record_types.h"
#include "multisig/multisig_clsag.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_sp_composition_proof.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types.h"
#include "txtype_base.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyMultisigRingSignaturePrepV1
// - data for producing a legacy ring signature using multisig
// - this struct contains a subset of data found in LegacyRingSignaturePrepV1 because, in multisig, legacy ring signature
//   preps need to be created before a tx proposal is available (this information is used to build multisig input proposals
//   and multisig tx proposals)
///
struct LegacyMultisigRingSignaturePrepV1 final
{
    /// ledger indices of legacy enotes referenced by the proof
    std::vector<std::uint64_t> reference_set;
    /// the referenced enotes ({Ko, C}((legacy)) representation)
    rct::ctkeyV referenced_enotes;
    /// the index of the real enote being referenced within the reference set
    std::uint64_t real_reference_index;
    /// key image of the real reference
    crypto::key_image key_image;
};

////
// LegacyMultisigInputProposalV1
// - propose a legacy tx input to be signed with multisig (for sending to other multisig participants)
///
struct LegacyMultisigInputProposalV1 final
{
    /// the enote to spend
    LegacyEnoteVariant enote;
    /// the enote's key image
    crypto::key_image key_image;
    /// the enote's ephemeral pubkey
    rct::key enote_ephemeral_pubkey;
    /// t: the enote's output index in the tx that created it
    std::uint64_t tx_output_index;
    /// u: the enote's unlock time
    std::uint64_t unlock_time;

    /// mask
    crypto::secret_key commitment_mask;

    /// cached legacy enote indices for a legacy ring signature (should include a reference to this input proposal's enote)
    std::vector<std::uint64_t> reference_set;
};

////
// SpMultisigInputProposalV1
// - propose a seraphis tx input to be signed with multisig (for sending to other multisig participants)
///
struct SpMultisigInputProposalV1 final
{
    /// enote to spend
    SpEnoteVariant enote;
    /// the enote's ephemeral pubkey
    crypto::x25519_pubkey enote_ephemeral_pubkey;
    /// the enote's input context
    rct::key input_context;

    /// t_k
    crypto::secret_key address_mask;
    /// t_c
    crypto::secret_key commitment_mask;
};

////
// SpMultisigTxProposalV1
// - propose to fund a set of outputs with multisig inputs
///
struct SpMultisigTxProposalV1 final
{
    /// legacy tx inputs to sign with multisig (SORTED)
    std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals;
    /// seraphis tx inputs to sign with multisig (NOT SORTED; get sorted seraphis input proposals by converting to
    ///   a normal tx proposal)
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals;
    /// legacy ring signature proposals (CLSAGs) for each legacy input proposal (ALIGNED TO SORTED LEGACY INPUTS)
    std::vector<multisig::CLSAGMultisigProposal> legacy_input_proof_proposals;
    /// composition proof proposals for each seraphis input proposal (ALIGNED TO SORTED SERAPHIS INPUTS)
    std::vector<multisig::SpCompositionProofMultisigProposal> sp_input_proof_proposals;
    /// all multisig signers who may participate in signing this proposal
    /// - the set may be larger than 'threshold', in which case every permutation of 'threshold' signers will attempt to sign
    multisig::signer_set_filter aggregate_signer_set_filter;

    /// normal tx outputs (NOT SORTED)
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    /// self-send tx outputs (NOT SORTED)
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    /// proposed transaction fee
    DiscretizedFee tx_fee;
    /// miscellaneous memo elements to add to the tx memo
    TxExtra partial_memo;

    /// encoding of intended tx version
    tx_version_t tx_version;
};

/// comparison method for sorting: a.KI < b.KI
bool compare_KI(const LegacyMultisigInputProposalV1 &a, const LegacyMultisigInputProposalV1 &b);

/**
* brief: get_legacy_input_proposal_v1 - convert a multisig input proposal to a legacy input proposal
* param: multisig_input_proposal -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* outparam: input_proposal_out -
*/
void get_legacy_input_proposal_v1(const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    LegacyInputProposalV1 &input_proposal_out);
/**
* brief: get_sp_input_proposal_v1 - convert a multisig input proposal to a seraphis input proposal
* param: multisig_input_proposal -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* outparam: input_proposal_out -
*/
void get_sp_input_proposal_v1(const SpMultisigInputProposalV1 &multisig_input_proposal,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpInputProposalV1 &input_proposal_out);
/**
* brief: get_v1_tx_proposal_v1 - convert a multisig tx proposal to a plain tx proposal
* param: multisig_tx_proposal -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* outparam: tx_proposal_out -
*/
void get_v1_tx_proposal_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxProposalV1 &tx_proposal_out);
/**
* brief: get_tx_proposal_prefix_v1 - get the tx proposal prefix of a multisig tx proposal
* param: multisig_tx_proposal -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* outparam: tx_proposal_prefix_out -
*/
void get_tx_proposal_prefix_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    rct::key &tx_proposal_prefix_out);
/**
* brief: matches_with - check if a multisig input proposal matches against other data types
* ...
* return: true if all alignment checks pass
*/
bool matches_with(const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const multisig::CLSAGMultisigProposal &proof_proposal);
bool matches_with(const LegacyMultisigInputProposalV1 &multisig_input_proposal, const LegacyEnoteRecord &enote_record);
bool matches_with(const SpMultisigInputProposalV1 &multisig_input_proposal, const SpEnoteRecordV1 &enote_record);

} //namespace sp
