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

// Seraphis transaction-builder helper types.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
namespace jamtis
{
    struct JamtisPaymentProposalV1;
    struct JamtisPaymentProposalSelfSendV1;
}
    struct tx_version_t;
}

namespace sp
{

////
// SpInputProposalV1
///
struct SpInputProposalV1 final
{
    /// core of the proposal
    SpInputProposalCore core;
};

/// get the proposal's amount
rct::xmr_amount amount_ref(const SpInputProposalV1 &proposal);
/// get the proposal's key image
const crypto::key_image& key_image_ref(const SpInputProposalV1 &proposal);

////
// SpCoinbaseOutputProposalV1
///
struct SpCoinbaseOutputProposalV1 final
{
    /// proposed enote
    SpCoinbaseEnoteV1 enote;

    /// xK_e: enote ephemeral pubkey
    crypto::x25519_pubkey enote_ephemeral_pubkey;
    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

/// get the proposal's amount
rct::xmr_amount amount_ref(const SpCoinbaseOutputProposalV1 &proposal);

////
// SpOutputProposalV1
///
struct SpOutputProposalV1 final
{
    /// core of the proposal
    SpOutputProposalCore core;

    /// xK_e: enote ephemeral pubkey
    crypto::x25519_pubkey enote_ephemeral_pubkey;
    /// enc_a
    jamtis::encoded_amount_t encoded_amount;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t view_tag;

    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

/// get the proposal's amount
rct::xmr_amount amount_ref(const SpOutputProposalV1 &proposal);

////
// SpMembershipProofPrepV1
// - data for producing a membership proof
///
struct SpMembershipProofPrepV1 final
{
    /// ref set size = n^m
    std::size_t ref_set_decomp_n;
    std::size_t ref_set_decomp_m;
    /// binned representation of ledger indices of enotes referenced by the proof
    /// - only enotes in the ledger can have a membership proof
    SpBinnedReferenceSetV1 binned_reference_set;
    /// the referenced enotes (squashed representation)
    std::vector<rct::key> referenced_enotes_squashed;
    /// the real enote being referenced (plain enote representation)
    SpEnoteCoreVariant real_reference_enote;
    /// image masks for the real reference
    crypto::secret_key address_mask;
    crypto::secret_key commitment_mask;
};

////
// SpAlignableMembershipProofV1
// - the masked address can be used to match this membership proof with the corresponding input image
//   - note: matching can fail if a masked address is reused in a tx, but that is almost definitely an implementation
//     error!
///
struct SpAlignableMembershipProofV1 final
{
    /// masked address used in the membership proof (for matching with corresponding input image)
    rct::key masked_address;
    /// the membership proof
    SpMembershipProofV1 membership_proof;
};

////
// SpCoinbaseTxProposalV1
// - the proposed block height, reward, outputs, and miscellaneous memos
///
struct SpCoinbaseTxProposalV1 final
{
    /// block height
    std::uint64_t block_height;
    /// block reward
    rct::xmr_amount block_reward;
    /// outputs (SORTED)
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    /// partial memo
    TxExtra partial_memo;
};

////
// SpTxProposalV1
// - the proposed set of inputs and outputs, with tx fee and miscellaneous memos
///
struct SpTxProposalV1 final
{
    /// legacy input proposals (SORTED)
    std::vector<LegacyInputProposalV1> legacy_input_proposals;
    /// seraphis input proposals (SORTED)
    std::vector<SpInputProposalV1> sp_input_proposals;
    /// outputs (SORTED)
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    /// tx fee
    DiscretizedFee tx_fee;
    /// partial memo
    TxExtra partial_memo;
};

////
// SpPartialInputV1
// - enote spent
// - cached amount and amount blinding factor, and image masks (for balance and membership proofs)
// - spend proof for input (and proof the input's key image is properly constructed)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct SpPartialInputV1 final
{
    /// input's image
    SpEnoteImageV1 input_image;
    /// input image's proof (demonstrates ownership of the underlying enote and that the key image is correct)
    SpImageProofV1 image_proof;
    /// image masks
    crypto::secret_key address_mask;
    crypto::secret_key commitment_mask;

    /// tx proposal prefix (represents the tx inputs/outputs/fee/memo; signed by this partial input's image proof)
    rct::key tx_proposal_prefix;

    /// the input enote's core; used for making a membership proof
    SpEnoteCoreVariant input_enote_core;
    /// input amount
    rct::xmr_amount input_amount;
    /// input amount commitment's blinding factor; used for making the balance proof
    crypto::secret_key input_amount_blinding_factor;
};

////
// SpPartialTxV1
// - everything needed for a tx except seraphis input membership proofs
///
struct SpPartialTxV1 final
{
    /// legacy tx input images  (spent legacy enotes) (SORTED)
    std::vector<LegacyEnoteImageV2> legacy_input_images;
    /// seraphis tx input images  (spent seraphis enotes) (SORTED)
    std::vector<SpEnoteImageV1> sp_input_images;
    /// tx outputs (new enotes) (SORTED)
    std::vector<SpEnoteV1> outputs;
    /// balance proof (balance proof and range proofs)
    SpBalanceProofV1 balance_proof;
    /// legacy ring signatures: membership/ownership/unspentness for each legacy input (ALIGNED TO LEGACY INPUTS)
    std::vector<LegacyRingSignatureV4> legacy_ring_signatures;
    /// composition proofs: ownership/unspentness for each seraphis input (ALIGNED TO SERAPHIS INPUTS)
    std::vector<SpImageProofV1> sp_image_proofs;
    /// tx fee (discretized representation)
    DiscretizedFee tx_fee;
    /// supplemental data for tx
    SpTxSupplementV1 tx_supplement;

    /// ring members for each legacy input; for validating ring signatures stored here (ALIGNED TO LEGACY INPUTS)
    std::vector<rct::ctkeyV> legacy_ring_signature_rings;

    /// seraphis input enotes; for creating seraphis input membership proofs (ALIGNED TO SERAPHIS INPUTS)
    std::vector<SpEnoteCoreVariant> sp_input_enotes;
    /// seraphis image masks; for creating seraphis input membership proofs (ALIGNED TO SERAPHIS INPUTS)
    std::vector<crypto::secret_key> sp_address_masks;
    std::vector<crypto::secret_key> sp_commitment_masks;
};

/// comparison method for sorting: a.Ko < b.Ko
bool compare_Ko(const SpCoinbaseOutputProposalV1 &a, const SpCoinbaseOutputProposalV1 &b);
bool compare_Ko(const SpOutputProposalV1 &a, const SpOutputProposalV1 &b);
/// comparison method for sorting: a.KI < b.KI
bool compare_KI(const SpInputProposalV1 &a, const SpInputProposalV1 &b);
bool compare_KI(const SpPartialInputV1 &a, const SpPartialInputV1 &b);
/// alignment checks for aligning seraphis membership proofs: test if masked addresses are equal
bool alignment_check(const SpAlignableMembershipProofV1 &a, const SpAlignableMembershipProofV1 &b);
bool alignment_check(const SpAlignableMembershipProofV1 &proof, const rct::key &masked_address);

/**
* brief: get_enote_image_v1 - get the input proposal's enote image in the squashed enote model
* param: proposal -
* outparam: image_out -
*/
void get_enote_image_v1(const SpInputProposalV1 &proposal, SpEnoteImageV1 &image_out);
/**
* brief: get_squash_prefix - get the input proposal's enote's squash prefix
* param: proposal -
* outparam: squash_prefix_out - H_n(Ko, C)
*/
void get_squash_prefix(const SpInputProposalV1 &proposal, rct::key &squash_prefix_out);
/**
* brief: get_enote_v1 - extract the output proposal's enote
* param: proposal -
* outparam: enote_out -
*/
void get_enote_v1(const SpOutputProposalV1 &proposal, SpEnoteV1 &enote_out);
/**
* brief: get_coinbase_output_proposals_v1 - convert the tx proposal's payment proposals into coinbase output proposals
* param: tx_proposal -
* outparam: output_proposals_out -
*/
void get_coinbase_output_proposals_v1(const SpCoinbaseTxProposalV1 &tx_proposal,
    std::vector<SpCoinbaseOutputProposalV1> &output_proposals_out);
/**
* brief: get_coinbase_output_proposals_v1 - convert the tx proposal's payment proposals into output proposals
* param: tx_proposal -
* param: k_view_balance -
* outparam: output_proposals_out -
*/
void get_output_proposals_v1(const SpTxProposalV1 &tx_proposal,
    const crypto::secret_key &k_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_out);
/**
* brief: get_tx_proposal_prefix_v1 - get the message to be signed by input spend proofs
* param: tx_proposal -
* param: tx_version -
* param: k_view_balance -
* outparam: tx_proposal_prefix_out -
*/
void get_tx_proposal_prefix_v1(const SpTxProposalV1 &tx_proposal,
    const tx_version_t &tx_version,
    const crypto::secret_key &k_view_balance,
    rct::key &tx_proposal_prefix_out);
/**
* brief: gen_sp_input_proposal_v1 - generate an input proposal
* param: sp_spend_privkey -
* param: k_view_balance -
* param: amount -
* return: random input proposal
*/
SpInputProposalV1 gen_sp_input_proposal_v1(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount amount);
/**
* brief: gen_sp_coinbase_output_proposal_v1 - generate a coinbase output proposal
* param: amount -
* param: num_random_memo_elements -
* return: random coinbase output proposal
*/
SpCoinbaseOutputProposalV1 gen_sp_coinbase_output_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements);
/**
* brief: gen_sp_output_proposal_v1 - generate an output proposal
* param: amount -
* param: num_random_memo_elements -
* return: random output proposal
*/
SpOutputProposalV1 gen_sp_output_proposal_v1(const rct::xmr_amount amount, const std::size_t num_random_memo_elements);

} //namespace sp
