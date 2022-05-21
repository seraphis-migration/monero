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

// Seraphis tx-builder/component-builder implementations (tx inputs).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_binned_reference_set.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_enote_record_types.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: make_binned_ref_set_generator_seed_v1 - compute a generator seed for making a binned reference set
*   s = H("domain-sep", Ko', C')
* param: masked_address -
* param: masked_commitment -
* outparam: generator_seed_out -
*/
void make_binned_ref_set_generator_seed_v1(const rct::key &masked_address,
    const rct::key &masked_commitment,
    rct::key &generator_seed_out);
void make_binned_ref_set_generator_seed_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &generator_seed_out);
/**
* brief: align_v1_membership_proofs_v1 - rearrange membership proofs so they line up with a set of input images
*   sort order: key images ascending with byte-wise comparisons
* param: input_images -
* param: membership_proofs_sortable -
* outparam: membership_proofs_out -
*/
void align_v1_membership_proofs_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpAlignableMembershipProofV1> membership_proofs_sortable,
    std::vector<SpMembershipProofV1> &membership_proofs_out);
/**
* brief: make_tx_membership_proof_message_v1 - message for membership proofs
*   - H(crypto project name, {binned reference set})
* param: - binned_reference_set -
* outparam: message_out - the message to sign in a membership proof
*/
void make_tx_membership_proof_message_v1(const SpBinnedReferenceSetV1 &binned_reference_set, rct::key &message_out);
/**
* brief: prepare_input_commitment_factors_for_balance_proof_v1 - collect input amounts and input image amount
*   commitment blinding factors
* param: input_proposals -
* param: image_amount_masks -
* outparam: input_amounts_out -
* outparam: blinding_factors_out -
*/
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
/**
* brief: make_input_proposal - make the core of an input proposal
* param: enote_core -
* param: key_image -
* param: enote_view_privkey -
* param: input_amount_blinding_factor -
* param: input_amount -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_input_proposal(const SpEnote &enote_core,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposal &proposal_out);
/**
* brief: make_v1_input_proposal_v1 - make an input proposal
* param: enote_record -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out);
/**
* brief: try_make_v1_input_proposal_v1 - try to make an input proposal from an enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
bool try_make_v1_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out);
//todo
void make_standard_input_context_from_v1_input_proposals(const std::vector<SpInputProposalV1> &input_proposals,
    rct::key &input_context_out);
/**
* brief: make_v1_image_proof_v1 - make a seraphis composition proof in the squashed enote model
* param: input_proposal -
* param: message -
* param: spendbase_privkey -
* outparam: image_proof_out -
*/
void make_v1_image_proof_v1(const SpInputProposal &input_proposal,
    const rct::key &message,
    const crypto::secret_key &spendbase_privkey,
    SpImageProofV1 &image_proof_out);
/**
* brief: make_v1_image_proofs_v1 - make a set of seraphis composition proofs in the squashed enote model
* param: input_proposals -
* param: message -
* param: spendbase_privkey -
* outparam: image_proofs_out -
*/
void make_v1_image_proofs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &message,
    const crypto::secret_key &spendbase_privkey,
    std::vector<SpImageProofV1> &image_proofs_out);
/**
* brief: make_v1_membership_proof_v1 - make a concise grootle membership proof in the squashed enote model
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* param: binned_reference_set -
* param: referenced_enotes_squashed -
* param: real_spend_index_in_set -
* param: real_reference_enote -
* param: image_address_mask -
* param: image_commitment_mask -
* outparam: membership_proof_out -
*/
void make_v1_membership_proof_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpBinnedReferenceSetV1 binned_reference_set,
    std::vector<rct::key> referenced_enotes_squashed,
    const std::size_t real_spend_index_in_set,
    const SpEnote &real_reference_enote,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_commitment_mask,
    SpMembershipProofV1 &membership_proof_out);
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep, SpMembershipProofV1 &membership_proof_out);
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep,
    SpAlignableMembershipProofV1 &alignable_membership_proof_out);
/**
* brief: make_v1_membership_proofs_v1 - make a set of concise grootle membership proofs in the squashed enote model
* param: membership_proof_preps -
* outparam: membership_proofs_out -
*/
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpMembershipProofV1> &membership_proofs_out);
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proof_out);
/**
* brief: make_v1_partial_input_v1 - make a v1 partial input
* param: input_proposal -
* param: proposal_prefix -
* param: spendbase_privkey -
* outparam: partial_input_out -
*/
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    SpPartialInputV1 &partial_input_out);
/**
* brief: make_v1_partial_inputs_v1 - make a full set of v1 partial inputs
* param: input_proposals -
* param: proposal_prefix -
* param: spendbase_privkey -
* outparam: partial_inputs_out -
*/
void make_v1_partial_inputs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    std::vector<SpPartialInputV1> &partial_inputs_out);
/**
* brief: gen_mock_sp_input_proposals_v1 - create random mock inputs
* param: spendbase_privkey -
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const crypto::secret_key &spendbase_privkey,
    const std::vector<rct::xmr_amount> in_amounts);
/**
* brief: gen_mock_sp_membership_proof_prep_v1 - create a random reference set for an enote, with real spend at a random index,
*   and update mock ledger to include all members of the reference set (including squashed enotes)
* param: input_enote -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: a reference set that can be used to make a membership proof
*/
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_v1(
    const SpEnote &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpEnote> &real_referenced_enotes,
    const std::vector<crypto::secret_key> &address_masks,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);

} //namespace sp
