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

// Seraphis tx-builder/component-builder implementations (multisig).
// WARNING: Passing a semantic check here, or successfully making a component, does not guarantee that the
//          component is well-formed (i.e. can ultimately be used to make a valid transaction). The checks should be
//          considered sanity checks that only a malicious implementation can/will circumvent. Note that multisig
//          is only assumed to work when a threshold of honest players are interacting.
//          - The semantic checks SHOULD detect unintended behavior that would allow a successful transaction. For example,
//            the checks prevent a multisig tx proposer from proposing a tx with no self-sends (which would make balance
//            checks much more difficult).
//          - If users encounter tx construction failures, it may be necessary to identify malicious players and
//            exclude them.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_signing_errors.h"
#include "multisig/multisig_signing_helper_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_component_types.h"
#include "tx_fee_calculator.h"
#include "tx_input_selection.h"
#include "txtype_squashed_v1.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations
namespace multisig { class MultisigNonceCache; }
namespace sp { struct tx_version_t; }

namespace sp
{

/**
* brief: check_v1_legacy_multisig_input_proposal_semantics_v1 - check semantics of a legacy multisig input proposal
*   - throws if a check fails
*   - note: does not verify that the caller owns the input's enote
* param: multisig_input_proposal -
*/
void check_v1_legacy_multisig_input_proposal_semantics_v1(const LegacyMultisigInputProposalV1 &multisig_input_proposal);
/**
* brief: make_v1_legacy_multisig_input_proposal_v1 - make a legacy multisig input proposal (can be sent to other people)
* param: enote -
* param: key_image -
* param: enote_ephemeral_pubkey -
* param: tx_output_index -
* param: unlock_time -
* param: commitment_mask -
* param: reference_set -
* outparam: proposal_out -
*/
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteVariant &enote,
    const crypto::key_image &key_image,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out);
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out);
/**
* brief: check_v1_sp_multisig_input_proposal_semantics_v1 - check semantics of a seraphis multisig input proposal
*   - throws if a check fails
*   - note: does not verify that the caller owns the input's enote
* param: multisig_input_proposal -
*/
void check_v1_sp_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &multisig_input_proposal);
/**
* brief: make_v1_sp_multisig_input_proposal_v1 - make a seraphis multisig input proposal (can be sent to other people)
* param: enote -
* param: enote_ephemeral_pubkey -
* param: input_context -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
/**
* brief: check_v1_multisig_tx_proposal_semantics_v1 - check semantics of a multisig tx proposal
*   - throws if a check fails
*   - not checked: semantics satisfy the desired tx semantic rules version (can check these with the simulate tx method)
* param: multisig_tx_proposal -
* param: expected_tx_version -
* param: threshold -
* param: num_signers -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
*/
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const tx_version_t &expected_tx_version,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: try_simulate_tx_from_multisig_tx_proposal_v1 - try to simulate a squashed v1 tx from a multisig tx proposal
*   - checks the proposal semantics then simulates a transaction and tries to fully validate it against the specified
*     semantics rules
*   - note: to check that a multisig tx proposal MAY ultimately succeed, combine this simulation with A) checks that
*     all inputs are owned and spendable by the local user, B) checks that legacy ring members are valid references
* param: multisig_tx_proposal -
* param: semantic_rules_version -
* param: threshold -
* param: num_signers -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* inoutparam: hwdev -
* return: true if the tx was successfully simulated
*/
bool try_simulate_tx_from_multisig_tx_proposal_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    hw::device &hwdev);
/**
* brief: make_v1_multisig_tx_proposal_v1 - make a multisig tx proposal
* param: legacy_multisig_input_proposals -
* param: sp_multisig_input_proposals -
* param: legacy_ring_signature_preps -
* param: aggregate_signer_set_filter -
* param: normal_payment_proposals -
* param: selfsend_payment_proposals -
* param: discretized_transaction_fee -
* param: additional_memo_elements -
* param: tx_version -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey
* param: k_view_balance -
* outparam: proposal_out -
*/
void make_v1_multisig_tx_proposal_v1(std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals,
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_ring_signature_preps,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &proposal_out);
void make_v1_multisig_tx_proposal_v1(const std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs,
    const std::vector<SpContextualEnoteRecordV1> &sp_contextual_inputs,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_ring_signature_preps,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    TxExtra partial_memo_for_tx,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &multisig_tx_proposal_out);
/**
* brief: make_v1_multisig_init_sets_for_inputs_v1 - make init sets for legacy and seraphis multisig tx input proofs
* param: signer_id -
* param: threshold -
* param: multisig_signers -
* param: multisig_tx_proposal -
* param: expected_tx_version -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* inoutparam: nonce_record_inout -
* outparam: legacy_input_init_set_collection_out -
* outparam: sp_input_init_set_collection_out -
*/
void make_v1_multisig_init_sets_for_inputs_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const tx_version_t &expected_tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    multisig::MultisigNonceCache &nonce_record_inout,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> &legacy_input_init_set_collection_out,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> &sp_input_init_set_collection_out);
/**
* brief: try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1 - try to make multisig partial signatures for legacy
*   tx inputs
*   - weak preconditions: ignores invalid proof initializers from non-local signers
*   - will throw if local signer is not in the aggregate signer filter (or has an invalid initializer)
*   - will only succeed (return true) if a partial sig set can be made that includes each  of the legacy inputs found in
*     the multisig tx proposal
* param: signer_account -
* param: multisig_tx_proposal -
* param: legacy_subaddress_map -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* param: expected_tx_version -
* param: local_input_init_set_collection -
* param: other_input_init_set_collections -
* inoutparam: multisig_errors_inout -
* inoutparam: nonce_record_inout -
* outparam: legacy_input_partial_sig_sets_out -
* return: true if at least one set of partial signatures was created (containing a partial sig for each input)
*/
bool try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const tx_version_t &expected_tx_version,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        other_input_init_set_collections,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    multisig::MultisigNonceCache &nonce_record_inout,
    std::vector<multisig::MultisigPartialSigSetV1> &legacy_input_partial_sig_sets_out);
/**
* brief: try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1 - try to make multisig partial signatures for seraphis
*   tx inputs
*   - weak preconditions: ignores invalid proof initializers from non-local signers
*   - will throw if local signer is not in the aggregate signer filter (or has an invalid initializer)
*   - will only succeed (return true) if a partial sig set can be made that includes each  of the seraphis inputs found in
*     the multisig tx proposal
* param: signer_account -
* param: multisig_tx_proposal -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: expected_tx_version -
* param: local_input_init_set_collection -
* param: other_input_init_set_collections -
* inoutparam: multisig_errors_inout -
* inoutparam: nonce_record_inout -
* outparam: sp_input_partial_sig_sets_out -
* return: true if at least one set of partial signatures was created (containing a partial sig for each input)
*/
bool try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const tx_version_t &expected_tx_version,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        other_input_init_set_collections,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    multisig::MultisigNonceCache &nonce_record_inout,
    std::vector<multisig::MultisigPartialSigSetV1> &sp_input_partial_sig_sets_out);
/**
* brief: try_make_inputs_for_multisig_v1 - try to make legacy inputs and seraphis partial inputs from a collection of
*   multisig partial signatures
*   - weak preconditions: ignores invalid partial signature sets (including sets that are only partially invalid)
*   - will only succeed if a legacy input and seraphis partial input can be made for each of the inputs found in the
*     multisig tx proposal
* param: multisig_tx_proposal -
* param: multisig_signers -
* param: legacy_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* param: jamtis_spend_pubkey -
* param: k_view_balance -
* param: legacy_input_partial_sigs_per_signer -
* param: sp_input_partial_sigs_per_signer -
* inoutparam: multisig_errors_inout -
* outparam: legacy_inputs_out -
* outparam: sp_partial_inputs_out -
* return: true if legacy_inputs_out and sp_partial_inputs_out contain inputs/partial inputs corresponding to each input
*         proposal in the multisig tx proposal
*/
bool try_make_inputs_for_multisig_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &legacy_input_partial_sigs_per_signer,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &sp_input_partial_sigs_per_signer,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    std::vector<LegacyInputV1> &legacy_inputs_out,
    std::vector<SpPartialInputV1> &sp_partial_inputs_out);

} //namespace sp
