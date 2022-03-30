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

// Seraphis transaction-builder helper types for multisig
// WARNING: Passing a semantic check here, or successfully making a component, does not guarantee that the
//          component is well-formed (i.e. can ultimately be used to make a valid transaction). The checks should be
//          considered sanity checks that only a malicious implementation can/will circumvent. Note that multisig
//          is only assumed to work when a threshold of honest players are interacting.
//          - If users encounter tx construction failures, it may be necessary to identify malicious player(s) and
//            exclude them.
//          - TODO: Provide better ways to track down malicious players (more informative exceptions?).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_payment_proposal.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_component_types.h"
#include "tx_extra.h"
#include "tx_record_types.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

void make_v1_multisig_public_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigPublicInputProposalV1 &proposal_out);

//temp
void check_v1_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &input_proposal);
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
bool try_get_v1_multisig_input_proposal_v1(const SpMultisigPublicInputProposalV1 &proposal_core,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigInputProposalV1 &proposal_out);

//temp
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance);
void make_v1_multisig_tx_proposal_v1(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    std::string version_string,
    const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out);

//temp
void check_v1_multisig_input_init_set_semantics_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers);
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proposal_prefix,
    const rct::keyV &masked_addresses,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out);
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out);

//temp
// - should be 'loose': make as many responses as possible, ignore signer sets that don't have nonces in the record
//   (in case earlier responses removed nonces from the record)
void check_v1_multisig_input_partial_sig_semantics_v1(const SpMultisigInputPartialSigV1 &input_partial_sig);
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
    const std::vector<SpMultisigInputPartialSigV1> &input_partial_sigs,
    SpPartialInputV1 &partial_input_out);

} //namespace sp
