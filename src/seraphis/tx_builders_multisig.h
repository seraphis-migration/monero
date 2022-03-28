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
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_multisig_input_proposal_v1(const SpMultisigPublicInputProposalV1 &proposal_core,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigInputProposalV1 &proposal_out);

//temp
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::string &version_string);
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    const std::string &version_string,
    std::vector<SpMultisigInputProposalV1> input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out);

//temp
void check_v1_multisig_input_init_semantics_v1(const SpMultisigInputInitV1 &input_init);
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
