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

// Seraphis tx-builder/component-builder implementations (legacy tx inputs).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: check_v1_legacy_input_proposal_semantics_v1 - check semantics of a legacy v1 input proposal
*   - throws on failure
* param: input_proposal -
* param: legacy_spend_pubkey -
*/
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &legacy_spend_pubkey);
/**
* brief: make_v1_legacy_input_proposal_v1 - make a legacy v1 input proposal
* param: onetime_address -
* param: amount_commitment -
* param: key_image -
* param: enote_view_extension -
* param: input_amount -
* param: input_amount_blinding_factor -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_extension,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &commitment_mask,
    SpInputProposalCore &proposal_out);
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out);
/**
* brief: make_tx_legacy_ring_signature_message_v1 - message to sign in legacy ring signatures used in a transaction
*   - H_32(tx proposal message, {reference set indices})
* param: tx_proposal_message - represents the transaction being signed (inputs, outputs, and memos), excluding proofs
* param: reference_set_indices - indices into the ledger's set of legacy enotes
* outparam: message_out - the message to sign in a legacy ring signature
*/
void make_tx_legacy_ring_signature_message_v1(const rct::key &tx_proposal_message,
    const std::vector<std::uint64_t> &reference_set_indices,
    rct::key &message_out);
/**
* brief: make_v3_legacy_ring_signature - make a legacy v3 ring signature
* param: message -
* param: reference_set -
* param: referenced_enotes -
* param: real_reference_index -
* param: masked_commitment -
* param: reference_view_privkey -
* param: reference_commitment_mask -
* param: legacy_spend_privkey -
* inoutparam: hwdev -
* outparam: ring_signature_out -
*/
void make_v3_legacy_ring_signature(const rct::key &message,
    std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t real_reference_index,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyRingSignatureV4 &ring_signature_out);
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyRingSignatureV4 &ring_signature_out);
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    std::vector<LegacyRingSignatureV4> &ring_signatures_out);
/**
* brief: check_v1_legacy_input_semantics_v1 - check semantics of a legacy input
*   - throws on failure
* param: input -
*/
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input);
/**
* brief: make_v1_legacy_input_v1 - make a legacy v1 input
* param: tx_proposal_prefix -
* param: input_proposal -
* param: ring_signature -
* param: referenced_enotes -
* param: legacy_spend_pubkey -
* inoutparam: hwdev -
* outparam: input_out -
*/
void make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignatureV4 ring_signature,
    rct::ctkeyV referenced_enotes,
    const rct::key &legacy_spend_pubkey,
    LegacyInputV1 &input_out);
void make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyInputV1 &input_out);
void make_v1_legacy_inputs_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,  //must align with input_proposals
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    std::vector<LegacyInputV1> &inputs_out);
/**
* brief: get_legacy_input_commitment_factors_v1 - collect input amounts and blinding factors
* param: input_proposals -
* outparam: input_amounts_out -
* outparam: blinding_factors_out -
*/
void get_legacy_input_commitment_factors_v1(const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);
void get_legacy_input_commitment_factors_v1(const std::vector<LegacyInputV1> &inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out);

} //namespace sp
