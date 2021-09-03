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

//paired header
#include "tx_builder_types_multisig.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "enote_record_types.h"
#include "enote_record_utils_legacy.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyMultisigInputProposalV1 &a, const LegacyMultisigInputProposalV1 &b)
{
    return a.key_image < b.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_input_proposal_v1(const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    LegacyInputProposalV1 &input_proposal_out)
{
    // extract legacy intermediate enote record from proposal
    LegacyIntermediateEnoteRecord legacy_intermediate_record;

    CHECK_AND_ASSERT_THROW_MES(try_get_legacy_intermediate_enote_record(multisig_input_proposal.enote,
            multisig_input_proposal.enote_ephemeral_pubkey,
            multisig_input_proposal.tx_output_index,
            multisig_input_proposal.unlock_time,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            hw::get_device("default"),
            legacy_intermediate_record),
        "legacy multisig input proposal to legacy input proposal: could not recover intermediate enote record for input"
        "proposal's enote.");

    // upgrade to full legacy enote record
    LegacyEnoteRecord legacy_enote_record;
    get_legacy_enote_record(legacy_intermediate_record, multisig_input_proposal.key_image, legacy_enote_record);

    // make the legacy input proposal
    make_v1_legacy_input_proposal_v1(legacy_enote_record, multisig_input_proposal.commitment_mask, input_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_sp_input_proposal_v1(const SpMultisigInputProposalV1 &multisig_input_proposal,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpInputProposalV1 &input_proposal_out)
{
    CHECK_AND_ASSERT_THROW_MES(try_make_v1_input_proposal_v1(multisig_input_proposal.enote,
            multisig_input_proposal.enote_ephemeral_pubkey,
            multisig_input_proposal.input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            multisig_input_proposal.address_mask,
            multisig_input_proposal.commitment_mask,
            input_proposal_out),
        "seraphis multisig input proposal to seraphis input proposal: conversion failed (wallet may not own this input).");
}
//-------------------------------------------------------------------------------------------------------------------
void get_v1_tx_proposal_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxProposalV1 &tx_proposal_out)
{
    // extract legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals;
    legacy_input_proposals.reserve(multisig_tx_proposal.legacy_multisig_input_proposals.size());

    for (const LegacyMultisigInputProposalV1 &multisig_input_proposal :
        multisig_tx_proposal.legacy_multisig_input_proposals)
    {
        get_legacy_input_proposal_v1(multisig_input_proposal,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            tools::add_element(legacy_input_proposals));
    }

    // extract seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals;
    sp_input_proposals.reserve(multisig_tx_proposal.sp_multisig_input_proposals.size());

    for (const SpMultisigInputProposalV1 &multisig_input_proposal : multisig_tx_proposal.sp_multisig_input_proposals)
    {
        get_sp_input_proposal_v1(multisig_input_proposal,
            jamtis_spend_pubkey,
            k_view_balance,
            tools::add_element(sp_input_proposals));
    }

    // extract memo field elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(multisig_tx_proposal.partial_memo,
            additional_memo_elements),
        "multisig tx proposal: could not parse partial memo.");

    // make the tx proposal
    make_v1_tx_proposal_v1(std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        multisig_tx_proposal.normal_payment_proposals,
        multisig_tx_proposal.selfsend_payment_proposals,
        multisig_tx_proposal.tx_fee,
        std::move(additional_memo_elements),
        tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_tx_proposal_prefix_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    rct::key &tx_proposal_prefix_out)
{
    // extract proposal
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // get prefix from proposal
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool matches_with(const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const multisig::CLSAGMultisigProposal &proof_proposal)
{
    // onetime address to sign
    if (!(onetime_address_ref(multisig_input_proposal.enote) == main_proof_key_ref(proof_proposal)))
        return false;

    // amount commitment to sign
    const rct::key amount_commitment{amount_commitment_ref(multisig_input_proposal.enote)};
    if (!(amount_commitment == auxilliary_proof_key_ref(proof_proposal)))
        return false;

    // pseudo-output commitment
    rct::key masked_commitment;
    mask_key(multisig_input_proposal.commitment_mask, amount_commitment, masked_commitment);
    if (!(masked_commitment == proof_proposal.masked_C))
        return false;

    // key image
    if (!(multisig_input_proposal.key_image == proof_proposal.KI))
        return false;

    // auxilliary key image
    crypto::key_image auxilliary_key_image;
    make_legacy_auxilliary_key_image_v1(multisig_input_proposal.commitment_mask,
        onetime_address_ref(multisig_input_proposal.enote),
        hw::get_device("default"),
        auxilliary_key_image);

    if (!(auxilliary_key_image == proof_proposal.D))
        return false;

    // references line up 1:1
    if (multisig_input_proposal.reference_set.size() != proof_proposal.ring_members.size())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool matches_with(const LegacyMultisigInputProposalV1 &multisig_input_proposal, const LegacyEnoteRecord &enote_record)
{
    // onetime address
    if (!(onetime_address_ref(multisig_input_proposal.enote) == onetime_address_ref(enote_record.enote)))
        return false;

    // amount commitment
    if (!(amount_commitment_ref(multisig_input_proposal.enote) == amount_commitment_ref(enote_record.enote)))
        return false;

    // key image
    if (!(multisig_input_proposal.key_image == enote_record.key_image))
        return false;

    // misc
    if (!(multisig_input_proposal.enote_ephemeral_pubkey == enote_record.enote_ephemeral_pubkey))
        return false;
    if (!(multisig_input_proposal.tx_output_index == enote_record.tx_output_index))
        return false;
    if (!(multisig_input_proposal.unlock_time <= enote_record.unlock_time))  //<= in case of duplicate enotes
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool matches_with(const SpMultisigInputProposalV1 &multisig_input_proposal, const SpEnoteRecordV1 &enote_record)
{
    // enote
    if (!(multisig_input_proposal.enote == enote_record.enote))
        return false;

    // enote ephemeral pubkey
    if (!(multisig_input_proposal.enote_ephemeral_pubkey == enote_record.enote_ephemeral_pubkey))
        return false;

    // input context
    if (!(multisig_input_proposal.input_context == enote_record.input_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
