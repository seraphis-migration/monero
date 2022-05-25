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

//paired header
#include "tx_builder_types_multisig.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigPublicInputProposalV1::get_masked_address(rct::key &masked_address_out) const
{
    // Ko' = t_k G + H(Ko,C) Ko
    make_seraphis_squashed_address_key(m_enote.m_core.m_onetime_address,
        m_enote.m_core.m_amount_commitment,
        masked_address_out);  //H(Ko,C) Ko
    sp::mask_key(m_address_mask, masked_address_out, masked_address_out);  //t_k G + H(Ko,C) Ko
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigPublicInputProposalV1::get_squash_prefix(crypto::secret_key &squash_prefix_out) const
{
    // H(Ko,C)
    make_seraphis_squash_prefix(m_enote.m_core.m_onetime_address, m_enote.m_core.m_amount_commitment, squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigPublicInputProposalV1::get_input_proposal_v1(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpInputProposalV1 &input_proposal_out) const
{
    CHECK_AND_ASSERT_THROW_MES(try_make_v1_input_proposal_v1(m_enote,
            m_enote_ephemeral_pubkey,
            m_input_context,
            wallet_spend_pubkey,
            k_view_balance,
            m_address_mask,
            m_commitment_mask,
            input_proposal_out),
        "multisig public input proposal to plain input proposal: conversion failed (wallet may not own this input.");
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigTxProposalV1::get_v1_tx_proposal_v1(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxProposalV1 &tx_proposal_out) const
{
    // extract input proposals
    std::vector<SpInputProposalV1> plain_input_proposals;

    for (const SpMultisigPublicInputProposalV1 &public_input_proposal : m_input_proposals)
    {
        plain_input_proposals.emplace_back();
        public_input_proposal.get_input_proposal_v1(wallet_spend_pubkey, k_view_balance, plain_input_proposals.back());
    }

    // extract memo field elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(m_partial_memo, additional_memo_elements),
        "multisig tx proposal: could not parse partial memo.");

    // make the tx proposal
    make_v1_tx_proposal_v1(m_normal_payment_proposals,
        m_selfsend_payment_proposals,
        m_tx_fee,
        std::move(plain_input_proposals),
        std::move(additional_memo_elements),
        tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigTxProposalV1::get_proposal_prefix_v1(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    rct::key &proposal_prefix_out) const
{
    // extract proposal
    SpTxProposalV1 tx_proposal;
    this->get_v1_tx_proposal_v1(wallet_spend_pubkey, k_view_balance, tx_proposal);

    // get prefix from proposal
    tx_proposal.get_proposal_prefix(m_version_string, k_view_balance, proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpMultisigInputInitSetV1::try_get_nonces(const rct::key &masked_address,
    const std::size_t nonces_index,
    SpCompositionProofMultisigPubNonces &nonces_out) const
{
    if (m_input_inits.find(masked_address) == m_input_inits.end())
        return false;

    if (m_input_inits.at(masked_address).size() <= nonces_index)
        return false;

    nonces_out = m_input_inits.at(masked_address)[nonces_index];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
