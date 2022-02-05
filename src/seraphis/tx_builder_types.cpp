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
#include "tx_builder_types.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalV1::get_enote_v1(SpEnoteV1 &enote_out) const
{
    // enote core
    enote_out.m_enote_core.m_onetime_address = m_proposal_core.m_onetime_address;
    enote_out.m_enote_core.m_amount_commitment =
        rct::commit(m_proposal_core.m_amount, m_proposal_core.m_amount_blinding_factor);

    // enote misc. details
    enote_out.m_encoded_amount = m_encoded_amount;
    enote_out.m_view_tag = m_view_tag;
    enote_out.m_addr_tag_enc = m_addr_tag_enc;
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalV1::gen(const rct::xmr_amount amount)
{
    // gen base of destination
    m_proposal_core.gen(amount);

    m_enote_ephemeral_pubkey = rct::pkGen();
    m_encoded_amount = crypto::rand_idx(rct::xmr_amount{-1});
    m_view_tag = crypto::rand_idx(view_tag_t{-1});
    crypto::rand(sizeof(m_addr_tag_enc), m_addr_tag_enc.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
SpTxProposalV1::SpTxProposalV1(std::vector<SpOutputProposalV1> output_proposals)
{
    // outputs should be sorted by onetime address
    std::sort(output_proposals.begin(), output_proposals.end());

    // sanity-check semantics
    check_v1_output_proposals_semantics_sp_v1(output_proposals);

    // make outputs
    // make tx supplement
    // prepare for range proofs
    make_v1_tx_outputs_sp_v1(output_proposals,
        m_outputs,
        m_tx_supplement,
        m_output_amounts,
        m_output_amount_commitment_blinding_factors);

    // sanity-check semantics
    check_v1_tx_supplement_semantics_sp_v1(m_tx_supplement, m_outputs.size());
}
//-------------------------------------------------------------------------------------------------------------------
rct::key SpTxProposalV1::get_proposal_prefix(const std::string &version_string) const
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() > 0, "Tried to get proposal prefix for a tx proposal with no outputs!");

    return get_tx_image_proof_message_sp_v1(version_string, m_outputs, m_tx_supplement);
}
//-------------------------------------------------------------------------------------------------------------------
SpTxPartialInputV1::SpTxPartialInputV1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix)
{
    // prepare input image
    input_proposal.m_proposal_core.get_enote_image_squashed_base(m_input_image.m_enote_image_core);

    // copy misc. proposal info
    m_image_address_mask           = input_proposal.m_proposal_core.m_address_mask;
    m_image_commitment_mask        = input_proposal.m_proposal_core.m_commitment_mask;
    m_proposal_prefix              = proposal_prefix;
    m_input_amount                 = input_proposal.m_proposal_core.m_amount;
    m_input_amount_blinding_factor = input_proposal.m_proposal_core.m_amount_blinding_factor;
    input_proposal.m_proposal_core.get_enote_base(m_input_enote_core);

    // construct image proof
    make_v1_tx_image_proof_sp_v1(input_proposal.m_proposal_core,
        m_input_image.m_enote_image_core.m_masked_address,
        m_proposal_prefix,
        m_image_proof);
}
//-------------------------------------------------------------------------------------------------------------------
SpTxPartialV1::SpTxPartialV1(const SpTxProposalV1 &proposal,
    std::vector<SpTxPartialInputV1> partial_inputs,
    const std::string &version_string)
{
    /// prepare

    // inputs and proposal must be compatible
    rct::key proposal_prefix{proposal.get_proposal_prefix(version_string)};

    for (const auto &partial_input : partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.m_proposal_prefix,
            "Incompatible tx pieces when making partial tx.");
    }

    // sort the inputs by key image
    std::sort(partial_inputs.begin(), partial_inputs.end());


    /// balance proof

    // get input image amount commitment blinding factors and amounts
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;
    std::vector<rct::xmr_amount> input_amounts;
    prepare_input_commitment_factors_for_balance_proof_v1(partial_inputs,
        input_image_amount_commitment_blinding_factors,
        input_amounts);

    // check balance (TODO: add fee)
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(input_amounts, proposal.m_output_amounts),
        "Amounts don't balance when making partial tx.");

    // make balance proof
    make_v1_tx_balance_proof_sp_v1(input_amounts,
        proposal.m_output_amounts,
        input_image_amount_commitment_blinding_factors,
        proposal.m_output_amount_commitment_blinding_factors,
        m_balance_proof);


    /// copy misc tx pieces

    // gather tx input parts
    m_input_images.reserve(partial_inputs.size());
    m_image_proofs.reserve(partial_inputs.size());
    m_input_enotes.reserve(partial_inputs.size());
    m_image_address_masks.reserve(partial_inputs.size());
    m_image_commitment_masks.reserve(partial_inputs.size());

    for (auto &partial_input : partial_inputs)
    {
        m_input_images.emplace_back(partial_input.m_input_image);
        m_image_proofs.emplace_back(std::move(partial_input.m_image_proof));
        m_input_enotes.emplace_back(partial_input.m_input_enote);
        m_image_address_masks.emplace_back(partial_input.m_image_address_mask);
        m_image_commitment_masks.emplace_back(partial_input.m_image_commitment_mask);
    }

    // gather tx output parts
    m_outputs = proposal.m_outputs;
    m_tx_supplement = proposal.m_tx_supplement;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
