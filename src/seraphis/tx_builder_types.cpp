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
#include "sp_crypto_utils.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalV1::get_enote_v1(SpEnoteV1 &enote_out) const
{
    // enote core
    enote_out.m_core.m_onetime_address = m_core.m_onetime_address;
    enote_out.m_core.m_amount_commitment = rct::commit(this->get_amount(), rct::sk2rct(m_core.m_amount_blinding_factor));

    // enote misc. details
    enote_out.m_encoded_amount = m_encoded_amount;
    enote_out.m_addr_tag_enc = m_addr_tag_enc;
    enote_out.m_view_tag = m_view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalV1::gen(const rct::xmr_amount amount, const std::size_t num_random_memo_elements)
{
    // gen base of destination
    m_core.gen(amount);

    m_enote_ephemeral_pubkey = x25519_pubkey_gen();
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    crypto::rand(sizeof(m_addr_tag_enc), m_addr_tag_enc.bytes);
    m_view_tag = crypto::rand_idx(static_cast<jamtis::view_tag_t>(-1));

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), m_partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void SpTxProposalV1::get_output_proposals_v1(const crypto::secret_key &k_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_out) const
{
    CHECK_AND_ASSERT_THROW_MES(m_normal_payment_proposals.size() + m_selfsend_payment_proposals.size() > 0,
        "Tried to get output proposals for a tx proposal with no outputs!");

    // input context
    rct::key input_context;
    make_standard_input_context_v1(m_input_proposals, input_context);

    // output proposals
    output_proposals_out.clear();
    output_proposals_out.reserve(m_normal_payment_proposals.size() + m_selfsend_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : m_normal_payment_proposals)
    {
        output_proposals_out.emplace_back();
        normal_payment_proposal.get_output_proposal_v1(input_context, output_proposals_out.back());
    }

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : m_selfsend_payment_proposals)
    {
        output_proposals_out.emplace_back();
        selfsend_payment_proposal.get_output_proposal_v1(k_view_balance, input_context, output_proposals_out.back());
    }

    // sort output proposals
    std::sort(output_proposals_out.begin(), output_proposals_out.end());
}
//-------------------------------------------------------------------------------------------------------------------
void SpTxProposalV1::get_proposal_prefix(const std::string &version_string,
    const crypto::secret_key &k_view_balance,
    rct::key &proposal_prefix_out) const
{
    // get output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    this->get_output_proposals_v1(k_view_balance, output_proposals);

    // sanity check semantics
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // make the proposal prefix
    make_tx_image_proof_message_v1(version_string,
        m_input_proposals,
        output_proposals,
        m_partial_memo,
        m_tx_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
