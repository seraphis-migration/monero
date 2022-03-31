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
#include "sp_crypto_utils.h"
#include "sp_core_enote_utils.h"
#include "tx_builder_types.h"
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
bool SpMultisigInputProposalV1::operator<(const SpMultisigInputProposalV1 &other_proposal) const
{
    crypto::key_image this_KI, other_KI;
    this->get_key_image(this_KI);
    other_proposal.get_key_image(other_KI);
    return memcmp(&this_KI, &other_KI, sizeof(rct::key)) < 0;
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigInputProposalV1::get_key_image(crypto::key_image &key_image_out) const
{
    // KI = k_b/k_a U
    rct::key temp_K;
    temp_K = m_core.m_enote.m_core.m_onetime_address;  //Ko = k_a X + k_b U
    reduce_seraphis_spendkey(m_enote_view_privkey, temp_K);  //k_b U
    make_seraphis_key_image(m_enote_view_privkey, rct::rct2pk(temp_K), key_image_out);  //k_b/k_a U
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigInputProposalV1::get_enote_core(SpEnote &enote_out) const
{
    enote_out = m_core.m_enote.m_core;
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigInputProposalV1::get_enote_image(SpEnoteImage &image_out) const
{
    // {Ko, C}
    SpEnote enote_temp;
    this->get_enote_core(enote_temp);

    // Ko' = t_k G + H(Ko,C) Ko
    make_seraphis_squashed_address_key(enote_temp.m_onetime_address,
        enote_temp.m_amount_commitment,
        image_out.m_masked_address);  //H(Ko,C) Ko
    sp::mask_key(m_core.m_address_mask,
        image_out.m_masked_address,
        image_out.m_masked_address);  //t_k G + H(Ko,C) Ko

    // C' = t_c G + C
    sp::mask_key(m_core.m_commitment_mask, enote_temp.m_amount_commitment, image_out.m_masked_commitment);

    // KI = k_a X + k_b U
    this->get_key_image(image_out.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultisigTxProposalV1::get_v1_tx_proposal_v1(SpTxProposalV1 &tx_proposal_out) const
{
    // assemble output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    output_proposals.reserve(m_explicit_payments.size() + m_opaque_payments.size());

    output_proposals = m_opaque_payments;

    for (const jamtis::JamtisPaymentProposalV1 &explicit_payment : m_explicit_payments)
    {
        output_proposals.emplace_back();
        explicit_payment.get_output_proposal_v1(output_proposals.back());
    }

    // extract memo field elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(m_partial_memo, additional_memo_elements),
        "multisig tx proposal: could not parse partial memo.");

    // make the tx proposal
    make_v1_tx_proposal_v1(std::move(output_proposals),
        std::move(additional_memo_elements),
        tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
rct::key SpMultisigTxProposalV1::get_proposal_prefix_v1() const
{
    SpTxProposalV1 tx_proposal;
    this->get_v1_tx_proposal_v1(tx_proposal);
    return tx_proposal.get_proposal_prefix(m_version_string);
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
