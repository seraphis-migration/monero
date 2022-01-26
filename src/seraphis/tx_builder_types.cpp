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
#include "device/device.hpp"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_utils.h"
#include "tx_misc_utils.h"
#include "tx_utils.h"
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
void SpInputProposalV1::gen(const rct::xmr_amount amount)
{
    // generate a tx input: random secrets, random memo pieces (does not support info recovery)

    // input secrets
    this->gen_base(amount);

    // enote pubkey (these are stored separate from enotes)
    m_enote_pubkey = rct::pkGen();

    // enote
    rct::key recipient_spendbase;
    make_seraphis_spendbase(m_spendbase_privkey, recipient_spendbase);

    m_enote.make_base_with_address_extension(m_enote_view_privkey, recipient_spendbase, m_amount_blinding_factor, m_amount);

    m_enote.m_view_tag = crypto::rand_idx(static_cast<unsigned char>(-1));
    m_enote.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
void SpDestinationV1::get_amount_blinding_factor(const std::size_t enote_index,
    crypto::secret_key &amount_blinding_factor) const
{
    // r_t: sender-receiver shared secret
    rct::key sender_receiver_secret;
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        memwipe(&sender_receiver_secret, sizeof(rct::key));
    });

    make_seraphis_sender_receiver_secret(m_enote_privkey,
        m_recipient_viewkey,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    // x_t: amount commitment mask (blinding factor)
    make_seraphis_amount_commitment_mask(rct::rct2sk(sender_receiver_secret), rct::zero(), amount_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteV1 SpDestinationV1::to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const
{
    SpEnoteV1 enote;

    enote.make(m_enote_privkey,
        m_recipient_DHkey,
        m_recipient_viewkey,
        m_recipient_spendkey,
        m_amount,
        output_index,
        false,
        enote_pubkey_out);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void SpDestinationV1::gen(const rct::xmr_amount amount)
{
    // gen base of destination
    this->gen_base(amount);

    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
SpTxProposalV1::SpTxProposalV1(std::vector<SpDestinationV1> destinations)
{
    // destinations should be randomly ordered
    std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    m_destinations = std::move(destinations);

    // make outputs
    // make tx supplement
    // prepare for range proofs
    make_v1_tx_outputs_sp_v1(m_destinations,
        m_outputs,
        m_output_amounts,
        m_output_amount_commitment_blinding_factors,
        m_tx_supplement);
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
    // record proposal info
    m_input_enote = input_proposal.m_enote;
    m_input_amount = input_proposal.m_amount;
    m_input_amount_blinding_factor = input_proposal.m_amount_blinding_factor;
    m_proposal_prefix = proposal_prefix;

    // prepare input image
    make_v1_tx_image_sp_v1(input_proposal,
        m_input_image,
        m_image_address_mask,
        m_image_amount_mask);

    // construct image proof
    make_v1_tx_image_proof_sp_v1(input_proposal,
        m_input_image,
        m_image_address_mask,
        m_proposal_prefix,
        m_image_proof);
}
//-------------------------------------------------------------------------------------------------------------------
SpTxPartialV1::SpTxPartialV1(const SpTxProposalV1 &proposal,
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    const std::string &version_string)
{
    // inputs and proposal must be for the same tx
    rct::key proposal_prefix{proposal.get_proposal_prefix(version_string)};

    for (const auto &partial_input : partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.m_proposal_prefix,
            "Incompatible tx pieces when making partial tx.");
    }

    // prepare for sorting
    std::vector<std::size_t> input_sort_order{get_tx_input_sort_order_v1(partial_inputs)};
    CHECK_AND_ASSERT_THROW_MES(input_sort_order.size() == partial_inputs.size(),
        "Vector size mismatch when making partial tx.");

    // get input image amount commitment blinding factors
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;
    prepare_input_commitment_factors_for_balance_proof_v1(partial_inputs,
        input_image_amount_commitment_blinding_factors);

    // get input amounts
    std::vector<rct::xmr_amount> input_amounts;
    input_amounts.reserve(partial_inputs.size());
    for (const auto &partial_input : partial_inputs)
        input_amounts.emplace_back(partial_input.m_input_amount);

    // sort input pieces for balance proof
    CHECK_AND_ASSERT_THROW_MES(
        rearrange_vector(input_sort_order, input_image_amount_commitment_blinding_factors) &&
        rearrange_vector(input_sort_order, input_amounts),
        "Rearrange vector failed.");

    // make balance proof
    make_v1_tx_balance_proof_sp_v1(input_amounts,
        proposal.m_output_amounts,
        input_image_amount_commitment_blinding_factors,
        proposal.m_output_amount_commitment_blinding_factors,
        m_balance_proof);

    // gather and sort tx input parts
    m_input_images.reserve(partial_inputs.size());
    m_image_proofs.reserve(partial_inputs.size());
    m_input_enotes.reserve(partial_inputs.size());
    m_image_amount_masks.reserve(partial_inputs.size());
    m_image_address_masks.reserve(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(input_sort_order[input_index] < partial_inputs.size(),
            "Invalid old index for input pieces.");

        m_input_images.emplace_back(partial_inputs[input_sort_order[input_index]].m_input_image);
        m_image_proofs.emplace_back(partial_inputs[input_sort_order[input_index]].m_image_proof);
        m_input_enotes.emplace_back(partial_inputs[input_sort_order[input_index]].m_input_enote);
        m_image_address_masks.emplace_back(partial_inputs[input_sort_order[input_index]].m_image_address_mask);
        m_image_amount_masks.emplace_back(partial_inputs[input_sort_order[input_index]].m_image_amount_mask);
    }

    // gather the remaining tx parts
    m_outputs = proposal.m_outputs;
    m_tx_supplement = proposal.m_tx_supplement;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
