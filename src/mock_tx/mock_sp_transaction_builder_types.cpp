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
#include "mock_sp_transaction_builder_types.h"

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "mock_sp_transaction_component_types.h"
#include "mock_sp_transaction_utils.h"
#include "mock_sp_core_utils.h"
#include "mock_tx_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
// Sort order for tx inputs: key images ascending with byte-wise comparisons
//-------------------------------------------------------------------------------------------------------------------
static std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<MockTxPartialInputSpV1> &partial_inputs)
{
    std::vector<std::size_t> original_indices;
    original_indices.resize(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
        original_indices[input_index] = input_index;

    // sort: key images ascending with byte-wise comparisons
    std::sort(original_indices.begin(), original_indices.end(),
            [&partial_inputs](const std::size_t input_index_1, const std::size_t input_index_2) -> bool
            {
                return memcmp(&(partial_inputs[input_index_1].get_input_image().m_key_image),
                    &(partial_inputs[input_index_2].get_input_image().m_key_image), sizeof(crypto::key_image)) < 0;
            }
        );

    return original_indices;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSpV1::gen(const rct::xmr_amount amount)
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
void MockDestinationSpV1::get_amount_blinding_factor(const std::size_t enote_index,
    crypto::secret_key &amount_blinding_factor) const
{
    // r_t: sender-receiver shared secret
    rct::key sender_receiver_secret;
    make_seraphis_sender_receiver_secret(m_enote_privkey,
        m_recipient_viewkey,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    // x_t: amount commitment mask (blinding factor)
    make_seraphis_amount_commitment_mask(rct::rct2sk(sender_receiver_secret), amount_blinding_factor);

    memwipe(&sender_receiver_secret, sizeof(rct::key));
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteSpV1 MockDestinationSpV1::to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const
{
    MockENoteSpV1 enote;

    enote.make(m_enote_privkey,
        m_recipient_DHkey,
        m_recipient_viewkey,
        m_recipient_spendkey,
        m_amount,
        output_index,
        enote_pubkey_out);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestinationSpV1::gen(const rct::xmr_amount amount)
{
    // gen base of destination
    this->gen_base(amount);

    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
MockTxProposalSpV1::MockTxProposalSpV1(std::vector<MockDestinationSpV1> destinations,
    const std::size_t max_rangeproof_splits)
{
    // destinations should be randomly ordered
    std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    m_destinations = std::move(destinations);

    // make outputs
    // make tx supplement
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;

    make_v1_tx_outputs_sp_v1(m_destinations,
        m_outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        m_tx_supplement);

    // make balance proof (i.e. just range proofs in v1)
    make_v1_tx_balance_proof_sp_v1(output_amounts,
        output_amount_commitment_blinding_factors,
        max_rangeproof_splits,
        m_balance_proof);
}
//-------------------------------------------------------------------------------------------------------------------
rct::key MockTxProposalSpV1::get_proposal_prefix(const std::string &version_string) const
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() > 0, "Tried to get proposal prefix for a tx proposal with no outputs!");

    return get_tx_image_proof_message_sp_v1(version_string, m_outputs, m_balance_proof, m_tx_supplement);
}
//-------------------------------------------------------------------------------------------------------------------
MockTxPartialInputSpV1::MockTxPartialInputSpV1(const MockInputProposalSpV1 &input_proposal,
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
MockTxPartialInputSpV1::MockTxPartialInputSpV1(const MockInputProposalSpV1 &input_proposal,
        const rct::key &proposal_prefix,
        const MockTxProposalSpV1 &tx_proposal,
        const std::vector<MockTxPartialInputSpV1> &other_inputs)
{
    // record proposal info
    m_input_enote = input_proposal.m_enote;
    m_input_amount = input_proposal.m_amount;
    m_input_amount_blinding_factor = input_proposal.m_amount_blinding_factor;
    m_proposal_prefix = proposal_prefix;

    // prepare last input image
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> input_amount_blinding_factors;
    output_amount_commitment_blinding_factors.resize(tx_proposal.get_destinations().size());
    input_amount_blinding_factors.reserve(other_inputs.size());

    for (std::size_t output_index{0}; output_index < tx_proposal.get_destinations().size(); ++output_index)
    {
        // y_t  (for index 't')
        tx_proposal.get_destinations()[output_index].get_amount_blinding_factor(output_index,
            output_amount_commitment_blinding_factors[output_index]);
    }

    for (const auto &other_input : other_inputs)
    {
        // v_c = x + t_c
        input_amount_blinding_factors.emplace_back(other_input.m_input_amount_blinding_factor);  // x
        sc_add(&(input_amount_blinding_factors.back()),
            &(input_amount_blinding_factors.back()),
            &(other_input.m_image_amount_mask));  // + t_c
    }

    make_v1_tx_image_last_sp_v1(input_proposal,
        output_amount_commitment_blinding_factors,
        input_amount_blinding_factors,
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
MockTxPartialSpV1::MockTxPartialSpV1(const MockTxProposalSpV1 &proposal,
        const std::vector<MockTxPartialInputSpV1> &partial_inputs,
        const std::string &version_string)
{
    // inputs and proposal must be for the same tx
    rct::key proposal_prefix{proposal.get_proposal_prefix(version_string)};

    for (const auto &partial_input : partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.get_proposal_prefix(),
            "Incompatible tx pieces when making partial tx.");
    }

    // gather tx input parts (sorted)
    m_input_images.reserve(partial_inputs.size());
    m_image_proofs.reserve(partial_inputs.size());
    m_input_enotes.reserve(partial_inputs.size());
    m_image_amount_masks.reserve(partial_inputs.size());
    m_image_address_masks.reserve(partial_inputs.size());

    std::vector<std::size_t> input_sort_order{get_tx_input_sort_order_v1(partial_inputs)};
    CHECK_AND_ASSERT_THROW_MES(input_sort_order.size() == partial_inputs.size(),
        "Vector size mismatch when making partial tx.");

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(input_sort_order[input_index] < partial_inputs.size(),
            "Invalid old index for input pieces.");

        m_input_images.emplace_back(partial_inputs[input_sort_order[input_index]].get_input_image());
        m_image_proofs.emplace_back(partial_inputs[input_sort_order[input_index]].get_image_proof());
        m_input_enotes.emplace_back(partial_inputs[input_sort_order[input_index]].get_input_enote());
        m_image_address_masks.emplace_back(partial_inputs[input_sort_order[input_index]].get_image_address_mask());
        m_image_amount_masks.emplace_back(partial_inputs[input_sort_order[input_index]].get_image_amount_mask());
    }

    // gather the remaining tx parts
    m_outputs = proposal.get_outputs();
    m_tx_supplement = proposal.get_tx_supplement();
    m_balance_proof = proposal.get_balance_proof();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
