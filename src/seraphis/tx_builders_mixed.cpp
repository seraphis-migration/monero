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
#include "tx_builders_mixed.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// convert a crypto::secret_key vector to an rct::key vector, and obtain a memwiper for the rct::key vector
//-------------------------------------------------------------------------------------------------------------------
static auto convert_skv_to_rctv(const std::vector<crypto::secret_key> &skv, rct::keyV &rctv_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&rctv_out]()
            {
                memwipe(rctv_out.data(), rctv_out.size()*sizeof(rct::key));
            }
        );

    rctv_out.clear();
    rctv_out.reserve(skv.size());

    for (const auto &skey : skv)
        rctv_out.emplace_back(rct::sk2rct(skey));

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<SpEnoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &proof_message_out)
{
    // H(crypto project name, version string, output enotes, enote ephemeral pubkeys, memos)
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) +
        version_string.size() +
        output_enotes.size()*SpEnoteV1::get_size_bytes() +
        tx_supplement.get_size_bytes());

    hash = CRYPTONOTE_NAME;
    hash += version_string;
    for (const auto &output_enote : output_enotes)
    {
        output_enote.append_to_string(hash);
    }
    for (const auto &enote_pubkey : tx_supplement.m_output_enote_ephemeral_pubkeys)
    {
        hash.append(reinterpret_cast<const char*>(enote_pubkey.bytes), sizeof(enote_pubkey));
    }
    hash.append(reinterpret_cast<const char*>(tx_supplement.m_tx_extra.data()), tx_supplement.m_tx_extra.size());

    rct::hash_to_scalar(proof_message_out, hash.data(), hash.size());
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_balance_proof_v1(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out)
{
    // for squashed enote model

    // check balance
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(input_amounts, output_amounts, transaction_fee),
        "Amounts don't balance when making balance proof.");

    // combine inputs and outputs
    std::vector<rct::xmr_amount> amounts;
    std::vector<crypto::secret_key> blinding_factors;
    amounts.reserve(input_amounts.size() + output_amounts.size());
    blinding_factors.reserve(input_amounts.size() + output_amounts.size());

    amounts = input_amounts;
    amounts.insert(amounts.end(), output_amounts.begin(), output_amounts.end());
    blinding_factors = input_image_amount_commitment_blinding_factors;
    blinding_factors.insert(blinding_factors.end(),
        output_amount_commitment_blinding_factors.begin(),
        output_amount_commitment_blinding_factors.end());

    // make range proofs
    rct::BulletproofPlus range_proofs;

    rct::keyV amount_commitment_blinding_factors;
    auto vec_wiper = convert_skv_to_rctv(blinding_factors, amount_commitment_blinding_factors);
    make_bpp_rangeproofs(amounts,
        amount_commitment_blinding_factors,
        range_proofs);

    balance_proof_out.m_bpp_proof = std::move(range_proofs);

    // set the remainder blinding factor
    crypto::secret_key remainder_blinding_factor;
    subtract_secret_key_vectors(input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        remainder_blinding_factor);

    balance_proof_out.m_remainder_blinding_factor = rct::sk2rct(remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const rct::xmr_amount transaction_fee)
{
    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;
    in_amounts.reserve(input_proposals.size());
    out_amounts.reserve(output_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        in_amounts.emplace_back(input_proposal.m_core.m_amount);
    }
    for (const auto &output_proposal : output_proposals)
    {
        out_amounts.emplace_back(output_proposal.m_core.m_amount);
    }

    return balance_check_in_out_amnts(in_amounts, out_amounts, transaction_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(const SpTxProposalV1 &proposal,
    std::vector<SpPartialInputV1> partial_inputs,
    const rct::xmr_amount transaction_fee,
    const std::string &version_string,
    SpPartialTxV1 &partial_tx_out)
{
    // reset tx
    partial_tx_out = SpPartialTxV1{};


    /// prepare

    // inputs and proposal must be compatible
    rct::key proposal_prefix;
    proposal.get_proposal_prefix(version_string, proposal_prefix);

    for (const auto &partial_input : partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.m_proposal_prefix,
            "Incompatible tx pieces when making partial tx.");
    }

    // sort the inputs by key image
    std::sort(partial_inputs.begin(), partial_inputs.end());


    /// balance proof

    // get input amounts and image amount commitment blinding factors
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;
    prepare_input_commitment_factors_for_balance_proof_v1(partial_inputs,
        input_amounts,
        input_image_amount_commitment_blinding_factors);

    // make balance proof
    make_v1_balance_proof_v1(input_amounts,
        proposal.m_output_amounts,
        transaction_fee,
        input_image_amount_commitment_blinding_factors,
        proposal.m_output_amount_commitment_blinding_factors,
        partial_tx_out.m_balance_proof);


    /// copy misc tx pieces

    // gather tx input parts
    partial_tx_out.m_input_images.reserve(partial_inputs.size());
    partial_tx_out.m_image_proofs.reserve(partial_inputs.size());
    partial_tx_out.m_input_enotes.reserve(partial_inputs.size());
    partial_tx_out.m_image_address_masks.reserve(partial_inputs.size());
    partial_tx_out.m_image_commitment_masks.reserve(partial_inputs.size());

    for (auto &partial_input : partial_inputs)
    {
        partial_tx_out.m_input_images.emplace_back(partial_input.m_input_image);
        partial_tx_out.m_image_proofs.emplace_back(std::move(partial_input.m_image_proof));
        partial_tx_out.m_input_enotes.emplace_back(partial_input.m_input_enote_core);
        partial_tx_out.m_image_address_masks.emplace_back(partial_input.m_image_address_mask);
        partial_tx_out.m_image_commitment_masks.emplace_back(partial_input.m_image_commitment_mask);
    }

    // gather tx output parts
    partial_tx_out.m_outputs = proposal.m_outputs;
    partial_tx_out.m_tx_supplement = proposal.m_tx_supplement;
    partial_tx_out.m_tx_fee = transaction_fee;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
