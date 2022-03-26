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
//-------------------------------------------------------------------------------------------------------------------
static std::unordered_map<crypto::key_image, std::vector<SpMultisigInputInitV1>> organize_by_key_image(
    std::vector<SpMultisigInputInitV1> input_inits)
{
    return std::unordered_map<crypto::key_image, std::vector<SpMultisigInputInitV1>>{};
}
//-------------------------------------------------------------------------------------------------------------------
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
    temp_K = m_core.m_enote.m_core.m_onetime_address;  //Ko = (k_{a, sender} + k_{a, recipient}) X + k_b U
    reduce_seraphis_spendkey(m_enote_view_privkey, temp_K);  //k_b U
    make_seraphis_key_image(m_enote_view_privkey, temp_K, key_image_out);  //k_b/(k_{a, sender} + k_{a, recipient}) U
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
void check_v1_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &proposal)
{
    // input amount components should be able to reproduce the amount commitment
    rct::key reconstructed_amount_commitment{
            rct::commit(proposal.m_input_amount, rct::sk2rct(proposal.m_input_amount_blinding_factor))
        };
    CHECK_AND_ASSERT_THROW_MES(reconstructed_amount_commitment == proposal.m_core.m_enote.m_core.m_amount_commitment,
        "multisig input proposal: could not reconstruct the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    // add components
    SpMultisigInputProposalV1 temp_proposal;

    temp_proposal.m_core.m_enote = enote;
    temp_proposal.m_core.m_address_mask = address_mask;
    temp_proposal.m_core.m_commitment_mask = commitment_mask;
    temp_proposal.m_enote_view_privkey = enote_view_privkey;
    temp_proposal.m_input_amount = input_amount;
    temp_proposal.m_input_amount_blinding_factor = input_amount_blinding_factor;

    // make sure it is well-formed before setting the output
    check_v1_multisig_input_proposal_semantics_v1(temp_proposal);
    proposal_out = std::move(temp_proposal);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    SpMultisigInputProposalV1 &proposal_out)
{
    make_v1_multisig_input_proposal_v1(enote,
        enote_view_privkey,
        input_amount,
        input_amount_blinding_factor,
        rct::rct2sk(rct::skGen()),
        rct::rct2sk(rct::skGen()),
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &version_string)
{
    // unique onetime addresses
    // if only 2 outputs, should be 1 unique enote ephemeral pubkey, otherwise 1:1 with outputs and all unique
    // - converting to a plain tx proposal does these checks internally
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(tx_proposal);
    rct::key proposal_prefix{tx_proposal.get_proposal_prefix(version_string)};

    // output amounts >= input amounts (note: equality in real txs is unlikely due to tx fees)
    using boost::multiprecision::uint128_t;
    uint128_t input_sum{0};
    uint128_t output_sum{0};

    for (const SpMultisigInputProposalV1 &input_proposal : multisig_tx_proposal.m_input_proposals)
        input_sum += input_proposal.m_input_amount;

    for (const rct::xmr_amount out_amount : tx_proposal.m_output_amounts)
        output_sum += out_amount;

    CHECK_AND_ASSERT_THROW_MES(input_sum <= output_sum, "multisig tx proposal: input amount exceeds proposed output amount.");

    // input proposals line up 1:1 with input proof proposals
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() ==
        multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig tx proposal: input proposals don't line up with input proposal proofs.");

    SpEnote enote_core_temp;
    SpEnoteImage enote_image_temp;
    for (std::size_t input_index{0}; input_index < multisig_tx_proposal.m_input_proposals.size(); ++input_index)
    {
        // input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].message == proposal_prefix,
            "multisig tx proposal: input proof proposal does not match the tx proposal (different proposal prefix).");

        // input proof proposal keys and key images all line up 1:1 and match with input proposals
        multisig_tx_proposal.m_input_proposals[input_index].get_enote_core(enote_core_temp);
        multisig_tx_proposal.m_input_proposals[input_index].get_enote_image(enote_image_temp);
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].K ==
            enote_core_temp.m_onetime_address,
            "multisig tx proposal: input proof proposal does not match input proposal (different onetime addresses).");
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].KI ==
            enote_image_temp.m_key_image,
            "multisig tx proposal: input proof proposal does not match input proposal (different key images).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    const std::string &version_string,
    std::vector<SpMultisigInputProposalV1> input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out)
{
    SpMultisigTxProposalV1 temp_proposal;

    // add miscellaneous components
    temp_proposal.m_explicit_payments = std::move(explicit_payments);
    temp_proposal.m_opaque_payments = std::move(opaque_payments);
    temp_proposal.m_partial_memo = std::move(partial_memo);
    temp_proposal.m_input_proposals = std::move(input_proposals);
    temp_proposal.m_aggregate_signer_set_filter = aggregate_signer_set_filter;

    // get proposal prefix (it is safe to do this before preparing composition proofs)
    SpTxProposalV1 tx_proposal;
    temp_proposal.get_v1_tx_proposal_v1(tx_proposal);
    rct::key proposal_prefix{tx_proposal.get_proposal_prefix(version_string)};

    // prepare composition proofs for each input
    temp_proposal.m_input_proof_proposals.clear();
    temp_proposal.m_input_proof_proposals.reserve(temp_proposal.m_input_proposals.size());
    SpEnote enote_core_temp;
    SpEnoteImage enote_image_temp;

    for (const SpMultisigInputProposalV1 &input_proposal : temp_proposal.m_input_proposals)
    {
        input_proposal.get_enote_core(enote_core_temp);
        input_proposal.get_enote_image(enote_image_temp);
        temp_proposal.m_input_proof_proposals.emplace_back(
                sp_composition_multisig_proposal(proposal_prefix,
                    enote_core_temp.m_onetime_address,
                    enote_image_temp.m_key_image)
            );
    }

    // make sure the proposal is well-formed before setting output
    check_v1_multisig_tx_proposal_semantics_v1(temp_proposal, version_string);

    proposal_out = std::move(temp_proposal);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_init_v1(const crypto::public_key &signer_id,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::uint32_t threshold,
    const rct::key &proposal_prefix,
    const crypto::key_image &key_image,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitV1 &input_init_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_inits_v1(const crypto::public_key &signer_id,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::uint32_t threshold,
    const SpMultisigTxProposalV1 &tx_proposal,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputInitV1> &input_inits_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_partial_sig_v1(const multisig::multisig_account &signer_account,
    const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,
    const rct::key &proposal_prefix,
    const multisig::signer_set_filter signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputPartialSigV1 &input_partial_sig_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_partial_sigs_single_input_v1(const multisig::multisig_account &signer_account,
    const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,
    const std::vector<SpMultisigInputInitV1> &input_inits,  //including from self
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigV1> &input_partial_sigs_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_partial_sigs_multiple_inputs_v1(const multisig::multisig_account &signer_account,
    const std::vector<SpMultisigInputProposalV1> &input_proposals,
    const std::unordered_map<crypto::key_image, crypto::secret_key> &input_enote_view_privkeys,
    const std::vector<SpMultisigInputInitV1> &input_inits,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::unordered_map<crypto::key_image, std::vector<SpMultisigInputPartialSigV1>> &input_partial_sigs_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_input_v1(const SpMultisigInputProposalV1 &input_proposal,
    const crypto::secret_key &input_enote_view_privkey,  //use to verify that key images match for 'correct by construction'
    const std::vector<SpMultisigInputPartialSigV1> &input_partial_sigs,
    SpPartialInputV1 &partial_input_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
