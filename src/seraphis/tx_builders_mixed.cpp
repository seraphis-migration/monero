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
#include "jamtis_core_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis_config_temp.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "txtype_squashed_v1.h"

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

    for (const crypto::secret_key &skey : skv)
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
    for (const SpEnoteV1 &output_enote : output_enotes)
    {
        output_enote.append_to_string(hash);
    }
    for (const rct::key &enote_pubkey : tx_supplement.m_output_enote_ephemeral_pubkeys)
    {
        hash.append(reinterpret_cast<const char*>(enote_pubkey.bytes), sizeof(enote_pubkey));
    }
    hash.append(reinterpret_cast<const char*>(tx_supplement.m_tx_extra.data()), tx_supplement.m_tx_extra.size());

    rct::hash_to_scalar(proof_message_out, hash.data(), hash.size());
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_image_proof_message_v1(const std::string &version_string,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    rct::key &proof_message_out)
{
    // extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    // collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // get proof message
    make_tx_image_proof_message_v1(version_string, output_enotes, tx_supplement, proof_message_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_proposal_semantics_v1(const SpTxProposalV1 &tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// validate self-send payment proposals

    // 1. there must be at least one self-send output
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_selfsend_payments.size() > 0,
        "Semantics check tx proposal v1: there are no self-send outputs (at least one is expected).");

    // 2. there cannot be two self-send outputs of the same type and no other outputs
    if (tx_proposal.m_normal_payments.size() == 0 &&
        tx_proposal.m_selfsend_payments.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_selfsend_payments[0].m_type != tx_proposal.m_selfsend_payments[1].m_type,
            "Semantics check tx proposal v1: there are two self-send outputs of the same type but no other outputs "
            "(not allowed).");
    }

    // 3. all self-send destinations must be owned by the wallet
    crypto::secret_key k_find_received;
    crypto::secret_key s_generate_address;
    rct::key findreceived_pubkey;
    jamtis::make_jamtis_findreceived_key(k_view_balance, k_find_received);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    rct::scalarmultBase(findreceived_pubkey, rct::sk2rct(k_find_received));
    jamtis::address_index_t j_temp;

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment : tx_proposal.m_selfsend_payments)
    {
        CHECK_AND_ASSERT_THROW_MES(jamtis::try_get_jamtis_index_from_destination_v1(selfsend_payment.m_destination,
                wallet_spend_pubkey,
                findreceived_pubkey,
                s_generate_address,
                j_temp),
            "Semantics check tx proposal v1: invalid self-send destination (not a destination of this wallet).");
    }


    /// check consistency of outputs

    // 1. extract output proposals from tx proposal (and check their semantics)
    std::vector<SpOutputProposalV1> output_proposals;
    tx_proposal.get_output_proposals_v1(k_view_balance, output_proposals);

    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract outputs from the output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    finalize_tx_extra_v1(tx_proposal.m_partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // 3. at least two outputs are expected
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() >= 2,
        "Semantics check tx proposal v1: there are fewer than 2 outputs.");

    // 4. outputs should be sorted
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(output_enotes.begin(), output_enotes.end()),
        "Semantics check tx proposal v1: outputs aren't sorted.");

    // 5. outputs should be unique (can use adjacent_find when sorted)
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(output_enotes.begin(),
            output_enotes.end(),
            equals_from_less{}) == output_enotes.end(),
        "Semantics check tx proposal v1: output onetime addresses are not all unique.");

    // 6. onetime addresses should be canonical (sanity check so our tx outputs don't have duplicate key images)
    for (const SpEnoteV1 &output_enote : output_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(output_enote.m_core.onetime_address_is_canonical(),
            "Semantics check tx proposal v1: an output onetime address is not in the prime subgroup.");
    }

    // 7. check that output amount commitments can be reproduced
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amounts.size(),
        "Semantics check tx proposal v1: outputs don't line up with output amounts.");
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amount_commitment_blinding_factors.size(),
        "Semantics check tx proposal v1: outputs don't line up with output amount commitment blinding factors.");

    for (std::size_t output_index{0}; output_index < output_enotes.size(); ++output_index)
    {
        CHECK_AND_ASSERT_THROW_MES(output_enotes[output_index].m_core.m_amount_commitment ==
                rct::commit(output_amounts[output_index],
                    rct::sk2rct(output_amount_commitment_blinding_factors[output_index])),
            "Semantics check tx proposal v1: could not reproduce an output's amount commitment.");
    }

    // 8. check tx supplement (especially enote ephemeral pubkeys)
    check_v1_tx_supplement_semantics_v1(tx_supplement, output_enotes.size());


    /// input checks

    // 1. there should be at least one input
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_input_proposals.size() >= 1,
        "Semantics check tx proposal v1: there are no inputs.");

    // 2. input proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(tx_proposal.m_input_proposals.begin(),
            tx_proposal.m_input_proposals.end()),
        "Semantics check tx proposal v1: input proposals are not sorted.");

    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(tx_proposal.m_input_proposals.begin(),
            tx_proposal.m_input_proposals.end(),
            equals_from_less{}) == tx_proposal.m_input_proposals.end(),
        "Semantics check tx proposal v1: input proposal key images are not unique.");

    // 3. input proposal semantics should be valid
    for (const SpInputProposalV1 &input_proposal : tx_proposal.m_input_proposals)
        check_v1_input_proposal_semantics_v1(input_proposal, wallet_spend_pubkey, k_view_balance);


    /// check that amounts balance in the proposal

    // 1. extract the fee value
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(tx_proposal.m_tx_fee, raw_transaction_fee),
        "Semantics check tx proposal v1: could not extract fee value from discretized fee.");

    // 2. get input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(tx_proposal.m_input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : tx_proposal.m_input_proposals)
        in_amounts.emplace_back(input_proposal.get_amount());

    // 3. check: sum(input amnts) == sum(output amnts) + fee
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, output_amounts, raw_transaction_fee),
        "Semantics check tx proposal v1: input/output amounts did not balance with desired fee.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payments,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payments,
    const DiscretizedFee &tx_fee,
    std::vector<SpInputProposalV1> input_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &proposal_out)
{
    // inputs should be sorted by key image
    std::sort(input_proposals.begin(), input_proposals.end());

    // set fields
    proposal_out.m_normal_payments = std::move(normal_payments);
    proposal_out.m_selfsend_payments = std::move(selfsend_payments);
    proposal_out.m_tx_fee = tx_fee;
    proposal_out.m_input_proposals = std::move(input_proposals);
    make_tx_extra(std::move(additional_memo_elements), proposal_out.m_partial_memo);
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
    make_bpp_rangeproofs(amounts, amount_commitment_blinding_factors, range_proofs);

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
    const DiscretizedFee &discretized_transaction_fee)
{
    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;
    in_amounts.reserve(input_proposals.size());
    out_amounts.reserve(output_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
        in_amounts.emplace_back(input_proposal.get_amount());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        out_amounts.emplace_back(output_proposal.get_amount());

    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "balance check in out amnts v1: unable to extract transaction fee from discretized fee representation.");

    return balance_check_in_out_amnts(in_amounts, out_amounts, raw_transaction_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_partial_tx_semantics_v1(const SpPartialTxV1 &partial_tx,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    // prepare a mock ledger
    MockLedgerContext mock_ledger;

    // get parameters for making mock ref sets (use minimum parameters for efficiency when possible)
    const SemanticConfigRefSetV1 ref_set_config{semantic_config_ref_sets_v1(semantic_rules_version)};
    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.m_bin_radius_min),
            .m_num_bin_members = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.m_num_bin_members_min),
        };

    // make mock membership proof ref sets
    std::vector<SpMembershipProofPrepV1> membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(partial_tx.m_input_enotes,
                partial_tx.m_address_masks,
                partial_tx.m_commitment_masks,
                ref_set_config.m_decomp_n_min,
                ref_set_config.m_decomp_m_min,
                bin_config,
                mock_ledger)
        };

    // make the mock membership proofs
    std::vector<SpMembershipProofV1> membership_proofs;
    make_v1_membership_proofs_v1(std::move(membership_proof_preps), membership_proofs);

    // make tx
    SpTxSquashedV1 test_tx;
    make_seraphis_tx_squashed_v1(partial_tx, std::move(membership_proofs), semantic_rules_version, test_tx);

    // validate tx
    CHECK_AND_ASSERT_THROW_MES(validate_tx(test_tx, mock_ledger, false),
        "v1 partial tx semantics check (v1): test transaction was invalid using requested semantics rules version!");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(std::vector<SpPartialInputV1> partial_inputs,
    std::vector<SpOutputProposalV1> output_proposals,
    const TxExtra &partial_memo,
    const DiscretizedFee &tx_fee,
    const std::string &version_string,
    SpPartialTxV1 &partial_tx_out)
{
    /// preparation and checks
    partial_tx_out = SpPartialTxV1{};

    // 1. sort the inputs by key image
    std::sort(partial_inputs.begin(), partial_inputs.end());

    // 2. sort the outputs by onetime address
    std::sort(output_proposals.begin(), output_proposals.end());

    // 3. extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);

    // 4. collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // 5. check: inputs and proposal must have consistent proposal prefixes
    rct::key proposal_prefix;
    make_tx_image_proof_message_v1(version_string, output_enotes, tx_supplement, proposal_prefix);

    for (const SpPartialInputV1 &partial_input : partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(proposal_prefix == partial_input.m_proposal_prefix,
            "making partial tx: a partial input's proposal prefix doesn't match with the tx proposal.");
    }


    /// balance proof

    // get input amounts and image amount commitment blinding factors
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;
    prepare_input_commitment_factors_for_balance_proof_v1(partial_inputs,
        input_amounts,
        input_image_amount_commitment_blinding_factors);

    // extract the fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(tx_fee, raw_transaction_fee),
        "making partial tx: could not extract a fee value from the discretized fee.");

    // make balance proof
    make_v1_balance_proof_v1(input_amounts,
        output_amounts,
        raw_transaction_fee,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        partial_tx_out.m_balance_proof);


    /// copy misc tx pieces

    // gather tx input parts
    partial_tx_out.m_input_images.reserve(partial_inputs.size());
    partial_tx_out.m_image_proofs.reserve(partial_inputs.size());
    partial_tx_out.m_input_enotes.reserve(partial_inputs.size());
    partial_tx_out.m_address_masks.reserve(partial_inputs.size());
    partial_tx_out.m_commitment_masks.reserve(partial_inputs.size());

    for (SpPartialInputV1 &partial_input : partial_inputs)
    {
        partial_tx_out.m_input_images.emplace_back(partial_input.m_input_image);
        partial_tx_out.m_image_proofs.emplace_back(std::move(partial_input.m_image_proof));
        partial_tx_out.m_input_enotes.emplace_back(partial_input.m_input_enote_core);
        partial_tx_out.m_address_masks.emplace_back(partial_input.m_address_mask);
        partial_tx_out.m_commitment_masks.emplace_back(partial_input.m_commitment_mask);
    }

    // gather tx output parts
    partial_tx_out.m_outputs = std::move(output_enotes);
    partial_tx_out.m_tx_supplement = std::move(tx_supplement);
    partial_tx_out.m_tx_fee = tx_fee;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<SpPartialInputV1> partial_inputs,
    const std::string &version_string,
    const crypto::secret_key &k_view_balance,
    SpPartialTxV1 &partial_tx_out)
{
    // 1. sort the inputs by key image
    std::sort(partial_inputs.begin(), partial_inputs.end());

    // 2. partial inputs must line up with input proposals in the tx proposal
    CHECK_AND_ASSERT_THROW_MES(partial_inputs.size() == tx_proposal.m_input_proposals.size(),
        "making partial tx: number of partial inputs doesn't match number of input proposals.");

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_inputs[input_index].key_image() == 
                tx_proposal.m_input_proposals[input_index].key_image(),
            "making partial tx: partial inputs and input proposals don't line up (inconsistent key images).");
    }

    // 3. extract output proposals from tx proposal
    std::vector<SpOutputProposalV1> output_proposals;
    tx_proposal.get_output_proposals_v1(k_view_balance, output_proposals);

    // 4. construct partial tx
    make_v1_partial_tx_v1(std::move(partial_inputs),
        std::move(output_proposals),
        tx_proposal.m_partial_memo,
        tx_proposal.m_tx_fee,
        version_string,
        partial_tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
