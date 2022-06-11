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
#include "txtype_squashed_v1.h"

//local headers
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/multiexp.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_core_types.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "tx_binned_reference_set.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_discretized_fee.h"
#include "tx_misc_utils.h"
#include "tx_validation_context.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_bin_members,
    const TxExtra &tx_extra)
{
    // doesn't include:
    // - ring member references (e.g. indices or explicit copies)
    // - miscellaneous serialization bytes
    std::size_t size{0};

    // input images
    size += num_inputs * SpEnoteImageV1::get_size_bytes();

    // outputs
    size += num_outputs * SpEnoteV1::get_size_bytes();

    // balance proof
    size += SpBalanceProofV1::get_size_bytes(num_inputs, num_outputs);

    // ownership/key-image-legitimacy proof for all inputs
    size += num_inputs * SpImageProofV1::get_size_bytes();

    // membership proofs
    size += num_inputs * SpMembershipProofV1::get_size_bytes(ref_set_decomp_n, ref_set_decomp_m, num_bin_members);

    // extra data in tx
    size += SpTxSupplementV1::get_size_bytes(num_outputs, tx_extra);

    // tx fee
    size += DiscretizedFee::get_size_bytes();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes() const
{
    const std::size_t ref_set_decomp_n{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_ref_set_decomp_n
            : 0
        };
    const std::size_t ref_set_decomp_m{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_ref_set_decomp_m
            : 0
        };
    const std::size_t num_bin_members{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_binned_reference_set.m_bin_config.m_num_bin_members
            : 0u
        };

    return SpTxSquashedV1::get_size_bytes(m_input_images.size(),
        m_outputs.size(),
        ref_set_decomp_n,
        ref_set_decomp_m,
        num_bin_members,
        m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_weight(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_bin_members,
    const TxExtra &tx_extra)
{
    // tx weight = tx size + balance proof clawback
    std::size_t weight{
            SpTxSquashedV1::get_size_bytes(num_inputs,
                num_outputs,
                ref_set_decomp_n,
                ref_set_decomp_m,
                num_bin_members,
                tx_extra)
        };

    // subtract balance proof size and add its weight
    weight -= SpBalanceProofV1::get_size_bytes(num_inputs, num_outputs);
    weight += SpBalanceProofV1::get_weight(num_inputs, num_outputs);

    return weight;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_weight() const
{
    const std::size_t ref_set_decomp_n{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_ref_set_decomp_n
            : 0
        };
    const std::size_t ref_set_decomp_m{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_ref_set_decomp_m
            : 0
        };
    const std::size_t num_bin_members{
            m_membership_proofs.size()
            ? m_membership_proofs[0].m_binned_reference_set.m_bin_config.m_num_bin_members
            : 0u
        };

    return SpTxSquashedV1::get_weight(m_input_images.size(),
        m_outputs.size(),
        ref_set_decomp_n,
        ref_set_decomp_m,
        num_bin_members,
        m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
void SpTxSquashedV1::get_hash(rct::key &tx_hash_out) const
{
    // tx_hash = H_32(image_proofs_message, input images, proofs)
    static const std::string domain_separator{config::HASH_KEY_SERAPHIS_TRANSACTION};

    // 1. image proofs message
    // H_32(crypto project name, version string, input key images, output enotes, enote ephemeral pubkeys, memos, fee)
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(m_tx_semantic_rules_version, version_string);

    rct::key image_proofs_message;
    make_tx_image_proof_message_v1(version_string,
        m_input_images,
        m_outputs,
        m_tx_supplement,
        m_tx_fee,
        image_proofs_message);

    // 2. input images (note: key images are represented in the tx hash twice (image proofs message and input images))
    // H_32({K', C', KI})
    rct::key input_images_prefix;
    make_input_images_prefix_v1(m_input_images, input_images_prefix);

    // 3. proofs
    // H_32(balance proof, image proofs, membership proofs)
    rct::key tx_proofs_prefix;
    make_tx_proofs_prefix_v1(m_balance_proof, m_image_proofs, m_membership_proofs, tx_proofs_prefix);

    // 4. tx hash
    // tx_hash = H_32(image_proofs_message, input images, proofs)
    std::string data;
    data.reserve(3*sizeof(rct::key));
    data.append(reinterpret_cast<const char*>(image_proofs_message.bytes), sizeof(rct::key));
    data.append(reinterpret_cast<const char*>(input_images_prefix.bytes), sizeof(rct::key));
    data.append(reinterpret_cast<const char*>(tx_proofs_prefix.bytes), sizeof(rct::key));

    sp_hash_to_32(domain_separator, data.data(), data.size(), tx_hash_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(std::vector<SpEnoteImageV1> input_images,
    std::vector<SpEnoteV1> outputs,
    SpBalanceProofV1 balance_proof,
    std::vector<SpImageProofV1> image_proofs,
    std::vector<SpMembershipProofV1> membership_proofs,
    SpTxSupplementV1 tx_supplement,
    const DiscretizedFee &discretized_transaction_fee,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    tx_out.m_input_images = std::move(input_images);
    tx_out.m_outputs = std::move(outputs);
    tx_out.m_balance_proof = std::move(balance_proof);
    tx_out.m_image_proofs = std::move(image_proofs);
    tx_out.m_membership_proofs = std::move(membership_proofs);
    tx_out.m_tx_supplement = std::move(tx_supplement);
    tx_out.m_tx_fee = discretized_transaction_fee;
    tx_out.m_tx_semantic_rules_version = semantic_rules_version;

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble an SpTxSquashedV1.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(SpPartialTxV1 partial_tx,
    std::vector<SpMembershipProofV1> membership_proofs,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    // check partial tx semantics
    check_v1_partial_tx_semantics_v1(partial_tx, semantic_rules_version);

    // note: membership proofs cannot be validated without the ledger used to construct them, so there is no check here

    // finish tx
    make_seraphis_tx_squashed_v1(
        std::move(partial_tx.m_input_images),
        std::move(partial_tx.m_outputs),
        std::move(partial_tx.m_balance_proof),
        std::move(partial_tx.m_image_proofs),
        std::move(membership_proofs),
        std::move(partial_tx.m_tx_supplement),
        partial_tx.m_tx_fee,
        semantic_rules_version,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(SpPartialTxV1 partial_tx,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    // line up the the membership proofs with the partial tx's input images (which are sorted)
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    align_v1_membership_proofs_v1(partial_tx.m_input_images,
        std::move(alignable_membership_proofs),
        tx_membership_proofs);

    // finish tx
    make_seraphis_tx_squashed_v1(std::move(partial_tx), std::move(tx_membership_proofs), semantic_rules_version, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<SpPartialInputV1> partial_inputs,
    std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // partial tx
    SpPartialTxV1 partial_tx;
    make_v1_partial_tx_v1(tx_proposal,
        std::move(partial_inputs),
        version_string,
        wallet_spend_pubkey,
        k_view_balance,
        partial_tx);

    // membership proofs (assumes the caller prepared to make a membership proof for each input)
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;
    make_v1_membership_proofs_v1(std::move(membership_proof_preps), alignable_membership_proofs);

    // finish tx
    make_seraphis_tx_squashed_v1(std::move(partial_tx),
        std::move(alignable_membership_proofs),
        semantic_rules_version,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const crypto::secret_key &spendbase_privkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // tx proposal prefix
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, k_view_balance, proposal_prefix);

    // partial inputs
    std::vector<SpPartialInputV1> partial_inputs;
    make_v1_partial_inputs_v1(tx_proposal.m_input_proposals, proposal_prefix, spendbase_privkey, partial_inputs);

    // wallet spend pubkey
    rct::key wallet_spend_pubkey;
    make_seraphis_spendkey(k_view_balance, spendbase_privkey, wallet_spend_pubkey);

    // finish tx
    make_seraphis_tx_squashed_v1(tx_proposal,
        std::move(partial_inputs),
        std::move(membership_proof_preps),
        semantic_rules_version,
        wallet_spend_pubkey,
        k_view_balance,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee &tx_fee,
    std::vector<SpInputProposalV1> input_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const crypto::secret_key &spendbase_privkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        tx_fee,
        std::move(input_proposals),
        std::move(additional_memo_elements),
        tx_proposal);

    // finish tx
    make_seraphis_tx_squashed_v1(tx_proposal,
        std::move(membership_proof_preps),
        semantic_rules_version,
        spendbase_privkey,
        k_view_balance,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigComponentCountsV1 config{};

    // note: in the squashed model, inputs + outputs must be <= the BP+ pre-generated generator array size ('maxM')
    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = 100000;
        config.m_min_outputs = 1;
        config.m_max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = config::SP_MAX_INPUTS_V1;
        config.m_min_outputs = 2;
        config.m_max_outputs = config::SP_MAX_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigRefSetV1 semantic_config_ref_sets_v1(const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigRefSetV1 config{};

    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        // note: if n*m exceeds GROOTLE_MAX_MN, an exception will be thrown
        config.m_decomp_n_min = 2;
        config.m_decomp_n_max = 100000;
        config.m_decomp_m_min = 2;
        config.m_decomp_m_max = 100000;
        config.m_bin_radius_min = 0;
        config.m_bin_radius_max = 30000;
        config.m_num_bin_members_min = 1;
        config.m_num_bin_members_max = 60000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_decomp_n_min = config::SP_GROOTLE_N_V1;
        config.m_decomp_n_max = config::SP_GROOTLE_N_V1;
        config.m_decomp_m_min = config::SP_GROOTLE_M_V1;
        config.m_decomp_m_max = config::SP_GROOTLE_M_V1;
        config.m_bin_radius_min = config::SP_REF_SET_BIN_RADIUS_V1;
        config.m_bin_radius_max = config::SP_REF_SET_BIN_RADIUS_V1;
        config.m_num_bin_members_min = config::SP_REF_SET_NUM_BIN_MEMBERS_V1;
        config.m_num_bin_members_max = config::SP_REF_SET_NUM_BIN_MEMBERS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxSquashedV1>(const SpTxSquashedV1 &tx)
{
    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_component_counts_v1(
            semantic_config_component_counts_v1(tx.m_tx_semantic_rules_version),
            tx.m_input_images.size(),
            tx.m_membership_proofs.size(),
            tx.m_image_proofs.size(),
            tx.m_outputs.size(),
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys.size(),
            tx.m_balance_proof.m_bpp_proof.V.size()))
        return false;

    // validate input proof reference set sizes
    if (!validate_sp_semantics_reference_sets_v1(
            semantic_config_ref_sets_v1(tx.m_tx_semantic_rules_version),
            tx.m_membership_proofs))
        return false;

    // validate linking tag semantics
    if (!validate_sp_semantics_input_images_v1(tx.m_input_images))
        return false;

    // validate layout (sorting, uniqueness) of input images, membershio proof ref sets, outputs, and tx supplement
    if (!validate_sp_semantics_layout_v1(tx.m_membership_proofs,
            tx.m_input_images,
            tx.m_outputs,
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys,
            tx.m_tx_supplement.m_tx_extra))
        return false;

    // validate the tx fee is well-formed
    if (!validate_sp_semantics_fee_v1(tx.m_tx_fee))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_linking_tags<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    // unspentness proof (key images not in ledger)
    if (!validate_sp_linking_tags_v1(tx.m_input_images, tx_validation_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxSquashedV1>(const SpTxSquashedV1 &tx)
{
    // balance proof
    if (!validate_sp_amount_balance_v1(tx.m_input_images, tx.m_outputs, tx.m_tx_fee, tx.m_balance_proof))
        return false;

    // deferred for batching: range proofs

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    // deferred for batching: membership proofs

    // ownership proof (and proof that key images are well-formed)
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(tx.m_tx_semantic_rules_version, version_string);

    rct::key image_proofs_message;
    make_tx_image_proof_message_v1(version_string,
        tx.m_input_images,
        tx.m_outputs,
        tx.m_tx_supplement,
        tx.m_tx_fee,
        image_proofs_message);

    if (!validate_sp_composition_proofs_v1(tx.m_image_proofs, tx.m_input_images, image_proofs_message))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxSquashedV1>(const std::vector<const SpTxSquashedV1*> &txs,
    const TxValidationContext &tx_validation_context)
{
    std::vector<const SpMembershipProofV1*> membership_proof_ptrs;
    std::vector<const SpEnoteImage*> input_image_ptrs;
    std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
    membership_proof_ptrs.reserve(txs.size()*20);  //heuristic... (most tx have 1-2 inputs)
    input_image_ptrs.reserve(txs.size()*20);
    range_proof_ptrs.reserve(txs.size());

    // prepare for batch-verification
    for (const SpTxSquashedV1 *tx : txs)
    {
        if (!tx)
            return false;

        // gather membership proof pieces
        for (const auto &membership_proof : tx->m_membership_proofs)
            membership_proof_ptrs.push_back(&membership_proof);

        for (const auto &input_image : tx->m_input_images)
            input_image_ptrs.push_back(&(input_image.m_core));

        // gather range proofs
        range_proof_ptrs.push_back(&(tx->m_balance_proof.m_bpp_proof));
    }

    // batch verification: collect pippenger data sets for an aggregated multiexponentiation
    std::vector<rct::pippenger_prep_data> validation_data;
    validation_data.resize(2);

    // membership proofs
    if (!try_get_sp_membership_proofs_v1_validation_data(membership_proof_ptrs,
            input_image_ptrs,
            tx_validation_context,
            validation_data[0]))
        return false;

    // range proofs
    if (!rct::try_get_bulletproof_plus_verification_data(range_proof_ptrs, validation_data[1]))
        return false;

    // batch verify
    if (!multiexp_is_identity(validation_data))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPackV1 &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const DiscretizedFee &tx_fee,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out)
{
    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "SpTxSquashedV1: tried to make mock tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to make mock tx without any outputs.");

    // mock semantics version
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{SpTxSquashedV1::SemanticRulesVersion::MOCK};

    // make wallet spendbase privkey (master key)
    const crypto::secret_key spendbase_privkey{rct::rct2sk(rct::skGen())};

    // make mock inputs
    // enote, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(spendbase_privkey, in_amounts)};
    std::sort(input_proposals.begin(), input_proposals.end());

    // make mock outputs
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, params.num_random_memo_elements)
        };

    // for 2-out tx, the enote ephemeral pubkey is shared by both outputs
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // expect amounts to balance
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts_v1(input_proposals, output_proposals, tx_fee),
        "SpTxSquashedV1: tried to make mock tx with unbalanced amounts.");

    // make partial memo
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(params.num_random_memo_elements);

    for (ExtraFieldElement &element : additional_memo_elements)
        element.gen();

    TxExtra partial_memo;
    make_tx_extra(std::move(additional_memo_elements), partial_memo);

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // proposal prefix
    rct::key proposal_prefix;
    make_tx_image_proof_message_v1(version_string,
        input_proposals,
        output_proposals,
        partial_memo,
        tx_fee,
        proposal_prefix);

    // make partial inputs
    std::vector<SpPartialInputV1> partial_inputs;
    make_v1_partial_inputs_v1(input_proposals, proposal_prefix, spendbase_privkey, partial_inputs);

    // prepare partial tx
    SpPartialTxV1 partial_tx;

    make_v1_partial_tx_v1(std::move(partial_inputs),
        std::move(output_proposals),
        partial_memo,
        tx_fee,
        version_string,
        partial_tx);

    // make mock membership proof ref sets
    std::vector<SpMembershipProofPrepV1> membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(input_proposals,
                params.ref_set_decomp_n,
                params.ref_set_decomp_m,
                params.bin_config,
                ledger_context_inout)
        };

    // membership proofs (assumes the caller prepared to make a membership proof for each input)
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;
    make_v1_membership_proofs_v1(std::move(membership_proof_preps), alignable_membership_proofs);

    // make tx
    make_seraphis_tx_squashed_v1(std::move(partial_tx),
        std::move(alignable_membership_proofs),
        semantic_rules_version,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
