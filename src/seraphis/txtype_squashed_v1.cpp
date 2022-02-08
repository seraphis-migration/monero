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
#include "ledger_context.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// semantic validation config: component counts
//-------------------------------------------------------------------------------------------------------------------
static SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(const unsigned char tx_semantic_rules_version)
{
    SemanticConfigComponentCountsV1 config{};

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
// semantic validation config: reference set size
//-------------------------------------------------------------------------------------------------------------------
static SemanticConfigRefSetSizeV1 semantic_config_ref_set_size_v1(const unsigned char tx_semantic_rules_version)
{
    SemanticConfigRefSetSizeV1 config{};

    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_decom_n_min = 0;
        config.m_decom_n_max = 100000;
        config.m_decom_m_min = 0;
        config.m_decom_m_max = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_decom_n_min = config::SP_GROOTLE_N_V1;
        config.m_decom_n_max = config::SP_GROOTLE_N_V1;
        config.m_decom_m_min = config::SP_GROOTLE_M_V1;
        config.m_decom_m_max = config::SP_GROOTLE_M_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpTxSquashedV1::SpTxSquashedV1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpOutputProposalV1> output_proposals,
    const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SemanticRulesVersion semantic_rules_version)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts_sp_v1(input_proposals, output_proposals, 0),
        "Tried to make tx with unbalanced amounts.");  //TODO: include fee in balance check

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    SpTxSquashedV1::get_versioning_string(semantic_rules_version, version_string);

    // tx proposal
    SpTxProposalV1 tx_proposal{std::move(output_proposals)};
    rct::key proposal_prefix{tx_proposal.get_proposal_prefix(version_string)};

    // partial inputs
    std::vector<SpTxPartialInputV1> partial_inputs;
    make_v1_tx_partial_inputs_sp_v1(input_proposals, proposal_prefix, partial_inputs);

    // membership proofs (input proposals are assumed to line up with membership ref sets)
    std::vector<SpMembershipProofAlignableV1> tx_membership_proofs_sortable;
    make_v1_tx_membership_proofs_sp_v1(membership_ref_sets, partial_inputs, tx_membership_proofs_sortable);

    // partial tx
    SpTxPartialV1 partial_tx{tx_proposal, std::move(partial_inputs), version_string};

    // line up the the membership proofs with the partial tx's input images (which are sorted)
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    align_v1_tx_membership_proofs_sp_v1(partial_tx.m_input_images,
        std::move(tx_membership_proofs_sortable),
        tx_membership_proofs);

    // assemble tx
    *this = SpTxSquashedV1{std::move(partial_tx), std::move(tx_membership_proofs), semantic_rules_version};
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTxSquashedV1::validate_tx_semantics() const
{
    if (m_balance_proof.get() == nullptr)
        return false;

    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_component_counts_v1(
        semantic_config_component_counts_v1(m_tx_semantic_rules_version),
        m_input_images.size(),
        m_membership_proofs.size(),
        m_image_proofs.size(),
        m_outputs.size(),
        m_supplement.m_output_enote_ephemeral_pubkeys.size(),
        m_balance_proof->m_bpp_proof.V.size()))
    {
        return false;
    }

    // validate input proof reference set sizes
    if (!validate_sp_semantics_ref_set_size_v1(
        semantic_config_ref_set_size_v1(m_tx_semantic_rules_version),
        m_membership_proofs))
    {
        return false;
    }

    // validate linking tag semantics
    if (!validate_sp_semantics_input_images_v1(
        m_input_images))
    {
        return false;
    }

    // validate input images, membershio proof ref sets, and outputs are sorted
    if (!validate_sp_semantics_sorting_v1(
        m_membership_proofs,
        m_input_images,
        m_outputs))
    {
        return false;
    }

    //TODO: validate memo semantics

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTxSquashedV1::validate_tx_linking_tags(const std::shared_ptr<const LedgerContext> ledger_context) const
{
    // unspentness proof (key images not in ledger)
    if (!validate_sp_linking_tags_v1(m_input_images, ledger_context))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTxSquashedV1::validate_tx_amount_balance(const bool defer_batchable) const
{
    if (!validate_sp_amount_balance_v1(m_input_images, m_outputs, m_balance_proof, defer_batchable))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTxSquashedV1::validate_tx_input_proofs(const std::shared_ptr<const LedgerContext> ledger_context,
    const bool defer_batchable) const
{
    // membership proofs
    if (!validate_sp_membership_proofs_v1(m_membership_proofs,
        m_input_images,
        ledger_context))
    {
        return false;
    }

    // ownership proof (and proof that key images are well-formed)
    std::string version_string;
    version_string.reserve(3);
    this->SpTx::get_versioning_string(version_string);

    rct::key image_proofs_message{get_tx_image_proof_message_sp_v1(version_string, m_outputs, m_supplement)};

    if (!validate_sp_composition_proofs_v1(m_image_proofs,
        m_input_images,
        image_proofs_message))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes() const
{
    // doesn't include:
    // - ring member references (e.g. indices or explicit copies)
    // - tx fees
    // - memos
    // - miscellaneous serialization bytes
    std::size_t size{0};

    // input images
    size += m_input_images.size() * SpEnoteImageV1::get_size_bytes();

    // outputs
    size += m_outputs.size() * SpEnoteV1::get_size_bytes();

    // balance proof
    if (m_balance_proof.get() != nullptr)
        size += m_balance_proof->get_size_bytes();

    // membership proofs
    // - assumes all have the same size
    if (m_membership_proofs.size())
        size += m_membership_proofs.size() * m_membership_proofs[0].get_size_bytes();

    // ownership/key-image-legitimacy proof for all inputs
    // - assumes all have the same size
    if (m_image_proofs.size())
        size += m_image_proofs.size() * m_image_proofs[0].get_size_bytes();

    // extra data in tx
    size += m_supplement.get_size_bytes();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
std::shared_ptr<SpTxSquashedV1> make_mock_tx<SpTxSquashedV1>(const SpTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

    // make mock outputs
    std::vector<SpOutputProposalV1> output_proposals{gen_mock_sp_output_proposals_v1(out_amounts)};

    // for 2-out tx, the enote ephemeral pubkey is shared by both outputs
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // make mock membership proof ref sets
    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v1(input_proposals,
                params.ref_set_decomp_n,
                params.ref_set_decomp_m,
                ledger_context_inout)
        };

    // make tx
    return std::make_shared<SpTxSquashedV1>(input_proposals, output_proposals,
        membership_ref_sets, SpTxSquashedV1::SemanticRulesVersion::MOCK);
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_mock_txs<SpTxSquashedV1>(const std::vector<std::shared_ptr<SpTxSquashedV1>> &txs_to_validate,
    const std::shared_ptr<const LedgerContext> ledger_context)
{
    std::vector<const rct::BulletproofPlus*> range_proofs;
    range_proofs.reserve(txs_to_validate.size());

    for (const std::shared_ptr<SpTxSquashedV1> &tx : txs_to_validate)
    {
        if (!tx || tx.use_count() == 0)
            return false;

        // validate unbatchable parts of tx
        if (!validate_sp_tx(*tx, ledger_context, true))
            return false;

        // gather range proofs
        const std::shared_ptr<const SpBalanceProofV1> balance_proof{tx->get_balance_proof()};

        if (balance_proof.get() == nullptr)
            return false;

        range_proofs.push_back(&(balance_proof->m_bpp_proof));
    }

    // batch verify range proofs
    if (!rct::bulletproof_plus_VERIFY(range_proofs))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
