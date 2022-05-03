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

// Seraphis implemented with concise Grootle membership proofs on squashed enotes and separate
//     composition proofs for each input image

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_base.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

////
// Seraphis tx: based on concise grootle membership proofs on squashed enotes,
//              with separate composition proofs for input images
///
struct SpTxSquashedV1 final
{
    enum class SemanticRulesVersion : unsigned char
    {
        MOCK = 0,
        ONE = 1
    };

    /// tx input images (spent e-notes)
    std::vector<SpEnoteImageV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<SpEnoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    SpBalanceProofV1 m_balance_proof;
    /// composition proofs: ownership/key-image-legitimacy for each input
    std::vector<SpImageProofV1> m_image_proofs;
    /// concise Grootle proofs on squashed enotes: membership for each input
    std::vector<SpMembershipProofV1> m_membership_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 m_supplement;
    /// the transaction fee
    rct::xmr_amount m_fee;

    /// semantic rules version
    SemanticRulesVersion m_tx_semantic_rules_version;

    /// get size of a possible tx
    static std::size_t get_size_bytes(const std::size_t num_inputs,
        const std::size_t num_outputs,
        const std::size_t ref_set_decomp_m,
        const std::size_t ref_set_decomp_n,
        const std::size_t num_bin_members,
        const TxExtra &tx_extra);
    /// get size of the tx
    std::size_t get_size_bytes() const;
    /// get weight of a possible tx
    static std::size_t get_weight(const std::size_t num_inputs,
        const std::size_t num_outputs,
        const std::size_t ref_set_decomp_n,
        const std::size_t ref_set_decomp_m,
        const std::size_t num_bin_members,
        const TxExtra &tx_extra);
    /// get weight of the tx
    std::size_t get_weight() const;
};

/**
* brief: make_seraphis_tx_squashed_v1 - make an SpTxSquashedV1 transaction
* ...
* outparam: tx_out -
*/
void make_seraphis_tx_squashed_v1(std::vector<SpEnoteImageV1> input_images,
    std::vector<SpEnoteV1> outputs,
    SpBalanceProofV1 balance_proof,
    std::vector<SpImageProofV1> image_proofs,
    std::vector<SpMembershipProofV1> membership_proofs,
    SpTxSupplementV1 tx_supplement,
    const rct::xmr_amount transaction_fee,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out);
void make_seraphis_tx_squashed_v1(SpPartialTxV1 partial_tx,
    std::vector<SpMembershipProofV1> membership_proofs,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out);
void make_seraphis_tx_squashed_v1(SpPartialTxV1 partial_tx,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out);
void make_seraphis_tx_squashed_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpOutputProposalV1> output_proposals,
    const rct::xmr_amount transaction_fee,
    std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out);

//todo
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version);
//todo
SemanticConfigRefSetV1 semantic_config_ref_sets_v1(const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version);


//// tx base concept implementations

/// short descriptor of the tx type
template <>
inline std::string get_descriptor<SpTxSquashedV1>() { return "Sp-Squashed-V1"; }

/// tx structure version
template <>
inline unsigned char get_structure_version<SpTxSquashedV1>()
{
    return static_cast<unsigned char>(TxStructureVersionSp::TxTypeSpSquashedV1);
}

/// versioning string for an SpTxSquashedV1 tx
inline void make_versioning_string(const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version,
    std::string &version_string_out)
{
    make_versioning_string<SpTxSquashedV1>(static_cast<unsigned char>(tx_semantic_rules_version), version_string_out);
}

/// transaction validators
template <>
bool validate_tx_semantics<SpTxSquashedV1>(const SpTxSquashedV1 &tx);
template <>
bool validate_tx_linking_tags<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const LedgerContext &ledger_context);
template <>
bool validate_tx_amount_balance<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const bool defer_batchable);
template <>
bool validate_tx_input_proofs<SpTxSquashedV1>(const SpTxSquashedV1 &tx,
    const LedgerContext &ledger_context,
    const bool defer_batchable);
template <>
bool validate_txs_batchable<SpTxSquashedV1>(const std::vector<const SpTxSquashedV1*> &txs,
    const LedgerContext &ledger_context);


//// mock-ups

////
// SpTxParamPackV1 - parameter pack (for unit tests/mockups/etc.)
///
struct SpTxParamPackV1
{
    std::size_t ref_set_decomp_n{0};
    std::size_t ref_set_decomp_m{0};
    std::size_t num_random_memo_elements{0};
    SpBinnedReferenceSetConfigV1 bin_config{0, 0};
};
/**
* brief: make_mock_tx - make an SpTxSquashedV1 transaction
* param: params -
* param: in_amounts -
* param: out_amounts -
* inoutparam: ledger_context_inout -
* outparam: tx_out -
*/
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPackV1 &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const rct::xmr_amount transaction_fee,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out);

} //namespace sp
