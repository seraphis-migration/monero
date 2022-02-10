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

// Seraphis implemented with concise Grootle membership proofs on squashed enotes and separate
//     composition proofs for each input image
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_base.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations


namespace sp
{

////
// Seraphis tx: based on concise grootle membership proofs on squashed enotes,
//              with separate composition proofs for input images
///
struct SpTxSquashedV1 final : public SpTx
{
    friend class MockLedgerContext;

//member types
    enum SemanticRulesVersion : unsigned char
    {
        MIN = 0,
        MOCK = 0,
        ONE = 1,
        MAX = 1
    };

//constructors
    /// default constructor
    SpTxSquashedV1() = default;

    /// normal constructor: new tx from pieces
    SpTxSquashedV1(std::vector<SpEnoteImageV1> input_images,
        std::vector<SpEnoteV1> outputs,
        std::shared_ptr<const SpBalanceProofV1> balance_proof,
        std::vector<SpImageProofV1> image_proofs,
        std::vector<SpMembershipProofV1> membership_proofs,
        SpTxSupplementV1 tx_supplement,
        const SemanticRulesVersion semantic_rules_version) :
            SpTx{TxEraSp, TxStructureVersionSp::TxTypeSpSquashedV1, semantic_rules_version},  //base class
            m_input_images{std::move(input_images)},
            m_outputs{std::move(outputs)},
            m_balance_proof{std::move(balance_proof)},
            m_image_proofs{std::move(image_proofs)},
            m_membership_proofs{std::move(membership_proofs)},
            m_supplement{std::move(tx_supplement)}
        {
            CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(), "Failed to assemble SpTxSquashedV1.");
            CHECK_AND_ASSERT_THROW_MES(semantic_rules_version <= SemanticRulesVersion::MAX,
                "Invalid validation rules version.");
        }

    /// normal constructor: finalize from a partial tx
    SpTxSquashedV1(SpTxPartialV1 partial_tx,
        std::vector<SpMembershipProofV1> membership_proofs,
        const SemanticRulesVersion semantic_rules_version) :
            SpTxSquashedV1{
                std::move(partial_tx.m_input_images),
                std::move(partial_tx.m_outputs),
                std::move(partial_tx.m_balance_proof),
                std::move(partial_tx.m_image_proofs),
                std::move(membership_proofs),
                std::move(partial_tx.m_tx_supplement),
                semantic_rules_version
            }
    {}

    /// normal constructor: monolithic tx builder (complete tx in one step)
    SpTxSquashedV1(const std::vector<SpInputProposalV1> &input_proposals,
        std::vector<SpOutputProposalV1> output_proposals,
        const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
        const SemanticRulesVersion semantic_rules_version);

    /// normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    /// get size of tx
    std::size_t get_size_bytes() const override;

    /// get a short description of the tx type
    std::string get_descriptor() const override { return "Sp-Squashed"; }

    /// get the tx version string: era | format | semantic rules
    static void get_versioning_string(const unsigned char tx_semantic_rules_version,
        std::string &version_string)
    {
        SpTx::get_versioning_string(TxEraSp,
            TxStructureVersionSp::TxTypeSpSquashedV1,
            tx_semantic_rules_version,
            version_string);
    }

    //get_tx_byte_blob()

    /// validate pieces of the tx
    bool validate_tx_semantics() const override;
    bool validate_tx_linking_tags(const std::shared_ptr<const LedgerContext> ledger_context) const override;
    bool validate_tx_amount_balance(const bool defer_batchable) const override;
    bool validate_tx_input_proofs(const std::shared_ptr<const LedgerContext> ledger_context,
        const bool defer_batchable) const override;

//member variables
    /// tx input images  (spent e-notes)
    std::vector<SpEnoteImageV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<SpEnoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<const SpBalanceProofV1> m_balance_proof;
    /// composition proofs: ownership/key-image-legitimacy for each input
    std::vector<SpImageProofV1> m_image_proofs;
    /// concise Grootle proofs on squashed enotes: membership for each input
    std::vector<SpMembershipProofV1> m_membership_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 m_supplement;
};

/**
* brief: make_mock_tx - make a SpTxSquashedV1 transaction (function specialization)
* param: params -
* param: in_amounts -
* param: out_amounts -
* inoutparam: ledger_context_inout -
* return: a SpTxSquashedV1 tx
*/
template <>
std::shared_ptr<SpTxSquashedV1> make_mock_tx<SpTxSquashedV1>(const SpTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
/**
* brief: validate_mock_txs - validate a set of SpTxSquashedV1 transactions (function specialization)
* param: txs_to_validate -
* param: ledger_context -
* return: true/false on validation result
*/
template <>
bool validate_mock_txs<SpTxSquashedV1>(const std::vector<std::shared_ptr<SpTxSquashedV1>> &txs_to_validate,
    const std::shared_ptr<const LedgerContext> ledger_context);

} //namespace sp
