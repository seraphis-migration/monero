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

// Mock tx: Seraphis implemented with concise Grootle membership proofs and separate composition proofs for
//          each input image
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_tx.h"
#include "mock_sp_base.h"
#include "mock_sp_component_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations


namespace mock_tx
{

////
// Interface for interacting with a ledger when validating a tx.
///
class LedgerContext
{
    virtual bool linking_tag_exists_sp_v1(const rct::key &linking_tag) const = 0;
    virtual void get_reference_set_sp_v1(const std::vector<std::size_t> &indices,
        std::vector<MockENoteSpV1> &enotes_out) const = 0;
};

////
// Mock ledger context for testing
///
class MockLedgerContext final : public LedgerContext
{
    bool linking_tag_exists_sp_v1(const rct::key &linking_tag) const override;
    void get_reference_set_sp_v1(const std::vector<std::size_t> &indices,
        std::vector<MockENoteSpV1> &enotes_out) const override;

    std::unordered_set<rct::key> m_sp_linking_tags;
    std::vector<MockENoteSpV1> m_sp_enotes;
};

////
// Tx proposal: outputs and memos
///
class MockTxProposalSpV1 final
{
    /// hash of proposal
    std::string get_proposal_prefix();
};

////
// Partial tx input
// - input spent
// - cached blinding factors
// - composition proof
// - proposal prefix (composition proof msg) [for consistency checks when handling this struct]
///
class MockTxInputPartialSpV1 final //need InputSetPartial for merged composition proofs
{
    //vec<InputImage> get_input_images();
};

////
// Multisig tx proposal
// - outputs and memos
// - some/all inputs + cached blinding factors
// - multisig composition proof proposal(s) for input images
// - proposer's multisig openers (pubkeys only)
///
class MockTxMultisigProposalSpV1 final
{
    //MockTxProposalSpV1 core_proposal;
};

////
// Partial tx: no membership proof
///
class MockTxPartialSpV1 final
{
    //MockTxPartialSpV1(MockTxProposalSpV1 &proposal, vec<MockTxInputPartialSpV1> &inputs, BalanceProof)
    //MockTxPartialSpV1(MockTxMultisigProposalSpV1 &proposal, vec<MockTxInputPartialSpV1> &extra_inputs, BalanceProof)
};

////
// Complete tx
///
class MockTxSpConcise final : public MockTx
{
public:
//constructors
    /// default constructor
    MockTxSpConcise() = default;

    /// normal constructor: new tx
    MockTxSpConcise(std::vector<MockENoteImageSpV1> &input_images,
        std::vector<MockENoteSpV1> &outputs,
        std::shared_ptr<MockBalanceProofSpV1> &balance_proof,
        std::vector<MockImageProofSpV1> &image_proofs,
        std::vector<MockMembershipProofSpV1> &membership_proofs) :
            m_input_images{std::move(input_images)},
            m_outputs{std::move(outputs)},
            m_balance_proof{std::move(balance_proof)},
            m_image_proofs{std::move(image_proofs)},
            m_membership_proofs{std::move(membership_proofs)}
        {
            CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(), "Failed to assemble MockTxSpConcise.");
        }

    /// normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    /// validate tx
    bool validate(const std::shared_ptr<const LedgerContext> ledger_context,
        const bool defer_batchable = false) const override
    {
        // punt to the parent class
        return this->MockTx::validate(ledger_context, defer_batchable);
    }

    /// get size of tx
    std::size_t get_size_bytes() const override;

    /// get a short description of the tx type
    std::string get_descriptor() const override { return "Sp-Concise"; }

    /// get balance proof
    const std::shared_ptr<MockBalanceProofSpV1> get_balance_proof() const { return m_balance_proof; }

    //get_tx_byte_blob()

private:
    /// validate pieces of the tx
    bool validate_tx_semantics() const override;
    bool validate_tx_linking_tags(const std::shared_ptr<const LedgerContext> ledger_context) const override;
    bool validate_tx_amount_balance(const bool defer_batchable) const override;
    bool validate_tx_input_proofs(const std::shared_ptr<const LedgerContext> ledger_context,
        const bool defer_batchable) const override;

//member variables
    /// tx input images  (spent e-notes)
    std::vector<MockENoteImageSpV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<MockENoteSpV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<MockBalanceProofSpV1> m_balance_proof;
    /// composition proofs: ownership/unspentness for each input
    std::vector<MockImageProofSpV1> m_image_proofs;
    /// concise Grootle proofs: membership for each input
    std::vector<MockMembershipProofSpV1> m_membership_proofs;
};

/**
* brief: make_mock_tx - make a MockTxSpConcise transaction (function specialization)
* param: params -
* param: in_amounts -
* param: out_amounts -
* return: a MockTxSpConcise tx
*/
template <>
std::shared_ptr<MockTxSpConcise> make_mock_tx<MockTxSpConcise>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts);
/**
* brief: validate_mock_txs - validate a set of MockTxSpConcise transactions (function specialization)
* param: txs_to_validate -
* return: true/false on validation result
*/
template <>
bool validate_mock_txs<MockTxSpConcise>(const std::vector<std::shared_ptr<MockTxSpConcise>> &txs_to_validate);

} //namespace mock_tx
