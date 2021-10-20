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

// Mock tx: plain RingCT on CLSAG with BP+
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_tx.h"
#include "mock_rct_base.h"
#include "mock_rct_components.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

//forward declarations
namespace mock_tx
{
    class LedgerContext;
    class MockLedgerContext;
}


namespace mock_tx
{

class MockTxCLSAG final : public MockTx
{
public:
//constructors
    /// default constructor
    MockTxCLSAG() = default;

    /// normal constructor: new tx
    MockTxCLSAG(std::vector<MockENoteImageRctV1> &input_images,
        std::vector<MockENoteRctV1> &outputs,
        std::shared_ptr<MockRctBalanceProofV1> &balance_proof,
        std::vector<MockRctProofV1> &tx_proofs) :
            m_input_images{std::move(input_images)},
            m_outputs{std::move(outputs)},
            m_balance_proof{std::move(balance_proof)},
            m_tx_proofs{std::move(tx_proofs)}
        {
            CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(), "Failed to assemble MockTxCLSAG.");
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
    std::string get_descriptor() const override { return "CLSAG"; }

    /// get balance proof
    const std::shared_ptr<MockRctBalanceProofV1> get_balance_proof() const { return m_balance_proof; }

    /// add key images to ledger context
    void add_key_images_to_ledger(std::shared_ptr<LedgerContext> ledger_context) const override
    {}

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
    std::vector<MockENoteImageRctV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<MockENoteRctV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<MockRctBalanceProofV1> m_balance_proof;
    /// CLSAGs proving membership/ownership/unspentness for each input
    std::vector<MockRctProofV1> m_tx_proofs;
};

/**
* brief: make_mock_tx - make a MockTxCLSAG transaction (function specialization)
* param: params -
* param: in_amounts -
* param: out_amounts -
* return: a MockTxCLSAG tx
*/
template <>
std::shared_ptr<MockTxCLSAG> make_mock_tx<MockTxCLSAG>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    std::shared_ptr<MockLedgerContext> ledger_context);
/**
* brief: validate_mock_txs - validate a set of MockTxCLSAG transactions (function specialization)
* param: txs_to_validate -
* return: true/false on validation result
*/
template <>
bool validate_mock_txs<MockTxCLSAG>(const std::vector<std::shared_ptr<MockTxCLSAG>> &txs_to_validate,
    const std::shared_ptr<const LedgerContext> ledger_context);

} //namespace mock_tx
