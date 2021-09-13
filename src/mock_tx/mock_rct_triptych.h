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
#include "mock_tx_rct_base.h"
#include "mock_tx_rct_components.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

//forward declarations


namespace mock_tx
{

class MockTxTriptych final : public MockTx
{
    ////
    // Differences from MockTxCLSAG
    // - proofs: MockRctProofV2
    //   - Triptych proofs for membership/ownership/unspentness
    // - e-note images: linking tags are constructed with Triptych-style inversion on generator U,
    //   instead of CryptoNote-style
    ///

public:
//constructors
    /// default constructor
    MockTxTriptych() = default;

    /// normal constructor: new tx
    MockTxTriptych(std::vector<MockENoteImageRctV1> &input_images,
        std::vector<MockENoteRctV1> &outputs,
        std::vector<rct::BulletproofPlus> &range_proofs,
        std::vector<MockRctProofV2> &tx_proofs) :
            m_input_images{std::move(input_images)},
            m_outputs{std::move(outputs)},
            m_range_proofs{std::move(range_proofs)},
            m_tx_proofs{std::move(tx_proofs)}
        {
            CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(), "Failed to assemble MockTxTriptych.");
        }

    /// normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    /// validate tx
    bool validate(const bool defer_batchable = false) const override
    {
        // punt to the parent class
        return this->MockTx::validate(defer_batchable);
    }

    /// get size of tx
    std::size_t get_size_bytes() const override;

    /// get a short description of the tx type
    std::string get_descriptor() const override { return "Triptych"; }

    /// get range proof
    const std::vector<rct::BulletproofPlus>& get_range_proofs() const {return m_range_proofs;}

    //get_tx_byte_blob()

private:
    /// validate pieces of the tx
    bool validate_tx_semantics() const override;
    bool validate_tx_linking_tags() const override;
    bool validate_tx_amount_balance(const bool defer_batchable) const override;
    bool validate_tx_input_proofs(const bool defer_batchable) const override;

//member variables
    /// tx input images  (spent e-notes)
    std::vector<MockENoteImageRctV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<MockENoteRctV1> m_outputs;
    /// range proofs
    std::vector<rct::BulletproofPlus> m_range_proofs;
    /// Triptych proofs demonstrating membership/ownership/unspentness for each input
    std::vector<MockRctProofV2> m_tx_proofs;
};

/**
* brief: make_mock_tx - make a MockTxTriptych transaction (function specialization)
* param: params -
* param: in_amounts -
* param: out_amounts -
* return: a MockTxTriptych tx
*/
template <>
std::shared_ptr<MockTxTriptych> make_mock_tx<MockTxTriptych>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts);
/**
* brief: validate_mock_txs - validate a set of MockTxTriptych transactions (function specialization)
* param: txs_to_validate -
* return: true/false on validation result
*/
template <>
bool validate_mock_txs<MockTxTriptych>(const std::vector<std::shared_ptr<MockTxTriptych>> &txs_to_validate);

} //namespace mock_tx








