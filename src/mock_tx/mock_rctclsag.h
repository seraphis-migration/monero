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

// Mock tx: plain RCT on CLSAG with BP+
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_tx_interface.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

//forward declarations


namespace mock_tx
{

class MockTxCLSAG;

template <>
struct MockENote<MockTxCLSAG>
{
    crypto::public_key m_onetime_address;
    crypto::public_key m_amount_commitment;

    // memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    static std::size_t get_size_bytes() {return 32*3 + 8;}
};
using MockCLSAGENote = MockENote<MockTxCLSAG>;

template <>
struct MockENoteImage<MockTxCLSAG>
{
    crypto::public_key m_pseudo_amount_commitment;
    crypto::key_image m_key_image;

    static std::size_t get_size_bytes() {return 32*2;}
};
using MockCLSAGENoteImage = MockENoteImage<MockTxCLSAG>;

template <>
struct MockInput<MockTxCLSAG>
{
    crypto::secret_key m_onetime_privkey;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;
    std::vector<MockCLSAGENote> m_input_ref_set;
    std::size_t m_input_ref_set_real_index;

    // convert this input to an e-note-image
    MockCLSAGENoteImage to_enote_image(const crypto::secret_key &pseudo_blinding_factor) const;
};
using MockTxCLSAGInput = MockInput<MockTxCLSAG>;

template <>
struct MockDest<MockTxCLSAG>
{
    // destination (for creating an e-note to send an amount to someone)

    crypto::public_key m_onetime_address;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;

    // for the memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    // convert this destination into an e-note
    MockCLSAGENote to_enote() const;
};
using MockTxCLSAGDest = MockDest<MockTxCLSAG>;

struct MockCLSAGProof final
{
    // the CLSAG proof
    rct::clsag m_clsag_proof;
    // vector of pairs <Ko_i, C_i> for referenced enotes
    rct::ctkeyV m_referenced_enotes_converted;
};

// create mock enote from known info
MockCLSAGENote make_mock_tx_clsag_enote(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor, const rct::xmr_amount amount);

// create random mock enote
MockCLSAGENote gen_mock_tx_clsag_enote();

// create random mock inputs
// note: number of inputs implied by size of 'amounts'
template <>
std::vector<MockTxCLSAGInput> gen_mock_tx_inputs(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m);

// create random mock destinations
// note: number of destinations implied by size of 'amounts'
template <>
std::vector<MockTxCLSAGDest> gen_mock_tx_dests(const std::vector<rct::xmr_amount> &amounts);

template <>
struct MockTxParamPack<MockTxCLSAG>
{
    std::size_t max_rangeproof_splits;
};


class MockTxCLSAG final : public MockTx<MockTxCLSAG>
{
public:
//constructors
    // default constructor
    MockTxCLSAG() = default;

    // normal constructor: new tx
    MockTxCLSAG(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
        const std::vector<MockTxCLSAGDest> &destinations,
        const MockTxParamPack<MockTxCLSAG> &param_pack) : MockTx<MockTxCLSAG>{inputs_to_spend, destinations, param_pack}
    {}

    // normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    // validate the transaction
    // - if 'defer_batchable' is set, then batchable validation steps won't be executed
    bool validate(const bool defer_batchable = false) const override;

    // get size of tx
    std::size_t get_size_bytes() const override;

    // get range proof
    const std::vector<rct::BulletproofPlus>& get_range_proofs() const {return m_range_proofs;}

    //get_tx_byte_blob()

private:
    // make a transaction
    void validate_and_make_tx(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
        const std::vector<MockTxCLSAGDest> &destinations,
        const MockTxParamPack<MockTxCLSAG> &param_pack) override;

    void make_tx(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
        const std::vector<MockTxCLSAGDest> &destinations,
        const std::size_t max_rangeproof_splits);

//member variables
    // tx input images  (spent e-notes)
    std::vector<MockCLSAGENoteImage> m_input_images;
    // tx outputs (new e-notes)
    std::vector<MockCLSAGENote> m_outputs;

    // range proofs
    std::vector<rct::BulletproofPlus> m_range_proofs;

    // CLSAGs proving membership/ownership/unspentness for each input
    std::vector<MockCLSAGProof> m_tx_proofs;
};

// validate a set of mock tx
template <>
bool validate_mock_txs(const std::vector<std::shared_ptr<MockTxCLSAG>> &txs_to_validate);

} //namespace mock_tx








