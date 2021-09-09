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

// Mock tx: RingCT on Triptych with BP+
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_tx_common_rct.h"
#include "mock_tx_interface.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

//forward declarations


namespace mock_tx
{

class MockTxTriptych;

template <>
struct MockENote<MockTxTriptych> : public MockENoteRCT
{};
using MockTriptychENote = MockENote<MockTxTriptych>;

template <>
struct MockENoteImage<MockTxTriptych> : public MockENoteImageRCT
{};
using MockTriptychENoteImage = MockENoteImage<MockTxTriptych>;

template <>
struct MockInput<MockTxTriptych> : public MockInputRCT<MockTxTriptych>
{
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    // convert this input to an e-note-image
    MockTriptychENoteImage to_enote_image(const crypto::secret_key &pseudo_blinding_factor) const;
};
using MockTxTriptychInput = MockInput<MockTxTriptych>;

template <>
struct MockDest<MockTxTriptych> : public MockDestRCT
{
    // destination (for creating an e-note to send an amount to someone)

    // convert this destination into an e-note
    MockTriptychENote to_enote() const;
};
using MockTxTriptychDest = MockDest<MockTxTriptych>;

struct MockTriptychProof final
{
    // the Triptych proof
    rct::TriptychProof m_triptych_proof;
    // onetime addresses Ko
    rct::keyV m_onetime_addresses;
    // output commitments C
    rct::keyV m_commitments;
    // pseudo-output commitment C'
    rct::key m_pseudo_amount_commitment;
};

// create random mock inputs
// note: number of inputs implied by size of 'amounts'
template <>
std::vector<MockTxTriptychInput> gen_mock_tx_inputs<MockTxTriptych>(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m);

// create random mock destinations
// note: number of destinations implied by size of 'amounts'
template <>
std::vector<MockTxTriptychDest> gen_mock_tx_dests<MockTxTriptych>(const std::vector<rct::xmr_amount> &amounts);

template <>
struct MockTxParamPack<MockTxTriptych>
{
    std::size_t max_rangeproof_splits;
};
using MockTxTriptychParams = MockTxParamPack<MockTxTriptych>;


class MockTxTriptych final : public MockTx<MockTxTriptych>
{
public:
//constructors
    // default constructor
    MockTxTriptych() = default;

    // normal constructor: new tx
    MockTxTriptych(const std::vector<MockTxTriptychInput> &inputs_to_spend,
        const std::vector<MockTxTriptychDest> &destinations,
        const MockTxTriptychParams &param_pack) : MockTx<MockTxTriptych>{inputs_to_spend, destinations, param_pack}
    {
        make_tx(inputs_to_spend, destinations, param_pack);
    }

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
    void make_tx(const std::vector<MockTxTriptychInput> &inputs_to_spend,
        const std::vector<MockTxTriptychDest> &destinations,
        const MockTxTriptychParams &param_pack);

    // make transfers: input images, outputs, balance proof
    void make_tx_transfers(const std::vector<MockTxTriptychInput> &inputs_to_spend,
        const std::vector<MockTxTriptychDest> &destinations,
        std::vector<rct::xmr_amount> &output_amounts,
        std::vector<rct::key> &output_amount_commitment_blinding_factors,
        std::vector<crypto::secret_key> &pseudo_blinding_factors);

    // make input proofs: membership, ownership, unspentness (i.e. prove key images are constructed correctly)
    void make_tx_input_proofs(const std::vector<MockTxTriptychInput> &inputs_to_spend,
        const std::vector<crypto::secret_key> &pseudo_blinding_factors);

    // validate pieces of the tx
    bool validate_tx_semantics() const;
    bool validate_tx_linking_tags() const;
    bool validate_tx_amount_balance() const;
    bool validate_tx_rangeproofs(const bool defer_batchable) const;
    bool validate_tx_input_proofs() const;

//member variables
    // tx input images  (spent e-notes)
    std::vector<MockTriptychENoteImage> m_input_images;
    // tx outputs (new e-notes)
    std::vector<MockTriptychENote> m_outputs;

    // range proofs
    std::vector<rct::BulletproofPlus> m_range_proofs;

    // Triptych proofs proving membership/ownership/unspentness for each input
    std::vector<MockTriptychProof> m_tx_proofs;
    // decomposition of ref set size: n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
};

// validate a set of mock tx
template <>
bool validate_mock_txs<MockTxTriptych>(const std::vector<std::shared_ptr<MockTxTriptych>> &txs_to_validate);

} //namespace mock_tx








