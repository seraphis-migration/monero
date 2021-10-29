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

// Mock tx: Seraphis transaction-builder helper types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_sp_base_types.h"
#include "mock_sp_component_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace mock_tx
{

////
// MockInputProposalSpV1 - Input V1
///
struct MockInputProposalSpV1 final : public MockInputProposalSp
{
    MockENoteSpV1 m_enote;
    rct::key m_enote_pubkey;

    /// generate a v1 input (all random; does not support info recovery)
    void gen(const rct::xmr_amount amount);

protected:
    virtual const MockENoteSp& get_enote_base() const { return m_enote; }
};

////
// MockMembershipReferenceSetSpV1 - Records info about a membership reference set
///
struct MockMembershipReferenceSetSpV1 final
{
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
    std::vector<std::size_t> m_ledger_enote_indices;
    std::vector<MockENoteSpV1> m_referenced_enotes;
    std::size_t m_real_spend_index_in_set;
};

////
// MockDestinationSpV1 - Destination V1
///
struct MockDestinationSpV1 final : public MockDestinationSp
{
    /// r_t
    crypto::secret_key m_enote_privkey;

    /// get the amount blinding factor
    void get_amount_blinding_factor(const std::size_t output_index, crypto::secret_key &amount_blinding_factor) const;

    /// convert this destination into a v1 enote
    MockENoteSpV1 to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const;

    /**
    * brief: gen - generate a V1 Destination (random)
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// MockTxProposalSpV1: set of destinations (and miscellaneous memos), and a balance proof
// - in this version, balance proofs are independent of inputs (the balance proof itself is implicit, only range proofs
//   require storage), so a tx's balance proof can be stored in the tx proposal
///
class MockTxProposalSpV1 final
{
public:
//constructors
    /// default constructor
    MockTxProposalSpV1() = default;

    /// normal constructor: make a tx proposal from destinations (a.k.a. outlays)
    MockTxProposalSpV1(std::vector<MockDestinationSpV1> destinations, const std::size_t max_rangeproof_splits);

//member functions
    /// message to be signed by input spend proofs
    rct::key get_proposal_prefix(const std::string &version_string);

    /// stored destinations
    const std::vector<MockDestinationSpV1>& get_destinations() { return m_destinations; }

    /// proposed outputs
    const std::vector<MockENoteSpV1>& get_outputs() { return m_outputs; }

    /// proposed tx supplement
    const MockSupplementSpV1& get_tx_supplement() { return m_tx_supplement; }

    /// proposed balance proof
    const std::shared_ptr<const MockBalanceProofSpV1> get_balance_proof() { return m_balance_proof; }

//member variables
private:
    std::vector<MockDestinationSpV1> m_destinations;
    //TODO: miscellaneous memo(s)
    std::vector<MockENoteSpV1> m_outputs;
    MockSupplementSpV1 m_tx_supplement;
    std::shared_ptr<MockBalanceProofSpV1> m_balance_proof;
};

////
// MockTxPartialInputSpV1
// - enote spent
// - cached amount and amount blinding factor, image masks (for balance and membership proofs)
// - spend proof for input (and proof the input's key image is properly constructed)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
//
// note: when making last input, need to set amount commitment mask to satisfy balance proof
//   - caller may also need to choose the input's amount to satisfy tx fee (e.g. in collaborative funding)
///
class MockTxPartialInputSpV1 final //needs to be InputSetPartial for merged composition proofs
{
public:
//constructors
    /// default constructor
    MockTxPartialInputSpV1() = default;

    /// normal constructor: normal input
    MockTxPartialInputSpV1(const MockInputProposalSpV1 &input_proposal, const rct::key &proposal_prefix);

    /// normal constructor: last input (amount commitment must complete the implicit balance proof)
    MockTxPartialInputSpV1(const MockInputProposalSpV1 &input_proposal,
        const rct::key &proposal_prefix,
        const MockTxProposalSpV1 &tx_proposal,
        const std::vector<MockTxPartialInputSpV1> &other_inputs);

//member functions
    /// the input's image
    const MockENoteImageSpV1& get_input_image() { return m_input_image; }

    /// the input's image
    const MockImageProofSpV1& get_image_proof() { return m_image_proof; }

    /// the input's image
    const crypto::secret_key& get_image_address_mask() { return m_image_address_mask; }

    /// the input's image
    const crypto::secret_key& get_image_amount_mask() { return m_image_amount_mask; }

    /// the input's image
    const rct::key& get_proposal_prefix() { return m_proposal_prefix; }

    /// the input's image
    const MockENoteSpV1& get_input_enote() { return m_input_enote; }

    /// the input's image
    rct::xmr_amount get_input_amount() { return m_input_amount; }

//member variables
private:
    MockENoteImageSpV1 m_input_image;
    MockImageProofSpV1 m_image_proof;
    crypto::secret_key m_image_address_mask;
    crypto::secret_key m_image_amount_mask;

    rct::key m_proposal_prefix;

    MockENoteSpV1 m_input_enote;
    rct::xmr_amount m_input_amount;
    crypto::secret_key m_input_amount_blinding_factor;  // has no getter, it is only used for making the last input
};

////
// MockTxPartialSpV1: everything needed for a tx except input membership proofs
//
// TODO: from multisig - multisigproposal.txproposal, multisig inputs + extra inputs, balance proof
///
struct MockTxPartialSpV1 final
{
//constructors
    /// default constructor
    MockTxPartialSpV1() = default;

    /// normal constructor: standard assembly
    MockTxPartialSpV1(const MockTxProposalSpV1 &proposal,
        const std::vector<MockTxPartialInputSpV1> &inputs);

    /// normal constructor (TODO): assembly from multisig pieces

//member variables
    /// tx input images  (spent e-notes)
    std::vector<MockENoteImageSpV1> m_input_images;
    /// tx outputs (new e-notes)
    std::vector<MockENoteSpV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    std::shared_ptr<MockBalanceProofSpV1> m_balance_proof;
    /// composition proofs: ownership/unspentness for each input
    std::vector<MockImageProofSpV1> m_image_proofs;
    /// supplemental data for tx
    MockSupplementSpV1 m_tx_supplement;

    /// sorted input enotes
    std::vector<MockENoteSpV1> m_input_enotes;
    /// sorted image masks for creating input membership proofs
    std::vector<crypto::secret_key> m_image_address_masks;
    std::vector<crypto::secret_key> m_image_amount_masks;
};

/**
* brief: gen_mock_sp_input_proposals_v1 - create random mock inputs
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<MockInputProposalSpV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts);
/**
* brief: gen_mock_sp_membership_ref_sets_v1 - create random reference sets for tx inputs, with real spend at a random index,
*   and update mock ledger to include all members of the reference set
* param: input_proposals -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: set of membership proof reference sets
*/
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<MockInputProposalSpV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout);
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<MockENoteSpV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
/**
* brief: gen_mock_sp_dests_v1 - create random mock destinations
* param: out_amounts -
* return: set of generated destinations
*/
std::vector<MockDestinationSpV1> gen_mock_sp_dests_v1(const std::vector<rct::xmr_amount> &out_amounts);

} //namespace mock_tx
