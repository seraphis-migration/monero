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

#include "crypto/crypto.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_finding_context_mocks.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_context_simple.h"
#include "seraphis/tx_enote_store.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_random_address_for_user(const sp::jamtis::jamtis_mock_keys &user_keys,
    sp::jamtis::JamtisDestinationV1 &user_address_out)
{
    using namespace sp;
    using namespace jamtis;

    address_index_t address_index;
    address_index.gen();

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.K_ua,
        user_keys.K_fr,
        user_keys.s_ga,
        address_index,
        user_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const sp::jamtis::JamtisDestinationV1 &destination,
    sp::jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    using namespace sp;
    using namespace jamtis;

    payment_proposal_out = JamtisPaymentProposalV1{
            .m_destination = destination,
            .m_amount = outlay_amount,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = TxExtra{}
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void send_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const sp::jamtis::JamtisDestinationV1 &user_address,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    std::vector<SpEnoteV1> coinbase_enotes;
    SpTxSupplementV1 tx_supplement;
    JamtisPaymentProposalV1 payment_proposal_temp;
    const rct::key mock_input_context{rct::pkGen()};
    coinbase_enotes.reserve(coinbase_amounts.size());
    tx_supplement.m_output_enote_ephemeral_pubkeys.reserve(coinbase_amounts.size());

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount, user_address, payment_proposal_temp);

        // get output proposal
        SpOutputProposalV1 output_proposal;
        payment_proposal_temp.get_output_proposal_v1(mock_input_context, output_proposal);

        // save enote and ephemeral pubkey
        coinbase_enotes.emplace_back();
        output_proposal.get_enote_v1(coinbase_enotes.back());
        tx_supplement.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }

    // commit coinbase enotes as new block
    ASSERT_NO_THROW(ledger_context_inout.commit_unconfirmed_txs_v1(mock_input_context,
        std::move(tx_supplement),
        std::move(coinbase_enotes)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store(const sp::jamtis::jamtis_mock_keys &user_keys,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreV1 &user_enote_store_inout)
{
    using namespace sp;
    using namespace jamtis;

    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.k_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        user_keys.K_1_base,
        user_keys.k_vb,
        enote_scanning_context,
        user_enote_store_inout));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_tx_proposal_for_transfer(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::SpEnoteStoreMockV1 &local_user_enote_store,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::pair<rct::xmr_amount, sp::jamtis::JamtisDestinationV1>> &outlays,
    sp::SpTxProposalV1 &tx_proposal_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings_out)
{
    using namespace sp;
    using namespace jamtis;

    // prepare normal outputs for the tx
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const std::pair<rct::xmr_amount, JamtisDestinationV1> &outlay : outlays)
    {
        normal_payment_proposals.emplace_back();
        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<JamtisDestinationV1>(outlay),
            normal_payment_proposals.back());
    }

    // select inputs for the tx
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;  //no predefined self-send payments

    const sp::OutputSetContextForInputSelectionV1 output_set_context{
            normal_payment_proposals,
            selfsend_payment_proposals
        };
    const sp::InputSelectorMockV1 input_selector{local_user_enote_store};

    rct::xmr_amount reported_final_fee;
    std::list<SpContextualEnoteRecordV1> contextual_inputs;
    ASSERT_TRUE(try_get_input_set_v1(output_set_context,
        max_inputs,
        input_selector,
        fee_per_tx_weight,
        tx_fee_calculator,
        reported_final_fee,
        contextual_inputs));

    // save input indices for making membership proofs
    input_ledger_mappings_out.clear();

    for (const SpContextualEnoteRecordV1 &contextual_input : contextual_inputs)
    {
        input_ledger_mappings_out[contextual_input.m_record.m_key_image] = 
            contextual_input.m_origin_context.m_enote_ledger_index;
    }

    // convert inputs to input proposals
    std::vector<SpInputProposalV1> input_proposals;

    for (const sp::SpContextualEnoteRecordV1 &contextual_input : contextual_inputs)
    {
        input_proposals.emplace_back();

        ASSERT_NO_THROW(make_v1_input_proposal_v1(contextual_input.m_record,
            make_secret_key(),
            make_secret_key(),
            input_proposals.back()));
    }

    // get total input amount
    boost::multiprecision::uint128_t total_input_amount{0};
    for (const SpInputProposalV1 &input_proposal : input_proposals)
        total_input_amount += input_proposal.m_core.m_amount;

    // prepare dummy and change addresses
    JamtisDestinationV1 dummy_address;
    JamtisDestinationV1 change_address;
    make_random_address_for_user(local_user_keys, dummy_address);
    make_random_address_for_user(local_user_keys, change_address);

    // finalize output set
    DiscretizedFee discretized_transaction_fee;
    ASSERT_NO_THROW(discretized_transaction_fee = DiscretizedFee{reported_final_fee});
    ASSERT_TRUE(discretized_transaction_fee == reported_final_fee);

    ASSERT_NO_THROW(finalize_v1_output_proposal_set_v1(total_input_amount,
        reported_final_fee,
        dummy_address,
        change_address,
        local_user_keys.k_vb,
        normal_payment_proposals,
        selfsend_payment_proposals));

    ASSERT_TRUE(tx_fee_calculator.get_fee(fee_per_tx_weight,
            contextual_inputs.size(),
            normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
        reported_final_fee);

    // assemble into tx proposal
    SpTxProposalV1 tx_proposal;

    ASSERT_NO_THROW(make_v1_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        std::move(input_proposals),
        std::vector<ExtraFieldElement>{},
        tx_proposal_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_proof_preps_for_inputs(const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<sp::SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    const sp::MockLedgerContext &ledger_context,
    std::vector<sp::SpMembershipProofPrepV1> &membership_proof_preps_out)
{
    ASSERT_TRUE(input_ledger_mappings.size() == input_proposals.size());

    using namespace sp;
    using namespace jamtis;

    membership_proof_preps_out.clear();
    membership_proof_preps_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        ASSERT_TRUE(input_ledger_mappings.find(input_proposal.m_core.m_key_image) != input_ledger_mappings.end());

        membership_proof_preps_out.emplace_back(
                gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(input_proposal.m_core.m_enote_core,
                        input_ledger_mappings.at(input_proposal.m_core.m_key_image),
                        input_proposal.m_core.m_address_mask,
                        input_proposal.m_core.m_commitment_mask,
                        ref_set_decomp_n,
                        ref_set_decomp_m,
                        bin_config,
                        ledger_context)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void transfer_funds(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::SpEnoteStoreMockV1 &local_user_enote_store,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::pair<rct::xmr_amount, sp::jamtis::JamtisDestinationV1>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    /// build transaction
    // 1. tx proposal
    SpTxProposalV1 tx_proposal;
    std::unordered_map<crypto::key_image, std::uint64_t> input_ledger_mappings;
    ASSERT_NO_THROW(make_tx_proposal_for_transfer(local_user_keys,
        local_user_enote_store,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        tx_proposal,
        input_ledger_mappings));

    // 2. prepare for membership proofs
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_proof_preps_for_inputs(input_ledger_mappings,
        tx_proposal.m_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        membership_proof_preps));

    // 3. complete tx
    SpTxSquashedV1 completed_tx;
    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(tx_proposal,
        std::move(membership_proof_preps),
        SpTxSquashedV1::SemanticRulesVersion::MOCK,
        local_user_keys.k_m,
        local_user_keys.k_vb,
        completed_tx));


    /// validate and submit transaction to ledger
    const sp::TxValidationContextMock tx_validation_context{ledger_context_inout};
    ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context));
    ASSERT_TRUE(try_add_tx_to_ledger(completed_tx, ledger_context_inout));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, txtype_squashed_v1_send_receive)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)
    using namespace sp;
    using namespace jamtis;


    /// config
    const std::size_t max_inputs{10000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{};


    /// make two users

    // a. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // b. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // c. user enote stores (refresh height = 0)
    SpEnoteStoreMockV1 enote_store_A{0};
    SpEnoteStoreMockV1 enote_store_B{0};


    /// initial funding for user A
    send_coinbase_amounts_to_user({1000000, 1000000, 1000000, 1000000}, destination_A, ledger_context);


    /// send funds back and forth between users

    // A -> B: 2000000
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginContextV1::OriginStatus::ONCHAIN},
        {SpEnoteSpentContextV1::SpentStatus::SPENT_ONCHAIN}) >= 2000000);
    transfer_funds(user_keys_A,
        enote_store_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2000000, destination_B}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // B -> A: 1000000
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginContextV1::OriginStatus::ONCHAIN},
        {SpEnoteSpentContextV1::SpentStatus::SPENT_ONCHAIN}) >= 1000000);
    transfer_funds(user_keys_B,
        enote_store_B,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1000000, destination_A}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // A -> B: 1500000
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginContextV1::OriginStatus::ONCHAIN},
        {SpEnoteSpentContextV1::SpentStatus::SPENT_ONCHAIN}) >= 1500000);
    transfer_funds(user_keys_A,
        enote_store_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1500000, destination_B}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, txtype_squashed_v1)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)
    using namespace sp;
    using namespace jamtis;


    /// config
    const std::size_t max_inputs{10000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t num_bin_members{2};


    /// fake ledger context for this test
    sp::MockLedgerContext ledger_context{};


    /// make two users
    jamtis_mock_keys keys_user_A, keys_user_B;
    make_jamtis_mock_keys(keys_user_A);
    make_jamtis_mock_keys(keys_user_B);


    /// 1] send money to user A
    // a) make an address for user A to receive funds
    address_index_t j_A;
    j_A.gen();
    JamtisDestinationV1 user_address_A;

    ASSERT_NO_THROW(make_jamtis_destination_v1(keys_user_A.K_1_base,
        keys_user_A.K_ua,
        keys_user_A.K_fr,
        keys_user_A.s_ga,
        j_A,
        user_address_A));

    // b) make a plain enote paying to user A
    const rct::xmr_amount in_amount_A{1000000};  //enough for fee

    const JamtisPaymentProposalV1 payment_proposal_A{
            .m_destination = user_address_A,
            .m_amount = in_amount_A,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = TxExtra{}
        };
    SpOutputProposalV1 output_proposal_A;
    payment_proposal_A.get_output_proposal_v1(rct::zero(), output_proposal_A);

    SpEnoteV1 input_enote_A;
    output_proposal_A.get_enote_v1(input_enote_A);
    const rct::key input_enote_ephemeral_pubkey_A{output_proposal_A.m_enote_ephemeral_pubkey};

    // c) extract info from the enote 'sent' to the address   //todo: find enote in mock ledger -> enote store
    SpEnoteRecordV1 input_enote_record_A;

    ASSERT_TRUE(try_get_enote_record_v1(input_enote_A,
        input_enote_ephemeral_pubkey_A,
        rct::zero(),
        keys_user_A.K_1_base,
        keys_user_A.k_vb,
        input_enote_record_A));

    // d) double check information recovery
    ASSERT_TRUE(input_enote_record_A.m_amount == in_amount_A);
    ASSERT_TRUE(input_enote_record_A.m_address_index == j_A);
    ASSERT_TRUE(input_enote_record_A.m_type == JamtisEnoteType::PLAIN);

    // e) add enote record to enote store
    sp::SpEnoteStoreMockV1 enote_store_A;
    enote_store_A.add_record(
            SpContextualEnoteRecordV1{
                    .m_record = input_enote_record_A
                }
        );


    /// 2] user A makes tx sending money to user B   //todo: use wallet to make tx
    // a) make an address for user B to receive funds
    address_index_t j_B;
    j_B.gen();
    JamtisDestinationV1 user_address_B;

    ASSERT_NO_THROW(make_jamtis_destination_v1(keys_user_B.K_1_base,
        keys_user_B.K_ua,
        keys_user_B.K_fr,
        keys_user_B.s_ga,
        j_B,
        user_address_B));

    // b) make payment proposal for paying to user B
    const rct::xmr_amount out_amount_B{5};

    const JamtisPaymentProposalV1 payment_proposal_B{
            .m_destination = user_address_B,
            .m_amount = out_amount_B,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = TxExtra{}
        };

    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.emplace_back(payment_proposal_B);

    // c) select inputs for the tx
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;  //no self-send payments

    const sp::OutputSetContextForInputSelectionV1 output_set_context{
            normal_payment_proposals,
            selfsend_payment_proposals
        };
    const sp::InputSelectorMockV1 input_selector{enote_store_A};
    const sp::FeeCalculatorSpTxSquashedV1 tx_fee_calculator{
            ref_set_decomp_m,
            ref_set_decomp_n,
            num_bin_members,
            TxExtra{}
        };

    rct::xmr_amount reported_final_fee;
    std::list<SpContextualEnoteRecordV1> contextual_inputs;
    ASSERT_TRUE(try_get_input_set_v1(output_set_context,
        max_inputs,
        input_selector,
        fee_per_tx_weight,
        tx_fee_calculator,
        reported_final_fee,
        contextual_inputs));

    // d) finalize output proposals
    DiscretizedFee discretized_transaction_fee;
    ASSERT_NO_THROW(discretized_transaction_fee = DiscretizedFee{reported_final_fee});
    ASSERT_TRUE(discretized_transaction_fee == reported_final_fee);

    ASSERT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount_A,
        reported_final_fee,
        user_address_A,
        user_address_A,
        keys_user_A.k_vb,
        normal_payment_proposals,
        selfsend_payment_proposals));

    ASSERT_TRUE(tx_fee_calculator.get_fee(fee_per_tx_weight,
            contextual_inputs.size(),
            normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
        reported_final_fee);

    // e) make input proposals to fund the tx
    std::vector<SpInputProposalV1> input_proposals;

    for (const sp::SpContextualEnoteRecordV1 &contextual_input : contextual_inputs)
    {
        input_proposals.emplace_back();

        ASSERT_NO_THROW(make_v1_input_proposal_v1(contextual_input.m_record,
            make_secret_key(),
            make_secret_key(),
            input_proposals.back()));
    }

    // f) make a tx proposal
    SpTxProposalV1 tx_proposal;

    sp::make_v1_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        std::move(input_proposals),
        std::vector<ExtraFieldElement>{},
        tx_proposal);

    // g) prepare a reference set for the input's membership proof
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;

    ASSERT_NO_THROW(membership_proof_preps =
            gen_mock_sp_membership_proof_preps_v1(tx_proposal.m_input_proposals,
                ref_set_decomp_m,
                ref_set_decomp_n,
                SpBinnedReferenceSetConfigV1{.m_bin_radius = 1, .m_num_bin_members = num_bin_members},
                ledger_context)
        );

    // h) make the transaction
    SpTxSquashedV1 completed_tx;

    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(tx_proposal,
        std::move(membership_proof_preps),
        SpTxSquashedV1::SemanticRulesVersion::MOCK,
        keys_user_A.k_m,
        keys_user_A.k_vb,
        completed_tx));

    ASSERT_TRUE(completed_tx.m_tx_fee == tx_fee_calculator.get_fee(fee_per_tx_weight, completed_tx));


    /// 3] add tx to ledger
    // a) validate tx
    const sp::TxValidationContextMock tx_validation_context{ledger_context};

    ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context));

    // b) add the tx to the ledger
    ASSERT_TRUE(try_add_tx_to_ledger(completed_tx, ledger_context));


    /// 4] user A finds change output in ledger (TODO)


    /// 5] user B finds newly received money in ledger (TODO)

}
//-------------------------------------------------------------------------------------------------------------------
