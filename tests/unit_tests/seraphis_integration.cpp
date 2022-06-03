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
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
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
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


struct jamtis_keys
{
    crypto::secret_key k_m;   //master
    crypto::secret_key k_vb;  //view-balance
    crypto::secret_key k_fr;  //find-received
    crypto::secret_key s_ga;  //generate-address
    crypto::secret_key s_ct;  //cipher-tag
    rct::key K_1_base;        //wallet spend base
    rct::key K_fr;            //find-received pubkey
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = make_secret_key();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_keys(jamtis_keys &keys_out)
{
    using namespace sp;
    using namespace jamtis;

    make_secret_key(keys_out.k_m);
    make_secret_key(keys_out.k_vb);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.k_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    make_seraphis_spendkey(keys_out.k_vb, keys_out.k_m, keys_out.K_1_base);
    rct::scalarmultBase(keys_out.K_fr, rct::sk2rct(keys_out.k_fr));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, txtype_squashed_v1)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)
    using namespace sp;
    using namespace jamtis;


    /// config
    const std::size_t max_inputs{10000};
    const std::size_t tx_fee_per_weight{1};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t num_bin_members{2};


    /// fake ledger context for this test
    sp::MockLedgerContext ledger_context{};


    /// make two users
    jamtis_keys keys_user_A, keys_user_B;
    make_jamtis_keys(keys_user_A);
    make_jamtis_keys(keys_user_B);


    /// 1] send money to user A
    // a) make an address for user A to receive funds
    address_index_t j_A;
    j_A.gen();
    JamtisDestinationV1 user_address_A;

    ASSERT_NO_THROW(make_jamtis_destination_v1(keys_user_A.K_1_base,
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
        tx_fee_per_weight,
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

    ASSERT_TRUE(tx_fee_calculator.get_fee(tx_fee_per_weight,
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

    ASSERT_TRUE(completed_tx.m_fee == tx_fee_calculator.get_fee(tx_fee_per_weight, completed_tx));


    /// 3] add tx to ledger
    // a) validate tx
    const sp::TxValidationContextMock tx_validation_context{ledger_context};

    ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context));

    // b) add the tx to the ledger
    ASSERT_TRUE(try_add_tx_to_ledger<sp::SpTxSquashedV1>(completed_tx, ledger_context));


    /// 4] user A finds change output in ledger (TODO)


    /// 5] user B finds newly received money in ledger (TODO)

}
//-------------------------------------------------------------------------------------------------------------------
