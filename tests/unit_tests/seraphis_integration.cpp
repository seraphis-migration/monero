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
#include "seraphis/ledger_context.h"
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
#include "seraphis/tx_extra.h"
#include "seraphis/tx_misc_utils.h"
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
    const rct::xmr_amount in_amount_A{10};

    const JamtisPaymentProposalV1 payment_proposal_A{
            .m_destination = user_address_A,
            .m_amount = in_amount_A,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = TxExtra{}
        };
    SpOutputProposalV1 output_proposal_A;
    payment_proposal_A.get_output_proposal_v1(output_proposal_A);

    SpEnoteV1 input_enote_A;
    output_proposal_A.get_enote_v1(input_enote_A);
    const rct::key input_enote_ephemeral_pubkey_A{output_proposal_A.m_enote_ephemeral_pubkey};

    // c) extract info from the enote 'sent' to the multisig address   //todo: find enote in mock ledger -> enote store
    SpEnoteRecordV1 input_enote_record_A;

    ASSERT_TRUE(try_get_enote_record_v1(input_enote_A,
        input_enote_ephemeral_pubkey_A,
        keys_user_A.K_1_base,
        keys_user_A.k_vb,
        input_enote_record_A));

    // d) double check information recovery
    ASSERT_TRUE(input_enote_record_A.m_amount == in_amount_A);
    ASSERT_TRUE(input_enote_record_A.m_address_index == j_A);
    ASSERT_TRUE(input_enote_record_A.m_type == JamtisEnoteType::PLAIN);


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
    SpOutputProposalV1 output_proposal_B;
    payment_proposal_B.get_output_proposal_v1(output_proposal_B);

    // c) finalize output proposals
    const rct::xmr_amount real_transaction_fee{1};
    DiscretizedFee discretized_transaction_fee;  //todo: use fee oracle mockup
    ASSERT_NO_THROW(discretized_transaction_fee = DiscretizedFee{real_transaction_fee});
    ASSERT_TRUE(discretized_transaction_fee == real_transaction_fee);  //a tx fee of 1 should discretize perfectly

    std::vector<SpOutputProposalV1> output_proposals;
    output_proposals.emplace_back(output_proposal_B);

    ASSERT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount_A,
        real_transaction_fee,
        user_address_A,
        user_address_A,
        keys_user_A.K_1_base,
        keys_user_A.k_vb,
        output_proposals));

    // d) make an input proposal to fund the tx
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.emplace_back();

    ASSERT_NO_THROW(make_v1_input_proposal_v1(input_enote_record_A,
        keys_user_A.k_m,
        make_secret_key(),
        make_secret_key(),
        input_proposals.back()));

    // e) prepare a reference set for the input's membership proof
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;

    ASSERT_NO_THROW(membership_proof_preps =
            gen_mock_sp_membership_proof_preps_v1(input_proposals,
                2,
                2,
                SpBinnedReferenceSetConfigV1{.m_bin_radius = 1, .m_num_bin_members = 2},
                ledger_context)
        );

    // f) make the transaction
    SpTxSquashedV1 completed_tx;

    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(input_proposals,
        std::move(output_proposals),
        discretized_transaction_fee,
        std::move(membership_proof_preps),
        std::vector<ExtraFieldElement>{},
        SpTxSquashedV1::SemanticRulesVersion::MOCK,
        completed_tx));


    /// 3] add tx to ledger
    // a) validate tx
    ASSERT_TRUE(validate_tx(completed_tx, ledger_context, false));

    // b) add the tx to the ledger
    ASSERT_TRUE(try_add_tx_to_ledger<sp::SpTxSquashedV1>(completed_tx, ledger_context));


    /// 4] user A finds change output in ledger (TODO)


    /// 5] user B finds newly received money in ledger (TODO)

}
//-------------------------------------------------------------------------------------------------------------------
