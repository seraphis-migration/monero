// Copyright (c) 2023, The Monero Project
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

#include <boost/format.hpp>
#include <boost/format/format_fwd.hpp>
#include <boost/none.hpp>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <utility>
#include <vector>

#include "boost/multiprecision/cpp_int.hpp"
#include "common/container_helpers.h"
#include "common/scoped_message_writer.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "encrypt_file.h"
#include "enote_store.h"
#include "gtest/gtest.h"
#include "jamtis_mock_keys.h"
#include "legacy_enote_types.h"
#include "legacy_mock_keys.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store_utils.h"
// #include "seraphis_impl/scanning_context_simple.h"
#include "seraphis_impl/tx_fee_calculator_squashed_v1.h"
#include "seraphis_impl/tx_input_selection_output_context_v1.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "seraphis_wallet/show_enotes.h"
#include "seraphis_wallet/transaction_history.h"
#include "seraphis_wallet/transaction_utils.h"
#include "serialization_demo_utils.h"
#include "serialization_types.h"
#include "sp_knowledge_proofs.h"

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;
using namespace sp::knowledge_proofs;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_coinbase_enotes(MockLedgerContext &ledger_context,
    SpEnoteStore &enote_store_in_out,
    SpTransactionHistory &tx_history_in_out,
    const legacy_mock_keys &legacy_user_keys_A,
    const jamtis_mock_keys &user_keys_A,
    const uint64_t number_txs)
{
    /// config
    const std::size_t legacy_ring_size{2};

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    const FeeCalculatorMockTrivial fee_calculator;  // trivial calculator for easy fee (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};

    /// prepare for membership proofs
    // a. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);

    // b. add enough fake legacy enotes to the ledger so we can reliably make legacy ring signatures
    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};

    send_legacy_coinbase_amounts_to_user(
        fake_legacy_enote_amounts, fake_legacy_spendkey, fake_legacy_viewkey, ledger_context);
    /// make two users

    // b. legacy user address
    rct::key legacy_subaddr_spendkey_A;
    rct::key legacy_subaddr_viewkey_A;
    cryptonote::subaddress_index legacy_subaddr_index_A;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

    gen_legacy_subaddress(legacy_user_keys_A.Ks,
        legacy_user_keys_A.k_v,
        legacy_subaddr_spendkey_A,
        legacy_subaddr_viewkey_A,
        legacy_subaddr_index_A);

    legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

    // user keys B
    jamtis_mock_keys user_keys_B;

    make_jamtis_mock_keys(user_keys_B);

    // b. destination address
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // c. user enote stores (refresh index = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStore enote_store_B{0, 0, 0};

    // d. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_in_out};
    const InputSelectorMockV1 input_selector_B{enote_store_B};

    /// initial funding for user A: seraphis 1000

    /// initial funding for user A: legacy 1000
    // send_legacy_coinbase_amounts_to_user(
    //     {1000, 1000, 1000, 1000, 1000}, legacy_subaddr_spendkey_A, legacy_subaddr_viewkey_A, ledger_context);
    for (uint64_t i = 0; i < number_txs; i++)
    {
        send_legacy_coinbase_amounts_to_user(
            {100}, legacy_subaddr_spendkey_A, legacy_subaddr_viewkey_A, ledger_context);
        refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
            legacy_subaddress_map_A,
            legacy_user_keys_A.k_s,
            legacy_user_keys_A.k_v,
            refresh_config,
            ledger_context,
            enote_store_in_out);

        // send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_A, ledger_context);
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_transfers2(MockLedgerContext &ledger_context,
    SpEnoteStore &enote_store_in_out,
    SpTransactionHistory &tx_history_in_out,
    const legacy_mock_keys &legacy_user_keys_A,
    const jamtis_mock_keys &user_keys_A,
    const uint64_t number_txs)
{
    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    const FeeCalculatorMockTrivial fee_calculator;  // trivial calculator for easy fee (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};

    /// prepare for membership proofs
    // a. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);

    // b. add enough fake legacy enotes to the ledger so we can reliably make legacy ring signatures
    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};

    send_legacy_coinbase_amounts_to_user(
        fake_legacy_enote_amounts, fake_legacy_spendkey, fake_legacy_viewkey, ledger_context);
    /// make two users

    // b. legacy user address
    rct::key legacy_subaddr_spendkey_A;
    rct::key legacy_subaddr_viewkey_A;
    cryptonote::subaddress_index legacy_subaddr_index_A;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

    gen_legacy_subaddress(legacy_user_keys_A.Ks,
        legacy_user_keys_A.k_v,
        legacy_subaddr_spendkey_A,
        legacy_subaddr_viewkey_A,
        legacy_subaddr_index_A);

    legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

    // user keys B
    jamtis_mock_keys user_keys_B;

    make_jamtis_mock_keys(user_keys_B);

    // b. destination address
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // c. user enote stores (refresh index = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStore enote_store_B{0, 0, 0};

    // d. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_in_out};
    const InputSelectorMockV1 input_selector_B{enote_store_B};

    /// variables of one tx
    SpTxSquashedV1 single_tx;
    const TxValidationContextMock tx_validation_context{ledger_context};
    std::vector<JamtisPaymentProposalV1> normal_payments;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;

    /// Send 5 confirmed txs
    for (int i = 0; i < number_txs; i++)
    {
        normal_payments.clear();
        selfsend_payments.clear();

        rct::xmr_amount to_send{10};
        // rct::xmr_amount to_send{static_cast<uint64_t>(rand() % 100)};
        // std::cout << "to send: " << to_send << std::endl;
        std::pair<JamtisDestinationV1, rct::xmr_amount> outlays{destination_B, to_send};
        // 1. make one tx
        construct_tx_for_mock_ledger_v1(legacy_user_keys_A,
            user_keys_A,
            input_selector_A,
            fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            {{outlays.second, outlays.first, TxExtra{}}},
            legacy_ring_size,
            ref_set_decomp_n,
            ref_set_decomp_m,
            bin_config,
            ledger_context,
            single_tx,
            selfsend_payments,
            normal_payments);

        // 2. validate and submit to the mock ledger
        const TxValidationContextMock tx_validation_context{ledger_context};
        CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
            "transfer funds single mock unconfirmed sp only: validating tx failed.");
        CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
            "transfer funds single mock unconfirmed sp only: validating tx failed.");

        // 3. refresh user stores
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);
        refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
            legacy_subaddress_map_A,
            legacy_user_keys_A.k_s,
            legacy_user_keys_A.k_v,
            refresh_config,
            ledger_context,
            enote_store_in_out);

        // 4. add tx to tx_records
        tx_history_in_out.add_single_tx_to_tx_history(single_tx,
            selfsend_payments,
            normal_payments);
    }
}
// -------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------
// There is nothing to be evaluated in the show functions 
// These 'TESTS' are only a demonstrator to see how the show functions would look like
// -------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------

TEST(seraphis_wallet_show, show_enotes_all)
{
    // Test to display info stored in the tx_store class

    // 1. generate enote_store and tx_history
    SpEnoteStore enote_store_A{0, 0, 0};
    SpTransactionHistory tx_history_A;
    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};

    // 2. generate user A keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);
    make_legacy_mock_keys(legacy_user_keys_A);

    std::vector<ContextualRecordVariant> enote_records;

    // 3. add coinbase enotes
    add_coinbase_enotes(ledger_context, enote_store_A, tx_history_A, legacy_user_keys_A, user_keys_A, 10);

    // 4. get all enotes initially
    std::cout << "Initial account statement: " << std::endl;

    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {0, -1}, enote_records);
    show_enotes(enote_records);

    // 5. make transfers to fill enote_store and tx_store
    make_transfers2(ledger_context, enote_store_A, tx_history_A, legacy_user_keys_A, user_keys_A, 10);

    std::cout << "Account statement after transaction: " << std::endl;

    // 6. show and filter enotes after transactions
    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {0, -1}, enote_records);
    show_enotes(enote_records);

    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {0, -1}, enote_records);
    show_enotes(enote_records);

    get_enotes(enote_store_A, SpTxDirectionStatus::IN_ONCHAIN, {0, -1}, enote_records);
    show_enotes(enote_records);

    get_enotes(enote_store_A, SpTxDirectionStatus::OUT_ONCHAIN, {0, -1}, enote_records);
    show_enotes(enote_records);

    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {20, 40}, enote_records);
    show_enotes(enote_records);

    // std::cout << "Balance onchain : "
    //           << get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN})
    //           << std::endl;
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_wallet_show, show_legacy_enote_with_sent_proof)
{
    // 1. generate enote_store and tx_store
    SpEnoteStore enote_store_A{0, 0, 0};
    SpTransactionHistory tx_history_A;
    // mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};
    // define network and address type
    JamtisAddressNetwork address_network = JamtisAddressNetwork::MAINNET;
    JamtisAddressVersion address_version = JamtisAddressVersion::V1;

    // 2. generate user A keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);
    make_legacy_mock_keys(legacy_user_keys_A);

    // 3. add coinbase enotes
    add_coinbase_enotes(ledger_context, enote_store_A, tx_history_A, legacy_user_keys_A, user_keys_A, 1);

    // 4. get all enotes initially
    // std::cout << "1) Initial account statement: " << std::endl;
    std::vector<ContextualRecordVariant> enote_records;
    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {0, -1}, enote_records);
    show_enotes(enote_records);

    // 5. make transfers to fill enote_store and tx_store
    make_transfers2(ledger_context, enote_store_A, tx_history_A, legacy_user_keys_A, user_keys_A, 1);

    // 6. show and filter enotes after transactions
    // std::cout << "2) Account statement after transaction: " << std::endl;
    get_enotes(enote_store_A, SpTxDirectionStatus::ALL, {0, -1}, enote_records);
    show_enotes(enote_records);

    // 7. get specific enote
    const auto last_txs{tx_history_A.get_last_N_txs(1)};
    rct::key tx_id_proof = last_txs[0].second;

    // 8. from tx_id get enote_record
    TransactionRecordV1 tx_record;
    tx_history_A.try_get_tx_record_from_txid(tx_id_proof, tx_record);

    // 9. show specific enote
    // std::cout << "3) Show specific enote with key-image:  " << tx_record.legacy_spent_enotes[0] << std::endl;
    show_specific_enote(enote_store_A, tx_history_A, tx_record.legacy_spent_enotes[0], address_version, address_network);

    // 10. From tx_id get all output enotes of a tx by querying node.
    std::vector<SpEnoteVariant> out_enotes = ledger_context.get_sp_enotes_out_from_tx(tx_id_proof);

    // 11. get input context
    rct::key input_context;
    make_jamtis_input_context_standard(tx_record.legacy_spent_enotes, tx_record.sp_spent_enotes, input_context);

    // 12. try to match enotes with destinations
    std::vector<EnoteInfo> enote_out_info;
    CHECK_AND_ASSERT_THROW_MES(try_get_enote_out_info(out_enotes,
                                   tx_record.normal_payments,
                                   tx_record.selfsend_payments,
                                   input_context,
                                   user_keys_A.k_vb,
                                   enote_out_info),
        "Error in get_enote_out_info. Could not match onetime adresses with destinations.");

    // 13. make enote ownership proof for normal and selfsend enotes
    // std::cout << "4) Get sent_proof of enote using the info obtained looking where it was spent. " << std::endl;
    std::string str_proof;
    for (auto enote_info : enote_out_info)
    {
        if (!enote_info.selfsend)
        {
            // std::cout << "Making proof for enote: " << onetime_address_ref(enote_info.enote)
            //           << " with amount: " << enote_info.amount << "XMR"
            //           << " and amount commitment: " << amount_commitment_ref(enote_info.enote) << std::endl;

            str_proof = get_enote_sent_proof(tx_id_proof,
                user_keys_A.k_vb,
                enote_info,
                tx_history_A,
                boost::none);

            // std::cout << "Proof generated: " << str_proof << std::endl;
            // std::cout << " ---------------------------------------------------- " << std::endl;
            // std::cout << "From the verifier side, he needs the proof, the onetime-address and the amount commitment."
            //           << std::endl;
            // read enote ownership proof
            CHECK_AND_ASSERT_THROW_MES(read_enote_sent_proof(boost::none,
                                           str_proof,
                                           amount_commitment_ref(enote_info.enote),
                                           onetime_address_ref(enote_info.enote)),
                "Verification of enote_sent_proof failed.");

            // std::cout << "If the verifier refuses to accept the proof, the prover can openly publish: the "
            //              "ephemeral_private_key and the recipient address. So any third party looking at the proof "
            //              "must agree that the person in possession of those information created the transaction and "
            //              "the address claimed indeed received the funds."
            //           << std::endl;

            // std::cout << "There is a big problem though, once all these info is revealed anyone can claim that they "
            //              "made this transaction. So if this point is reached then only the re-generation of the "
            //              "transaction with the input parameters can prove that the person made the transaction. So the "
            //              "prover should provide a legacy_spend_proof."
            //           << std::endl;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
