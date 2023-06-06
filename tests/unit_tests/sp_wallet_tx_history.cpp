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
#include <cstddef>
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
#include "legacy_mock_keys.h"
#include "misc_language.h"
#include "misc_log_ex.h"
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
#include "seraphis_wallet/transaction_history.h"
#include "seraphis_wallet/transaction_utils.h"
#include "serialization_demo_utils.h"
#include "serialization_types.h"

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;
using namespace sp::knowledge_proofs;

static void fill_tx_store(const SpTxSquashedV1 &single_tx,
                          const std::pair<JamtisDestinationV1, rct::xmr_amount> &outlays, SpTxStatus status,
                          SpEnoteStore &enote_store_in_out, SpTransactionHistory &tx_store_in_out)
{
    /// 1. prepare variables of tx_store
    rct::key tx_id;
    std::vector<std::pair<JamtisDestinationV1, rct::xmr_amount>> outlays_vec;
    std::vector<crypto::key_image> legacy_spent_ki;
    std::vector<crypto::key_image> sp_spent_ki;
    TransactionRecordV1 record;
    SpContextualEnoteRecordV1 temp_sp_enote_records{};
    LegacyContextualEnoteRecordV1 temp_legacy_enote_records{};

    // a. tx_id
    get_sp_tx_squashed_v1_txid(single_tx, tx_id);

    // b. legacy_spent_key_images
    legacy_spent_ki.clear();
    for (auto legacy_images : single_tx.legacy_input_images)
    {
        legacy_spent_ki.push_back(legacy_images.key_image);
    }

    // c. sp_spent_key_images
    sp_spent_ki.clear();
    for (auto sp_images : single_tx.sp_input_images)
    {
        sp_spent_ki.push_back(sp_images.core.key_image);
    }

    // d. insert outlays to vector
    outlays_vec.clear();
    outlays_vec.push_back(outlays);

    // e. fee
    rct::xmr_amount tx_fee;
    try_get_fee_value(single_tx.tx_fee, tx_fee);

    // f. get TransactionRecord
    record = TransactionRecordV1{legacy_spent_ki, sp_spent_ki, outlays_vec, outlays.second, tx_fee};

    // 2. add record to tx_record by tx_id
    tx_store_in_out.add_entry_to_tx_records(tx_id, std::move(record));

    // 3. get ContextualEnote records
    enote_store_in_out.try_get_sp_enote_record(sp_spent_ki[0], temp_sp_enote_records);

    // 4. update with either the info from legacy or sp context
    tx_store_in_out.add_entry_txs(status, temp_sp_enote_records.spent_context.block_index, tx_id);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_transfers(SpEnoteStore &enote_store_in_out, SpTransactionHistory &tx_store_in_out)
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

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};

    /// prepare for membership proofs
    // a. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);

    /// make two users

    // a. user keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;

    make_legacy_mock_keys(legacy_user_keys_A);

    // CHECK_AND_ASSERT_THROW_MES(read_master_wallet("masterA.wallet", "passwordA", user_keys_A),
    //                                "Reading master wallet failed.");

    // CHECK_AND_ASSERT_THROW_MES(read_master_wallet("masterB.wallet", "passwordB", user_keys_B),
    //                                "Reading master wallet failed.");

    make_jamtis_mock_keys(user_keys_A);
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
    send_sp_coinbase_amounts_to_user({1000}, destination_A, ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);

    /// variables of one tx
    SpTxSquashedV1 single_tx;
    std::pair<JamtisDestinationV1, rct::xmr_amount> outlays{destination_B, 10};
    const TxValidationContextMock tx_validation_context{ledger_context};

    /// Send 5 confirmed txs
    for (int i = 0; i < 5; i++)
    {
        // 1. make one tx
        construct_tx_for_mock_ledger_v1(legacy_user_keys_A, user_keys_A, input_selector_A, fee_calculator,
                                        fee_per_tx_weight, max_inputs, {{outlays.second, outlays.first, TxExtra{}}},
                                        legacy_ring_size, ref_set_decomp_n, ref_set_decomp_m, bin_config,
                                        ledger_context, single_tx);

        // 2. validate and submit to the mock ledger
        const TxValidationContextMock tx_validation_context{ledger_context};
        CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
                                   "transfer funds single mock unconfirmed sp only: validating tx failed.");
        CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
                                   "transfer funds single mock unconfirmed sp only: validating tx failed.");

        // 3. refresh user stores
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);

        // 4. add tx to tx_records
        fill_tx_store(single_tx, outlays, SpTxStatus::CONFIRMED, enote_store_in_out, tx_store_in_out);
    }

    // Send 5 unconfirmed_txs
    for (int i = 0; i < 5; i++)
    {
        // 1. make one tx
        construct_tx_for_mock_ledger_v1(legacy_user_keys_A, user_keys_A, input_selector_A, fee_calculator,
                                        fee_per_tx_weight, max_inputs, {{outlays.second, outlays.first, TxExtra{}}},
                                        legacy_ring_size, ref_set_decomp_n, ref_set_decomp_m, bin_config,
                                        ledger_context, single_tx);

        // 2. validate and submit to the mock ledger
        CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
                                   "transfer funds single mock unconfirmed sp only: validating tx failed.");
        CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
                                   "transfer funds single mock unconfirmed sp only: validating tx failed.");

        // 3. refresh user stores
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);

        // 4. add tx to tx_records
        fill_tx_store(single_tx, outlays, SpTxStatus::UNCONFIRMED, enote_store_in_out, tx_store_in_out);

    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_wallet, show_transfers)
{
    // Test to display info stored in the tx_store class

    // 1. generate enote_store and tx_store
    SpEnoteStore enote_store_A{0, 0, 0};
    SpTransactionHistory tx_store_A;

    // 2. make transfers to fill enote_store and tx_store
    make_transfers(enote_store_A, tx_store_A);

    // 3. example of block to show info from tx_store (using the enote store)
    tx_store_A.show_tx_hashes(3);
}

TEST(seraphis_wallet, read_write_history)
{
    // 1. generate enote_store and tx_store
    SpEnoteStore enote_store_A{0, 0, 0};
    SpTransactionHistory tx_store_A;

    // 2. make transfers to fill enote_store and tx_store
    make_transfers(enote_store_A, tx_store_A);

    // 3. save to file 
    if (!tx_store_A.write_sp_tx_history("wallet.history", "UserA"))
        std::cout << "Error writing tx_history" << std::endl;

    // 4. read from file
    SpTransactionHistory tx_store_recovered;
    SpTransactionStoreV1 tx_store_v1_recovered;
    if (!tx_store_A.read_sp_tx_history("wallet.history", "UserA", tx_store_v1_recovered))
        std::cout << "Error reading tx_history" << std::endl;

    tx_store_recovered.set_tx_store(tx_store_v1_recovered);

    // 5. Assert if Tx record is the same
    CHECK_AND_ASSERT_THROW_MES(tx_store_A.get_tx_store() == tx_store_recovered.get_tx_store(),"Tx stores are not the same.");

    // 6. show info from tx_store (using the enote store)
    // std::cout << "tx_hist A: " << std::endl;
    // tx_store_A.show_tx_hashes(3);
}



TEST(seraphis_wallet, read_write_serialization)
{
    // 1. generate enote_store and tx_store
    SpEnoteStore enote_store_A{0, 0, 0};
    SpTransactionHistory tx_store_A;

    // 2. make transfers to fill enote_store and tx_store
    make_transfers(enote_store_A, tx_store_A);

    // 3. Get serializable of structure
    ser_SpTransactionStoreV1 ser_tx_store;
    make_serializable_sp_transaction_store_v1(tx_store_A.get_tx_store(), ser_tx_store);

    // 4. Recover struct from serializable
    SpTransactionHistory tx_store_recovered;
    SpTransactionStoreV1 tx_store_v1_recovered;
    recover_sp_transaction_store_v1(ser_tx_store,tx_store_v1_recovered);

    tx_store_recovered.set_tx_store(tx_store_v1_recovered);

    // 5. Assert if Tx record is the same
    CHECK_AND_ASSERT_THROW_MES(tx_store_A.get_tx_store() == tx_store_recovered.get_tx_store(),"Tx stores are not the same.");
}