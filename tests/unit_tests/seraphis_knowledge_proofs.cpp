// Copyright (c) 2022, The Monero Project
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
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
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

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <vector>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;
using namespace sp::knowledge_proofs;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void enote_knowledge_proofs_helper(const jamtis_mock_keys &keys,
    const SpEnoteCore &enote_core,
    const SpEnoteRecordV1 &enote_record,
    const EnoteOwnershipProofV1 &sender_enote_ownership_proof)
{
    // 1. SENDER: validate the sender's enote ownership proof
    ASSERT_TRUE(verify_enote_ownership_proof_v1(sender_enote_ownership_proof,
        enote_core.amount_commitment,
        enote_core.onetime_address));

    // 2. RECIPIENT: enote ownership proof
    EnoteOwnershipProofV1 enote_ownership_proof_recipient;
    make_enote_ownership_proof_v1_receiver(enote_record, keys.K_1_base, keys.k_vb, enote_ownership_proof_recipient);

    ASSERT_TRUE(verify_enote_ownership_proof_v1(enote_ownership_proof_recipient,
        enote_core.amount_commitment,
        enote_core.onetime_address));

    // 3. SENDER/RECIPIENT: enote amount proof
    EnoteAmountProofV1 enote_amount_proof;
    make_enote_amount_proof_v1(enote_record.amount,
        enote_record.amount_blinding_factor,
        amount_commitment_ref(enote_record.enote),
        enote_amount_proof);

    ASSERT_TRUE(verify_enote_amount_proof_v1(enote_amount_proof, enote_core.amount_commitment));

    // 4. RECIPIENT: enote key image proof
    EnoteKeyImageProofV1 enote_key_image_proof;
    make_enote_key_image_proof_v1(enote_record, keys.k_m, keys.k_vb, enote_key_image_proof);

    ASSERT_TRUE(verify_enote_key_image_proof_v1(enote_key_image_proof,
        enote_core.onetime_address,
        enote_record.key_image));

    // 5. RECIPIENT: enote unspent proof for random key image
    const crypto::key_image random_key_image{rct::rct2ki(rct::pkGen())};

    EnoteUnspentProofV1 enote_unspent_proof_valid;
    make_enote_unspent_proof_v1(enote_record, keys.k_m, keys.k_vb, random_key_image, enote_unspent_proof_valid);

    ASSERT_TRUE(verify_enote_unspent_proof_v1(enote_unspent_proof_valid,
        enote_core.onetime_address,
        random_key_image));

    // 6. RECIPIENT: enote unspent proof for the enote's key image (should fail)
    EnoteUnspentProofV1 enote_unspent_proof_invalid;
    make_enote_unspent_proof_v1(enote_record,
        keys.k_m,
        keys.k_vb,
        enote_record.key_image,
        enote_unspent_proof_invalid);

    ASSERT_FALSE(verify_enote_unspent_proof_v1(enote_unspent_proof_invalid,
        enote_core.onetime_address,
        enote_record.key_image));

    // 7. SENDER: tx funded proof
    TxFundedProofV1 tx_funded_proof;
    make_tx_funded_proof_v1(rct::zero(), enote_record, keys.k_m, keys.k_vb, tx_funded_proof);  //with mock message

    ASSERT_TRUE(verify_tx_funded_proof_v1(tx_funded_proof, rct::zero(), enote_record.key_image));

    // 8. SENDER: enote sent proof
    EnoteSentProofV1 enote_sent_proof;
    make_enote_sent_proof_v1(sender_enote_ownership_proof, enote_amount_proof, enote_sent_proof);

    ASSERT_TRUE(verify_enote_sent_proof_v1(enote_sent_proof, enote_core.amount_commitment, enote_core.onetime_address));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void reserve_proof_helper(const TxValidationContext &validation_context,
    const jamtis_mock_keys &prover_keys,
    const SpEnoteStore &enote_store,
    const boost::multiprecision::uint128_t expected_reserve_amount)
{
    // 1. get all of the user's enote records
    std::vector<SpContextualEnoteRecordV1> all_enote_records;
    all_enote_records.reserve(enote_store.sp_records().size());

    for (const auto &enote_record : enote_store.sp_records())
        all_enote_records.emplace_back(enote_record.second);

    // 2. make a reserve proof for the user's full balance
    ReserveProofV1 reserve_proof;
    make_reserve_proof_v1(rct::zero(),
        all_enote_records,
        prover_keys.K_1_base,
        prover_keys.k_m,
        prover_keys.k_vb,
        reserve_proof);

    // 3. verify the reserve proof against the validation context
    ASSERT_TRUE(verify_reserve_proof_v1(reserve_proof, rct::zero(), validation_context));

    // 4. check the reserve amount
    ASSERT_TRUE(total_reserve_amount(reserve_proof) == expected_reserve_amount);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, address_ownership_proof_K_s)
{
    // 1. prepare keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // 2. address ownership proof on K_s = k_vb X + k_m U
    AddressOwnershipProofV1 proof;
    make_address_ownership_proof_v1(rct::zero(), keys.k_m, keys.k_vb, proof);  //with mock message

    // 3. validate the address ownership proof
    ASSERT_TRUE(verify_address_ownership_proof_v1(proof, rct::zero(), keys.K_1_base));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, address_ownership_and_index_proof_K_1)
{
    // 1. prepare keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // 2. make random address index
    const address_index_t j{gen_address_index()};

    // 3. make jamtis destination
    JamtisDestinationV1 destination;
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j, destination);

    // 4. address ownership proof on K_1
    AddressOwnershipProofV1 address_ownership_proof;
    make_address_ownership_proof_v1(rct::zero(), keys.k_m, keys.k_vb, j, address_ownership_proof);  //with mock message

    // 5. validate the address ownership proof
    ASSERT_TRUE(verify_address_ownership_proof_v1(address_ownership_proof, rct::zero(), destination.addr_K1));

    // 6. address index proof on K_1
    AddressIndexProofV1 address_index_proof;
    make_address_index_proof_v1(keys.K_1_base, j, keys.s_ga, address_index_proof);

    // 7. validate the address index proof
    ASSERT_TRUE(verify_address_index_proof_v1(address_index_proof, destination.addr_K1));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, enote_proofs_selfsend_normal)
{
    /// send selfsend enote to user

    // 1. user keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // 2. user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // 3. make a self-spend enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};

    const jamtis::JamtisSelfSendType self_send_type{JamtisSelfSendType::SELF_SPEND};
    JamtisPaymentProposalSelfSendV1 payment_proposal_selfspend{user_address,
        amount,
        self_send_type,
        enote_privkey};
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal_selfspend, keys.k_vb, rct::zero(), output_proposal);
    SpEnoteV1 enote;
    get_enote_v1(output_proposal, enote);

    // 4. user recovers an enote record from the enote
    SpEnoteRecordV1 enote_record;
    ASSERT_TRUE(try_get_enote_record_v1(enote,
        output_proposal.enote_ephemeral_pubkey,
        rct::zero(),
        keys.K_1_base,
        keys.k_vb,
        enote_record));

    // 5. enote ownership proof: sender-selfsend
    EnoteOwnershipProofV1 enote_ownership_proof_sender_selfsend;
    make_enote_ownership_proof_v1_sender_selfsend(output_proposal.enote_ephemeral_pubkey,
        user_address.addr_K1,
        rct::zero(),
        keys.k_vb,
        self_send_type,
        enote.core.amount_commitment,
        enote.core.onetime_address,
        enote_ownership_proof_sender_selfsend);

    // 6. complete enote knowledge proof checks
    enote_knowledge_proofs_helper(keys, enote.core, enote_record, enote_ownership_proof_sender_selfsend);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, enote_proofs_selfsend_special)
{
    /// send special selfsend enote to user
    /// - for 2-out case where the selfsend enote shares its ephemeral pubkey with the other enote

    // 1. user keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // 2. user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // 3. make a special change enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    const crypto::x25519_pubkey first_enote_ephemeral_pubkey{crypto::x25519_pubkey_gen()};

    JamtisPaymentProposalSelfSendV1 payment_proposal_special_change;
    make_additional_output_selfsend_v1(OutputProposalSetExtraTypeV1::SPECIAL_CHANGE,
        first_enote_ephemeral_pubkey,
        user_address,
        user_address,
        keys.k_vb,
        amount,
        payment_proposal_special_change);
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal_special_change, keys.k_vb, rct::zero(), output_proposal);
    SpEnoteV1 enote;
    get_enote_v1(output_proposal, enote);

    // 4. user recovers an enote record from the enote
    SpEnoteRecordV1 enote_record;
    ASSERT_TRUE(try_get_enote_record_v1(enote,
        output_proposal.enote_ephemeral_pubkey,
        rct::zero(),
        keys.K_1_base,
        keys.k_vb,
        enote_record));

    // 5. enote ownership proof: sender-selfsend
    EnoteOwnershipProofV1 enote_ownership_proof_sender_selfsend;
    make_enote_ownership_proof_v1_sender_selfsend(output_proposal.enote_ephemeral_pubkey,
        user_address.addr_K1,
        rct::zero(),
        keys.k_vb,
        payment_proposal_special_change.type,
        enote.core.amount_commitment,
        enote.core.onetime_address,
        enote_ownership_proof_sender_selfsend);

    // 6. complete enote knowledge proof checks
    enote_knowledge_proofs_helper(keys, enote.core, enote_record, enote_ownership_proof_sender_selfsend);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, enote_proofs_normal_enote)
{
    /// send normal enote to user

    // 1. user keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // 2. user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // 3. make a plain enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};

    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal, rct::zero(), output_proposal);
    SpEnoteV1 enote;
    get_enote_v1(output_proposal, enote);

    // 4. user recovers an enote record from the enote
    SpEnoteRecordV1 enote_record;
    ASSERT_TRUE(try_get_enote_record_v1(enote,
        output_proposal.enote_ephemeral_pubkey,
        rct::zero(),
        keys.K_1_base,
        keys.k_vb,
        enote_record));

    // 5. enote ownership proof: sender-plain
    EnoteOwnershipProofV1 enote_ownership_proof_sender_plain;
    make_enote_ownership_proof_v1_sender_plain(payment_proposal.enote_ephemeral_privkey,
        user_address,
        rct::zero(),
        enote.core.amount_commitment,
        enote.core.onetime_address,
        enote_ownership_proof_sender_plain);

    // 6. complete enote knowledge proof checks
    enote_knowledge_proofs_helper(keys, enote.core, enote_record, enote_ownership_proof_sender_plain);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, reserve_proof)
{
    //// send funds back and forth between two users, then each user makes a reserve proof

    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //trivial calculator for easy fee (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};


    /// prepare for membership proofs
    // a. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
            static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)),
            0
        );
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


    /// make two users

    // a. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // b. seraphis user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // c. user enote stores (refresh index = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};

    // d. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};


    /// initial funding for user A: seraphis 40
    send_sp_coinbase_amounts_to_user({10, 10, 10, 10}, destination_A, ledger_context);


    /// send funds back and forth between users

    // A -> B: 30 (fee: 1)
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    transfer_funds_single_mock_v1(legacy_mock_keys{},
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{30, destination_B, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // B -> A: 20 (fee: 1)
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    transfer_funds_single_mock_v1(legacy_mock_keys{},
        user_keys_B,
        input_selector_B,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{20, destination_A, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // refresh user stores
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);

    // make and validate their reserve proofs
    const TxValidationContextMock tx_validation_context{ledger_context};

    reserve_proof_helper(tx_validation_context, user_keys_A, enote_store_A, 29);
    reserve_proof_helper(tx_validation_context, user_keys_B, enote_store_B, 9);
}
//-------------------------------------------------------------------------------------------------------------------
/*
TEST(seraphis_knowledge_proofs, sp_all_knowledge_proofs)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)

    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    // const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scan_machine::ScanConfig refresh_config{
            .reorg_avoidance_depth = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};

    // add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
            static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)),
            0
        );
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


    /// make two users

    // a. user keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_legacy_mock_keys(legacy_user_keys_A);
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

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

    // c. seraphis user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // d. user enote stores (refresh height = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};

    // e. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};


    // tx0: coinbase creation to A : 5 enotes of 10 pXMR each
    // tx1: A sends 20 pXMR. 19 pXMR to B and 1 pXMR for fees.
    // tx2: B sends 10 pXMR. 9 pXMR to A and 1 pXMR for fees.

    // In the end:
    // A has 39 pXMR
    // B has 9 pXMR

    send_sp_coinbase_amounts_to_user({10,10,10,10,10}, destination_A, ledger_context);

    refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
        legacy_subaddress_map_A,
        legacy_user_keys_A.k_s,
        legacy_user_keys_A.k_v,
        refresh_config,
        ledger_context,
        enote_store_A);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 30);
    

    std::cout << "A Balance before tx 1: "<< get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

    std::cout << "B Balance before tx 1: "<< get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

    // make tx1
    SpTxSquashedV1 tx1;
    rct::key input_context_tx1;
    rct::xmr_amount amount_to_send = 20;
    construct_tx_for_mock_ledger_v1(legacy_mock_keys{},
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount_to_send, destination_B, TxExtra{}}},
        2,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        tx1);

    make_standard_input_context_v1(tx1.legacy_input_images,tx1.sp_input_images,input_context_tx1);

    // validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{ledger_context};

    CHECK_AND_ASSERT_THROW_MES(validate_tx(tx1, tx_validation_context),
        "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(tx1, ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    
    std::cout << "A Balance after tx 1: "<< get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;
    std::cout << "B Balance after tx 1: "<< get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

    // make tx2
    SpTxSquashedV1 tx2;
    rct::key input_context_tx2;
    rct::xmr_amount amount_to_send2 = 10;
    construct_tx_for_mock_ledger_v1(legacy_mock_keys{},
        user_keys_B,
        input_selector_B,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount_to_send2, destination_A, TxExtra{}}},
        2,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        tx2);

    make_standard_input_context_v1(tx2.legacy_input_images,tx2.sp_input_images,input_context_tx2);

    CHECK_AND_ASSERT_THROW_MES(validate_tx(tx2, tx_validation_context),
        "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(tx2, ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    
    std::cout << "A Balance after tx 2: "<< get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;
    std::cout << "B Balance after tx 2: "<< get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;


    // Reserve proofs:

    // Get all enotes that are owned by A
    EnoteScanningChunkLedgerV1 chunk_A;
    ledger_context.get_onchain_chunk_sp(0, 1000, user_keys_A.xk_fr, chunk_A);

    rct::xmr_amount total_unspent{0};

    SpEnoteRecordV1 enote_record;
    SpEnoteVariant enote;
    rct::key rp_q;
    crypto::secret_key rp_x_new, rp_y_new, rp_z_new;
    uint64_t rp_ledger_index;
    JamtisSelfSendType enote_selfsend_type;
    rct::key K_1_recovered;

    EnoteOwnershipProofV1 rp_ownership_proof;
    EnoteAmountProofV1 rp_amount_proof;
    EnoteKeyImageProofV1 rp_ki_proof;

    std::vector<EnoteOwnershipProofV1> vec_enote_ownership_proof;
    std::vector<EnoteAmountProofV1> vec_amount_proof;
    std::vector<EnoteKeyImageProofV1> vec_ki_proof;
    std::vector<SpEnoteVariant> vec_unspent_enotes;
    std::vector<crypto::key_image> vec_ki;
    std::vector<uint64_t> vec_enote_ledger_index;

    // For verification
    std::vector<rct::key> squashed_enotes;

    // Filter unspent enotes from A
    // Loop over each chunk of ContextualBasicRecordVariant
    for (auto basic_record_chunk : chunk_A.basic_records_per_tx)
    {
        // Loop over ContextualBasicRecordVariant in each tx
        for (auto basic_record : basic_record_chunk.second) 
        {
            // basic_record contains all the enotes owned by A
            if (try_get_enote_record_v1(basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record.enote,
                basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record.enote_ephemeral_pubkey,
                basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record.input_context,
                user_keys_A.K_1_base,
                user_keys_A.k_vb,
                enote_record))
            {
                if (ledger_context.seraphis_key_image_exists_onchain(enote_record.key_image))
                {
                    // Key image of enote record is on-chain therefore enote was spent
                }
                else 
                {
                    // Key image of enote record is not on-chain therefore the enote was not spent yet
                    total_unspent += enote_record.amount;

                    // Get all unspent enotes
                    enote = enote_record.enote;
                    vec_unspent_enotes.push_back(enote);
                    
                    // Make enote_onwnership proof
                    // Filter plain and self-send enotes
                    if (enote_record.type == JamtisEnoteType::PLAIN)
                    {
                        make_jamtis_sender_receiver_secret_plain(user_keys_A.xk_fr, enote_record.enote_ephemeral_pubkey, enote_record.enote_ephemeral_pubkey,
                        enote_record.input_context, rp_q);
                        make_enote_ownership_proof_v1(rp_q, destination_A.addr_K1,
                        onetime_address_ref(enote),rp_ownership_proof);
                    }
                    else 
                    {
                        make_jamtis_address_spend_key(user_keys_A.K_1_base, user_keys_A.s_ga, enote_record.address_index, K_1_recovered);
                        EXPECT_TRUE(try_get_jamtis_self_send_type(enote_record.type,enote_selfsend_type)); 
                        make_jamtis_sender_receiver_secret_selfsend(user_keys_A.k_vb, 
                            enote_record.enote_ephemeral_pubkey,
                            enote_record.input_context,
                            enote_selfsend_type,
                            rp_q);
                        make_enote_ownership_proof_v1(rp_q, K_1_recovered,
                        onetime_address_ref(enote),rp_ownership_proof);
                    }
                    
                    vec_enote_ownership_proof.push_back(rp_ownership_proof);

                    // Make enote_amount proof
                    make_enote_amount_proof_v1(enote_record.amount, enote_record.amount_blinding_factor, amount_commitment_ref(enote),rp_amount_proof);
                    vec_amount_proof.push_back(rp_amount_proof);

                    // Make enote_key_image proof
                    rp_x_new = enote_record.enote_view_extension_g;
                    sc_add(to_bytes(rp_y_new),to_bytes(enote_record.enote_view_extension_x),to_bytes(user_keys_A.k_vb));
                    sc_add(to_bytes(rp_z_new),to_bytes(enote_record.enote_view_extension_u),to_bytes(user_keys_A.k_m));
                    make_enote_key_image_proof_v1(onetime_address_ref(enote),rp_x_new,rp_y_new,rp_z_new,rp_ki_proof);
                    vec_ki_proof.push_back(rp_ki_proof);
                    vec_ki.emplace_back();
                    make_seraphis_key_image(rp_y_new,rp_z_new,vec_ki.back());

                    rp_ledger_index = basic_record.unwrap<SpContextualBasicEnoteRecordV1>().origin_context.enote_ledger_index;
                    vec_enote_ledger_index.push_back(rp_ledger_index);
                }
            }
        }
    }
    
    // Make reserve_proofs with unspent enotes
    ReserveProofsV1 reserve_proof;
    make_reserve_proof_v1(vec_enote_ownership_proof,
        vec_amount_proof,
        vec_ki_proof,
        vec_unspent_enotes,
        vec_ki,
        vec_enote_ledger_index,
        reserve_proof);

    // Verify reserve_proofs
    // Verify that enotes are in the ledger:
    size_t number_proofs{vec_enote_ownership_proof.size()};
    ledger_context.get_reference_set_proof_elements_v2(vec_enote_ledger_index, squashed_enotes);
    rct::key squashed_test;
    for (size_t i=0;i<number_proofs;i++)
    {
        make_seraphis_squashed_enote_Q(onetime_address_ref(reserve_proof.vec_enotes[i]),
            amount_commitment_ref(reserve_proof.vec_enotes[i]),
            squashed_test);
        CHECK_AND_ASSERT_THROW_MES(squashed_test == squashed_enotes[i],
            "verify reserve proofs: Squashed enote was not found on chain.");
    }
    //Verify that key images are not on chain:
    for (size_t i=0;i<number_proofs;i++)
    {
        CHECK_AND_ASSERT_THROW_MES(!ledger_context.seraphis_key_image_exists_onchain(reserve_proof.vec_ki[i]),
            "verify reserve proofs: Key image was found on chain. Enote has been spent.");
    }

    rct::xmr_amount total_reserves{0};
    if (verify_reserve_proof_v1(reserve_proof))
    {
        for (size_t i=0;i<number_proofs;i++)
        {
            total_reserves += reserve_proof.vec_amount_proof[i].amount;
        }
        std::cout << "Reserve proofs are correct. Prover has " << total_reserves  << " pXMR available to spend." << std::endl;
    }

    std::cout << "Total unspent by A:" << total_unspent << std::endl;


    // All other proofs
    
    // A simple scanning is done to find if the enote being proved is part of the tx
    
    // The idea is to go through all the generated enotes (outputs) in tx1
    // and get the enote record of the corresponding ephemeral public key at index 0.

    //Provide index of jamtis_proposal payment which the proof will be based on
    SpEnoteRecordV1 enote_output_record_tx1;
    for (SpEnoteV1 enote : tx1.outputs)
    {
        if (try_get_enote_record_v1(enote,
        tx1.tx_supplement.output_enote_ephemeral_pubkeys[0],
        input_context_tx1,
        user_keys_B.K_1_base,
        user_keys_B.k_vb,
        enote_output_record_tx1))
        {

            //EnoteOwnershipProof            
            //goal 1: B wants to prove that (his) address K_1 owns a certain enote
            //goal 2: A wants to prove that address K_1 (from B) owns a certain enote
            //derived key: xK_d = xr * xK_2 = xkfr * xK_e
            //If B is generating the proof, then he needs to use his view_key
            //If A is generating the proof, then he needs to know the private_ephemeral_key of the enote 
            std::cout<< "Enote Ownership proof from B: " << std::endl;
            crypto::x25519_pubkey xK_d;
            crypto::x25519_scmul_key(user_keys_B.xk_fr, enote_output_record_tx1.enote_ephemeral_pubkey, xK_d);
            rct::key q;
            make_jamtis_sender_receiver_secret_plain(xK_d, enote_output_record_tx1.enote_ephemeral_pubkey, input_context_tx1, q);
            EnoteOwnershipProofV1 ownership_proof;
            make_enote_ownership_proof_v1(q, destination_B.addr_K1, enote.core.onetime_address,ownership_proof);
            EXPECT_TRUE(verify_enote_ownership_proof_v1(ownership_proof,enote));

            //EnoteAmountProof            
            //goal 1: B wants to prove that he knows the amount in one of his enotes.
            //goal 2: A wants to prove that he knows the amount in one of B's enotes.
            std::cout<< "Enote Amout proof from B: " << std::endl;
            EnoteAmountProofV1 amount_proof;
            make_enote_amount_proof_v1(enote_output_record_tx1.amount, enote_output_record_tx1.amount_blinding_factor, enote.core.amount_commitment,amount_proof);
            EXPECT_TRUE(verify_enote_amount_proof_v1(amount_proof, enote.core.amount_commitment));

            //EnoteSentProof 
            //goal 1: A or B wants to prove that a certain enote was sent to address K_1,K_2,K_3 that he knows
            //Similar to InProofs and OutProofs
            std::cout << "Enote Sent proof: " << std::endl;
            EnoteSentProofV1 enote_sent_proof;
            make_enote_sent_proof_v1(ownership_proof, amount_proof,enote_sent_proof);
            EXPECT_TRUE(verify_enote_sent_proof_v1(enote_sent_proof, enote));

            //AddressOwnershipProof
            //Make proof for K_1 and K_1_Base
            std::cout<< "Address Ownership proof using K_1_Base (K_s): " << std::endl;
            // rct::key message_address;
            // message_address = rct::skGen();
            AddressOwnershipProofV1 address_ownership;
            make_address_ownership_proof_v1(user_keys_B.K_1_base, rct::rct2sk(rct::zero()), user_keys_B.k_vb, user_keys_B.k_m,address_ownership);
            EXPECT_TRUE(verify_address_ownership_proof_v1(address_ownership,user_keys_B.K_1_base));

            //AddressIndexProof
            std::cout<< "Address Index proof: " << std::endl;
            AddressIndexProofV1 address_index;
            make_address_index_proof_v1(user_keys_B.K_1_base, enote_output_record_tx1.address_index, user_keys_B.s_ga,address_index);
            EXPECT_TRUE(verify_address_index_proof_v1(address_index));

            //Enote Key Image proof
            std::cout<< "Enote Key Image proof: " << std::endl;
            crypto::secret_key x_new, y_new, z_new;
            x_new = enote_output_record_tx1.enote_view_extension_g;
            sc_add(to_bytes(y_new),to_bytes(enote_output_record_tx1.enote_view_extension_x),to_bytes(user_keys_B.k_vb));
            sc_add(to_bytes(z_new),to_bytes(enote_output_record_tx1.enote_view_extension_u),to_bytes(user_keys_B.k_m));
            EnoteKeyImageProofV1 ki_proof;
            make_enote_key_image_proof_v1(enote.core.onetime_address,x_new,y_new,z_new,ki_proof);
            EXPECT_TRUE(verify_enote_key_image_proof_v1(ki_proof, enote.core.onetime_address,enote_output_record_tx1.key_image));

            //TxFundedProof
            // B wants to prove that he funded tx2 by proving knowledge
            // of the enote key image of one of his outputs from tx1
            // First let`s get which enote was used to fund tx2
            for (SpEnoteImageV1 ki_in_tx2 : tx2.sp_input_images)
            {
                if (ki_in_tx2.core.key_image == enote_output_record_tx1.key_image)
                {
                    std::cout<< "Tx Funded proof tests: " << std::endl;
                    // enote_output_record_tx1 contains the information of the enote spent in tx2
                    TxFundedProofV1 funded_tx;
                    make_tx_funded_proof_v1(enote_output_record_tx1, enote.core.onetime_address, user_keys_B.k_vb,user_keys_B.k_m,funded_tx);
                    EXPECT_TRUE(verify_tx_funded_proof_v1(funded_tx,ki_in_tx2.core.key_image));
                    
                    // More EnoteUnspentProof tests should be implemented
                    rct::key msg_up{rct::skGen()};
                    EnoteUnspentProofV1 unspent_proof;
                    make_enote_unspent_proof_v1(msg_up, enote_output_record_tx1, user_keys_B.k_vb, user_keys_B.k_m, enote.core.onetime_address, enote_output_record_tx1.key_image, unspent_proof);
                    EXPECT_FALSE(verify_enote_unspent_proof_v1(unspent_proof, enote, enote_output_record_tx1.key_image));
                }
            }
        }
    }
}
*/
//-------------------------------------------------------------------------------------------------------------------