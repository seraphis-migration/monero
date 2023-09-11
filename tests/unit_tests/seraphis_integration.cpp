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
#include "seraphis_impl/jamtis_address_checksum.h"
#include "seraphis_impl/tx_fee_calculator_squashed_v1.h"
#include "seraphis_impl/tx_input_selection_output_context_v1.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <vector>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;

static std::string create_random_base32_string(size_t len)
{
    std::string s;
    s.resize(len);
    srand(crypto::rand<unsigned int>());
    for (int i = 0; i < s.size(); ++i)
        s[i] = base32::JAMTIS_ALPHABET[rand() % 32];
    return s;
}

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, txtype_squashed_v1)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)

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

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};


    /// prepare for membership proofs

    // a. add enough fake enotes to the ledger so we can reliably make legacy ring signatures
    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};

    send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
        fake_legacy_spendkey,
        fake_legacy_viewkey,
        ledger_context);

    // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
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

    // d. user enote stores (refresh index = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};

    // e. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};


    /// initial funding for user A: legacy 4000000 + seraphis 4000000
    send_legacy_coinbase_amounts_to_user(
            {1000000, 1000000, 1000000, 1000000},
            legacy_subaddr_spendkey_A,
            legacy_subaddr_viewkey_A,
            ledger_context
        );
    send_sp_coinbase_amounts_to_user({1000000, 1000000, 1000000, 1000000}, destination_A, ledger_context);


    /// send funds back and forth between users

    // A -> B: 6000000
    refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
        legacy_subaddress_map_A,
        legacy_user_keys_A.k_s,
        legacy_user_keys_A.k_v,
        refresh_config,
        ledger_context,
        enote_store_A);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 8000000);
    transfer_funds_single_mock_v1(legacy_user_keys_A,
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{6000000, destination_B, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // B -> A: 3000000
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 6000000);
    transfer_funds_single_mock_v1(legacy_mock_keys{},
        user_keys_B,
        input_selector_B,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3000000, destination_A, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    // A -> B: 4000000
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 4000000);
    transfer_funds_single_mock_v1(legacy_user_keys_A,
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{4000000, destination_B, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_integration, jamtis_checksum_create_verify)
{
    for (size_t datalen = 0; datalen < 250; ++datalen)
    {
        for (size_t i = 0; i < 10; ++i)
        {
            const std::string random_b32 = create_random_base32_string(datalen);

            char checksum[sp::jamtis::ADDRESS_CHECKSUM_SIZE_ENCODED];
            EXPECT_TRUE(sp::jamtis::create_address_checksum(random_b32.data(), random_b32.size(), checksum));

            EXPECT_TRUE(sp::jamtis::verify_address_checksum(random_b32.data(), random_b32.size(), checksum));
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
