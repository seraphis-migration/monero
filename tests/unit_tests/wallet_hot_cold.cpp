// Copyright (c) 2025, The Monero Project
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

#include "gtest/gtest.h"

#include "carrot_impl/format_utils.h"
#include "carrot_impl/key_image_device_precomputed.h"
#include "carrot_impl/spend_device_ram_borrowed.h"
#include "carrot_impl/tx_builder_inputs.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_mock_helpers.h"
#include "fcmp_pp/prove.h"
#include "output_opening_types.h"
#include "tx_construction_helpers.h"
#include "wallet/hot_cold_serialization.h"
#include "wallet/tx_builder.h"
#include "wallet/scanning_tools.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "unit_tests.wallet_hot_cold"

namespace
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static std::vector<wallet2_basic::transfer_details> hot_scan_into_transfer_details(
    const carrot::mock::mock_carrot_and_legacy_keys &bob,
    const cryptonote::transaction &tx,
    const std::uint64_t block_index = 0,
    const std::uint64_t global_output_index = 0)
{
    const auto enote_scan_infos = tools::wallet::view_incoming_scan_transaction(tx,
        bob.k_view_incoming_dev,
        *bob.addr_dev,
        bob.subaddress_map);
    std::vector<wallet2_basic::transfer_details> res;
    for (std::size_t local_output_index = 0; local_output_index < enote_scan_infos.size(); ++local_output_index)
    {
        const auto &enote_scan_info = enote_scan_infos.at(local_output_index);
        if (!enote_scan_info || !enote_scan_info->subaddr_index)
            continue;

        wallet2_basic::transfer_details &td = res.emplace_back();
        td.m_block_height = block_index;
        td.m_tx = tx;
        td.m_txid = crypto::rand<crypto::hash>(),
        td.m_internal_output_index = local_output_index;
        td.m_global_output_index = global_output_index;
        td.m_spent = false;
        td.m_frozen = false;
        td.m_spent_height = 0;
        td.m_key_image = crypto::key_image{};
        td.m_mask = enote_scan_info->amount_blinding_factor;
        td.m_amount = enote_scan_info->amount;
        td.m_rct = tx.version == 2;
        td.m_key_image_known = false;
        td.m_key_image_request = true;
        td.m_pk_index = enote_scan_info->main_tx_pubkey_index;
        td.m_subaddr_index.major = enote_scan_info->subaddr_index->index.major;
        td.m_subaddr_index.minor = enote_scan_info->subaddr_index->index.minor;
        td.m_key_image_partial = false;
        td.m_multisig_k.clear();
        td.m_multisig_info.clear();
        td.m_uses.clear();
    }

    return res;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
enum class AddressType
{
    MAIN = 0,
    INTEGRATED = 1,
    SUBADDRESS = 2,
    MIN = MAIN,
    MAX = SUBADDRESS
};
static inline AddressType operator++(AddressType &a)
{
    a = static_cast<AddressType>((static_cast<std::underlying_type_t<AddressType>>(a) + 1));
    return a;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static carrot::CarrotDestinationV1 gen_destination_to(
    const carrot::mock::mock_carrot_and_legacy_keys &bob,
    const AddressType addr_type,
    const carrot::AddressDeriveType addr_derive_type = carrot::AddressDeriveType::Auto)
{
    const carrot::subaddress_index subaddr_index = (addr_type == AddressType::SUBADDRESS)
        ? carrot::mock::gen_subaddress_index() : carrot::subaddress_index{0, 0};

    switch (addr_type)
    {
    case AddressType::MAIN:
        return bob.cryptonote_address({}, addr_derive_type);
    case AddressType::INTEGRATED:
        return bob.cryptonote_address(carrot::gen_payment_id(), addr_derive_type);
    case AddressType::SUBADDRESS:
        return bob.subaddress({subaddr_index, addr_derive_type});
    default:
        ASSERT_MES_AND_THROW("unrecognized address type");
    }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static wallet2_basic::transfer_details gen_transfer_details_to(
    const carrot::mock::mock_carrot_and_legacy_keys &bob,
    const AddressType addr_type,
    const rct::xmr_amount amount,
    const uint8_t hf_version,
    const bool is_coinbase,
    const bool is_unmixable_sweep = false,
    const carrot::AddressDeriveType addr_derive_type = carrot::AddressDeriveType::Auto)
{
    cryptonote::transaction tx;
    const carrot::CarrotDestinationV1 bob_destination = gen_destination_to(bob, addr_type, addr_derive_type);
    if (is_coinbase)
    {
        const cryptonote::account_public_address addr
            = carrot::mock::convert_destination_v1(bob.cryptonote_address({}, addr_derive_type), 0).addr;
        tx = mock::construct_miner_tx_fake_reward_1out(carrot::mock::gen_block_index(),
            amount, addr, hf_version);
    }
    if (hf_version < HF_VERSION_FCMP_PLUS_PLUS)
    {
        std::vector<cryptonote::tx_destination_entry> dst{
            carrot::mock::convert_destination_v1(bob_destination, amount)};
        tx = mock::construct_pre_carrot_tx_with_fake_inputs(dst, 2304, hf_version, is_unmixable_sweep);
    }
    else if (hf_version <= HF_VERSION_FCMP_PLUS_PLUS + 1)
    {
        cryptonote::account_base aether;
        aether.generate();
        std::vector<carrot::CarrotPaymentProposalV1> normal_payment_proposals{carrot::CarrotPaymentProposalV1{
            .destination = bob_destination,
            .amount = amount,
            .randomness = carrot::gen_janus_anchor()
        }};
        tx = mock::construct_carrot_pruned_transaction_fake_inputs(normal_payment_proposals, {}, aether.get_keys());
    }
    else
    {
        ASSERT_MES_AND_THROW("unrecognized HF version: " << hf_version);
    }

    const wallet2_basic::transfer_container scanned_transfers = hot_scan_into_transfer_details(bob, tx);
    CHECK_AND_ASSERT_THROW_MES(scanned_transfers.size() == 1, "unexpected scanned transfers size");
    return scanned_transfers.at(0);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static carrot::mock::mock_carrot_and_legacy_keys make_hot_keys(const carrot::mock::mock_carrot_and_legacy_keys &cold)
{
    carrot::mock::mock_carrot_and_legacy_keys hot = cold;
    hot.legacy_acb.forget_spend_key();
    hot.k_prove_spend = crypto::null_skey;
    return hot;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
//                                  hf ver, miner, unmix sweep
static const std::vector<std::tuple<uint8_t, bool, bool>> enote_types_to_test{
    {1, true, false},
    {1, false, false},
    {1, false, true},
    {HF_VERSION_DYNAMIC_FEE, true, false},
    {HF_VERSION_DYNAMIC_FEE, false, false},
    {HF_VERSION_SMALLER_BP, false, false},
    {HF_VERSION_VIEW_TAGS, true, false},
    {HF_VERSION_VIEW_TAGS, false, true},
    {HF_VERSION_VIEW_TAGS, false, false},
    {HF_VERSION_CARROT, true, false},
    {HF_VERSION_CARROT, false, false},
};
} //anonymous namespace
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(wallet_hot_cold, export_import_simple)
{
    // Test that hot wallet can scan enotes, export to cold wallet, and generate key images:
    //   a. pre-ringct coinbase
    //   b. pre-ringct
    //   c. ringct coinbase
    //   d. ringct long-amount
    //   e. ringct short-amount
    //   f. view-tagged ringct coinbase
    //   g. view-tagged pre-ringct (only possible in unmixable sweep txs)
    //   h. view-tagged ringct
    //   i. carrot v1 coinbase
    //   j. carrot v1 normal
    //   k. carrot v1 special
    //   l. carrot v1 internal (@TODO)
    //   m. carrot v1 normal subaddress
    //   n. carrot v1 normal integrated
    //   o. carrot v1 special subaddress
    //   p. carrot v1 internal subaddress (@TODO)
    //
    // All enotes are addressed to the main address in 2-out non-coinbase txs or 1-out coinbase txs.
    // We also don't test reorgs here.

    carrot::mock::mock_carrot_and_legacy_keys bob_cold;
    bob_cold.generate();
    const cryptonote::account_public_address bob_addr = bob_cold.legacy_acb.get_keys().m_account_address;

    carrot::mock::mock_carrot_and_legacy_keys bob_hot = make_hot_keys(bob_cold);

    const auto verify_cold_sal = [&bob_cold](const wallet2_basic::transfer_details &td)
        -> std::optional<crypto::key_image>
    {
        const crypto::hash signable_tx_hash = crypto::rand<crypto::hash>();

        const carrot::OutputOpeningHintVariant opening_hint
            = tools::wallet::make_sal_opening_hint_from_transfer_details(td);

        const FcmpRerandomizedOutputCompressed rerandomized_output = fcmp_pp::rerandomize_output(
            onetime_address_ref(opening_hint),
            rct::rct2pt(amount_commitment_ref(opening_hint)),
            carrot::use_biased_hash_to_point(opening_hint));

        fcmp_pp::FcmpPpSalProof sal_proof;
        crypto::key_image spent_key_image;
        try
        {
            carrot::make_sal_proof_any_to_legacy_v1(signable_tx_hash,
                rerandomized_output,
                opening_hint,
                bob_cold.legacy_acb.get_keys().m_spend_secret_key,
                bob_cold.cn_addr_dev,
                sal_proof,
                spent_key_image);
        }
        catch (...)
        {
            return std::nullopt;
        }

        if (!fcmp_pp::verify_sal(signable_tx_hash,
                rerandomized_output.input,
                spent_key_image,
                sal_proof))
            return std::nullopt;

        return spent_key_image;
    };

    // a. scan pre-ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 300;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/1,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // b. pre-ringct tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 400;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            /*hf_version=*/1);
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // c. ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 500;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_DYNAMIC_FEE,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // d. ringct long-amount tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 600;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_DYNAMIC_FEE);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // e. ringct short-amount tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 700;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_SMALLER_BP);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // f. view-tagged ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 800;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_VIEW_TAGS,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // g. view-tagged pre-ringct (only possible in unmixable sweep txs) tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 900;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_VIEW_TAGS,
            /*sweep_unmixable_override=*/true);
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // h. view-tagged ringct tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_VIEW_TAGS,
            /*sweep_unmixable_override=*/false);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // i. carrot v1 coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 1100;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_CARROT,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // j. carrot v1 normal tx
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{carrot::mock::convert_normal_payment_proposal_v1(dests.front()), /*main*/}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // k. carrot v1 special tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            /*normal_payment_proposals=*/{},
            {{carrot::mock::convert_selfsend_payment_proposal_v1(dests.front()), {/*main*/}}},
            bob_hot.legacy_acb.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(2, scanned_enotes.size()); // b/c transfer always adds a self-send
        const wallet2_basic::transfer_details &dest_enote = (scanned_enotes.front().amount() == amount)
            ? scanned_enotes.front() : scanned_enotes.back();
        EXPECT_TRUE(verify_cold_sal(dest_enote));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(dest_enote, bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // l. carrot v1 internal (@TODO)

    // m. carrot v1 normal tx subaddress
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::subaddress_index_extended bob_subaddr_index{
            .index = carrot::mock::gen_subaddress_index(),
            .derive_type = carrot::AddressDeriveType::PreCarrot};
        const carrot::CarrotDestinationV1 bob_subaddr = bob_hot.subaddress(bob_subaddr_index);
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{bob_subaddr, amount, carrot::gen_janus_anchor()}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // n. carrot v1 normal integrated
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::CarrotDestinationV1 bob_integrated_addr = bob_hot.cryptonote_address(carrot::gen_payment_id(),
            carrot::AddressDeriveType::PreCarrot);
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{bob_integrated_addr, amount, carrot::gen_janus_anchor()}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        EXPECT_TRUE(verify_cold_sal(scanned_enotes.front()));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // o. carrot v1 special subaddress
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::subaddress_index_extended bob_subaddr_index{
            .index = carrot::mock::gen_subaddress_index(),
            .derive_type = carrot::AddressDeriveType::PreCarrot};
        const carrot::CarrotDestinationV1 bob_subaddr = bob_hot.subaddress(bob_subaddr_index);
        const carrot::CarrotPaymentProposalVerifiableSelfSendV1 selfsend_proposal{
            .proposal = {
                .destination_address_spend_pubkey = bob_subaddr.address_spend_pubkey,
                .amount = amount,
                .enote_type = carrot::CarrotEnoteType::PAYMENT
            },
            .subaddr_index = bob_subaddr_index
        };
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            /*normal_payment_proposals=*/{},
            {selfsend_proposal},
            bob_hot.legacy_acb.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(2, scanned_enotes.size()); // b/c transfer always adds a self-send
        const wallet2_basic::transfer_details &dest_enote = (scanned_enotes.front().amount() == amount)
            ? scanned_enotes.front() : scanned_enotes.back();
        EXPECT_TRUE(verify_cold_sal(dest_enote));
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(dest_enote, bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_cold_sal(imported_td));
    }

    // p. carrot v1 internal subaddress (@TODO)
}

namespace
{
template <typename T>
static bool verify_serialization_completeness(T v)
{
    std::stringstream ss;
    binary_archive<true> sar(ss);
    if (!::serialization::serialize(sar, v))
        return false;
    const std::string blob = ss.str();
    binary_archive<false> lar(epee::to_byte_span(epee::to_span(blob)));
    T lv;
    if (!::serialization::serialize(lar, lv))
        return false;
    return lv == v;
}
}

TEST(wallet_hot_cold, export_serialization_completeness)
{
    // Test serialization completeness for the following exported enote types:
    //   a. pre-ringct coinbase
    //   b. pre-ringct
    //   c. ringct coinbase
    //   d. ringct long-amount
    //   e. ringct short-amount
    //   f. view-tagged ringct coinbase
    //   g. view-tagged pre-ringct (only possible in unmixable sweep txs)
    //   h. view-tagged ringct
    //   i. carrot v1 coinbase
    //   j. carrot v1 normal
    //   k. carrot v1 special
    //   l. carrot v1 internal (@TODO)
    //   m. carrot v1 normal subaddress
    //   n. carrot v1 normal integrated
    //   o. carrot v1 special subaddress
    //   p. carrot v1 internal subaddress (@TODO)

    carrot::mock::mock_carrot_and_legacy_keys bob_cold;
    bob_cold.generate();
    const cryptonote::account_public_address bob_addr = bob_cold.legacy_acb.get_keys().m_account_address;

    carrot::mock::mock_carrot_and_legacy_keys bob_hot = make_hot_keys(bob_cold);

    // a. scan pre-ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 300;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/1,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // b. pre-ringct tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 400;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            /*hf_version=*/1);
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // c. ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 500;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_DYNAMIC_FEE,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // d. ringct long-amount tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 600;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_DYNAMIC_FEE);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // e. ringct short-amount tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 700;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_SMALLER_BP);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // f. view-tagged ringct coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 800;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_VIEW_TAGS,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // g. view-tagged pre-ringct (only possible in unmixable sweep txs) tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 900;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_VIEW_TAGS,
            /*sweep_unmixable_override=*/true);
        ASSERT_EQ(1, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // h. view-tagged ringct tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const rct::xmr_amount fee = 42;
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(
            dests,
            fee,
            HF_VERSION_VIEW_TAGS,
            /*sweep_unmixable_override=*/false);
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_pre_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_pre_carrot_output(scanned_enotes.front());
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_pre_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // i. carrot v1 coinbase tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount reward = 42;
        const std::uint64_t global_output_index = 1100;
        const cryptonote::transaction tx = mock::construct_miner_tx_fake_reward_1out(
            block_index,
            reward,
            bob_addr,
            /*hf_version=*/HF_VERSION_CARROT,
            /*num_tx_outputs=*/1
        );
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(block_index + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(1, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(reward, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // j. carrot v1 normal tx
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{carrot::mock::convert_normal_payment_proposal_v1(dests.front()), /*main*/}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // k. carrot v1 special tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        std::vector<cryptonote::tx_destination_entry> dests = {
            cryptonote::tx_destination_entry(amount, bob_addr, false)};
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            /*normal_payment_proposals=*/{},
            {{carrot::mock::convert_selfsend_payment_proposal_v1(dests.front()), {/*main*/}}},
            bob_hot.legacy_acb.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(2, scanned_enotes.size()); // b/c transfer always adds a self-send
        const wallet2_basic::transfer_details &dest_enote = (scanned_enotes.front().amount() == amount)
            ? scanned_enotes.front() : scanned_enotes.back();
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(dest_enote, bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // l. carrot v1 internal (@TODO)

    // m. carrot v1 normal subaddress tx
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::subaddress_index_extended bob_subaddr_index{
            .index = carrot::mock::gen_subaddress_index(),
            .derive_type = carrot::AddressDeriveType::PreCarrot};
        const carrot::CarrotDestinationV1 bob_subaddr = bob_hot.subaddress(bob_subaddr_index);
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{bob_subaddr, amount, carrot::gen_janus_anchor()}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // n. carrot v1 normal integrated tx
    {
        cryptonote::account_base aether;
        aether.generate();
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::CarrotDestinationV1 bob_integrated_addr = bob_hot.cryptonote_address(carrot::gen_payment_id(),
            carrot::AddressDeriveType::PreCarrot);
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            {{bob_integrated_addr, amount, carrot::gen_janus_anchor()}},
            {},
            aether.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(1, scanned_enotes.size());
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(scanned_enotes.front(), bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // o. carrot v1 special subaddress tx
    {
        const std::uint64_t block_index = 21;
        const rct::xmr_amount amount = rct::randXmrAmount(COIN);
        const std::uint64_t global_output_index = 1000;
        const carrot::subaddress_index_extended bob_subaddr_index{
            .index = carrot::mock::gen_subaddress_index(),
            .derive_type = carrot::AddressDeriveType::PreCarrot};
        const carrot::CarrotDestinationV1 bob_subaddr = bob_hot.subaddress(bob_subaddr_index);
        const carrot::CarrotPaymentProposalVerifiableSelfSendV1 selfsend_proposal{
            .proposal = {
                .destination_address_spend_pubkey = bob_subaddr.address_spend_pubkey,
                .amount = amount,
                .enote_type = carrot::CarrotEnoteType::PAYMENT
            },
            .subaddr_index = bob_subaddr_index
        };
        const cryptonote::transaction tx = mock::construct_carrot_pruned_transaction_fake_inputs(
            /*normal_payment_proposals=*/{},
            {selfsend_proposal},
            bob_hot.legacy_acb.get_keys());
        ASSERT_EQ(2, tx.version);
        ASSERT_EQ(0, tx.unlock_time);
        ASSERT_EQ(1, tx.vin.size());
        ASSERT_EQ(2, tx.vout.size());
        const wallet2_basic::transfer_container scanned_enotes =
            hot_scan_into_transfer_details(bob_hot, tx, block_index, global_output_index);
        ASSERT_EQ(2, scanned_enotes.size()); // b/c transfer always adds a self-send
        const wallet2_basic::transfer_details &dest_enote = (scanned_enotes.front().amount() == amount)
            ? scanned_enotes.front() : scanned_enotes.back();
        const tools::wallet::cold::exported_carrot_transfer_details etd
            = tools::wallet::cold::export_cold_carrot_output(dest_enote, bob_hot.cn_addr_dev);
        const wallet2_basic::transfer_details imported_td = tools::wallet::cold::import_cold_carrot_output(etd,
            bob_cold.cn_addr_dev,
            *bob_cold.key_image_dev);
        EXPECT_EQ(amount, imported_td.amount());
        EXPECT_TRUE(verify_serialization_completeness(etd));
    }

    // p. carrot v1 internal subaddress tx (@TODO)
}

TEST(wallet_hot_cold, sign_transfer_stateless_1in_cryptonote_spender)
{
    // For all input enote types, all input address types, and all output address types, do the following:
    //    1. Alice (hot): Create a transfer-type tx proposal from Alice to Bob
    //    2. Alice (hot): Make an unsigned tx set
    //    3. Alice (cold): Sign tx set
    //    4. Alice (hot): Finalize enotes into pruned tx
    //    5. Bob: Verify SA/Ls
    //    6. Bob: Scan enotes

    carrot::mock::mock_carrot_and_legacy_keys alice;
    alice.generate();
    carrot::mock::mock_carrot_and_legacy_keys bob;
    bob.generate();

    // input: [1, 2) XMR
    // output: [0, 1] XMR
    const rct::xmr_amount input_amount = COIN + rct::randXmrAmount(COIN);
    const rct::xmr_amount output_amount = rct::randXmrAmount(COIN);

    // for all input enotes type...
    for (const auto &input_enote_type : enote_types_to_test)
    {
        const std::uint8_t input_hf_version = std::get<0>(input_enote_type);
        const bool input_is_coinbase = std::get<1>(input_enote_type);
        const bool input_is_unmixable_sweep = std::get<2>(input_enote_type);
        // for all address types to the input enote...
        for (AddressType input_addr_type = AddressType::MIN; input_addr_type <= AddressType::MAX; ++input_addr_type)
        {
            if (input_is_coinbase && input_addr_type != AddressType::MAIN)
                continue;

            const wallet2_basic::transfer_details alice_input_transfer = gen_transfer_details_to(alice,
                input_addr_type,
                input_amount,
                input_hf_version,
                input_is_coinbase,
                input_is_unmixable_sweep,
                carrot::AddressDeriveType::PreCarrot);
            const carrot::OutputOpeningHintVariant alice_input_proposal = tools::wallet::make_sal_opening_hint_from_transfer_details(alice_input_transfer);
            ASSERT_EQ(input_hf_version >= HF_VERSION_CARROT, std::holds_alternative<carrot::CarrotOutputOpeningHintV2>(alice_input_proposal));

            // for all address types to the output enote...
            for (AddressType output_addr_type = AddressType::MIN; output_addr_type <= AddressType::MAX; ++output_addr_type)
            {
                MDEBUG("wallet_hot_cold.sign_transfer_stateless_1in_cryptonote_spender:");
                MDEBUG("    input-enote-hf-version  : " << (int)input_hf_version);
                MDEBUG("    input-is-coinbase       : " << input_is_coinbase);
                MDEBUG("    input-is-unmixable-sweep: " << input_is_unmixable_sweep);
                MDEBUG("    input-addr-type         : " << (int)input_addr_type);
                MDEBUG("    output-addr-type        : " << (int)output_addr_type);
                MDEBUG("");

                // 1. Alice (hot): Create a transfer-type tx proposal from Alice to Bob
                const carrot::CarrotDestinationV1 bob_destination = gen_destination_to(bob, output_addr_type, carrot::AddressDeriveType::PreCarrot);
                const carrot::CarrotPaymentProposalV1 bob_payment_proposal = carrot::CarrotPaymentProposalV1{
                    .destination = bob_destination,
                    .amount = output_amount,
                    .randomness = carrot::gen_janus_anchor()
                };
                carrot::CarrotTransactionProposalV1 og_tx_proposal;
                carrot::make_carrot_transaction_proposal_v1_transfer({bob_payment_proposal},
                    /*selfsend_payment_proposals=*/{},
                    mock::fake_fee_per_weight,
                    /*extra=*/{},
                    carrot::select_inputs_func_t([&](const boost::multiprecision::uint128_t&,
                        const std::map<std::size_t, rct::xmr_amount>&,
                        const std::size_t,
                        const std::size_t,
                        std::vector<carrot::CarrotSelectedInput> &selected_in)
                        { selected_in = {{input_amount, alice_input_proposal}}; }),
                    alice.legacy_acb.get_keys().m_account_address.m_spend_public_key,
                    {{0, 0}, carrot::AddressDeriveType::PreCarrot},
                    /*subtractable_normal_payment_proposals=*/{},
                    /*subtractable_selfsend_payment_proposals=*/{},
                    og_tx_proposal);

                // 2. Alice (hot): Make an unsigned tx set
                const auto cold_tx_proposal = tools::wallet::cold::compress_carrot_transaction_proposal_lossy(
                    og_tx_proposal, crypto::rand<tools::wallet::cold::HotColdSeed>());
                const tools::wallet::cold::UnsignedCarrotTransactionSetV1 unsigned_tx_set{
                    .tx_proposals = {cold_tx_proposal},
                    .new_transfers = {tools::wallet::cold::export_cold_output(alice_input_transfer, alice.cn_addr_dev)},
                    .starting_transfer_index = 0,
                    .resend_tx_proposals = true
                };

                // 3. Alice (cold): Sign tx set
                const crypto::secret_key &alice_k_s = alice.legacy_acb.get_keys().m_spend_secret_key;
                const crypto::secret_key &alice_k_v = alice.legacy_acb.get_keys().m_view_secret_key;
                tools::wallet::cold::SignedCarrotTransactionSetV1 signed_tx_set;
                std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> ephemeral_tx_privkeys;
                tools::wallet::cold::sign_carrot_tx_set_v1(unsigned_tx_set,
                    {},
                    alice.cn_addr_dev,
                    carrot::spend_device_ram_borrowed(alice_k_s, alice_k_v),
                    signed_tx_set,
                    ephemeral_tx_privkeys);

                // 4. Alice (hot): Finalize enotes into pruned tx
                ASSERT_EQ(1, signed_tx_set.tx_proposals.size());
                ASSERT_EQ(0, signed_tx_set.tx_input_proposals.size());
                ASSERT_EQ(1, signed_tx_set.signed_inputs.size());
                const auto &signed_input = *signed_tx_set.signed_inputs.cbegin();
                ASSERT_EQ(onetime_address_ref(alice_input_proposal), signed_input.second.first);
                std::unordered_map<crypto::public_key, crypto::key_image> cold_kis{
                    {onetime_address_ref(alice_input_proposal), signed_input.first}};
                const carrot::key_image_device_precompted precomputed_ki_dev(std::move(cold_kis));
                carrot::CarrotTransactionProposalV1 expanded_tx_proposal;
                std::vector<crypto::key_image> input_key_images;
                std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
                tools::wallet::cold::expand_carrot_transaction_proposal_and_rerandomized_outputs (signed_tx_set.tx_proposals.at(0),
                    [&](const auto &){ return alice_input_proposal; },
                    alice.cn_addr_dev,
                    precomputed_ki_dev,
                    expanded_tx_proposal,
                    input_key_images,
                    rerandomized_outputs);
                ASSERT_EQ(1, input_key_images.size());
                ASSERT_EQ(1, rerandomized_outputs.size());
                const FcmpInputCompressed &input = rerandomized_outputs.at(0).input;
                cryptonote::transaction pruned_tx;
                carrot::make_pruned_transaction_from_proposal_v1(expanded_tx_proposal,
                    nullptr,
                    &alice.cn_addr_dev,
                    input_key_images,
                    pruned_tx);

                // 5. Bob: Verify SA/Ls
                const crypto::hash signable_tx_hash = carrot::calculate_signable_fcmp_pp_transaction_hash(pruned_tx);
                ASSERT_TRUE(fcmp_pp::verify_sal(signable_tx_hash,
                    input,
                    boost::get<cryptonote::txin_to_key>(pruned_tx.vin.at(0)).k_image,
                    signed_input.second.second));

                // 6. Bob: Scan enotes
                const auto bob_output_transfers = hot_scan_into_transfer_details(bob, pruned_tx);
                ASSERT_EQ(1, bob_output_transfers.size());
                ASSERT_EQ(output_amount, bob_output_transfers.at(0).amount());
            }
        }
    }
}

TEST(wallet_hot_cold, sign_transfer_noresend_1in_cryptonote_spender)
{
    // For all input enote types, all input address types, and all output address types, do the following:
    //    1. Alice (hot): Create a transfer-type tx proposal from Alice to Bob
    //    2. Alice (hot): Make an unsigned tx set
    //    3. Alice (hot): Remember tx proposal
    //    4. Alice (cold): Sign tx set (and do not resend tx proposal)
    //    5. Alice (hot): Finalize enotes into pruned tx
    //    6. Bob: Verify SA/Ls
    //    7. Bob: Scan enotes

    carrot::mock::mock_carrot_and_legacy_keys alice;
    alice.generate();
    carrot::mock::mock_carrot_and_legacy_keys bob;
    bob.generate();

    // input: [1, 2) XMR
    // output: [0, 1] XMR
    const rct::xmr_amount input_amount = COIN + rct::randXmrAmount(COIN);
    const rct::xmr_amount output_amount = rct::randXmrAmount(COIN);

    // for all input enotes type...
    for (const auto &input_enote_type : enote_types_to_test)
    {
        const std::uint8_t input_hf_version = std::get<0>(input_enote_type);
        const bool input_is_coinbase = std::get<1>(input_enote_type);
        const bool input_is_unmixable_sweep = std::get<2>(input_enote_type);
        // for all address types to the input enote...
        for (AddressType input_addr_type = AddressType::MIN; input_addr_type <= AddressType::MAX; ++input_addr_type)
        {
            if (input_is_coinbase && input_addr_type != AddressType::MAIN)
                continue;

            const wallet2_basic::transfer_details alice_input_transfer = gen_transfer_details_to(alice,
                input_addr_type,
                input_amount,
                input_hf_version,
                input_is_coinbase,
                input_is_unmixable_sweep,
                carrot::AddressDeriveType::PreCarrot);
            const carrot::OutputOpeningHintVariant alice_input_proposal = tools::wallet::make_sal_opening_hint_from_transfer_details(alice_input_transfer);
            ASSERT_EQ(input_hf_version >= HF_VERSION_CARROT, std::holds_alternative<carrot::CarrotOutputOpeningHintV2>(alice_input_proposal));

            // for all address types to the output enote...
            for (AddressType output_addr_type = AddressType::MIN; output_addr_type <= AddressType::MAX; ++output_addr_type)
            {
                MDEBUG("wallet_hot_cold.sign_transfer_noresend_1in_cryptonote_spender:");
                MDEBUG("    input-enote-hf-version  : " << (int)input_hf_version);
                MDEBUG("    input-is-coinbase       : " << input_is_coinbase);
                MDEBUG("    input-is-unmixable-sweep: " << input_is_unmixable_sweep);
                MDEBUG("    input-addr-type         : " << (int)input_addr_type);
                MDEBUG("    output-addr-type        : " << (int)output_addr_type);
                MDEBUG("");

                // 1. Alice (hot): Create a transfer-type tx proposal from Alice to Bob
                const carrot::CarrotDestinationV1 bob_destination = gen_destination_to(bob, output_addr_type, carrot::AddressDeriveType::PreCarrot);
                const carrot::CarrotPaymentProposalV1 bob_payment_proposal = carrot::CarrotPaymentProposalV1{
                    .destination = bob_destination,
                    .amount = output_amount,
                    .randomness = carrot::gen_janus_anchor()
                };
                carrot::CarrotTransactionProposalV1 og_tx_proposal;
                carrot::make_carrot_transaction_proposal_v1_transfer({bob_payment_proposal},
                    /*selfsend_payment_proposals=*/{},
                    mock::fake_fee_per_weight,
                    /*extra=*/{},
                    carrot::select_inputs_func_t([&](const boost::multiprecision::uint128_t&,
                        const std::map<std::size_t, rct::xmr_amount>&,
                        const std::size_t,
                        const std::size_t,
                        std::vector<carrot::CarrotSelectedInput> &selected_in)
                        { selected_in = {{input_amount, alice_input_proposal}}; }),
                    alice.legacy_acb.get_keys().m_account_address.m_spend_public_key,
                    {{0, 0}, carrot::AddressDeriveType::PreCarrot},
                    /*subtractable_normal_payment_proposals=*/{},
                    /*subtractable_selfsend_payment_proposals=*/{},
                    og_tx_proposal);

                // 2. Alice (hot): Make an unsigned tx set
                const auto cold_tx_proposal = tools::wallet::cold::compress_carrot_transaction_proposal_lossy(
                    og_tx_proposal, crypto::rand<tools::wallet::cold::HotColdSeed>());
                const tools::wallet::cold::UnsignedCarrotTransactionSetV1 unsigned_tx_set{
                    .tx_proposals = {cold_tx_proposal},
                    .new_transfers = {tools::wallet::cold::export_cold_output(alice_input_transfer, alice.cn_addr_dev)},
                    .starting_transfer_index = 0,
                    .resend_tx_proposals = false //! @note: this param differentiates this test from previous tests
                };

                // 3. Alice (hot): Remember tx proposal
                // *Alice thinks very hard...*

                // 4. Alice (cold): Sign tx set
                const crypto::secret_key &alice_k_s = alice.legacy_acb.get_keys().m_spend_secret_key;
                const crypto::secret_key &alice_k_v = alice.legacy_acb.get_keys().m_view_secret_key;
                tools::wallet::cold::SignedCarrotTransactionSetV1 signed_tx_set;
                std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> ephemeral_tx_privkeys;
                tools::wallet::cold::sign_carrot_tx_set_v1(unsigned_tx_set,
                    {},
                    alice.cn_addr_dev,
                    carrot::spend_device_ram_borrowed(alice_k_s, alice_k_v),
                    signed_tx_set,
                    ephemeral_tx_privkeys);

                // 5. Alice (hot): Finalize enotes into pruned tx
                ASSERT_EQ(0, signed_tx_set.tx_proposals.size()); // no resend
                ASSERT_EQ(0, signed_tx_set.tx_input_proposals.size());
                ASSERT_EQ(1, signed_tx_set.signed_inputs.size());
                const auto &signed_input = *signed_tx_set.signed_inputs.cbegin();
                ASSERT_EQ(onetime_address_ref(alice_input_proposal), signed_input.second.first);
                std::unordered_map<crypto::public_key, crypto::key_image> cold_kis{
                    {onetime_address_ref(alice_input_proposal), signed_input.first}};
                const carrot::key_image_device_precompted precomputed_ki_dev(std::move(cold_kis));
                carrot::CarrotTransactionProposalV1 expanded_tx_proposal;
                std::vector<crypto::key_image> input_key_images;
                std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
                tools::wallet::cold::expand_carrot_transaction_proposal_and_rerandomized_outputs (
                    cold_tx_proposal,
                    [&](const auto &){ return alice_input_proposal; },
                    alice.cn_addr_dev,
                    precomputed_ki_dev,
                    expanded_tx_proposal,
                    input_key_images,
                    rerandomized_outputs);
                ASSERT_EQ(1, input_key_images.size());
                ASSERT_EQ(1, rerandomized_outputs.size());
                const FcmpInputCompressed &input = rerandomized_outputs.at(0).input;
                cryptonote::transaction pruned_tx;
                carrot::make_pruned_transaction_from_proposal_v1(expanded_tx_proposal,
                    nullptr,
                    &alice.cn_addr_dev,
                    input_key_images,
                    pruned_tx);

                // 6. Bob: Verify SA/Ls
                const crypto::hash signable_tx_hash = carrot::calculate_signable_fcmp_pp_transaction_hash(pruned_tx);
                ASSERT_TRUE(fcmp_pp::verify_sal(signable_tx_hash,
                    input,
                    boost::get<cryptonote::txin_to_key>(pruned_tx.vin.at(0)).k_image,
                    signed_input.second.second));

                // 7. Bob: Scan enotes
                const auto bob_output_transfers = hot_scan_into_transfer_details(bob, pruned_tx);
                ASSERT_EQ(1, bob_output_transfers.size());
                ASSERT_EQ(output_amount, bob_output_transfers.at(0).amount());
            }
        }
    }
}

TEST(wallet_hot_cold, sign_transfer_coldinit_1in_cryptonote_spender)
{
    // For all input enote types, all input address types, and all output address types, do the following:
    //    1. Alice (hot): Generate input transfers
    //    2. Alice (hot): Export transfers to cold
    //    3. Alice (cold): Make tx proposal and sign
    //    4. Alice (hot): Finalize enotes into pruned tx
    //    5. Bob: Verify SA/Ls
    //    6. Bob: Scan enotes
    // This tests "cold-side initiated" transaction construction

    carrot::mock::mock_carrot_and_legacy_keys alice_cold;
    alice_cold.generate();
    carrot::mock::mock_carrot_and_legacy_keys alice_hot = make_hot_keys(alice_cold);
    carrot::mock::mock_carrot_and_legacy_keys bob;
    bob.generate();

    // input: [1, 2) XMR
    // output: [0, 1] XMR
    const rct::xmr_amount input_amount = COIN + rct::randXmrAmount(COIN);
    const rct::xmr_amount output_amount = rct::randXmrAmount(COIN);

    // for all input enotes type...
    for (const auto &input_enote_type : enote_types_to_test)
    {
        const std::uint8_t input_hf_version = std::get<0>(input_enote_type);
        const bool input_is_coinbase = std::get<1>(input_enote_type);
        const bool input_is_unmixable_sweep = std::get<2>(input_enote_type);
        // for all address types to the input enote...
        for (AddressType input_addr_type = AddressType::MIN; input_addr_type <= AddressType::MAX; ++input_addr_type)
        {
            if (input_is_coinbase && input_addr_type != AddressType::MAIN)
                continue;

            // 1. Alice (hot): Generate input transfers
            // 2. Alice (hot): Export transfers to cold
            const auto exported_output = tools::wallet::cold::export_cold_output(
                gen_transfer_details_to(
                    alice_hot,
                    input_addr_type,
                    input_amount,
                    input_hf_version,
                    input_is_coinbase,
                    input_is_unmixable_sweep,
                    carrot::AddressDeriveType::PreCarrot),
                alice_hot.cn_addr_dev);            
            // import output
            const wallet2_basic::transfer_details alice_imported_transfer = tools::wallet::cold::import_cold_output(
                exported_output, alice_cold.cn_addr_dev, *alice_cold.key_image_dev);

            // for all address types to the output enote...
            for (AddressType output_addr_type = AddressType::MIN; output_addr_type <= AddressType::MAX; ++output_addr_type)
            {
                MDEBUG("wallet_hot_cold.sign_transfer_stateless_1in_cryptonote_spender:");
                MDEBUG("    input-enote-hf-version  : " << (int)input_hf_version);
                MDEBUG("    input-is-coinbase       : " << input_is_coinbase);
                MDEBUG("    input-is-unmixable-sweep: " << input_is_unmixable_sweep);
                MDEBUG("    input-addr-type         : " << (int)input_addr_type);
                MDEBUG("    output-addr-type        : " << (int)output_addr_type);
                MDEBUG("");

                // 3. Alice (cold): Make tx proposal and sign
                const carrot::CarrotDestinationV1 bob_destination = gen_destination_to(bob,
                    output_addr_type, carrot::AddressDeriveType::PreCarrot);
                const carrot::CarrotPaymentProposalV1 bob_payment_proposal = carrot::CarrotPaymentProposalV1{
                    .destination = bob_destination,
                    .amount = output_amount,
                    .randomness = carrot::gen_janus_anchor()
                };
                const carrot::InputProposalV1 alice_input_proposal =
                    tools::wallet::make_sal_opening_hint_from_transfer_details(alice_imported_transfer);
                carrot::CarrotTransactionProposalV1 og_tx_proposal;
                carrot::make_carrot_transaction_proposal_v1_transfer({bob_payment_proposal},
                    /*selfsend_payment_proposals=*/{},
                    mock::fake_fee_per_weight,
                    /*extra=*/{},
                    carrot::select_inputs_func_t([input_amount, &alice_input_proposal](
                        const boost::multiprecision::uint128_t&,
                        const std::map<std::size_t, rct::xmr_amount>&,
                        const std::size_t,
                        const std::size_t,
                        std::vector<carrot::CarrotSelectedInput> &selected_in)
                        { selected_in = {
                            {input_amount, alice_input_proposal}}; }),
                    alice_cold.legacy_acb.get_keys().m_account_address.m_spend_public_key,
                    {{0, 0}, carrot::AddressDeriveType::PreCarrot},
                    /*subtractable_normal_payment_proposals=*/{},
                    /*subtractable_selfsend_payment_proposals=*/{},
                    og_tx_proposal);
                const tools::wallet::cold::HotColdCarrotTransactionProposalV1 cold_tx_proposal =
                    tools::wallet::cold::compress_carrot_transaction_proposal_lossy(
                        og_tx_proposal,
                        crypto::rand<tools::wallet::cold::HotColdSeed>());
                tools::wallet::cold::UnsignedCarrotTransactionSetV1 unsigned_tx_set{
                    .tx_proposals = {cold_tx_proposal},
                    .resend_tx_proposals = true
                };
                const crypto::secret_key &alice_k_s = alice_cold.legacy_acb.get_keys().m_spend_secret_key;
                const crypto::secret_key &alice_k_v = alice_cold.legacy_acb.get_keys().m_view_secret_key;
                tools::wallet::cold::SignedCarrotTransactionSetV1 signed_tx_set;
                std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> ephemeral_tx_privkeys;
                tools::wallet::cold::sign_carrot_tx_set_v1(unsigned_tx_set,
                    [&alice_input_proposal](auto){return alice_input_proposal;},
                    alice_cold.cn_addr_dev,
                    carrot::spend_device_ram_borrowed(alice_k_s, alice_k_v),
                    signed_tx_set,
                    ephemeral_tx_privkeys);

                // 4. Alice (hot): Finalize enotes into pruned tx
                ASSERT_EQ(1, signed_tx_set.tx_proposals.size());
                ASSERT_EQ(0, signed_tx_set.tx_input_proposals.size());
                ASSERT_EQ(1, signed_tx_set.signed_inputs.size());
                const auto &signed_input = *signed_tx_set.signed_inputs.cbegin();
                ASSERT_EQ(onetime_address_ref(alice_input_proposal), signed_input.second.first);
                std::unordered_map<crypto::public_key, crypto::key_image> cold_kis{
                    {onetime_address_ref(alice_input_proposal), signed_input.first}};
                const carrot::key_image_device_precompted precomputed_ki_dev(std::move(cold_kis));
                carrot::CarrotTransactionProposalV1 expanded_tx_proposal;
                std::vector<crypto::key_image> input_key_images;
                std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
                tools::wallet::cold::expand_carrot_transaction_proposal_and_rerandomized_outputs (signed_tx_set.tx_proposals.at(0),
                    [&](const auto &){ return alice_input_proposal; },
                    alice_hot.cn_addr_dev,
                    precomputed_ki_dev,
                    expanded_tx_proposal,
                    input_key_images,
                    rerandomized_outputs);
                ASSERT_EQ(1, input_key_images.size());
                ASSERT_EQ(1, rerandomized_outputs.size());
                const FcmpInputCompressed &input = rerandomized_outputs.at(0).input;
                cryptonote::transaction pruned_tx;
                carrot::make_pruned_transaction_from_proposal_v1(expanded_tx_proposal,
                    nullptr,
                    &alice_hot.cn_addr_dev,
                    input_key_images,
                    pruned_tx);

                // 5. Bob: Verify SA/Ls
                const crypto::hash signable_tx_hash = carrot::calculate_signable_fcmp_pp_transaction_hash(pruned_tx);
                ASSERT_TRUE(fcmp_pp::verify_sal(signable_tx_hash,
                    input,
                    boost::get<cryptonote::txin_to_key>(pruned_tx.vin.at(0)).k_image,
                    signed_input.second.second));

                // 6. Bob: Scan enotes
                const auto bob_output_transfers = hot_scan_into_transfer_details(bob, pruned_tx);
                ASSERT_EQ(1, bob_output_transfers.size());
                ASSERT_EQ(output_amount, bob_output_transfers.at(0).amount());
            }
        }
    }
}
