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

#include "unit_tests_utils.h"
#include "gtest/gtest.h"

#include <cctype>

#include "file_io_utils.h"
#include "wallet/wallet2.h"
#include "wallet/wallet2_basic/wallet2_storage.h"

using namespace boost::filesystem;
using namespace epee::file_io_utils;

static constexpr const char WALLET_00fd416a_PRIMARY_ADDRESS[] =
    "45p2SngJAPSJbqSiUvYfS3BfhEdxZmv8pDt25oW1LzxrZv9Uq6ARagiFViMGUE3gJk5VPWingCXVf1p2tyAy6SUeSHPhbve";

// https://github.com/monero-project/monero/blob/67d190ce7c33602b6a3b804f633ee1ddb7fbb4a1/src/wallet/wallet2.cpp#L156
static constexpr const char WALLET2_ASCII_OUTPUT_MAGIC[] = "MoneroAsciiDataV1";

static void check_wallet_9svHk1_key_contents(const tools::wallet2& w2, const tools::wallet2::ExportFormat export_format = tools::wallet2::Binary)
{
    // if wallet fails this first test, make sure that the wallet keys are decrypted
    EXPECT_EQ("a16cc88f85ee9403bc642def92334ed203032ce91b060d353e6a532f47ff6200", epee::string_tools::pod_to_hex(w2.get_account().get_keys().m_spend_secret_key));
    EXPECT_EQ("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", epee::string_tools::pod_to_hex(w2.get_account().get_keys().m_view_secret_key));
    EXPECT_EQ(1483262038, w2.get_account().get_createtime());
    EXPECT_EQ(false, w2.is_deprecated()); // getter for member field is_old_file_format
    EXPECT_EQ(false, w2.watch_only());

    EXPECT_EQ(false, w2.multisig());
    EXPECT_EQ(false, w2.is_multisig_enabled());
    // @TODO: missing fields m_multisig_signers, m_multisig_rounds_passed, m_multisig_threshold, m_multisig_derivations

    EXPECT_EQ("English", w2.get_seed_language());
    EXPECT_EQ(cryptonote::TESTNET, w2.nettype());
    EXPECT_EQ(true, w2.always_confirm_transfers());
    EXPECT_EQ(false, w2.print_ring_members());
    EXPECT_EQ(true, w2.store_tx_info());
    EXPECT_EQ(0, w2.default_mixin());
    EXPECT_EQ(0, w2.get_default_priority());
    EXPECT_EQ(true, w2.auto_refresh());
    EXPECT_EQ(wallet2_basic::RefreshDefault, w2.get_refresh_type());
    EXPECT_EQ(818413, w2.get_refresh_from_block_height());
    // @TODO: missing m_skip_to_height
    EXPECT_EQ(wallet2_basic::AskPasswordToDecrypt, w2.ask_password());
    EXPECT_EQ(ORPHANED_BLOCKS_MAX_COUNT, w2.max_reorg_depth());
    EXPECT_EQ(0, w2.get_min_output_count());
    EXPECT_EQ(0, w2.get_min_output_value());
    EXPECT_EQ(false, w2.merge_destinations());
    EXPECT_EQ(true, w2.confirm_backlog());
    EXPECT_EQ(0, w2.get_confirm_backlog_threshold());
    EXPECT_EQ(true, w2.confirm_export_overwrite());
    EXPECT_EQ(true, w2.auto_low_priority());
    EXPECT_EQ(true, w2.segregate_pre_fork_outputs());
    EXPECT_EQ(true, w2.key_reuse_mitigation2());
    EXPECT_EQ(0, w2.segregation_height());
    EXPECT_EQ(true, w2.ignore_fractional_outputs());
    EXPECT_EQ(MONEY_SUPPLY, w2.ignore_outputs_above());
    EXPECT_EQ(0, w2.ignore_outputs_below());
    EXPECT_EQ(false, w2.track_uses());
    EXPECT_EQ(false, w2.show_wallet_name_when_locked());
    EXPECT_EQ(wallet2_basic::DEFAULT_INACTIVITY_LOCK_TIMEOUT, w2.inactivity_lock_timeout());
    EXPECT_EQ(wallet2_basic::BackgroundMiningMaybe, w2.setup_background_mining());
    const std::pair<size_t, size_t> exp_lookahead = {wallet2_basic::SUBADDRESS_LOOKAHEAD_MAJOR, wallet2_basic::SUBADDRESS_LOOKAHEAD_MINOR};
    EXPECT_EQ(exp_lookahead, w2.get_subaddress_lookahead());
    // @TODO: missing m_original_keys_available, m_original_address
    EXPECT_EQ(export_format, w2.export_format());
    EXPECT_EQ(false, w2.load_deprecated_formats());
    EXPECT_EQ("default", w2.device_name());
    EXPECT_EQ("", w2.device_derivation_path());
    EXPECT_EQ(hw::device::device_type::SOFTWARE, w2.get_device_type());
    EXPECT_EQ(false, w2.is_mismatched_daemon_version_allowed());
}

static void check_wallet_9svHk1_key_contents(const wallet2_basic::keys_data& w2b,  const wallet2_basic::ExportFormat export_format = wallet2_basic::Binary)
{
    // if wallet fails this first test, make sure that the wallet keys are decrypted
    EXPECT_EQ("a16cc88f85ee9403bc642def92334ed203032ce91b060d353e6a532f47ff6200", epee::string_tools::pod_to_hex(w2b.m_account.get_keys().m_spend_secret_key));
    EXPECT_EQ("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", epee::string_tools::pod_to_hex(w2b.m_account.get_keys().m_view_secret_key));
    EXPECT_EQ(1483262038, w2b.m_account.get_createtime());
    EXPECT_EQ(false, w2b.is_old_file_format); // getter for member field is_old_file_format
    EXPECT_EQ(false, w2b.m_watch_only);

    EXPECT_EQ(false, w2b.m_multisig);
    EXPECT_EQ(false, w2b.m_enable_multisig);
    // @TODO: missing fields m_multisig_signers, m_multisig_rounds_passed, m_multisig_threshold, m_multisig_derivations

    EXPECT_EQ("English", w2b.seed_language);
    EXPECT_EQ(cryptonote::TESTNET, w2b.m_nettype);
    EXPECT_EQ(true, w2b.m_always_confirm_transfers);
    EXPECT_EQ(false, w2b.m_print_ring_members);
    EXPECT_EQ(true, w2b.m_store_tx_info);
    EXPECT_EQ(0, w2b.m_default_mixin);
    EXPECT_EQ(0, w2b.m_default_priority);
    EXPECT_EQ(true, w2b.m_auto_refresh);
    EXPECT_EQ(wallet2_basic::RefreshDefault, w2b.m_refresh_type);
    EXPECT_EQ(818413, w2b.m_refresh_from_block_height);
    // @TODO: missing m_skip_to_height
    EXPECT_EQ(true, w2b.m_confirm_non_default_ring_size);
    EXPECT_EQ(wallet2_basic::AskPasswordToDecrypt, w2b.m_ask_password);
    EXPECT_EQ(ORPHANED_BLOCKS_MAX_COUNT, w2b.m_max_reorg_depth);
    EXPECT_EQ(0, w2b.m_min_output_count);
    EXPECT_EQ(0, w2b.m_min_output_value);
    EXPECT_EQ(false, w2b.m_merge_destinations);
    EXPECT_EQ(true, w2b.m_confirm_backlog);
    EXPECT_EQ(0, w2b.m_confirm_backlog_threshold);
    EXPECT_EQ(true, w2b.m_confirm_export_overwrite);
    EXPECT_EQ(true, w2b.m_auto_low_priority);
    EXPECT_EQ(true, w2b.m_segregate_pre_fork_outputs);
    EXPECT_EQ(true, w2b.m_key_reuse_mitigation2);
    EXPECT_EQ(0, w2b.m_segregation_height);
    EXPECT_EQ(true, w2b.m_ignore_fractional_outputs);
    EXPECT_EQ(MONEY_SUPPLY, w2b.m_ignore_outputs_above);
    EXPECT_EQ(0, w2b.m_ignore_outputs_below);
    EXPECT_EQ(false, w2b.m_track_uses);
    EXPECT_EQ(false, w2b.m_show_wallet_name_when_locked);
    EXPECT_EQ(wallet2_basic::DEFAULT_INACTIVITY_LOCK_TIMEOUT, w2b.m_inactivity_lock_timeout);
    EXPECT_EQ(wallet2_basic::BackgroundMiningMaybe, w2b.m_setup_background_mining);
    EXPECT_EQ(wallet2_basic::SUBADDRESS_LOOKAHEAD_MAJOR, w2b.m_subaddress_lookahead_major);
    EXPECT_EQ(wallet2_basic::SUBADDRESS_LOOKAHEAD_MINOR, w2b.m_subaddress_lookahead_minor);
    // @TODO: missing m_original_keys_available, m_original_address
    EXPECT_EQ(export_format, w2b.m_export_format);
    EXPECT_EQ(false, w2b.m_load_deprecated_formats);
    EXPECT_EQ("default", w2b.m_device_name);
    EXPECT_EQ("", w2b.m_device_derivation_path);
    EXPECT_EQ(hw::device::device_type::SOFTWARE, w2b.m_key_device_type);
    EXPECT_EQ(false, w2b.m_allow_mismatched_daemon_version);
}

namespace tools
{
/*static*/ void check_wallet_9svHk1_cache_contents(const tools::wallet2& w2)
{
    /*
    fields of tools::wallet2 to be checked: 
        std::vector<crypto::hash>                                       m_blockchain
        std::vector<transfer_details>                                   m_transfers               // TODO
        cryptonote::account_public_address                              m_account_public_address
        std::unordered_map<crypto::key_image, size_t>                   m_key_images
        std::unordered_map<crypto::hash, unconfirmed_transfer_details>  m_unconfirmed_txs
        std::unordered_multimap<crypto::hash, payment_details>          m_payments
        std::unordered_map<crypto::hash, crypto::secret_key>            m_tx_keys
        std::unordered_map<crypto::hash, confirmed_transfer_details>    m_confirmed_txs
        std::unordered_map<crypto::hash, std::string>                   m_tx_notes
        std::unordered_map<crypto::hash, payment_details>               m_unconfirmed_payments
        std::unordered_map<crypto::public_key, size_t>                  m_pub_keys
        std::vector<tools::wallet2::address_book_row>                   m_address_book
    */
    // blockchain
    ASSERT_TRUE(w2.m_blockchain.size() == 1);
    EXPECT_TRUE(epee::string_tools::pod_to_hex(w2.m_blockchain[0]) == "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
    // transfers (TODO)
    EXPECT_TRUE(w2.m_transfers.size() == 3);
    // account public address
    EXPECT_TRUE(epee::string_tools::pod_to_hex(w2.m_account_public_address.m_view_public_key) == "e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad");
    EXPECT_TRUE(epee::string_tools::pod_to_hex(w2.m_account_public_address.m_spend_public_key) == "13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060");
    // key images
    ASSERT_TRUE(w2.m_key_images.size() == 3);
    {
        crypto::key_image ki[3];
        epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki[0]);
        epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki[1]);
        epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki[2]);
        EXPECT_EQ_MAP(0, w2.m_key_images, ki[0]);
        EXPECT_EQ_MAP(1, w2.m_key_images, ki[1]);
        EXPECT_EQ_MAP(2, w2.m_key_images, ki[2]);
    }
    // unconfirmed txs
    EXPECT_TRUE(w2.m_unconfirmed_txs.size() == 0);
    // payments
    ASSERT_TRUE(w2.m_payments.size() == 2);
    {
        auto pd0 = w2.m_payments.begin();
        auto pd1 = pd0;
        ++pd1;
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd0->first) == "0000000000000000000000000000000000000000000000000000000000000000");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd1->first) == "0000000000000000000000000000000000000000000000000000000000000000");
        if (epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc")
        swap(pd0, pd1);
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd1->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
        EXPECT_TRUE(pd0->second.m_amount == 13400845012231);
        EXPECT_TRUE(pd1->second.m_amount == 1200000000000);
        EXPECT_TRUE(pd0->second.m_block_height == 818424);
        EXPECT_TRUE(pd1->second.m_block_height == 818522);
        EXPECT_TRUE(pd0->second.m_unlock_time == 818484);
        EXPECT_TRUE(pd1->second.m_unlock_time == 0);
        EXPECT_TRUE(pd0->second.m_timestamp == 1483263366);
        EXPECT_TRUE(pd1->second.m_timestamp == 1483272963);
    }
    // tx keys
    ASSERT_TRUE(w2.m_tx_keys.size() == 2);
    {
        const std::vector<std::pair<std::string, std::string>> txid_txkey =
        {
        {"b9aac8c020ab33859e0c0b6331f46a8780d349e7ac17b067116e2d87bf48daad", "bf3614c6de1d06c09add5d92a5265d8c76af706f7bc6ac830d6b0d109aa87701"},
        {"6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", "e556884246df5a787def6732c6ea38f1e092fa13e5ea98f732b99c07a6332003"},
        };
        for (size_t i = 0; i < txid_txkey.size(); ++i)
        {
        crypto::hash txid;
        crypto::secret_key txkey;
        epee::string_tools::hex_to_pod(txid_txkey[i].first, txid);
        epee::string_tools::hex_to_pod(txid_txkey[i].second, txkey);
        EXPECT_EQ_MAP(txkey, w2.m_tx_keys, txid);
        }
    }
    // confirmed txs
    EXPECT_TRUE(w2.m_confirmed_txs.size() == 1);
    // tx notes
    ASSERT_TRUE(w2.m_tx_notes.size() == 2);
    {
        crypto::hash h[2];
        epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", h[0]);
        epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", h[1]);
        EXPECT_EQ_MAP("sample note", w2.m_tx_notes, h[0]);
        EXPECT_EQ_MAP("sample note 2", w2.m_tx_notes, h[1]);
    }
    // unconfirmed payments
    EXPECT_TRUE(w2.m_unconfirmed_payments.size() == 0);
    // pub keys
    ASSERT_TRUE(w2.m_pub_keys.size() == 3);
    {
        crypto::public_key pubkey[3];
        epee::string_tools::hex_to_pod("33f75f264574cb3a9ea5b24220a5312e183d36dc321c9091dfbb720922a4f7b0", pubkey[0]);
        epee::string_tools::hex_to_pod("5066ff2ce9861b1d131cf16eeaa01264933a49f28242b97b153e922ec7b4b3cb", pubkey[1]);
        epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8", pubkey[2]);
        EXPECT_EQ_MAP(0, w2.m_pub_keys, pubkey[0]);
        EXPECT_EQ_MAP(1, w2.m_pub_keys, pubkey[1]);
        EXPECT_EQ_MAP(2, w2.m_pub_keys, pubkey[2]);
    }
    // address book
    ASSERT_TRUE(w2.m_address_book.size() == 1);
    {
        auto address_book_row = w2.m_address_book.begin();
        EXPECT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_spend_public_key) == "9bc53a6ff7b0831c9470f71b6b972dbe5ad1e8606f72682868b1dda64e119fb3");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_view_public_key) == "49fece1ef97dc0c0f7a5e2106e75e96edd910f7e86b56e1e308cd0cf734df191");
        EXPECT_TRUE(address_book_row->m_description == "testnet wallet 9y52S6");
    }
}
} // namespace tools

static void check_wallet_9svHk1_cache_contents(const wallet2_basic::cache& c)
{
    /*
    This test suite is adapated from unit test Serialization.portability_wallet
    Cache fields to be checked:
        std::vector<crypto::hash>                                       m_blockchain
        std::vector<transfer_details>                                   m_transfers
        cryptonote::account_public_address                              m_account_public_address
        std::unordered_map<crypto::key_image, size_t>                   m_key_images
        std::unordered_map<crypto::hash, unconfirmed_transfer_details>  m_unconfirmed_txs
        std::unordered_multimap<crypto::hash, payment_details>          m_payments
        std::unordered_map<crypto::hash, crypto::secret_key>            m_tx_keys
        std::unordered_map<crypto::hash, confirmed_transfer_details>    m_confirmed_txs
        std::unordered_map<crypto::hash, std::string>                   m_tx_notes
        std::unordered_map<crypto::hash, payment_details>               m_unconfirmed_payments
        std::unordered_map<crypto::public_key, size_t>                  m_pub_keys
        std::vector<tools::wallet2::address_book_row>                   m_address_book
    */

    // blockchain
    EXPECT_TRUE(c.m_blockchain.size() == 1);
    EXPECT_TRUE(epee::string_tools::pod_to_hex(c.m_blockchain[0]) == "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
    // transfers (TODO)
    EXPECT_TRUE(c.m_transfers.size() == 3);
    // account public address
    EXPECT_TRUE(epee::string_tools::pod_to_hex(c.m_account_public_address.m_view_public_key) == "e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad");
    EXPECT_TRUE(epee::string_tools::pod_to_hex(c.m_account_public_address.m_spend_public_key) == "13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060");
    // key images
    ASSERT_TRUE(c.m_key_images.size() == 3);
    {
        crypto::key_image ki[3];
        epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki[0]);
        epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki[1]);
        epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki[2]);
        EXPECT_EQ_MAP(0, c.m_key_images, ki[0]);
        EXPECT_EQ_MAP(1, c.m_key_images, ki[1]);
        EXPECT_EQ_MAP(2, c.m_key_images, ki[2]);
    }
    // unconfirmed txs
    EXPECT_TRUE(c.m_unconfirmed_txs.size() == 0);
    // payments
    ASSERT_TRUE(c.m_payments.size() == 2);
    {
        auto pd0 = c.m_payments.begin();
        auto pd1 = pd0;
        ++pd1;
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd0->first) == "0000000000000000000000000000000000000000000000000000000000000000");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd1->first) == "0000000000000000000000000000000000000000000000000000000000000000");
        if (epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc")
            swap(pd0, pd1);
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(pd1->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
        EXPECT_TRUE(pd0->second.m_amount == 13400845012231);
        EXPECT_TRUE(pd1->second.m_amount == 1200000000000);
        EXPECT_TRUE(pd0->second.m_block_height == 818424);
        EXPECT_TRUE(pd1->second.m_block_height == 818522);
        EXPECT_TRUE(pd0->second.m_unlock_time == 818484);
        EXPECT_TRUE(pd1->second.m_unlock_time == 0);
        EXPECT_TRUE(pd0->second.m_timestamp == 1483263366);
        EXPECT_TRUE(pd1->second.m_timestamp == 1483272963);
    }
    // tx keys
    ASSERT_TRUE(c.m_tx_keys.size() == 2);
    {
        const std::vector<std::pair<std::string, std::string>> txid_txkey =
        {
            {"b9aac8c020ab33859e0c0b6331f46a8780d349e7ac17b067116e2d87bf48daad", "bf3614c6de1d06c09add5d92a5265d8c76af706f7bc6ac830d6b0d109aa87701"},
            {"6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", "e556884246df5a787def6732c6ea38f1e092fa13e5ea98f732b99c07a6332003"},
        };
        for (size_t i = 0; i < txid_txkey.size(); ++i)
        {
            crypto::hash txid;
            crypto::secret_key txkey;
            epee::string_tools::hex_to_pod(txid_txkey[i].first, txid);
            epee::string_tools::hex_to_pod(txid_txkey[i].second, txkey);
            EXPECT_EQ_MAP(txkey, c.m_tx_keys, txid);
        }
    }
    // confirmed txs
    EXPECT_TRUE(c.m_confirmed_txs.size() == 1);
    // tx notes
    ASSERT_TRUE(c.m_tx_notes.size() == 2);
    {
        crypto::hash h[2];
        epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", h[0]);
        epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", h[1]);
        EXPECT_EQ_MAP("sample note", c.m_tx_notes, h[0]);
        EXPECT_EQ_MAP("sample note 2", c.m_tx_notes, h[1]);
    }
    // unconfirmed payments
    EXPECT_TRUE(c.m_unconfirmed_payments.size() == 0);
    // pub keys
    ASSERT_TRUE(c.m_pub_keys.size() == 3);
    {
        crypto::public_key pubkey[3];
        epee::string_tools::hex_to_pod("33f75f264574cb3a9ea5b24220a5312e183d36dc321c9091dfbb720922a4f7b0", pubkey[0]);
        epee::string_tools::hex_to_pod("5066ff2ce9861b1d131cf16eeaa01264933a49f28242b97b153e922ec7b4b3cb", pubkey[1]);
        epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8", pubkey[2]);
        EXPECT_EQ_MAP(0, c.m_pub_keys, pubkey[0]);
        EXPECT_EQ_MAP(1, c.m_pub_keys, pubkey[1]);
        EXPECT_EQ_MAP(2, c.m_pub_keys, pubkey[2]);
    }
    // address book
    ASSERT_TRUE(c.m_address_book.size() == 1);
    {
        auto address_book_row = c.m_address_book.begin();
        EXPECT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_spend_public_key) == "9bc53a6ff7b0831c9470f71b6b972dbe5ad1e8606f72682868b1dda64e119fb3");
        EXPECT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_view_public_key) == "49fece1ef97dc0c0f7a5e2106e75e96edd910f7e86b56e1e308cd0cf734df191");
        EXPECT_TRUE(address_book_row->m_description == "testnet wallet 9y52S6");
    }
}

TEST(wallet_storage, store_to_file2file)
{
    const path source_wallet_file = unit_test::data_dir / "wallet_00fd416a";
    const path interm_wallet_file = unit_test::data_dir / "wallet_00fd416a_copy_file2file";
    const path target_wallet_file = unit_test::data_dir / "wallet_00fd416a_new_file2file";

    ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

    copy_file(source_wallet_file, interm_wallet_file, copy_option::overwrite_if_exists);
    copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys", copy_option::overwrite_if_exists);

    ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    epee::wipeable_string password("beepbeep");

    const auto files_are_expected = [&]()
    {
        EXPECT_FALSE(is_file_exist(interm_wallet_file.string()));
        EXPECT_FALSE(is_file_exist(interm_wallet_file.string() + ".keys"));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    };

    {
        tools::wallet2 w;
        w.load(interm_wallet_file.string(), password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
        w.store_to(target_wallet_file.string(), password);
        files_are_expected();
    }

    files_are_expected();

    {
        tools::wallet2 w;
        w.load(target_wallet_file.string(), password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
        w.store_to("", "");
        files_are_expected();
    }

    files_are_expected();
}

TEST(wallet_storage, store_to_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_mem2file";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    epee::wipeable_string password("beepbeep2");

    {
        tools::wallet2 w;
        w.generate("", password);
        w.store_to(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w;
        w.load(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
}

TEST(wallet_storage, change_password_same_file)
{
    const path source_wallet_file = unit_test::data_dir / "wallet_00fd416a";
    const path interm_wallet_file = unit_test::data_dir / "wallet_00fd416a_copy_change_password_same";

    ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

    copy_file(source_wallet_file, interm_wallet_file, copy_option::overwrite_if_exists);
    copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys", copy_option::overwrite_if_exists);

    ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

    epee::wipeable_string old_password("beepbeep");
    epee::wipeable_string new_password("meepmeep");

    {
        tools::wallet2 w;
        w.load(interm_wallet_file.string(), old_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
        w.change_password(w.get_wallet_file(), old_password, new_password);
    }

    {
        tools::wallet2 w;
        w.load(interm_wallet_file.string(), new_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
    }

    {
        tools::wallet2 w;
        EXPECT_THROW(w.load(interm_wallet_file.string(), old_password), tools::error::invalid_password);
    }
}

TEST(wallet_storage, change_password_different_file)
{
    const path source_wallet_file = unit_test::data_dir / "wallet_00fd416a";
    const path interm_wallet_file = unit_test::data_dir / "wallet_00fd416a_copy_change_password_diff";
    const path target_wallet_file = unit_test::data_dir / "wallet_00fd416a_new_change_password_diff";

    ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

    copy_file(source_wallet_file, interm_wallet_file, copy_option::overwrite_if_exists);
    copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys", copy_option::overwrite_if_exists);

    ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    epee::wipeable_string old_password("beepbeep");
    epee::wipeable_string new_password("meepmeep");

    {
        tools::wallet2 w;
        w.load(interm_wallet_file.string(), old_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
        w.change_password(target_wallet_file.string(), old_password, new_password);
    }

    EXPECT_FALSE(is_file_exist(interm_wallet_file.string()));
    EXPECT_FALSE(is_file_exist(interm_wallet_file.string() + ".keys"));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w;
        w.load(target_wallet_file.string(), new_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(WALLET_00fd416a_PRIMARY_ADDRESS, primary_address);
    }
}

TEST(wallet_storage, change_password_in_memory)
{
    const epee::wipeable_string password1("monero");
    const epee::wipeable_string password2("means money");
    const epee::wipeable_string password_wrong("is traceable");

    tools::wallet2 w;
    w.generate("", password1);
    const std::string primary_address_1 = w.get_address_as_str();
    w.change_password("", password1, password2);
    const std::string primary_address_2 = w.get_address_as_str();
    EXPECT_EQ(primary_address_1, primary_address_2);

    EXPECT_THROW(w.change_password("", password_wrong, password1), tools::error::invalid_password);
}

TEST(wallet_storage, change_password_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_change_password_mem2file";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    const epee::wipeable_string password1("https://safecurves.cr.yp.to/rigid.html");
    const epee::wipeable_string password2(
        "https://csrc.nist.gov/csrc/media/projects/crypto-standards-development-process/documents/dualec_in_x982_and_sp800-90.pdf");
    
    std::string primary_address_1, primary_address_2;
    {
        tools::wallet2 w;
        w.generate("", password1);
        primary_address_1 = w.get_address_as_str();
        w.change_password(target_wallet_file.string(), password1, password2);
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w;
        w.load(target_wallet_file.string(), password2);
        primary_address_2 = w.get_address_as_str();
    }

    EXPECT_EQ(primary_address_1, primary_address_2);
}

TEST(wallet_storage, gen_ascii_format)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_gen_ascii_format";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    const epee::wipeable_string password("https://safecurves.cr.yp.to/rigid.html");
    
    std::string primary_address_1, primary_address_2;
    {
        tools::wallet2 w;
        w.set_export_format(tools::wallet2::Ascii);
        ASSERT_EQ(tools::wallet2::Ascii, w.export_format());
        w.generate(target_wallet_file.string(), password);
        primary_address_1 = w.get_address_as_str();
    }

    ASSERT_TRUE(is_file_exist(target_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    // Assert that we store keys in ascii format
    {
        std::string key_file_contents;
        ASSERT_TRUE(epee::file_io_utils::load_file_to_string(target_wallet_file.string() + ".keys", key_file_contents));
        EXPECT_NE(std::string::npos, key_file_contents.find(WALLET2_ASCII_OUTPUT_MAGIC));
        for (const char c : key_file_contents)
            ASSERT_TRUE(std::isprint(c) || c == '\n' || c == '\r');
    }

    {
        tools::wallet2 w;
        w.set_export_format(tools::wallet2::Ascii);
        ASSERT_EQ(tools::wallet2::Ascii, w.export_format());
        w.load(target_wallet_file.string(), password);
        primary_address_2 = w.get_address_as_str();
    }

    EXPECT_EQ(primary_address_1, primary_address_2);
}

TEST(wallet_storage, change_export_format)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_change_export_format";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    const epee::wipeable_string password("https://safecurves.cr.yp.to/rigid.html");
    
    std::string primary_address_1, primary_address_2;
    {
        tools::wallet2 w;
        ASSERT_EQ(tools::wallet2::Binary, w.export_format());
        w.generate(target_wallet_file.string(), password);
        primary_address_1 = w.get_address_as_str();
        w.store();

        // Assert that we initially store keys in binary format
        {
            std::string key_file_contents;
            ASSERT_TRUE(epee::file_io_utils::load_file_to_string(target_wallet_file.string() + ".keys", key_file_contents));
            EXPECT_EQ(std::string::npos, key_file_contents.find(WALLET2_ASCII_OUTPUT_MAGIC));
            bool only_printable = true;
            for (const char c : key_file_contents)
            {
                if (!std::isprint(c) && c != '\n' && c != '\r')
                {
                    only_printable = false;
                    break;
                }
            }
            EXPECT_FALSE(only_printable);
        }

        // switch formats and store
        w.set_export_format(tools::wallet2::Ascii);
        ASSERT_EQ(tools::wallet2::Ascii, w.export_format());
        w.store_to("", password, /*force_rewrite_keys=*/ true);
    }

    ASSERT_TRUE(is_file_exist(target_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    // Assert that we store keys in ascii format
    {
        std::string key_file_contents;
        ASSERT_TRUE(epee::file_io_utils::load_file_to_string(target_wallet_file.string() + ".keys", key_file_contents));
        EXPECT_NE(std::string::npos, key_file_contents.find(WALLET2_ASCII_OUTPUT_MAGIC));
        for (const char c : key_file_contents)
            ASSERT_TRUE(std::isprint(c) || c == '\n' || c == '\r');
    }

    {
        tools::wallet2 w;
        w.set_export_format(tools::wallet2::Ascii);
        ASSERT_EQ(tools::wallet2::Ascii, w.export_format());
        w.load(target_wallet_file.string(), password);
        primary_address_2 = w.get_address_as_str();
    }

    EXPECT_EQ(primary_address_1, primary_address_2);
}

TEST(wallet_storage, legacy_load_sanity)
{
    const boost::filesystem::path original_wallet_file = unit_test::data_dir / "wallet_9svHk1";
    const epee::wipeable_string password = "test";

    tools::wallet2 w2(cryptonote::TESTNET, 1, true);
    w2.load(original_wallet_file.string(), password);

    check_wallet_9svHk1_cache_contents(w2);
    check_wallet_9svHk1_key_contents(w2);
}

TEST(wallet_storage, read_old_wallet)
{
    const boost::filesystem::path wallet_file = unit_test::data_dir / "wallet_9svHk1";
    const epee::wipeable_string password = "test";

    wallet2_basic::cache c;
    wallet2_basic::keys_data k;
    wallet2_basic::load_keys_and_cache_from_file(wallet_file.string(), password, c, k);

    check_wallet_9svHk1_cache_contents(c);
    check_wallet_9svHk1_key_contents(k);
}

TEST(wallet_storage, backwards_compatible_store_file)
{
    const boost::filesystem::path original_wallet_file = unit_test::data_dir / "wallet_9svHk1";
    const epee::wipeable_string password = "test";

    const boost::filesystem::path target_wallet_file = unit_test::data_dir / "wallet_9svHk1_backwards_compatible_store_file";

    wallet2_basic::cache c;
    wallet2_basic::keys_data k;

    // load then save to target_wallet_file
    wallet2_basic::load_keys_and_cache_from_file
    (
        original_wallet_file.string(),
        password,
        c,
        k
    );
    wallet2_basic::store_keys_and_cache_to_file
    (
        c,
        k,
        password,
        target_wallet_file.string()
    );

    tools::wallet2 w2(cryptonote::TESTNET, 1, true);
    w2.load(target_wallet_file.string(), password); // load the new file created by wallet2_basic

    check_wallet_9svHk1_cache_contents(w2);
    check_wallet_9svHk1_key_contents(w2);
}

TEST(wallet_storage, back_compat_ascii_format)
{
    const boost::filesystem::path original_wallet_file = unit_test::data_dir / "wallet_9svHk1";
    const boost::filesystem::path intermediate_wallet_file = unit_test::data_dir / "wallet_9svHk1_back_compat_ascii_load";
    const boost::filesystem::path final_wallet_file = unit_test::data_dir / "wallet_9svHk1_back_compat_ascii_load_w2b";
    const epee::wipeable_string password = "test";

    copy_file(original_wallet_file, intermediate_wallet_file, copy_option::overwrite_if_exists);
    copy_file(original_wallet_file.string() + ".keys", intermediate_wallet_file.string() + ".keys", copy_option::overwrite_if_exists);

    {
        tools::wallet2 w(cryptonote::TESTNET, 1, true);
        w.load(intermediate_wallet_file.string(), password);
        w.set_export_format(tools::wallet2::Ascii);
        w.store();
        w.rewrite(intermediate_wallet_file.string(), password);
    }

    {
        wallet2_basic::cache c;
        wallet2_basic::keys_data k;
        wallet2_basic::load_keys_and_cache_from_file
        (
            intermediate_wallet_file.string(),
            password,
            c,
            k
        );

        check_wallet_9svHk1_cache_contents(c);
        check_wallet_9svHk1_key_contents(k, wallet2_basic::Ascii);

        wallet2_basic::store_keys_and_cache_to_file
        (
            c,
            k,
            password,
            final_wallet_file.string(),
            1,
            wallet2_basic::Ascii
        );
    }

    {
        tools::wallet2 w(cryptonote::TESTNET, 1, true);
        w.set_export_format(tools::wallet2::Ascii);
        w.load(final_wallet_file.string(), password);

        check_wallet_9svHk1_cache_contents(w);
        check_wallet_9svHk1_key_contents(w, tools::wallet2::Ascii);
    }
}

TEST(wallet_storage, back_compat_kdf_rounds)
{
    static constexpr uint64_t const KDF_ROUNDS_TEST_MIN = 2;
    static constexpr uint64_t const KDF_ROUNDS_TEST_MAX = 8;
    static constexpr uint64_t const KDF_ROUNDS_TEST_STEP = 3;

    const boost::filesystem::path original_wallet_file = unit_test::data_dir / "wallet_9svHk1";
    const epee::wipeable_string password = "test";

    for (uint64_t kdf_rounds = KDF_ROUNDS_TEST_MIN; kdf_rounds <= KDF_ROUNDS_TEST_MAX; kdf_rounds += KDF_ROUNDS_TEST_STEP)
    {
        const boost::filesystem::path target_wallet_file = unit_test::data_dir / ("wallet_9svHk1_back_compat_kdf_rounds_" + std::to_string(kdf_rounds));

        wallet2_basic::cache c;
        wallet2_basic::keys_data k;

        // load then save to target_wallet_file
        wallet2_basic::load_keys_and_cache_from_file
        (
            original_wallet_file.string(),
            password,
            c,
            k
        );
        wallet2_basic::store_keys_and_cache_to_file
        (
            c,
            k,
            password,
            target_wallet_file.string(),
            kdf_rounds                                                   /// <----- non-standard KDF rounds
        );

        tools::wallet2 w2(cryptonote::TESTNET, kdf_rounds, true);        /// <----- non-standard KDF rounds
        w2.load(target_wallet_file.string(), password); // load the new file created by wallet2_basic

        check_wallet_9svHk1_cache_contents(w2);
        check_wallet_9svHk1_key_contents(w2);
    }
}

TEST(wallet_storage, load_multiple_kdf_rounds)
{
    const boost::filesystem::path wallet_file = unit_test::data_dir / "wallet_load_non_standard_kdf_rounds";
    const uint32_t kdf_rounds = 2 + crypto::rand_idx<uint32_t>(10); // kdf_rounds in [2, 11]
    const epee::wipeable_string password("88 FR 72701");
    const crypto::hash random_txid = crypto::rand<crypto::hash>();
    const std::string txid_note = "note for txid ;)";

    cryptonote::account_base acc1, acc2;

    if (exists(wallet_file))
        remove(wallet_file);
    if (exists(wallet_file.string() + ".keys"))
        remove(wallet_file.string() + ".keys");

    {
        tools::wallet2 w(cryptonote::STAGENET, kdf_rounds, true);
        w.generate(wallet_file.string(), password);
        acc1 = w.get_account();
        w.set_tx_note(random_txid, txid_note);
        w.store();
    }

    {
        wallet2_basic::cache c;
        wallet2_basic::keys_data k;

        wallet2_basic::load_keys_and_cache_from_file
        (
            wallet_file.string(),
            password,
            c,
            k,
            cryptonote::UNDEFINED,
            "",
            false,
            nullptr,
            kdf_rounds
        );

        acc2 = k.m_account;

        ASSERT_TRUE(c.m_tx_notes.find(random_txid) != c.m_tx_notes.cend());
        EXPECT_EQ(txid_note, c.m_tx_notes[random_txid]);
    }

    ASSERT_NE(crypto::secret_key{}, acc1.get_keys().m_spend_secret_key);
    ASSERT_NE(crypto::secret_key{}, acc2.get_keys().m_spend_secret_key);

    EXPECT_EQ(acc1.get_keys().m_view_secret_key, acc2.get_keys().m_view_secret_key);
    EXPECT_EQ(acc1.get_keys().m_spend_secret_key, acc2.get_keys().m_spend_secret_key);
    EXPECT_EQ(acc1.get_createtime(), acc2.get_createtime());
}
