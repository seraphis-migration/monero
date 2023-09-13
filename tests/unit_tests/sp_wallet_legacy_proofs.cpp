// // Copyright (c) 2023, The Monero Project
// //
// // All rights reserved.
// //
// // Redistribution and use in source and binary forms, with or without modification, are
// // permitted provided that the following conditions are met:
// //
// // 1. Redistributions of source code must retain the above copyright notice, this list of
// //    conditions and the following disclaimer.
// //
// // 2. Redistributions in binary form must reproduce the above copyright notice, this list
// //    of conditions and the following disclaimer in the documentation and/or other
// //    materials provided with the distribution.
// //
// // 3. Neither the name of the copyright holder nor the names of its contributors may be
// //    used to endorse or promote products derived from this software without specific
// //    prior written permission.
// //
// // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// // EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// // MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// // THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// // SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// // PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// // INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// // STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// // THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// #include "common/container_helpers.h"
// #include "common/unordered_containers_boost_serialization.h"
// #include "crypto/crypto.h"
// #include "cryptonote_config.h"
// #include "net/abstract_http_client.h"
// #include "net/http_client.h"
// #include "seraphis_wallet/legacy_knowledge_proofs.h"
// #include "unit_tests_utils.h"
// #include "wallet/wallet2_basic/wallet2_storage.h"

// #include "gtest/gtest.h"

// #include <cstdint>

// // This unit_test only works with a connection to a stagenet network at 127.0.0.1:38081
// // The wallet file t1 at 

// TEST(seraphis_wallet_legacy_proofs, spend_proof)
// {
//     // 1. set message and txid
//     std::string message{"message_test"};
//     crypto::hash txid;
//     std::string string_txid{"a1d653f138d2482cab17e16c4ecce8ed71f014178f4d8a10ac1b82641bbff36e"};
//     epee::string_tools::hex_to_pod(string_txid, txid);

//     // 2. set wallet
//     const boost::filesystem::path wallet_file = unit_test::data_dir / "t1";
//     const epee::wipeable_string password      = "";
//     wallet2_basic::cache c;
//     wallet2_basic::keys_data k;
//     wallet2_basic::load_keys_and_cache_from_file(wallet_file.string(), password, c, k);

//     // 3. set daemon 
//     std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client(
//         new epee::net_utils::http::http_simple_client);
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);
//     http_client->set_server("127.0.0.1:38081", boost::none);
//     http_client->connect(rpc_timeout);

//     // 4. get and check proof
//     std::string spend_proof;
//     spend_proof =
//         get_spend_proof_legacy(txid, message, c,k,http_client,rpc_timeout);

//     EXPECT_TRUE(check_spend_proof_legacy(txid,message,spend_proof,http_client,rpc_timeout));
//     EXPECT_FALSE(check_spend_proof_legacy(txid,"Wrong_message",spend_proof,http_client,rpc_timeout));
// }

// TEST(seraphis_wallet_legacy_proofs, in_proof)
// {

//     // 1. set message and txid
//     std::string message{"message_test"};
//     crypto::hash txid;
//     std::string string_txid{"12781423033e6abddf87990693ca5f70bb3ed4836fdb4c05187ecd6787b709fb"};
//     epee::string_tools::hex_to_pod(string_txid, txid);

//     // 2. set wallet
//     const boost::filesystem::path wallet_file = unit_test::data_dir / "t1";
//     const epee::wipeable_string password      = "";
//     wallet2_basic::cache c;
//     wallet2_basic::keys_data k;
//     wallet2_basic::load_keys_and_cache_from_file(wallet_file.string(), password, c, k);


//     // 3. set address to make proof on and get info about it
//     std::string str_address{"5AhDwDwTbBaEKYfLfDPUvGXse1BFNmybtWZnRiPVweocWw2fX3F6FCwLTxqDM4H2u8Vg9AbHXZ1TiR9KqAKgQEeZNvSNuMs"};
//     cryptonote::address_parse_info info;
//     if (!cryptonote::get_account_address_from_str(info, cryptonote::network_type::STAGENET, str_address))
//     {
//         std::cout << "failed to parse address" <<std::endl;
//     }

//     // 4. set daemon and device
//     std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client(
//         new epee::net_utils::http::http_simple_client);
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);
//     http_client->set_server("127.0.0.1:38081", boost::none);
//     http_client->connect(rpc_timeout);
//     // hw::device &hwdev = hw::get_device("default");
//     hw::device &hwdev = k.m_account.get_device();

//     // 5. get and check proof
//     std::string in_proof;
//     in_proof = get_tx_proof_legacy(txid, info.address, info.is_subaddress, message, c, k, http_client, rpc_timeout, hwdev);

//     uint64_t received, confirmations;
//     bool in_pool;
//     EXPECT_TRUE(check_tx_proof_legacy(txid,
//         info.address,
//         info.is_subaddress,
//         message,
//         in_proof,
//         received,
//         in_pool,
//         confirmations,
//         http_client,
//         rpc_timeout));

//     EXPECT_FALSE(check_tx_proof_legacy(txid,
//         info.address,
//         info.is_subaddress,
//         "wrong_message",
//         in_proof,
//         received,
//         in_pool,
//         confirmations,
//         http_client,
//         rpc_timeout));
// }

// TEST(seraphis_wallet_legacy_proofs, out_proof)
// {
//     // 1. set message and txid
//     std::string message{"message_test"};
//     crypto::hash txid;
//     std::string string_txid{"a1d653f138d2482cab17e16c4ecce8ed71f014178f4d8a10ac1b82641bbff36e"};
//     epee::string_tools::hex_to_pod(string_txid, txid);

//     // 2. set wallet
//     const boost::filesystem::path wallet_file = unit_test::data_dir / "t1";
//     const epee::wipeable_string password      = "";
//     wallet2_basic::cache c;
//     wallet2_basic::keys_data k;
//     wallet2_basic::load_keys_and_cache_from_file(wallet_file.string(), password, c, k);

//     // 3. set address to make proof on and get info about it
//     std::string str_address{
//         "5AHsGHScfvHgx5xzsTvkHFPwMnHvPX2HRTB2viVXHwL4KwjRV6LDc7uFXFmY9dLRWN7e6SaakqMm46G5t2pX5QnuSeVjgq4"};
//     cryptonote::address_parse_info info;
//     if (!cryptonote::get_account_address_from_str(info, cryptonote::network_type::STAGENET, str_address))
//     {
//         std::cout << "failed to parse address" << std::endl;
//     }

//     // 4. set daemon
//     std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client(
//         new epee::net_utils::http::http_simple_client);
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);
//     http_client->set_server("127.0.0.1:38081", boost::none);
//     http_client->connect(rpc_timeout);
//     // hw::device &hwdev = hw::get_device("default");
//     hw::device &hwdev = k.m_account.get_device();

//     // 5. get and check proof
//     std::string out_proof;
//     out_proof =
//         get_tx_proof_legacy(txid, info.address, info.is_subaddress, message, c, k, http_client, rpc_timeout, hwdev);

//     uint64_t received, confirmations;
//     bool in_pool;
//     EXPECT_TRUE(check_tx_proof_legacy(txid,
//         info.address,
//         info.is_subaddress,
//         message,
//         out_proof,
//         received,
//         in_pool,
//         confirmations,
//         http_client,
//         rpc_timeout));

//     EXPECT_FALSE(check_tx_proof_legacy(txid,
//         info.address,
//         info.is_subaddress,
//         "wrong_message",
//         out_proof,
//         received,
//         in_pool,
//         confirmations,
//         http_client,
//         rpc_timeout));
// }

// TEST(seraphis_wallet_legacy_proofs, reserve_proof)
// {
//     // 1. set message 
//     std::string message{"message_test"};

//     // 2. set wallet
//     const boost::filesystem::path wallet_file = unit_test::data_dir / "t1";
//     const epee::wipeable_string password      = "";
//     wallet2_basic::cache c;
//     wallet2_basic::keys_data k;
//     wallet2_basic::load_keys_and_cache_from_file(wallet_file.string(), password, c, k);

//     // 3. set daemon or find a way to check proof without it
//     std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client(
//         new epee::net_utils::http::http_simple_client);
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);
//     http_client->set_server("127.0.0.1:38081", boost::none);
//     http_client->connect(rpc_timeout);

//     // 4. set address to make proof on and get info about it
//     std::string str_address{
//         "5AhDwDwTbBaEKYfLfDPUvGXse1BFNmybtWZnRiPVweocWw2fX3F6FCwLTxqDM4H2u8Vg9AbHXZ1TiR9KqAKgQEeZNvSNuMs"};
//     cryptonote::address_parse_info info;
//     if (!cryptonote::get_account_address_from_str(info, cryptonote::network_type::STAGENET, str_address))
//     {
//         std::cout << "failed to parse address" << std::endl;
//     }

//     // 5. get and check proof
//     boost::optional<std::pair<uint32_t, uint64_t>> account_minreserve{{0, 1}};
//     std::string sig_reserve = get_reserve_proof_legacy(account_minreserve, message, c, k);

//     uint64_t total, spent;
//     EXPECT_FALSE(
//         check_reserve_proof_legacy(info.address, "Wrong_message", sig_reserve, total, spent, http_client, rpc_timeout));
//     EXPECT_TRUE(check_reserve_proof_legacy(info.address, message, sig_reserve, total, spent, http_client, rpc_timeout));
    
//     // Even if the signature is good, it does not mean that the user already has that reserve as it could be spent
//     // boost::format(tr("Good signature -- total: %s, spent: %s, unspent: %s")) % print_money(total) % print_money(spent) % print_money(total - spent);
// }
