// Copyright (c) 2017-2023, The Monero Project
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
#include "crypto/generators.h"
#include "cryptonote_basic/account_generators.h"
#include "multisig/multisig.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_account_era_conversion_msg.h"
#include "multisig/multisig_kex_msg.h"
#include "multisig/multisig_mocks.h"
#include "multisig/multisig_partial_cn_key_image_msg.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "wallet/wallet2.h"

#include "gtest/gtest.h"

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static const struct
{
  const char *address;
  const char *spendkey;
} test_addresses[] =
{
  {
    "9uvjbU54ZJb8j7Dcq1h3F1DnBRkxXdYUX4pbJ7mE3ghM8uF3fKzqRKRNAKYZXcNLqMg7MxjVVD2wKC2PALUwEveGSC3YSWD",
    "2dd6e34a234c3e8b5d29a371789e4601e96dee4ea6f7ef79224d1a2d91164c01"
  },
  {
    "9ywDBAyDbb6QKFiZxDJ4hHZqZEQXXCR5EaYNcndUpqPDeE7rEgs6neQdZnhcDrWbURYK8xUjhuG2mVjJdmknrZbcG7NnbaB",
    "fac47aecc948ce9d3531aa042abb18235b1df632087c55a361b632ffdd6ede0c"
  },
  {
    "9t6Hn946u3eah5cuncH1hB5hGzsTUoevtf4SY7MHN5NgJZh2SFWsyVt3vUhuHyRKyrCQvr71Lfc1AevG3BXE11PQFoXDtD8",
    "bbd3175ef9fd9f5eefdc43035f882f74ad14c4cf1799d8b6f9001bc197175d02"
  },
  {
    "9zmAWoNyNPbgnYSm3nJNpAKHm6fCcs3MR94gBWxp9MCDUiMUhyYFfyQETUDLPF7DP6ZsmNo6LRxwPP9VmhHNxKrER9oGigT",
    "f2efae45bef1917a7430cda8fcffc4ee010e3178761aa41d4628e23b1fe2d501"
  },
  {
    "9ue8NJMg3WzKxTtmjeXzWYF5KmU6dC7LHEt9wvYdPn2qMmoFUa8hJJHhSHvJ46UEwpDyy5jSboNMRaDBKwU54NT42YcNUp5",
    "a4cef54ed3fd61cd78a2ceb82ecf85a903ad2db9a86fb77ff56c35c56016280a"
  }
};

static const size_t KEYS_COUNT = 5;

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_wallet(unsigned int idx, tools::wallet2 &wallet)
{
  ASSERT_TRUE(idx < sizeof(test_addresses) / sizeof(test_addresses[0]));

  crypto::secret_key spendkey;
  epee::string_tools::hex_to_pod(test_addresses[idx].spendkey, spendkey);

  try
  {
    wallet.init("", boost::none, "", 0, true, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
    wallet.set_subaddress_lookahead(1, 1);
    wallet.generate("", "", spendkey, true, false);
    ASSERT_TRUE(test_addresses[idx].address == wallet.get_account().get_public_address_str(cryptonote::TESTNET));
    wallet.decrypt_keys("");
    ASSERT_TRUE(test_addresses[idx].spendkey == epee::string_tools::pod_to_hex(wallet.get_account().get_keys().m_spend_secret_key));
    wallet.encrypt_keys("");
  }
  catch (const std::exception &e)
  {
    MFATAL("Error creating test wallet: " << e.what());
    ASSERT_TRUE(0);
  }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static std::vector<std::string> exchange_round(std::vector<tools::wallet2>& wallets, const std::vector<std::string>& infos)
{
  std::vector<std::string> new_infos;
  new_infos.reserve(infos.size());

  for (size_t i = 0; i < wallets.size(); ++i)
    new_infos.push_back(wallets[i].exchange_multisig_keys("", infos));

  return new_infos;
}

static std::vector<std::string> exchange_round_force_update(std::vector<tools::wallet2>& wallets,
  const std::vector<std::string>& infos,
  const std::size_t round_in_progress)
{
  EXPECT_TRUE(wallets.size() == infos.size());
  std::vector<std::string> new_infos;
  std::vector<std::string> temp_force_update_infos;
  new_infos.reserve(infos.size());

  // when force-updating, we only need at most 'num_signers - 1 - (round - 1)' messages from other signers
  size_t num_other_messages_required{wallets.size() - 1 - (round_in_progress - 1)};
  if (num_other_messages_required > wallets.size())
    num_other_messages_required = 0;  //overflow case for post-kex verification round of 1-of-N

  for (size_t i = 0; i < wallets.size(); ++i)
  {
    temp_force_update_infos.clear();
    temp_force_update_infos.reserve(num_other_messages_required + 1);
    temp_force_update_infos.push_back(infos[i]);  //always include the local signer's message for this round

    size_t infos_collected{0};
    for (size_t wallet_index = 0; wallet_index < wallets.size(); ++wallet_index)
    {
      // skip the local signer's message
      if (wallet_index == i)
        continue;

      temp_force_update_infos.push_back(infos[wallet_index]);
      ++infos_collected;

      if (infos_collected == num_other_messages_required)
        break;
    }

    new_infos.push_back(wallets[i].exchange_multisig_keys("", temp_force_update_infos, true));
  }

  return new_infos;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void check_results(const std::vector<std::string> &intermediate_infos,
  std::vector<tools::wallet2>& wallets,
  const std::uint32_t M)
{
  // check results
  std::unordered_set<crypto::secret_key> unique_privkeys;
  rct::key composite_pubkey = rct::identity();

  ASSERT_TRUE(wallets.size() > 0);
  wallets[0].decrypt_keys("");
  crypto::public_key spend_pubkey = wallets[0].get_account().get_keys().m_account_address.m_spend_public_key;
  crypto::secret_key view_privkey = wallets[0].get_account().get_keys().m_view_secret_key;
  crypto::public_key view_pubkey;
  EXPECT_TRUE(crypto::secret_key_to_public_key(view_privkey, view_pubkey));
  wallets[0].encrypt_keys("");

  // at the end of multisig kex, all wallets should emit a post-kex message with the same two pubkeys
  std::vector<crypto::public_key> post_kex_msg_pubkeys;
  ASSERT_TRUE(intermediate_infos.size() == wallets.size());
  for (const std::string &intermediate_info : intermediate_infos)
  {
    multisig::multisig_kex_msg post_kex_msg;
    EXPECT_TRUE(!intermediate_info.empty());
    EXPECT_NO_THROW(post_kex_msg = intermediate_info);

    if (post_kex_msg_pubkeys.size() != 0)
      EXPECT_TRUE(post_kex_msg_pubkeys == post_kex_msg.get_msg_pubkeys());  //assumes sorting is always the same
    else
      post_kex_msg_pubkeys = post_kex_msg.get_msg_pubkeys();

    EXPECT_TRUE(post_kex_msg_pubkeys.size() == 2);
  }

  // the post-kex pubkeys should equal the account's public view and spend keys
  EXPECT_TRUE(std::find(post_kex_msg_pubkeys.begin(), post_kex_msg_pubkeys.end(), spend_pubkey) != post_kex_msg_pubkeys.end());
  EXPECT_TRUE(std::find(post_kex_msg_pubkeys.begin(), post_kex_msg_pubkeys.end(), view_pubkey) != post_kex_msg_pubkeys.end());

  // each wallet should have the same state (private view key, public spend key), and the public spend key should be
  //   reproducible from the private spend keys found in each account
  bool ready;
  uint32_t threshold, total;

  for (tools::wallet2 &wallet : wallets)
  {
    wallet.decrypt_keys("");
    EXPECT_TRUE(wallet.multisig(&ready, &threshold, &total));
    EXPECT_TRUE(ready);
    EXPECT_TRUE(threshold == M);
    EXPECT_TRUE(total == wallets.size());

    EXPECT_TRUE(wallets[0].get_account().get_public_address_str(cryptonote::TESTNET) ==
      wallet.get_account().get_public_address_str(cryptonote::TESTNET));
    
    EXPECT_EQ(spend_pubkey, wallet.get_account().get_keys().m_account_address.m_spend_public_key);
    EXPECT_EQ(view_privkey, wallet.get_account().get_keys().m_view_secret_key);
    EXPECT_EQ(view_pubkey, wallet.get_account().get_keys().m_account_address.m_view_public_key);

    // sum together unique multisig keys
    for (const auto &privkey : wallet.get_account().get_keys().m_multisig_keys)
    {
      EXPECT_NE(privkey, crypto::null_skey);

      if (unique_privkeys.find(privkey) == unique_privkeys.end())
      {
        unique_privkeys.insert(privkey);
        crypto::public_key pubkey;
        EXPECT_TRUE(crypto::secret_key_to_public_key(privkey, pubkey));
        EXPECT_NE(privkey, crypto::null_skey);
        EXPECT_NE(pubkey, crypto::null_pkey);
        EXPECT_NE(pubkey, rct::rct2pk(rct::identity()));
        rct::addKeys(composite_pubkey, composite_pubkey, rct::pk2rct(pubkey));
      }
    }
    wallet.encrypt_keys("");
  }

  // final key via sum of privkeys should equal the wallets' public spend key
  wallets[0].decrypt_keys("");
  EXPECT_EQ(wallets[0].get_account().get_keys().m_account_address.m_spend_public_key, rct::rct2pk(composite_pubkey));
  wallets[0].encrypt_keys("");
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_wallets(const unsigned int M, const unsigned int N, const bool force_update)
{
  std::vector<tools::wallet2> wallets(N);
  ASSERT_TRUE(wallets.size() > 1 && wallets.size() <= KEYS_COUNT);
  ASSERT_TRUE(M <= wallets.size());
  std::uint32_t total_rounds_required = multisig::multisig_setup_rounds_required(wallets.size(), M);
  std::uint32_t rounds_complete{0};

  // initialize wallets, get first round multisig kex msgs
  std::vector<std::string> initial_infos(wallets.size());

  for (size_t i = 0; i < wallets.size(); ++i)
  {
    make_wallet(i, wallets[i]);

    wallets[i].decrypt_keys("");
    initial_infos[i] = wallets[i].get_multisig_first_kex_msg();
    wallets[i].encrypt_keys("");
  }

  // wallets should not be multisig yet
  for (const auto &wallet: wallets)
  {
    ASSERT_FALSE(wallet.multisig());
  }

  // make wallets multisig, get second round kex messages (if appropriate)
  std::vector<std::string> intermediate_infos(wallets.size());

  for (size_t i = 0; i < wallets.size(); ++i)
  {
    intermediate_infos[i] = wallets[i].make_multisig("", initial_infos, M);
  }

  ++rounds_complete;

  // perform kex rounds until kex is complete
  bool ready;
  wallets[0].multisig(&ready);
  while (!ready)
  {
    if (force_update)
      intermediate_infos = exchange_round_force_update(wallets, intermediate_infos, rounds_complete + 1);
    else
      intermediate_infos = exchange_round(wallets, intermediate_infos);

    wallets[0].multisig(&ready);
    ++rounds_complete;
  }

  EXPECT_EQ(total_rounds_required, rounds_complete);

  check_results(intermediate_infos, wallets, M);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_wallets_boosting(std::vector<tools::wallet2>& wallets, unsigned int M)
{
  ASSERT_TRUE(wallets.size() > 1 && wallets.size() <= KEYS_COUNT);
  ASSERT_TRUE(M <= wallets.size());
  std::uint32_t kex_rounds_required = multisig::multisig_kex_rounds_required(wallets.size(), M);
  std::uint32_t rounds_required = multisig::multisig_setup_rounds_required(wallets.size(), M);
  std::uint32_t rounds_complete{0};

  // initialize wallets, get first round multisig kex msgs
  std::vector<std::string> initial_infos(wallets.size());

  for (size_t i = 0; i < wallets.size(); ++i)
  {
    make_wallet(i, wallets[i]);

    wallets[i].decrypt_keys("");
    initial_infos[i] = wallets[i].get_multisig_first_kex_msg();
    wallets[i].encrypt_keys("");
  }

  // wallets should not be multisig yet
  for (const auto &wallet: wallets)
  {
    ASSERT_FALSE(wallet.multisig());
  }

  // get round 2 booster messages for wallet0 (if appropriate)
  auto initial_infos_truncated = initial_infos;
  initial_infos_truncated.erase(initial_infos_truncated.begin());

  std::vector<std::string> wallet0_booster_infos;
  wallet0_booster_infos.reserve(wallets.size() - 1);

  if (rounds_complete + 1 < kex_rounds_required)
  {
    for (size_t i = 1; i < wallets.size(); ++i)
    {
      wallet0_booster_infos.push_back(
          wallets[i].get_multisig_key_exchange_booster("", initial_infos_truncated, M, wallets.size())
        );
    }
  }

  // make wallets multisig
  std::vector<std::string> intermediate_infos(wallets.size());

  for (size_t i = 0; i < wallets.size(); ++i)
    intermediate_infos[i] = wallets[i].make_multisig("", initial_infos, M);

  ++rounds_complete;

  // perform all kex rounds
  // boost wallet0 each round, so wallet0 is always 1 round ahead
  std::string wallet0_intermediate_info;
  std::vector<std::string> new_infos(intermediate_infos.size());
  bool ready;
  wallets[0].multisig(&ready);
  while (!ready)
  {
    // use booster infos to update wallet0 'early'
    if (rounds_complete < kex_rounds_required)
      new_infos[0] = wallets[0].exchange_multisig_keys("", wallet0_booster_infos);
    else
    {
      // force update the post-kex round with wallet0's post-kex message since wallet0 is 'ahead' of the other wallets
      wallet0_booster_infos = {wallets[0].exchange_multisig_keys("", {})};
      new_infos[0] = wallets[0].exchange_multisig_keys("", wallet0_booster_infos, true);
    }

    // get wallet0 booster infos for next round
    if (rounds_complete + 1 < kex_rounds_required)
    {
      // remove wallet0 info for this round (so boosters have incomplete kex message set)
      auto intermediate_infos_truncated = intermediate_infos;
      intermediate_infos_truncated.erase(intermediate_infos_truncated.begin());

      // obtain booster messages from all other wallets
      for (size_t i = 1; i < wallets.size(); ++i)
      {
        wallet0_booster_infos[i-1] =
          wallets[i].get_multisig_key_exchange_booster("", intermediate_infos_truncated, M, wallets.size());
      }
    }

    // update other wallets
    for (size_t i = 1; i < wallets.size(); ++i)
        new_infos[i] = wallets[i].exchange_multisig_keys("", intermediate_infos);

    intermediate_infos = new_infos;
    ++rounds_complete;
    wallets[0].multisig(&ready);
  }

  EXPECT_EQ(rounds_required, rounds_complete);

  check_results(intermediate_infos, wallets, M);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_multisig_signer_list(const std::uint32_t num_signers, std::vector<crypto::public_key> &signer_list_out)
{
  signer_list_out.clear();
  signer_list_out.reserve(num_signers);

  for (std::uint32_t i{0}; i < num_signers; ++i)
    signer_list_out.emplace_back(rct::rct2pk(rct::pkGen()));
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void test_multisig_signer_set_filter(const std::uint32_t threshold, const std::uint32_t num_signers)
{
  using namespace multisig;

  std::vector<crypto::public_key> signer_list;
  std::vector<crypto::public_key> allowed_signers;
  std::vector<crypto::public_key> filtered_signers;
  signer_set_filter aggregate_filter;
  std::vector<signer_set_filter> filters;

  make_multisig_signer_list(num_signers, signer_list);

  // all signers are allowed
  allowed_signers = signer_list;
  EXPECT_NO_THROW(multisig_signers_to_filter(allowed_signers, signer_list, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(threshold, num_signers, aggregate_filter, filters));
  for (const signer_set_filter filter : filters)
  {
    EXPECT_NO_THROW(get_filtered_multisig_signers(filter, threshold, signer_list, filtered_signers));
    EXPECT_TRUE(filtered_signers.size() == threshold);
  }

  // num_signers - 1 signers are allowed
  if (num_signers > threshold)
  {
    allowed_signers.pop_back();
    EXPECT_NO_THROW(multisig_signers_to_filter(allowed_signers, signer_list, aggregate_filter));
    EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(threshold, num_signers, aggregate_filter, filters));
    for (const signer_set_filter filter : filters)
    {
      EXPECT_NO_THROW(get_filtered_multisig_signers(filter, threshold, signer_list, filtered_signers));
      EXPECT_TRUE(filtered_signers.size() == threshold);
    }
  }

  // threshold signers are allowed
  while (allowed_signers.size() > threshold)
    allowed_signers.pop_back();

  EXPECT_NO_THROW(multisig_signers_to_filter(allowed_signers, signer_list, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(threshold, num_signers, aggregate_filter, filters));
  for (const signer_set_filter filter : filters)
  {
    EXPECT_NO_THROW(get_filtered_multisig_signers(filter, threshold, signer_list, filtered_signers));
    EXPECT_TRUE(filtered_signers.size() == threshold);
  }

  // < threshold signers are not allowed
  if (threshold > 0)
  {
    allowed_signers.pop_back();
    EXPECT_NO_THROW(multisig_signers_to_filter(allowed_signers, signer_list, aggregate_filter));
    EXPECT_ANY_THROW(aggregate_multisig_signer_set_filter_to_permutations(threshold, num_signers, aggregate_filter, filters));
  }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void test_multisig_cn_key_image_recovery(const std::uint32_t M, const std::uint32_t N)
{
  ASSERT_TRUE(M <= N);
  ASSERT_TRUE(N > 0);

  using namespace multisig;
  const cryptonote::account_generator_era cn_era = cryptonote::account_generator_era::cryptonote;

  // make M-of-N cryptonote-era multisig accounts
  std::vector<multisig_account> accounts;
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cn_era, M, N, accounts));
  ASSERT_TRUE(accounts.size() > 0);

  // collect multisig account private spend key
  std::unordered_set<crypto::secret_key> collected_multisig_privkeys;

  for (const multisig_account &account : accounts)
  {
    const auto &privkeys = account.get_multisig_privkeys();

    for (const crypto::secret_key &privkey : privkeys)
      collected_multisig_privkeys.insert(privkey);
  }

  crypto::secret_key k_s{rct::rct2sk(rct::Z)};

  for (const crypto::secret_key &k_s_partial : collected_multisig_privkeys)
    sc_add(to_bytes(k_s), to_bytes(k_s), to_bytes(k_s_partial));

  // sanity check: multisig pubkey from private keys
  const crypto::public_key recomputed_multisig_pubkey{rct::rct2pk(rct::scalarmultBase(rct::sk2rct(k_s)))};
  ASSERT_TRUE(recomputed_multisig_pubkey == accounts[0].get_multisig_pubkey());

  // generate random onetime addresses
  const std::size_t num_Kos{3};

  std::vector<crypto::public_key> rand_Kos;
  rand_Kos.resize(num_Kos);

  for (crypto::public_key &rand_Ko : rand_Kos)
    rand_Ko = rct::rct2pk(rct::pkGen());

  // compute expected key image cores k^s Hp(Ko)
  std::vector<crypto::key_image> expected_KI_cores;
  expected_KI_cores.resize(num_Kos);

  for (std::size_t i{0}; i < num_Kos; ++i)
    crypto::generate_key_image(rand_Kos[i], k_s, expected_KI_cores[i]);

  // save Kos and key image cores in a map for convenience
  std::unordered_map<crypto::public_key, crypto::public_key> expected_recovered_key_image_cores;

  for (std::size_t i{0}; i < num_Kos; ++i)
    expected_recovered_key_image_cores[rand_Kos[i]] = rct::rct2pk(rct::ki2rct(expected_KI_cores[i]));

  // each account makes partial KI messages for each Ko
  std::unordered_map<crypto::public_key,
    std::unordered_map<crypto::public_key, multisig_partial_cn_key_image_msg>> partial_ki_msgs;

  for (const multisig_account &account : accounts)
  {
    for (const crypto::public_key &rand_Ko : rand_Kos)
    {
      EXPECT_NO_THROW((partial_ki_msgs[rand_Ko][account.get_base_pubkey()] =
        multisig_partial_cn_key_image_msg{account.get_base_privkey(), rand_Ko, account.get_multisig_privkeys()}));
    }
  }

  // recover the key image cores
  std::unordered_map<crypto::public_key, signer_set_filter> onetime_addresses_with_insufficient_partial_kis;
  std::unordered_map<crypto::public_key, signer_set_filter> onetime_addresses_with_invalid_partial_kis;
  std::unordered_map<crypto::public_key, crypto::public_key> recovered_key_image_cores;

  EXPECT_NO_THROW(multisig_recover_cn_keyimage_cores(accounts[0].get_threshold(),
    accounts[0].get_signers(),
    accounts[0].get_multisig_pubkey(),
    partial_ki_msgs,
    onetime_addresses_with_insufficient_partial_kis,
    onetime_addresses_with_invalid_partial_kis,
    recovered_key_image_cores));

  // check that key image cores were recovered
  EXPECT_TRUE(expected_recovered_key_image_cores.size() == recovered_key_image_cores.size());
  EXPECT_TRUE(onetime_addresses_with_insufficient_partial_kis.size() == 0);
  EXPECT_TRUE(onetime_addresses_with_invalid_partial_kis.size() == 0);

  for (const auto &recovered_key_image_core : recovered_key_image_cores)
  {
    EXPECT_TRUE(expected_recovered_key_image_cores.find(recovered_key_image_core.first) != 
      expected_recovered_key_image_cores.end());

    EXPECT_TRUE(expected_recovered_key_image_cores.at(recovered_key_image_core.first) == 
      recovered_key_image_core.second);
  }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_1_2)
{
  make_wallets(1, 2, false);
  make_wallets(1, 2, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_1_3)
{
  make_wallets(1, 3, false);
  make_wallets(1, 3, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_2_2)
{
  make_wallets(2, 2, false);
  make_wallets(2, 2, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_3_3)
{
  make_wallets(3, 3, false);
  make_wallets(3, 3, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_2_3)
{
  make_wallets(2, 3, false);
  make_wallets(2, 3, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_2_4)
{
  make_wallets(2, 4, false);
  make_wallets(2, 4, true);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, make_2_4_boosting)
{
  std::vector<tools::wallet2> wallets(4);
  make_wallets_boosting(wallets, 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_kex_msg)
{
  using namespace multisig;

  crypto::public_key pubkey1;
  crypto::public_key pubkey2;
  crypto::public_key pubkey3;
  crypto::secret_key_to_public_key(rct::rct2sk(rct::skGen()), pubkey1);
  crypto::secret_key_to_public_key(rct::rct2sk(rct::skGen()), pubkey2);
  crypto::secret_key_to_public_key(rct::rct2sk(rct::skGen()), pubkey3);

  crypto::secret_key signing_skey = rct::rct2sk(rct::skGen());
  crypto::public_key signing_pubkey;
  while(!crypto::secret_key_to_public_key(signing_skey, signing_pubkey))
  {
    signing_skey = rct::rct2sk(rct::skGen());
  }

  const crypto::secret_key ancillary_skey{rct::rct2sk(rct::skGen())};

  // default version
  const std::uint32_t v{get_kex_msg_version(cryptonote::account_generator_era::cryptonote)};

  // misc. edge cases
  EXPECT_NO_THROW((multisig_kex_msg{}));
  EXPECT_EQ(multisig_kex_msg{}.get_version(), 0);
  EXPECT_NO_THROW((multisig_kex_msg{multisig_kex_msg{}.get_msg()}));
  EXPECT_ANY_THROW((multisig_kex_msg{"abc"}));
  EXPECT_ANY_THROW((multisig_kex_msg{v, 0, crypto::null_skey, std::vector<crypto::public_key>{}, crypto::null_skey}));
  EXPECT_ANY_THROW((multisig_kex_msg{v, 1, crypto::null_skey, std::vector<crypto::public_key>{}, crypto::null_skey}));
  EXPECT_ANY_THROW((multisig_kex_msg{v, 1, signing_skey, std::vector<crypto::public_key>{}, crypto::null_skey}));
  EXPECT_ANY_THROW((multisig_kex_msg{v, 1, crypto::null_skey, std::vector<crypto::public_key>{}, ancillary_skey}));
  EXPECT_ANY_THROW((multisig_kex_msg{v, 1, signing_skey, std::vector<crypto::public_key>{}, ancillary_skey}));

  // test that messages are both constructible and reversible

  // round 1
  EXPECT_NO_THROW((multisig_kex_msg{
      multisig_kex_msg{v, 1, signing_skey, std::vector<crypto::public_key>{pubkey1}, ancillary_skey}.get_msg()
    }));

  // round 2
  EXPECT_NO_THROW((multisig_kex_msg{
      multisig_kex_msg{v, 2, signing_skey, std::vector<crypto::public_key>{pubkey1}, ancillary_skey}.get_msg()
    }));
  EXPECT_NO_THROW((multisig_kex_msg{
      multisig_kex_msg{v, 2, signing_skey, std::vector<crypto::public_key>{pubkey1}, crypto::null_skey}.get_msg()
    }));
  EXPECT_NO_THROW((multisig_kex_msg{
      multisig_kex_msg{v, 2, signing_skey, std::vector<crypto::public_key>{pubkey1, pubkey2}, ancillary_skey}.get_msg()
    }));
  EXPECT_NO_THROW((multisig_kex_msg{
      multisig_kex_msg{v, 2, signing_skey, std::vector<crypto::public_key>{pubkey1, pubkey2, pubkey3}, crypto::null_skey}.get_msg()
    }));

  // prepare: test that keys can be recovered if stored in a message and the message's reverse
  auto test_recovery = [&](const std::uint32_t v)
  {
    // round 1
    multisig_kex_msg msg_rnd1{v, 1, signing_skey, std::vector<crypto::public_key>{pubkey1}, ancillary_skey};
    multisig_kex_msg msg_rnd1_reverse{msg_rnd1.get_msg()};
    EXPECT_EQ(msg_rnd1.get_version(), v);
    EXPECT_EQ(msg_rnd1.get_round(), 1);
    EXPECT_EQ(msg_rnd1.get_round(), msg_rnd1_reverse.get_round());
    EXPECT_EQ(msg_rnd1.get_signing_pubkey(), signing_pubkey);
    EXPECT_EQ(msg_rnd1.get_signing_pubkey(), msg_rnd1_reverse.get_signing_pubkey());
    EXPECT_EQ(msg_rnd1.get_msg_pubkeys().size(), 1);
    EXPECT_EQ(msg_rnd1.get_msg_pubkeys().size(), msg_rnd1_reverse.get_msg_pubkeys().size());
    EXPECT_EQ(msg_rnd1.get_msg_privkey(), ancillary_skey);
    EXPECT_EQ(msg_rnd1.get_msg_privkey(), msg_rnd1_reverse.get_msg_privkey());

    // round 2
    multisig_kex_msg msg_rnd2{v, 2, signing_skey, std::vector<crypto::public_key>{pubkey1, pubkey2}, ancillary_skey};
    multisig_kex_msg msg_rnd2_reverse{msg_rnd2.get_msg()};
    EXPECT_EQ(msg_rnd2.get_version(), v);
    EXPECT_EQ(msg_rnd2.get_round(), 2);
    EXPECT_EQ(msg_rnd2.get_round(), msg_rnd2_reverse.get_round());
    EXPECT_EQ(msg_rnd2.get_signing_pubkey(), signing_pubkey);
    EXPECT_EQ(msg_rnd2.get_signing_pubkey(), msg_rnd2_reverse.get_signing_pubkey());
    ASSERT_EQ(msg_rnd2.get_msg_pubkeys().size(), 2);
    ASSERT_EQ(msg_rnd2.get_msg_pubkeys().size(), msg_rnd2_reverse.get_msg_pubkeys().size());
    EXPECT_EQ(msg_rnd2.get_msg_pubkeys()[0], pubkey1);
    EXPECT_EQ(msg_rnd2.get_msg_pubkeys()[1], pubkey2);
    EXPECT_EQ(msg_rnd2.get_msg_pubkeys()[0], msg_rnd2_reverse.get_msg_pubkeys()[0]);
    EXPECT_EQ(msg_rnd2.get_msg_pubkeys()[1], msg_rnd2_reverse.get_msg_pubkeys()[1]);
    EXPECT_EQ(msg_rnd2.get_msg_privkey(), crypto::null_skey);
    EXPECT_EQ(msg_rnd2.get_msg_privkey(), msg_rnd2_reverse.get_msg_privkey());
  };

  // test that all versions work
  EXPECT_NO_THROW(test_recovery(get_kex_msg_version(cryptonote::account_generator_era::cryptonote)));
  EXPECT_NO_THROW(test_recovery(get_kex_msg_version(cryptonote::account_generator_era::seraphis)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_signer_set_filter)
{
  using namespace multisig;

  // 0 threshold, 0 signers
  test_multisig_signer_set_filter(0, 0);

  // 0 threshold, 1 signer
  test_multisig_signer_set_filter(0, 1);

  // 1 threshold, 1 signer
  test_multisig_signer_set_filter(1, 1);

  // 0 threshold, 2 signers
  test_multisig_signer_set_filter(0, 2);

  // 1 threshold, 2 signers
  test_multisig_signer_set_filter(1, 2);

  // 2 threshold, 2 signers
  test_multisig_signer_set_filter(2, 2);

  // 1 threshold, 3 signers
  test_multisig_signer_set_filter(1, 3);

  // 2 threshold, 3 signers
  test_multisig_signer_set_filter(2, 3);

  // 3 threshold, 3 signers
  test_multisig_signer_set_filter(3, 3);

  // 3 threshold, 7 signers
  test_multisig_signer_set_filter(3, 7);

  // check that signer set permutations have the expected members: 2 threshold, 4 signers -> 3 allowed

  using namespace multisig;

  std::vector<crypto::public_key> signer_list;
  std::vector<crypto::public_key> allowed_signers;
  std::vector<crypto::public_key> filtered_signers;
  signer_set_filter aggregate_filter;
  std::vector<signer_set_filter> filters;
  std::uint32_t threshold{2};
  std::uint32_t num_signers{4};

  make_multisig_signer_list(num_signers, signer_list);

  allowed_signers = signer_list;
  allowed_signers.pop_back();
  EXPECT_NO_THROW(multisig_signers_to_filter(allowed_signers, signer_list, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(threshold, num_signers, aggregate_filter, filters));
  EXPECT_TRUE(filters.size() == 3);

  EXPECT_NO_THROW(get_filtered_multisig_signers(filters[0], threshold, signer_list, filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[0]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[1]);

  EXPECT_NO_THROW(get_filtered_multisig_signers(filters[1], threshold, signer_list, filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[0]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[2]);

  EXPECT_NO_THROW(get_filtered_multisig_signers(filters[2], threshold, signer_list, filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[1]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[2]);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_partial_cn_ki_msg)
{
  using namespace multisig;

  std::vector<crypto::secret_key> privkeys;
  for (std::size_t i{0}; i < 3; ++i)
    privkeys.emplace_back(rct::rct2sk(rct::skGen()));

  crypto::secret_key signing_skey{rct::rct2sk(rct::skGen())};
  crypto::public_key signing_pubkey;
  crypto::secret_key_to_public_key(signing_skey, signing_pubkey);

  // create a message: misc. edge cases
  const crypto::public_key rand_Ko{rct::rct2pk(rct::pkGen())};

  EXPECT_NO_THROW((multisig_partial_cn_key_image_msg{}));
  EXPECT_NO_THROW((multisig_partial_cn_key_image_msg{multisig_partial_cn_key_image_msg{}.get_msg()}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{"abc"}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{crypto::null_skey, crypto::null_pkey, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{crypto::null_skey, rand_Ko, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{signing_skey, crypto::null_pkey, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{crypto::null_skey, rand_Ko, privkeys}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{signing_skey, crypto::null_pkey, privkeys}));
  EXPECT_ANY_THROW((multisig_partial_cn_key_image_msg{signing_skey, rand_Ko, std::vector<crypto::secret_key>{}}));

  // test that messages are both constructible and reversible
  EXPECT_NO_THROW((multisig_partial_cn_key_image_msg{
      multisig_partial_cn_key_image_msg{signing_skey, rand_Ko, std::vector<crypto::secret_key>{privkeys[0]}}.get_msg()
    }));
  EXPECT_NO_THROW((multisig_partial_cn_key_image_msg{
      multisig_partial_cn_key_image_msg{signing_skey, rand_Ko, privkeys}.get_msg()
    }));

  // test that message contents can be recovered if stored in a message and the message's reverse
  auto test_recovery = [&](const crypto::public_key &Ko, const crypto::key_image &KI_base)
  {
    std::vector<crypto::public_key> expected_multisig_keyshares;
    std::vector<crypto::public_key> expected_partial_keyimages;
    expected_multisig_keyshares.reserve(privkeys.size());
    expected_partial_keyimages.reserve(privkeys.size());
    for (const crypto::secret_key &privkey : privkeys)
    {
      expected_multisig_keyshares.emplace_back(
          rct::rct2pk(rct::scalarmultKey(rct::pk2rct(crypto::get_G()), rct::sk2rct(privkey)))
        );
      expected_partial_keyimages.emplace_back(
          rct::rct2pk(rct::scalarmultKey(rct::ki2rct(KI_base), rct::sk2rct(privkey)))
        );
    }

    multisig_partial_cn_key_image_msg recovery_test_msg{signing_skey, Ko, privkeys};
    multisig_partial_cn_key_image_msg recovery_test_msg_reverse{recovery_test_msg.get_msg()};
    EXPECT_EQ(recovery_test_msg.get_onetime_address(), Ko);
    EXPECT_EQ(recovery_test_msg.get_onetime_address(), recovery_test_msg_reverse.get_onetime_address());
    EXPECT_EQ(recovery_test_msg.get_signing_pubkey(), signing_pubkey);
    EXPECT_EQ(recovery_test_msg.get_signing_pubkey(), recovery_test_msg_reverse.get_signing_pubkey());
    EXPECT_EQ(recovery_test_msg.get_partial_key_images().size(), privkeys.size());
    EXPECT_EQ(recovery_test_msg.get_partial_key_images(), recovery_test_msg_reverse.get_partial_key_images());
    EXPECT_EQ(recovery_test_msg.get_partial_key_images().size(), recovery_test_msg.get_multisig_keyshares().size());
    EXPECT_EQ(recovery_test_msg.get_multisig_keyshares(), recovery_test_msg_reverse.get_multisig_keyshares());
    EXPECT_EQ(recovery_test_msg.get_multisig_keyshares(), expected_multisig_keyshares);
    EXPECT_EQ(recovery_test_msg.get_partial_key_images(), expected_partial_keyimages);
  };

  // get key image base
  crypto::key_image KI_base;
  crypto::generate_key_image(rand_Ko, rct::rct2sk(rct::I), KI_base);

  // test recovery
  EXPECT_NO_THROW(test_recovery(rand_Ko, KI_base));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_conversion_msg)
{
  using namespace multisig;

  std::vector<crypto::secret_key> privkeys;
  for (std::size_t i{0}; i < 3; ++i)
    privkeys.emplace_back(rct::rct2sk(rct::skGen()));

  crypto::secret_key signing_skey{rct::rct2sk(rct::skGen())};
  crypto::public_key signing_pubkey;
  crypto::secret_key_to_public_key(signing_skey, signing_pubkey);

  // misc. edge cases
  const auto zero = static_cast<cryptonote::account_generator_era>(0);
  const auto one = static_cast<cryptonote::account_generator_era>(1);

  EXPECT_NO_THROW((multisig_account_era_conversion_msg{}));
  EXPECT_NO_THROW((multisig_account_era_conversion_msg{multisig_account_era_conversion_msg{}.get_msg()}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{"abc"}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{crypto::null_skey, zero, zero, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{crypto::null_skey, one, one, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{signing_skey, zero, zero, std::vector<crypto::secret_key>{}}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{crypto::null_skey, one, one, privkeys}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{signing_skey, zero, zero, privkeys}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{signing_skey, zero, one, privkeys}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{signing_skey, one, zero, privkeys}));
  EXPECT_ANY_THROW((multisig_account_era_conversion_msg{signing_skey, one, one, std::vector<crypto::secret_key>{}}));

  // test that messages are both constructible and reversible
  EXPECT_NO_THROW((multisig_account_era_conversion_msg{
      multisig_account_era_conversion_msg{signing_skey, one, one, std::vector<crypto::secret_key>{privkeys[0]}}.get_msg()
    }));
  EXPECT_NO_THROW((multisig_account_era_conversion_msg{
      multisig_account_era_conversion_msg{signing_skey, one, one, privkeys}.get_msg()
    }));

  // test that message contents can be recovered if stored in a message and the message's reverse
  auto test_recovery = [&](const cryptonote::account_generator_era old_era, const cryptonote::account_generator_era new_era)
  {
    std::vector<crypto::public_key> expected_old_keyshares;
    std::vector<crypto::public_key> expected_new_keyshares;
    expected_old_keyshares.reserve(privkeys.size());
    expected_new_keyshares.reserve(privkeys.size());
    for (const crypto::secret_key &privkey : privkeys)
    {
      expected_old_keyshares.emplace_back(
          rct::rct2pk(rct::scalarmultKey(rct::pk2rct(cryptonote::get_primary_generator(old_era)), rct::sk2rct(privkey)))
        );
      expected_new_keyshares.emplace_back(
          rct::rct2pk(rct::scalarmultKey(rct::pk2rct(cryptonote::get_primary_generator(new_era)), rct::sk2rct(privkey)))
        );
    }

    multisig_account_era_conversion_msg recovery_test_msg{signing_skey, old_era, new_era, privkeys};
    multisig_account_era_conversion_msg recovery_test_msg_reverse{recovery_test_msg.get_msg()};
    EXPECT_EQ(recovery_test_msg.get_old_era(), old_era);
    EXPECT_EQ(recovery_test_msg_reverse.get_old_era(), old_era);
    EXPECT_EQ(recovery_test_msg.get_new_era(), new_era);
    EXPECT_EQ(recovery_test_msg_reverse.get_new_era(), new_era);
    EXPECT_EQ(recovery_test_msg.get_signing_pubkey(), signing_pubkey);
    EXPECT_EQ(recovery_test_msg.get_signing_pubkey(), recovery_test_msg_reverse.get_signing_pubkey());
    EXPECT_EQ(recovery_test_msg.get_old_keyshares().size(), privkeys.size());
    EXPECT_EQ(recovery_test_msg.get_old_keyshares(), recovery_test_msg_reverse.get_old_keyshares());
    EXPECT_EQ(recovery_test_msg.get_old_keyshares().size(), recovery_test_msg.get_new_keyshares().size());
    EXPECT_EQ(recovery_test_msg.get_new_keyshares(), recovery_test_msg_reverse.get_new_keyshares());
    EXPECT_EQ(recovery_test_msg.get_new_keyshares(), expected_new_keyshares);
    EXPECT_EQ(recovery_test_msg.get_old_keyshares(), expected_old_keyshares);
    if (old_era == new_era)
    {
      EXPECT_EQ(recovery_test_msg.get_new_keyshares(), recovery_test_msg.get_old_keyshares());
    }
  };

  // test all version combinations
  EXPECT_NO_THROW(test_recovery(cryptonote::account_generator_era::cryptonote, cryptonote::account_generator_era::cryptonote));
  EXPECT_NO_THROW(test_recovery(cryptonote::account_generator_era::cryptonote, cryptonote::account_generator_era::seraphis));
  EXPECT_NO_THROW(test_recovery(cryptonote::account_generator_era::seraphis, cryptonote::account_generator_era::cryptonote));
  EXPECT_NO_THROW(test_recovery(cryptonote::account_generator_era::seraphis, cryptonote::account_generator_era::seraphis));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_cn_key_image_recovery)
{
  test_multisig_cn_key_image_recovery(1, 2);
  test_multisig_cn_key_image_recovery(2, 2);
  test_multisig_cn_key_image_recovery(2, 3);
  test_multisig_cn_key_image_recovery(2, 4);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_account_conversions)
{
  std::vector<multisig::multisig_account> accounts;
  multisig::multisig_account converted_account;
  std::vector<multisig::multisig_account_era_conversion_msg> conversion_msgs;

  const auto cn_era = cryptonote::account_generator_era::cryptonote;
  const auto sp_era = cryptonote::account_generator_era::seraphis;

  // 1-of-2
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cn_era, 1, 2, accounts));
  conversion_msgs.clear();
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[0].get_account_era_conversion_msg(sp_era)));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[0], sp_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[1], sp_era, conversion_msgs, converted_account));
  EXPECT_EQ(converted_account.get_era(), sp_era);

  // 2-of-2: cryptonote -> seraphis
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cn_era, 2, 2, accounts));
  conversion_msgs.clear();
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[0].get_account_era_conversion_msg(sp_era)));
  EXPECT_ANY_THROW(get_multisig_account_with_new_generator_era(accounts[0], sp_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[1], sp_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(converted_account.get_signers_available_for_aggregation_signing());
  EXPECT_TRUE(converted_account.get_signers_available_for_aggregation_signing() == converted_account.get_signers());
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[1].get_account_era_conversion_msg(sp_era)));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[0], sp_era, conversion_msgs, converted_account));
  EXPECT_EQ(converted_account.get_era(), sp_era);

  // 2-of-2: cryptonote -> cryptonote
  conversion_msgs.clear();
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[0].get_account_era_conversion_msg(cn_era)));
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[1].get_account_era_conversion_msg(cn_era)));
  EXPECT_ANY_THROW(get_multisig_account_with_new_generator_era(accounts[0], cn_era, conversion_msgs, converted_account));

  // 2-of-2: seraphis -> cryptonote
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(sp_era, 2, 2, accounts));
  conversion_msgs.clear();
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[0].get_account_era_conversion_msg(cn_era)));
  EXPECT_ANY_THROW(get_multisig_account_with_new_generator_era(accounts[0], cn_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[1], cn_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[1].get_account_era_conversion_msg(cn_era)));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[0], cn_era, conversion_msgs, converted_account));
  EXPECT_EQ(converted_account.get_era(), cn_era);

  // 2-of-3: cryptonote -> seraphis
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cn_era, 2, 3, accounts));
  conversion_msgs.clear();
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[0].get_account_era_conversion_msg(sp_era)));
  EXPECT_ANY_THROW(get_multisig_account_with_new_generator_era(accounts[0], sp_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[1], sp_era, conversion_msgs, converted_account));
  // check that signer recommendations are preserved even if only 'threshold - 1' accounts participants in conversion
  EXPECT_NO_THROW(converted_account.get_signers_available_for_aggregation_signing());
  EXPECT_TRUE(converted_account.get_signers_available_for_aggregation_signing() == converted_account.get_signers());
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[2], sp_era, conversion_msgs, converted_account));
  EXPECT_NO_THROW(converted_account.get_signers_available_for_aggregation_signing());
  EXPECT_TRUE(converted_account.get_signers_available_for_aggregation_signing() == converted_account.get_signers());
  EXPECT_NO_THROW(conversion_msgs.emplace_back(accounts[1].get_account_era_conversion_msg(sp_era)));
  EXPECT_NO_THROW(get_multisig_account_with_new_generator_era(accounts[0], sp_era, conversion_msgs, converted_account));
  EXPECT_EQ(converted_account.get_era(), sp_era);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig, multisig_signer_recommendations_recovery)
{
  std::vector<multisig::multisig_account> accounts;
  multisig::multisig_account converted_account;
  multisig::multisig_account_era_conversion_msg conversion_msg;

  const auto cn_era = cryptonote::account_generator_era::cryptonote;

  // 2-of-3: can recover signer recommendations for aggregation if lost
  EXPECT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cn_era, 2, 3, accounts));

  // reset account to remove keyshare map
  accounts[0] = multisig::multisig_account{
      accounts[0].get_era(),
      accounts[0].get_threshold(),
      accounts[0].get_signers(),
      accounts[0].get_base_privkey(),
      accounts[0].get_base_common_privkey(),
      accounts[0].get_multisig_privkeys(),
      accounts[0].get_common_privkey(),
      accounts[0].get_multisig_pubkey(),
      multisig::multisig_keyshare_origins_map_t{},  //remove keyshare map
      accounts[0].get_kex_rounds_complete(),
      multisig::multisig_keyset_map_memsafe_t{},
      ""
    };

  // now only self is available for aggregation signing
  std::vector<crypto::public_key> available_signers{accounts[0].get_signers_available_for_aggregation_signing()};
  EXPECT_TRUE(available_signers.size() == 1);
  EXPECT_TRUE(available_signers[0] == accounts[0].get_base_pubkey());

  // add player 1
  EXPECT_NO_THROW(conversion_msg = accounts[1].get_account_era_conversion_msg(cn_era));
  EXPECT_NO_THROW(accounts[0].add_signer_recommendations(conversion_msg));

  // now self and player 1 are available
  available_signers = accounts[0].get_signers_available_for_aggregation_signing();
  EXPECT_TRUE(available_signers.size() == 2);

  // add player 2
  EXPECT_NO_THROW(conversion_msg = accounts[2].get_account_era_conversion_msg(cn_era));
  EXPECT_NO_THROW(accounts[0].add_signer_recommendations(conversion_msg));

  // now everyone is available for aggregation signing
  available_signers = accounts[0].get_signers_available_for_aggregation_signing();
  EXPECT_TRUE(available_signers == accounts[0].get_signers());
}
//-------------------------------------------------------------------------------------------------------------------
