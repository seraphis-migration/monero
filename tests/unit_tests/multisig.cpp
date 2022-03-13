// Copyright (c) 2017-2022, The Monero Project
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
#include "multisig/account_generator_era.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_kex_msg.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "wallet/wallet2.h"

#include "gtest/gtest.h"

#include <cstdint>

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
  {
      new_infos.push_back(wallets[i].exchange_multisig_keys("", infos));
  }

  return new_infos;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void check_results(const std::vector<std::string> &intermediate_infos,
  std::vector<tools::wallet2>& wallets,
  std::uint32_t M)
{
  // check results
  std::unordered_set<crypto::secret_key> unique_privkeys;
  rct::key composite_pubkey = rct::identity();

  wallets[0].decrypt_keys("");
  crypto::public_key spend_pubkey = wallets[0].get_account().get_keys().m_account_address.m_spend_public_key;
  crypto::secret_key view_privkey = wallets[0].get_account().get_keys().m_view_secret_key;
  crypto::public_key view_pubkey;
  EXPECT_TRUE(crypto::secret_key_to_public_key(view_privkey, view_pubkey));
  wallets[0].encrypt_keys("");

  for (size_t i = 0; i < wallets.size(); ++i)
  {
    EXPECT_TRUE(!intermediate_infos[i].empty());
    bool ready;
    uint32_t threshold, total;
    EXPECT_TRUE(wallets[i].multisig(&ready, &threshold, &total));
    EXPECT_TRUE(ready);
    EXPECT_TRUE(threshold == M);
    EXPECT_TRUE(total == wallets.size());

    wallets[i].decrypt_keys("");

    if (i != 0)
    {
      // "equals" is transitive relation so we need only to compare first wallet's address to each others' addresses.
      // no need to compare 0's address with itself.
      EXPECT_TRUE(wallets[0].get_account().get_public_address_str(cryptonote::TESTNET) ==
        wallets[i].get_account().get_public_address_str(cryptonote::TESTNET));
      
      EXPECT_EQ(spend_pubkey, wallets[i].get_account().get_keys().m_account_address.m_spend_public_key);
      EXPECT_EQ(view_privkey, wallets[i].get_account().get_keys().m_view_secret_key);
      EXPECT_EQ(view_pubkey, wallets[i].get_account().get_keys().m_account_address.m_view_public_key);
    }

    // sum together unique multisig keys
    for (const auto &privkey : wallets[i].get_account().get_keys().m_multisig_keys)
    {
      EXPECT_NE(privkey, crypto::null_skey);

      if (unique_privkeys.find(privkey) == unique_privkeys.end())
      {
        unique_privkeys.insert(privkey);
        crypto::public_key pubkey;
        crypto::secret_key_to_public_key(privkey, pubkey);
        EXPECT_NE(privkey, crypto::null_skey);
        EXPECT_NE(pubkey, crypto::null_pkey);
        EXPECT_NE(pubkey, rct::rct2pk(rct::identity()));
        rct::addKeys(composite_pubkey, composite_pubkey, rct::pk2rct(pubkey));
      }
    }
    wallets[i].encrypt_keys("");
  }

  // final key via sums should equal the wallets' public spend key
  wallets[0].decrypt_keys("");
  EXPECT_EQ(wallets[0].get_account().get_keys().m_account_address.m_spend_public_key, rct::rct2pk(composite_pubkey));
  wallets[0].encrypt_keys("");
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_wallets(std::vector<tools::wallet2>& wallets, unsigned int M)
{
  ASSERT_TRUE(wallets.size() > 1 && wallets.size() <= KEYS_COUNT);
  ASSERT_TRUE(M <= wallets.size());
  std::uint32_t total_rounds_required = multisig::multisig_kex_rounds_required(wallets.size(), M) + 1;
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
    intermediate_infos = exchange_round(wallets, intermediate_infos);
    wallets[0].multisig(&ready);

    ++rounds_complete;
  }

  EXPECT_EQ(total_rounds_required, rounds_complete);

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
static void test_multisig_signer_set_filter(const std::uint32_t num_signers, const std::uint32_t threshold)
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
  EXPECT_NO_THROW(multisig_signers_to_filter(signer_list, allowed_signers, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(num_signers, threshold, aggregate_filter, filters));
  for (const signer_set_filter filter : filters)
  {
    EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filter, filtered_signers));
    EXPECT_TRUE(filtered_signers.size() == threshold);
  }

  // num_signers - 1 signers are allowed
  if (num_signers > threshold)
  {
    allowed_signers.pop_back();
    EXPECT_NO_THROW(multisig_signers_to_filter(signer_list, allowed_signers, aggregate_filter));
    EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(num_signers, threshold, aggregate_filter, filters));
    for (const signer_set_filter filter : filters)
    {
      EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filter, filtered_signers));
      EXPECT_TRUE(filtered_signers.size() == threshold);
    }
  }

  // threshold signers are allowed
  while (allowed_signers.size() > threshold)
    allowed_signers.pop_back();

  EXPECT_NO_THROW(multisig_signers_to_filter(signer_list, allowed_signers, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(num_signers, threshold, aggregate_filter, filters));
  for (const signer_set_filter filter : filters)
  {
    EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filter, filtered_signers));
    EXPECT_TRUE(filtered_signers.size() == threshold);
  }

  // < threshold signers are not allowed
  if (threshold > 0)
  {
    allowed_signers.pop_back();
    EXPECT_NO_THROW(multisig_signers_to_filter(signer_list, allowed_signers, aggregate_filter));
    EXPECT_ANY_THROW(aggregate_multisig_signer_set_filter_to_permutations(num_signers, threshold, aggregate_filter, filters));
  }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------

TEST(multisig, make_1_2)
{
  std::vector<tools::wallet2> wallets(2);
  make_wallets(wallets, 1);
}

TEST(multisig, make_1_3)
{
  std::vector<tools::wallet2> wallets(3);
  make_wallets(wallets, 1);
}

TEST(multisig, make_2_2)
{
  std::vector<tools::wallet2> wallets(2);
  make_wallets(wallets, 2);
}

TEST(multisig, make_3_3)
{
  std::vector<tools::wallet2> wallets(3);
  make_wallets(wallets, 3);
}

TEST(multisig, make_2_3)
{
  std::vector<tools::wallet2> wallets(3);
  make_wallets(wallets, 2);
}

TEST(multisig, make_2_4)
{
  std::vector<tools::wallet2> wallets(4);
  make_wallets(wallets, 2);
}

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

  crypto::secret_key ancillary_skey = rct::rct2sk(rct::skGen());
  while (ancillary_skey == crypto::null_skey)
    ancillary_skey = rct::rct2sk(rct::skGen());

  // default version
  const std::uint32_t v{get_kex_msg_version(cryptonote::account_generator_era::cryptonote)};

  // misc. edge cases
  EXPECT_NO_THROW((multisig_kex_msg{}));
  EXPECT_ANY_THROW((multisig_kex_msg{multisig_kex_msg{}.get_msg()}));
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

TEST(multisig, multisig_signer_set_filter)
{
  using namespace multisig;

  // 0 signers, 0 threshold
  test_multisig_signer_set_filter(0, 0);

  // 1 signer, 0 threshold
  test_multisig_signer_set_filter(1, 0);

  // 1 signer, 1 threshold
  test_multisig_signer_set_filter(1, 1);

  // 2 signers, 0 threshold
  test_multisig_signer_set_filter(2, 0);

  // 2 signers, 1 threshold
  test_multisig_signer_set_filter(2, 1);

  // 2 signers, 2 threshold
  test_multisig_signer_set_filter(2, 2);

  // 3 signers, 1 threshold
  test_multisig_signer_set_filter(3, 1);

  // 3 signers, 2 threshold
  test_multisig_signer_set_filter(3, 2);

  // 3 signers, 3 threshold
  test_multisig_signer_set_filter(3, 3);

  // 7 signers, 3 threshold
  test_multisig_signer_set_filter(7, 3);

  // check that signer set permutations have the expected members: 4 signers, 2 threshold, 3 allowed

  using namespace multisig;

  std::vector<crypto::public_key> signer_list;
  std::vector<crypto::public_key> allowed_signers;
  std::vector<crypto::public_key> filtered_signers;
  signer_set_filter aggregate_filter;
  std::vector<signer_set_filter> filters;
  std::uint32_t num_signers{4};
  std::uint32_t threshold{2};

  make_multisig_signer_list(num_signers, signer_list);

  allowed_signers = signer_list;
  allowed_signers.pop_back();
  EXPECT_NO_THROW(multisig_signers_to_filter(signer_list, allowed_signers, aggregate_filter));
  EXPECT_NO_THROW(aggregate_multisig_signer_set_filter_to_permutations(num_signers, threshold, aggregate_filter, filters));
  EXPECT_TRUE(filters.size() == 3);

  EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filters[0], filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[0]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[1]);

  EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filters[1], filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[0]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[2]);

  EXPECT_NO_THROW(get_filtered_multisig_signers(signer_list, threshold, filters[2], filtered_signers));
  EXPECT_TRUE(filtered_signers.size() == threshold);
  EXPECT_TRUE(filtered_signers[0] == signer_list[1]);
  EXPECT_TRUE(filtered_signers[1] == signer_list[2]);
}
