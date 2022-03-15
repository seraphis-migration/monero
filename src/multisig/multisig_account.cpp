// Copyright (c) 2021-2022, The Monero Project
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

#include "multisig_account.h"

#include "account_generator_era.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "include_base_utils.h"
#include "multisig.h"
#include "multisig_kex_msg.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_account::multisig_account(const cryptonote::account_generator_era era,
    const crypto::secret_key &base_privkey,
    const crypto::secret_key &base_common_privkey) :
      m_account_era{era},
      m_base_privkey{base_privkey},
      m_base_common_privkey{base_common_privkey},
      m_multisig_pubkey{rct::rct2pk(rct::identity())},
      m_common_pubkey{rct::rct2pk(rct::identity())},
      m_kex_rounds_complete{0}
  {
    // initialize base pubkey
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(m_base_privkey, m_base_pubkey),
      "Failed to derive public key");

    // prepare initial kex message
    rct::key initial_pubkey{rct::scalarmultKey(get_primary_generator(m_account_era), rct::sk2rct(m_base_privkey))};
    m_next_round_kex_message =
      multisig_kex_msg{get_kex_msg_version(era), 1, base_privkey, {rct::rct2pk(initial_pubkey)}, base_common_privkey}.get_msg();
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_account::multisig_account(const cryptonote::account_generator_era era,
    const std::uint32_t threshold,
    std::vector<crypto::public_key> signers,
    const crypto::secret_key &base_privkey,
    const crypto::secret_key &base_common_privkey,
    std::vector<crypto::secret_key> multisig_privkeys,
    multisig_keyshare_origins_map_t keyshare_origins_map,
    const crypto::secret_key &common_privkey,
    const crypto::public_key &multisig_pubkey,
    const crypto::public_key &common_pubkey,
    const std::uint32_t kex_rounds_complete,
    multisig_keyset_map_memsafe_t kex_origins_map,
    std::string next_round_kex_message) :
      m_account_era{era},
      m_base_privkey{base_privkey},
      m_base_common_privkey{base_common_privkey},
      m_multisig_privkeys{std::move(multisig_privkeys)},
      m_keyshare_to_origins_map{std::move(keyshare_origins_map)},
      m_common_privkey{common_privkey},
      m_multisig_pubkey{multisig_pubkey},
      m_common_pubkey{common_pubkey},
      m_kex_rounds_complete{kex_rounds_complete},
      m_kex_keys_to_origins_map{std::move(kex_origins_map)},
      m_next_round_kex_message{std::move(next_round_kex_message)}
  {
    CHECK_AND_ASSERT_THROW_MES(kex_rounds_complete > 0, "multisig account: can't reconstruct account if its kex wasn't initialized");
    
    // initialize base pubkey
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(m_base_privkey, m_base_pubkey),
      "Failed to derive public key");

    // initialize keyshare pubkeys and keyshare map
    m_multisig_keyshare_pubkeys.reserve(m_multisig_privkeys.size());
    rct::key primary_generator(get_primary_generator(m_account_era));
    for (const crypto::secret_key &multisig_privkey : m_multisig_privkeys)
    {
      m_multisig_keyshare_pubkeys.emplace_back(rct::rct2pk(rct::scalarmultKey(primary_generator, rct::sk2rct(multisig_privkey))));
      m_keyshare_to_origins_map[m_multisig_keyshare_pubkeys.back()];  //this will add any missing keyshares
    }

    // add all other signers available for aggregation-style signing
    signer_set_filter temp_filter;
    for (const auto &keyshare_to_origins : m_keyshare_to_origins_map)
    {
      multisig_signers_to_filter(keyshare_to_origins.second, m_signers, temp_filter);
      m_available_signers_for_aggregation |= temp_filter;
    }

    // set config
    set_multisig_config(threshold, std::move(signers));

    // kex rounds should not exceed post-kex verification round
    const std::uint32_t kex_rounds_required{multisig_kex_rounds_required(m_signers.size(), m_threshold)};
    CHECK_AND_ASSERT_THROW_MES(m_kex_rounds_complete <= kex_rounds_required + 1,
      "multisig account: tried to reconstruct account, but kex rounds complete counter is invalid.");

    // once an account is done with kex, the 'next kex msg' is always the post-kex verification message
    //   i.e. the multisig account pubkey signed by the signer's privkey AND the common pubkey
    if (main_kex_rounds_done())
    {
      m_next_round_kex_message = multisig_kex_msg{kex_rounds_required + 1,
        m_base_privkey,
        std::vector<crypto::public_key>{m_multisig_pubkey, m_common_pubkey}}.get_msg();
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  bool multisig_account::account_is_active() const
  {
    return m_kex_rounds_complete > 0;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  bool multisig_account::main_kex_rounds_done() const
  {
    if (account_is_active())
      return m_kex_rounds_complete >= multisig_kex_rounds_required(m_signers.size(), m_threshold);
    else
      return false;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  bool multisig_account::multisig_is_ready() const
  {
    if (main_kex_rounds_done())
      return m_kex_rounds_complete >= multisig_kex_rounds_required(m_signers.size(), m_threshold) + 1;
    else
      return false;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account::set_multisig_config(const std::size_t threshold, std::vector<crypto::public_key> signers)
  {
    // validate
    CHECK_AND_ASSERT_THROW_MES(threshold > 0 && threshold <= signers.size(), "multisig account: tried to set invalid threshold.");
    CHECK_AND_ASSERT_THROW_MES(signers.size() >= 2 && signers.size() <= config::MULTISIG_MAX_SIGNERS,
      "multisig account: tried to set invalid number of signers.");

    for (auto signer_it = signers.begin(); signer_it != signers.end(); ++signer_it)
    {
      // signer pubkeys must be in main subgroup, and not identity
      CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(rct::pk2rct(*signer_it)) && !(*signer_it == rct::rct2pk(rct::identity())),
        "multisig account: tried to set signers, but a signer pubkey is invalid.");
    }

    // own pubkey should be in signers list
    CHECK_AND_ASSERT_THROW_MES(std::find(signers.begin(), signers.end(), m_base_pubkey) != signers.end(),
      "multisig account: tried to set signers, but did not find the account's base pubkey in signer list.");

    // sort signers
    std::sort(signers.begin(), signers.end());

    // signers should all be unique
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(signers.begin(), signers.end()) == signers.end(),
      "multisig account: tried to set signers, but there are duplicate signers unexpectedly.");

    // set
    m_threshold = threshold;
    m_signers = std::move(signers);

    // set signers available by default for aggregation-style signing
    if (m_threshold == m_signers.size())
    {
      // N-of-N: all signers
      m_available_signers_for_aggregation = static_cast<signer_set_filter>(-1);
    }
    else
    {
      // M-of-N: local signer
      signer_set_filter temp_filter;
      multisig_signer_to_filter(m_base_pubkey, m_signers, temp_filter);
      m_available_signers_for_aggregation |= temp_filter;
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account::initialize_kex(const std::uint32_t threshold,
    std::vector<crypto::public_key> signers,
    const std::vector<multisig_kex_msg> &expanded_msgs_rnd1)
  {
    CHECK_AND_ASSERT_THROW_MES(!account_is_active(), "multisig account: tried to initialize kex, but already initialized");
    CHECK_AND_ASSERT_THROW_MES(check_kex_msg_versions(expanded_msgs_rnd1, get_kex_msg_version(m_account_era)),
      "multisig account: tried to initialize kex with messages that have incompatible versions");

    // only mutate account if update succeeds
    multisig_account temp_account{*this};
    temp_account.set_multisig_config(threshold, std::move(signers));
    temp_account.kex_update_impl(expanded_msgs_rnd1);
    *this = std::move(temp_account);
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account::kex_update(const std::vector<multisig_kex_msg> &expanded_msgs)
  {
    CHECK_AND_ASSERT_THROW_MES(account_is_active(), "multisig account: tried to update kex, but kex isn't initialized yet.");
    CHECK_AND_ASSERT_THROW_MES(!multisig_is_ready(), "multisig account: tried to update kex, but kex is already complete.");
    CHECK_AND_ASSERT_THROW_MES(check_kex_msg_versions(expanded_msgs, get_kex_msg_version(m_account_era)),
      "multisig account: tried to update kex with messages that have incompatible versions");

    multisig_account temp_account{*this};
    temp_account.kex_update_impl(expanded_msgs);
    *this = std::move(temp_account);
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account::add_signer_recommendations(const crypto::public_key &signer,
    const std::vector<crypto::public_key> &recommended_keys)
  {
    CHECK_AND_ASSERT_THROW_MES(multisig_is_ready(),
      "multisig account: tried to add signer recommendations, but account isn't ready.");
    CHECK_AND_ASSERT_THROW_MES(std::find(m_signers.begin(), m_signers.end(), signer) != m_signers.end(),
      "multisig account: tried to add signer recommendations, but signer is unknown.");

    // add signer to 'available signers'
    signer_set_filter new_signer_flag;
    multisig_signer_to_filter(signer, m_signers, new_signer_flag);
    m_available_signers_for_aggregation |= new_signer_flag;

    // for each local keyshare that the other signer also recommends, add that signer as an 'origin'
    for (const crypto::public_key &keyshare : recommended_keys)
    {
      // skip keyshares that the local account doesn't have
      if (m_keyshare_to_origins_map.find(keyshare) == m_keyshare_to_origins_map.end())
        continue;

      m_keyshare_to_origins_map[keyshare].insert(signer);
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  bool multisig_account::try_get_aggregate_signing_key(const signer_set_filter filter, crypto::secret_key &aggregate_key_out)
  {
    CHECK_AND_ASSERT_THROW_MES(multisig_is_ready(), "multisig account: tried to get signing key, but account isn't ready.");
    CHECK_AND_ASSERT_THROW_MES(m_multisig_privkeys.size() == m_multisig_keyshare_pubkeys.size(),
      "multisig account: tried to get signing key, but there is a mismatch between multisig privkeys and pubkeys.");

    // check that local signer is able to make an aggregate key with all signers in input filter
    if ((filter & m_available_signers_for_aggregation) != filter)
      return false;

    // check if local signer is in input filter
    if (!signer_is_in_filter(m_base_pubkey, m_signers, filter))
      return false;

    // filter the signer list to get group of signers
    std::vector<crypto::public_key> filtered_signers;
    get_filtered_multisig_signers(filter, m_threshold, m_signers, filtered_signers);
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(filtered_signers.begin(), filtered_signers.end()),
      "multisig account: filtered signers are unsorted (bug).");

    // find local signer's location in filtered set
    auto self_location = std::find(filtered_signers.begin(), filtered_signers.end(), m_base_pubkey);
    CHECK_AND_ASSERT_THROW_MES(self_location != filtered_signers.end(),
      "multisig_account: local signer unexpectedly not in filtered signers despite filter match (bug).");

    // accumulate keyshares that other signers whose ids are lower in the filtered list won't be contributing
    aggregate_key_out = rct::rct2sk(rct::zero());

    for (std::size_t key_index{0}; key_index < m_multisig_privkeys.size(); ++key_index)
    {
      const auto &origins = m_keyshare_to_origins_map[m_multisig_keyshare_pubkeys[key_index]];

      if (std::find_if(origins.begin(), origins.end(),
          [&](const crypto::public_key &origin) -> bool
          {
            return std::find(filtered_signers.begin(), self_location, origin) != self_location;
          }
        ) == origins.end())
      {
        sc_add((unsigned char*)(&aggregate_key_out),
          (const unsigned char*)(&aggregate_key_out),
          (const unsigned char*)(&m_multisig_privkeys[key_index]));
      }
    }

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  std::uint32_t multisig_kex_rounds_required(const std::uint32_t num_signers, const std::uint32_t threshold)
  {
    CHECK_AND_ASSERT_THROW_MES(num_signers >= threshold, "num_signers must be >= threshold");
    CHECK_AND_ASSERT_THROW_MES(threshold >= 1, "threshold must be >= 1");
    return num_signers - threshold + 1;
  }
  //----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
