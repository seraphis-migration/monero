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
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "include_base_utils.h"
#include "multisig.h"
#include "multisig_partial_cn_key_image_msg.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
  //----------------------------------------------------------------------------------------------------------------------
  // note: keyshares stored in multisig_partial_cn_key_image_msg's are guaranteed to be canonical (prime order subgroup)
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_process_partial_ki_msg(const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &expected_onetime_address,
    const crypto::public_key &expected_msg_signer,
    const multisig_partial_cn_key_image_msg &partial_ki_msg,
    std::unordered_set<crypto::public_key> &collected_multisig_keyshares_inout,
    std::unordered_set<crypto::public_key> &collected_partial_key_images_inout)
  {
    // ignore messages from signers outside the designated signer list
    if (std::find(multisig_signers.begin(), multisig_signers.end(), expected_msg_signer) == multisig_signers.end())
      return false;

    // ignore message with unexpected signer (probably an upstream mapping bug)
    if (!(expected_msg_signer == partial_ki_msg.get_signing_pubkey()))
      return false;

    // ignore messages with unexpected onetime address (probably an upstream mapping bug)
    if (!(expected_onetime_address == partial_ki_msg.get_onetime_address()))
      return false;

    // save the multisig keyshares
    for (const crypto::public_key &multisig_keyshare : partial_ki_msg.get_multisig_keyshares())
      collected_multisig_keyshares_inout.insert(multisig_keyshare);

    // save the partial key images
    for (const crypto::public_key &partial_ki : partial_ki_msg.get_partial_key_images())
      collected_partial_key_images_inout.insert(partial_ki);

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_collect_partial_ki_keyshares(const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &expected_onetime_address,
    // [ signer : msg ]
    const std::unordered_map<crypto::public_key, multisig_partial_cn_key_image_msg> &partial_ki_msgs,
    // [ signer : signer group ]
    const std::unordered_map<crypto::public_key, signer_set_filter> &signers_as_filters,
    const signer_set_filter filter,
    std::unordered_set<crypto::public_key> &collected_multisig_keyshares_out,
    std::unordered_set<crypto::public_key> &collected_partial_key_images_out)
  {
    collected_multisig_keyshares_out.clear();
    collected_partial_key_images_out.clear();

    // collect multisig and ki keyshares for this signer subgroup
    for (const auto &partial_ki_msg : partial_ki_msgs)
    {
      // ignore messages with unknown associated signers (continuing here is probably due to a bug)
      if (signers_as_filters.find(partial_ki_msg.first) == signers_as_filters.end())
        continue;
      // ignore messages from signers not in the specified subgroup
      if (!(signers_as_filters.at(partial_ki_msg.first) & filter))
        continue;

      if (!try_process_partial_ki_msg(multisig_signers,
          expected_onetime_address,
          partial_ki_msg.first,
          partial_ki_msg.second,
          collected_multisig_keyshares_out,
          collected_partial_key_images_out))
        return false;
    }

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_combine_partial_ki_shares(const crypto::public_key &multisig_base_spend_key,
    const std::unordered_set<crypto::public_key> &collected_multisig_keyshares,
    const std::unordered_set<crypto::public_key> &collected_partial_key_images,
    crypto::public_key &recovered_key_image_core_out)
  {
    // partial ki shares cannot be combined safely if the multisig base spend key can't be reproduced from the associated
    //   multisig base spend key keyshares
    // - the entire purpose of partial KI messages (which contain dual-base vector proofs) is to prove that the constructed
    //   key image core has a proper discrete-log relation with the multisig group's base spend key k^s G
    // - note: this will fail if the multisig base spend key has a small order subgroup offset, because multisig
    //         keyshares collected from partial ki messages are 'small order sanitized'; preventing non-canonical multisig
    //         base spend keys is the responsibility of the account setup process
    rct::key nominal_base_spendkey{rct::identity()};

    for (const crypto::public_key &multisig_keyshare : collected_multisig_keyshares)
      rct::addKeys(nominal_base_spendkey, nominal_base_spendkey, rct::pk2rct(multisig_keyshare));

    if (!(nominal_base_spendkey == rct::pk2rct(multisig_base_spend_key)))
      return false;

    // compute the constructed key image core: k^s * Hp(Ko)
    rct::key key_image_core{rct::identity()};

    for (const crypto::public_key &partial_key_image : collected_partial_key_images)
      rct::addKeys(key_image_core, key_image_core, rct::pk2rct(partial_key_image));

    recovered_key_image_core_out = rct::rct2pk(key_image_core);
    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_get_key_image_core(const std::uint32_t multisig_threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &multisig_base_spend_key,
    const crypto::public_key &expected_onetime_address,
    // [ signer : msg ]
    const std::unordered_map<crypto::public_key, multisig_partial_cn_key_image_msg> &partial_ki_msgs,
    // [ Ko : missing signers ]
    std::unordered_map<crypto::public_key, signer_set_filter> &onetime_addresses_with_insufficient_partial_kis_inout,
    // [ Ko : possibly invalid signers ]
    std::unordered_map<crypto::public_key, signer_set_filter> &onetime_addresses_with_invalid_partial_kis_inout,
    // [ Ko : KI core ]
    std::unordered_map<crypto::public_key, crypto::public_key> &recovered_key_image_cores_inout)
  {
    CHECK_AND_ASSERT_THROW_MES(multisig_threshold <= multisig_signers.size(),
      "multisig recover cn key image bases: threshold is greater than the number of signers.");

    // 1. identify available signers
    signer_set_filter available_signers_filter{};
    std::unordered_map<crypto::public_key, signer_set_filter> signers_as_filters;

    for (const auto &signer_with_msg : partial_ki_msgs)
    {
      try { multisig_signer_to_filter(signer_with_msg.first, multisig_signers, signers_as_filters[signer_with_msg.first]); }
      catch (...)
      {
        // skip unknown signers
        signers_as_filters.erase(signer_with_msg.first);
        continue;
      }

      available_signers_filter |= signers_as_filters[signer_with_msg.first];
    }

    // 2. early return if there are insufficient valid signers
    if (signers_as_filters.size() < multisig_threshold)
    {
      onetime_addresses_with_insufficient_partial_kis_inout[expected_onetime_address] = available_signers_filter;
      return false;
    }

    // 3. get permutations of available signers so we can make a separate ki combination attempt for each possible
    //    subgroup (this way malicious signers can't pollute honest subgroups)
    std::vector<signer_set_filter> filter_permutations;
    aggregate_multisig_signer_set_filter_to_permutations(multisig_threshold,
      multisig_signers.size(),
      available_signers_filter,
      filter_permutations);

    // 4. for each permutation of available signers, try to assemble ki shares into a KI core for the specified Ko
    std::unordered_set<crypto::public_key> collected_multisig_keyshares_temp;
    std::unordered_set<crypto::public_key> collected_partial_key_images_temp;
    crypto::public_key recovered_key_image_core_temp;

    for (const signer_set_filter filter : filter_permutations)
    {
      // a. try to collect collect multisig and ki keyshares for this combination attempt
      if (!try_collect_partial_ki_keyshares(multisig_signers,
        expected_onetime_address,
        partial_ki_msgs,
        signers_as_filters,
        filter,
        collected_multisig_keyshares_temp,
        collected_partial_key_images_temp))
      {
        onetime_addresses_with_invalid_partial_kis_inout[expected_onetime_address] |= filter;
        continue;
      }

      // b. try to get the key image core using this subgroup
      if (!try_combine_partial_ki_shares(multisig_base_spend_key,
        collected_multisig_keyshares_temp,
        collected_partial_key_images_temp,
        recovered_key_image_core_temp))
      {
        // if the assembly attempt fails, record the signer subgroup that caused the failure (add to existing failures)
        onetime_addresses_with_invalid_partial_kis_inout[expected_onetime_address] |= filter;
        continue;
      }

      // c. assembly succeeded
      recovered_key_image_cores_inout[expected_onetime_address] = recovered_key_image_core_temp;
      return true;
    }

    return false;  //all attempts failed
  }
  //----------------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------------
  crypto::secret_key get_multisig_blinded_secret_key(const crypto::secret_key &key)
  {
    CHECK_AND_ASSERT_THROW_MES(key != crypto::null_skey, "Unexpected null secret key (danger!).");

    rct::key multisig_salt;
    static_assert(sizeof(rct::key) == sizeof(config::HASH_KEY_MULTISIG), "Hash domain separator is an unexpected size");
    memcpy(multisig_salt.bytes, config::HASH_KEY_MULTISIG, sizeof(rct::key));

    // private key = H(key, domain-sep)
    rct::keyV data;
    data.reserve(2);
    data.push_back(rct::sk2rct(key));
    data.push_back(multisig_salt);
    crypto::secret_key result = rct::rct2sk(rct::hash_to_scalar(data));
    memwipe(&data[0], sizeof(rct::key));
    return result;
  }
  //----------------------------------------------------------------------------------------------------------------------
  bool generate_multisig_key_image(const cryptonote::account_keys &keys,
    std::size_t multisig_key_index,
    const crypto::public_key& out_key,
    crypto::key_image& ki)
  {
    if (multisig_key_index >= keys.m_multisig_keys.size())
      return false;
    crypto::generate_key_image(out_key, keys.m_multisig_keys[multisig_key_index], ki);
    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  void generate_multisig_LR(const crypto::public_key pkey,
    const crypto::secret_key &k,
    crypto::public_key &L,
    crypto::public_key &R)
  {
    rct::scalarmultBase((rct::key&)L, rct::sk2rct(k));
    crypto::generate_key_image(pkey, k, (crypto::key_image&)R);
  }
  //----------------------------------------------------------------------------------------------------------------------
  bool generate_multisig_composite_key_image(const cryptonote::account_keys &keys,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
    const crypto::public_key &out_key,
    const crypto::public_key &tx_public_key,
    const std::vector<crypto::public_key> &additional_tx_public_keys,
    std::size_t real_output_index,
    const std::vector<crypto::key_image> &pkis,
    crypto::key_image &ki)
  {
    // create a multisig partial key image
    // KI_partial = ([view key component] + [subaddress component] + [multisig privkeys]) * Hp(output one-time address)
    // - the 'multisig priv keys' here are those held by the local account
    // - later, we add in the components held by other participants
    cryptonote::keypair in_ephemeral;
    if (!cryptonote::generate_key_image_helper(keys,
          subaddresses,
          out_key,
          tx_public_key,
          additional_tx_public_keys,
          real_output_index,
          in_ephemeral,
          ki,
          keys.get_device()))
      return false;
    std::unordered_set<crypto::key_image> used;

    // create a key image component for each of the local account's multisig private keys
    for (std::size_t m = 0; m < keys.m_multisig_keys.size(); ++m)
    {
      crypto::key_image pki;
      // pki = keys.m_multisig_keys[m] * Hp(out_key)
      // pki = key image component
      // out_key = one-time address of an output owned by the multisig group
      bool r = generate_multisig_key_image(keys, m, out_key, pki);
      if (!r)
        return false;

      // this KI component is 'used' because it was included in the partial key image 'ki' above
      used.insert(pki);
    }

    // add the KI components from other participants to the partial KI
    // if they not included yet
    for (const auto &pki: pkis)
    {
      if (used.find(pki) == used.end())
      {
        // ignore components that have already been 'used'
        used.insert(pki);

        // KI_partial = KI_partial + KI_component[...]
        rct::addKeys((rct::key&)ki, rct::ki2rct(ki), rct::ki2rct(pki));
      }
    }

    // at the end, 'ki' will hold the true key image for our output if inputs were sufficient
    // - if 'pkis' (the other participants' KI components) is missing some components
    //   then 'ki' will not be complete

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_recover_cn_keyimage_cores(const std::uint32_t multisig_threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &multisig_base_spend_key,
    // [ Ko : [ signer : msg ] ]
    const std::unordered_map<crypto::public_key,
      std::unordered_map<crypto::public_key, multisig_partial_cn_key_image_msg>> &partial_ki_msgs,
    // [ Ko : missing signers ]
    std::unordered_map<crypto::public_key, signer_set_filter> &onetime_addresses_with_insufficient_partial_kis_out,
    // [ Ko : possibly invalid signers ]
    std::unordered_map<crypto::public_key, signer_set_filter> &onetime_addresses_with_invalid_partial_kis_out,
    // [ Ko : KI core ]
    std::unordered_map<crypto::public_key, crypto::public_key> &recovered_key_image_cores_out)
  {
    onetime_addresses_with_insufficient_partial_kis_out.clear();
    onetime_addresses_with_invalid_partial_kis_out.clear();
    recovered_key_image_cores_out.clear();

    for (const auto &partial_ki_set : partial_ki_msgs)
    {
      try_get_key_image_core(multisig_threshold,
        multisig_signers,
        multisig_base_spend_key,
        partial_ki_set.first,
        partial_ki_set.second,
        onetime_addresses_with_insufficient_partial_kis_out,
        onetime_addresses_with_invalid_partial_kis_out,
        recovered_key_image_cores_out);
    }
  }
  //----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
