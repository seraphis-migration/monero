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

#pragma once

#include "account_generator_era.h"
#include "crypto/crypto.h"
#include "multisig_account_era_conversion_msg.h"
#include "multisig_kex_msg.h"
#include "multisig_signer_set_filter.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


namespace multisig
{
  /**
  * multisig account:
  * 
  * - handles account keys for an M-of-N multisig participant (M <= N; M >= 1; N >= 2)
  * - encapsulates multisig account construction process (via key exchange [kex])
  * - TODO: encapsulates key preparation for aggregation-style signing
  *
  * :: multisig pubkey: the private key is split, M group participants are required to reassemble (e.g. to sign something)
  *    - in cryptonote, this is the multisig spend key
  * :: multisig common pubkey: the private key is known to all participants (e.g. for authenticating as a group member)
  *    - in cryptonote, this is the multisig view key
  * 
  * 
  * multisig key exchange:
  * 
  * An 'M-of-N' (M <= N; M >= 1; N >= 2) multisignature key is a public key where at least 'M' out of 'N'
  * possible co-signers must collaborate in order to create a signature.
  * 
  * Constructing a multisig key involves a series of Diffie-Hellman exchanges between participants.
  * At the end of key exchange (kex), each participant will hold a number of private keys. Each private
  * key is shared by a group of (N - M + 1) participants. This way if (N - M) co-signers are missing, every
  * private key will be held by at least one of the remaining M people.
  * 
  * Note on MULTISIG_MAX_SIGNERS: During key exchange, participants will have up to '(N - 1) choose (N - M)'
  *   key shares. If N is large, then the max number of key shares (when M = (N-1)/2) can be huge. A limit of N <= 16 was
  *   arbitrarily chosen as a power of 2 that can accomodate the vast majority of practical use-cases. To increase the
  *   limit, FROST-style key aggregation should be used instead (it is more efficient than DH-based key generation
  *   when N - M > 1).
  * 
  * - Further reading
  *   - MRL-0009: https://www.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
  *   - MuSig2: https://eprint.iacr.org/2020/1261
  *   - ZtM2: https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf Ch. 9, especially Section 9.6.3
  *   - FROST: https://eprint.iacr.org/2018/417
  */
  using multisig_keyset_map_memsafe_t = 
    std::unordered_map<crypto::public_key_memsafe, std::unordered_set<crypto::public_key>>;
  using multisig_keyshare_origins_map_t = std::unordered_map<crypto::public_key, std::unordered_set<crypto::public_key>>;

  class multisig_account final
  {
  public:
  //constructors
    // default constructor
    multisig_account() = default;

    /**
    * construct from base privkeys
    * 
    * - prepares a kex msg for the first round of multisig key construction.
    *    - the local account's kex msgs are signed with the base_privkey
    *    - the first kex msg transmits the local base_common_privkey to other participants, for creating the group's common_privkey
    */
    multisig_account(const cryptonote::account_generator_era era,
      const crypto::secret_key &base_privkey,
      const crypto::secret_key &base_common_privkey);

    // reconstruct from full account details (not recommended)
    multisig_account(const cryptonote::account_generator_era era,
      const std::uint32_t threshold,
      std::vector<crypto::public_key> signers,
      const crypto::secret_key &base_privkey,
      const crypto::secret_key &base_common_privkey,
      std::vector<crypto::secret_key> multisig_privkeys,
      const crypto::secret_key &common_privkey,
      const crypto::public_key &multisig_pubkey,
      multisig_keyshare_origins_map_t keyshare_origins_map,
      const std::uint32_t kex_rounds_complete,
      multisig_keyset_map_memsafe_t kex_origins_map,
      std::string next_round_kex_message);

    // copy constructor: default

  //destructor: default
    ~multisig_account() = default;

  //overloaded operators: none

  //getters
    // get account era
    cryptonote::account_generator_era get_era() const { return m_account_era; }
    // get threshold
    std::uint32_t get_threshold() const { return m_threshold; }
    // get signers
    const std::vector<crypto::public_key>& get_signers() const { return m_signers; }
    // get signers who are available for aggregation-style signing
    std::vector<crypto::public_key> get_signers_available_for_aggregation_signing() const;
    // get base privkey
    const crypto::secret_key& get_base_privkey() const { return m_base_privkey; }
    // get base pubkey
    const crypto::public_key& get_base_pubkey() const { return m_base_pubkey; }
    // get base common privkey
    const crypto::secret_key& get_base_common_privkey() const { return m_base_common_privkey; }
    // get multisig privkeys
    const std::vector<crypto::secret_key>& get_multisig_privkeys() const { return m_multisig_privkeys; }
    // get common privkey
    const crypto::secret_key& get_common_privkey() const { return m_common_privkey; }
    // get multisig pubkey
    const crypto::public_key& get_multisig_pubkey() const { return m_multisig_pubkey; }
    // get common pubkey
    const crypto::public_key& get_common_pubkey() const { return m_common_pubkey; }
    // get keyshare to origins map
    const multisig_keyshare_origins_map_t& get_keyshares_to_origins_map() const { return m_keyshare_to_origins_map; }
    // get kex rounds complete
    std::uint32_t get_kex_rounds_complete() const { return m_kex_rounds_complete; }
    // get kex keys to origins map
    const multisig_keyset_map_memsafe_t& get_kex_keys_to_origins_map() const { return m_kex_keys_to_origins_map; }
    // get the kex msg for the next round
    const std::string& get_next_kex_round_msg() const { return m_next_round_kex_message; }
    // get account era conversion message for converting this account to 'new_era'
    multisig_account_era_conversion_msg get_account_era_conversion_msg(const cryptonote::account_generator_era new_era) const;

  //account status functions
    // account has been intialized, and the account holder can use the 'common' key
    bool account_is_active() const;
    // account has gone through main kex rounds, only remaining step is to verify all other participants are ready
    bool main_kex_rounds_done() const;
    // account is ready to make multisig signatures
    bool multisig_is_ready() const;

  //account helpers
  private:
    // set the threshold (M) and signers (N), and initialize the 'available signers for aggregation signing' filter
    void set_multisig_config(const std::size_t threshold, std::vector<crypto::public_key> signers);

  //account mutators: key exchange to set up account
  public:
    /**
    * brief: initialize_kex - initialize key exchange
    *    - Updates the account with a 'transactional' model. This account will only be mutated if the update succeeds.
    */
    void initialize_kex(const std::uint32_t threshold,
      std::vector<crypto::public_key> signers,
      const std::vector<multisig_kex_msg> &expanded_msgs_rnd1);
    /**
    * brief: kex_update - Complete the 'in progress' kex round and set the kex message for the next round.
    *    - Updates the account with a 'transactional' model. This account will only be mutated if the update succeeds.
    *    - The main interface for multisig key exchange, this handles all the work of processing input messages,
    *      creating new messages for new rounds, and finalizing the multisig shared public key when kex is complete.
    * param: expanded_msgs - kex messages corresponding to the account's 'in progress' round
    */
    void kex_update(const std::vector<multisig_kex_msg> &expanded_msgs);
    /**
    * brief: add_signer_recommendations - Update keyshare-to-origins map with a specific signer's recommendations.
    *    - Used to recover the keyshare-to-origins map if it is lost.
    *    - Note: It is not a security problem if the recommended keys vector is unvalidated. A malicious signer COULD
    *            provide an invalid keyshare recommendation list, which would likely prevent the local signer from
    *            successfully completing signatures with that signer, BUT malicious signers have
    *            other ways to prevent the local account from co-signing a message with them.
    *            It is worth noting that:
    *            1) The malicious signer recommending invalid keyshares CANNOT prevent the local account from co-signing
    *               messages with M-1 honest other signers.
    *            2) Not validating keyshare lists may make it difficult to properly track down which signer caused a given
    *               signature attempt to fail. However, effective validation would require messages from all signers
    *               in order to do something like evaluate_multisig_kex_round_msgs(). Unfortunately, requiring > M signers
    *               to recover aggregation-style signing would violate the invariant that a multisig account should only
    *               require M honest signers to work once account setup is complete.
    * param: conversion_msg - a conversion message from a non-local signer ('origin') with recommended keyshares
    *        (we abuse the conversion msg api instead of implementing an entirely new msg format and plumbing for this
    *        method that primarly exists to help legacy accounts)
    */
    void add_signer_recommendations(const multisig_account_era_conversion_msg &conversion_msg);

  private:
    // implementation of kex_update() (non-transactional)
    void kex_update_impl(const std::vector<multisig_kex_msg> &expanded_msgs);
    /**
    * brief: initialize_kex_update - Helper for kex_update_impl()
    *    - Collect the local signer's shared keys to ignore in incoming messages, build the aggregate ancillary key
    *      if appropriate.
    * param: generators - generators this account uses
    * param: expanded_msgs - set of multisig kex messages to process
    * param: kex_rounds_required - number of rounds required for kex (not including post-kex verification round)
    * outparam: exclude_pubkeys_out - keys held by the local account corresponding to round 'current_round'
    *    - If 'current_round' is the final round, these are the local account's shares of the final aggregate key.
    */
    void initialize_kex_update(const cryptonote::account_generators &generators,
      const std::vector<multisig_kex_msg> &expanded_msgs,
      const std::uint32_t kex_rounds_required,
      std::vector<crypto::public_key> &exclude_pubkeys_out);
    /**
    * brief: finalize_kex_update - Helper for kex_update_impl()
    * param: generators - generators this account uses
    * param: kex_rounds_required - number of rounds required for kex
    * param: result_keys_to_origins_map - map between keys for the next round and the other participants they correspond to
    * inoutparam: temp_account_inout - account to perform last update steps on
    */
    void finalize_kex_update(const cryptonote::account_generators &generators,
      const std::uint32_t kex_rounds_required,
      multisig_keyset_map_memsafe_t result_keys_to_origins_map);

  //account use functions
  public:
    /**
    * brief: try_get_aggregate_signing_key - Get an aggregate privkey corresponding to a filtered list of signers.
    *   - For each privkey share that the local signer has, it only contributes that privkey if it's signer id
    *     is ordered lowest in the filtered list.
    * param: filter - filter for selecting signers out of the signer list for creating a signature
    * outparam: aggregate_key_out - local signer's privkey contribution to a multisig signing event
    */
    bool try_get_aggregate_signing_key(const signer_set_filter filter, crypto::secret_key &aggregate_key_out) const;

  //member variables
  private:
    /// which era this account is calibrated for
    cryptonote::account_generator_era m_account_era;

    /// misc. account details
    // [M] minimum number of co-signers to sign a message with the aggregate pubkey
    std::uint32_t m_threshold{0};
    // [N] base keys of all participants in the multisig (used to initiate key exchange, and as participant ids for msg signing)
    std::vector<crypto::public_key> m_signers;

    /// local participant's personal keys
    // base keypair of the participant
    // - used for signing messages, to make the initial base key for key exchange, and to make DH derivations for key exchange
    crypto::secret_key m_base_privkey;
    // - used for signing messages (base_privkey * G)
    crypto::public_key m_base_pubkey;
    // common base privkey, used to produce the aggregate common privkey
    crypto::secret_key m_base_common_privkey;

    /// core multisig account keys
    // the account's private key shares of the multisig address
    std::vector<crypto::secret_key> m_multisig_privkeys;
    std::vector<crypto::public_key> m_multisig_keyshare_pubkeys;
    // a privkey owned by all multisig participants (e.g. a cryptonote view key)
    crypto::secret_key m_common_privkey;
    // the multisig public key (e.g. a cryptonote spend key)
    crypto::public_key m_multisig_pubkey;
    // the common public key (e.g. a view spend key)
    crypto::public_key m_common_pubkey;

    /// records which other signers have each of the local signer's multisig privkeys
    multisig_keyshare_origins_map_t m_keyshare_to_origins_map;
    /// helper filter that records which other signers are present in m_keyshare_to_origins_map
    signer_set_filter m_available_signers_for_aggregation{0};

    /// kex variables
    // number of key exchange rounds that have been completed (all messages for the round collected and processed)
    std::uint32_t m_kex_rounds_complete{0};
    // this account's pubkeys for the in-progress key exchange round
    // - either DH derivations (intermediate rounds), H(derivation)*G (final round), empty (when kex is done)
    multisig_keyset_map_memsafe_t m_kex_keys_to_origins_map;
    // the account's message for the in-progress key exchange round
    std::string m_next_round_kex_message;
  };

  /**
  * brief: multisig_kex_rounds_required - The number of key exchange rounds required to produce an M-of-N shared key.
  *    - Key exchange (kex) is a synchronous series of 'rounds'. In an 'active round', participants send messages
  *      to each other.
  *    - A participant considers a round 'complete' when they have collected sufficient messages
  *      from other participants, processed those messages, and updated their multisig account state.
  *    - Typically (as implemented in this module), completing a round coincides with making a message for the next round.
  * param: num_signers - number of participants in multisig (N)
  * param: threshold - threshold of multisig (M)
  * return: number of kex rounds required
  */
  std::uint32_t multisig_kex_rounds_required(const std::uint32_t num_signers, const std::uint32_t threshold);

  //todo
  // - new era != old era
  // - need at least M - 1 other signers (all members of account)
  // - verify old multisig pubkey can be recomputed from local keyshares + unique sent keyshares
  // - make keyshare_origins_map with local keyshares mapped to matching recommendations from input list
  //   - can be extended with add_signer_recommendations() later on
  void get_multisig_account_with_new_generator_era(const multisig_account &original_account,
    const cryptonote::account_generator_era new_era,
    const std::vector<multisig_account_era_conversion_msg> &conversion_msgs,
    multisig_account &new_account_out);
} //namespace multisig
