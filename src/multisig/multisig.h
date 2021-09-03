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

#pragma once

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "multisig_partial_cn_key_image_msg.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace cryptonote { struct account_keys; }

namespace multisig
{
  /**
  * @brief get_multisig_blinded_secret_key - converts an input private key into a blinded multisig private key
  *    Use 1a: converts account private spend key into multisig private key, which is used for key exchange and message signing
  *    Use 1b: converts account private view key into ancillary private key share, for the composite multisig private view key
  *    Use 2: converts DH shared secrets (curve points) into private keys, which are intermediate private keys in multisig key exchange
  * @param key - private key to transform
  * @return transformed private key
  */
  crypto::secret_key get_multisig_blinded_secret_key(const crypto::secret_key &key);

  bool generate_multisig_key_image(const cryptonote::account_keys &keys,
    std::size_t multisig_key_index,
    const crypto::public_key& out_key,
    crypto::key_image& ki);
  void generate_multisig_LR(const crypto::public_key pkey,
    const crypto::secret_key &k,
    crypto::public_key &L,
    crypto::public_key &R);
  bool generate_multisig_composite_key_image(const cryptonote::account_keys &keys,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
    const crypto::public_key &out_key,
    const crypto::public_key &tx_public_key,
    const std::vector<crypto::public_key> &additional_tx_public_keys,
    std::size_t real_output_index,
    const std::vector<crypto::key_image> &pkis,
    crypto::key_image &ki);
  /**
  * @brief multisig_recover_cn_keyimage_cores - recover cryptonote-style key image cores k^s * Hp(Ko) for onetime
  *      addresses Ko owned by a multisig group with aggregate spend privkey k^s
  *   - Processes multisig partial key image messages to collect key image cores for as many onetime addresses as possible
  *     with the given messages. The algorithm only requires messages from 'at least' M signers to complete a key image base,
  *     which means the algorithm works fine if there are more than M messages.
  *     - The algorithm will attempt to combine keyshares using every available group of messages of size M associated with a
  *       given onetime address, so malicious signers can't block honest subgroups of size M.
  *   - Records onetime addresses that have messages but don't have enough messages to complete their key image cores.
  *   - Records onetime addresses that have messages that record invalid key shares (e.g. because a keyshare that wasn't
  *     produced by the canonical multisig account setup process was used to make a message).
  *     - For each set of messages associated with a onetime address, the algorithm tries to compute the multisig group's base
  *       spend key k^s G by summing together unique 'multisig keyshares' from the messages. If the computed key equals k^s G,
  *       then the corresponding assembled key image base correctly equals k^s Hp(Ko).
  *   - NOTE: this algorithm only produces k^s Hp(Ko). It is up to the caller to add in any 'view key'-related material to
  *     make completed key images.
  * 
  * @param multisig_threshold - the threshold 'M' in the user's M-of-N multisig group
  * @param multisig_signers - message-signing pubkeys of all members of the user's multisig group
  * @param multisig_base_spend_key - base spend key of the user's multisig group: K^s = k^s G
  * @param partial_ki_msgs - map of partial key image messages with format [ Ko : [ signer : msg ] ]
  * @outparam onetime_addresses_with_insufficient_partial_kis_out - onetime addresses that don't have enough messages to
  *     assemble their key image cores, mapped to filters representing the signers who did NOT provide partial ki messages
  *     for those onetime addresses
  * @outparam onetime_addresses_with_invalid_partial_kis_out - onetime addresses with messages that contain invalid key
  *     shares, mapped to filters representing the signers who MAY have caused partial ki combination to fail; note that
  *     we include ALL signers who were members of failing subgroups, and don't subtract signers from succeeding subgroups;
  *     subtracting succeeding signers could allow two malicious signers to collaborate to 'blame' an honest signer for
  *     partial ki combination failures (i.e. by each of them contributing invalid keyshares that cancel when their messages
  *     are combined)
  * @outparam recovered_key_image_cores_out - successfully assembled key image cores k^s Hp(Ko) for onetime addresses Ko with
  *     format [ Ko : KI core ]
  */
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
    std::unordered_map<crypto::public_key, crypto::public_key> &recovered_key_image_cores_out);
} //namespace multisig
