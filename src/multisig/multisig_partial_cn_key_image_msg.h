// Copyright (c) 2021, The Monero Project
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

#include <cstdint>
#include <string>
#include <vector>

namespace sp { struct MatrixProof; }

namespace multisig
{

////
// multisig partial cryptonote key image message
// - This message contains a proof that a set of public keys on generator G have 1:1 discrete log relations with a
//   set of partial key images on base key Hp(Ko) for hash-to-point algorithm Hp() and some onetime address Ko.
// - A multisig group member (for an M-of-N multisig) can recover the key image KI for a cryptonote onetime address
//   Ko owned by the group by collecting these messages from M group members (where the private signing keys are
//   shares of the group key held by each group member). Once at least M messages are collected, sum together unique
//   partial KI keys from those message (plus the onetime address's view component times Hp(Ko)) to get the actual
//   key image KI. Verify the key image by summing the unique multisig public keyshares from the messages and expecting
//   the result to equal the group's base spend key.
// - INVARIANT: keyshares stored here are canonical prime-order subgroup points (this is guaranteed by obtaining the
//   keyshares from a MatrixProof).
///
class multisig_partial_cn_key_image_msg final
{
//constructors
public:
  // default constructor
  multisig_partial_cn_key_image_msg() = default;
  // construct from info (create message)
  multisig_partial_cn_key_image_msg(const crypto::secret_key &signing_privkey,
    const crypto::public_key &onetime_address,
    const std::vector<crypto::secret_key> &keyshare_privkeys);
  // construct from string (deserialize and validate message)
  multisig_partial_cn_key_image_msg(std::string msg);

//member functions
  // get msg string
  const std::string& get_msg() const { return m_msg; }
  // get onetime address this message is built for
  const crypto::public_key& get_onetime_address() const { return m_onetime_address; }
  // get the multisig group key keyshares (these are guaranteed to be canonical points)
  const std::vector<crypto::public_key>& get_multisig_keyshares() const { return m_multisig_keyshares; }
  // get the partial key image keys (these are guaranteed to be canonical points)
  const std::vector<crypto::public_key>& get_partial_key_images() const { return m_partial_key_images; }
  // get msg signing pubkey (guaranteed to be a canonical point)
  const crypto::public_key& get_signing_pubkey() const { return m_signing_pubkey; }

private:
  // set: msg string based on msg contents, with signing pubkey defined from signing privkey
  void construct_msg(const crypto::secret_key &signing_privkey, const sp::MatrixProof &matrix_proof);
  // parse msg string into parts, validate contents and signature
  void parse_and_validate_msg();

//member variables
private:
  // message as string
  std::string m_msg;

  // onetime address this message is built for
  crypto::public_key m_onetime_address;
  // the msg signer's multisig key keyshares
  std::vector<crypto::public_key> m_multisig_keyshares;
  // the msg signer's partial key images for the designated onetime address
  std::vector<crypto::public_key> m_partial_key_images;

  // pubkey used to sign this msg
  crypto::public_key m_signing_pubkey;
};

} //namespace multisig
