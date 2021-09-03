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
#include "cryptonote_basic/account_generators.h"

#include <cstdint>
#include <string>
#include <vector>

namespace sp { struct MatrixProof; }


namespace multisig
{
////
// multisig account era conversion msg
// - This message contains a proof that one set of keys correspond 1:1 with another set across two generators, which
//   are defined by account_generator_eras.
//     e.x. {a G, b G, c G} -> {a U, b U, c U}
// - In an M-of-N multisig, if M players send each other account conversion messages, that set of messages can be used
//   to trustlessly convert an old account to one with a new account_generator_era.
//   See the multisig::get_multisig_account_with_new_generator_era() method for more information.
// - INVARIANT: keyshares stored here are canonical prime-order subgroup points.
//
// matrix_proof_msg = versioning-domain-sep || signing_pubkey || old_era || new_era
//
// msg = versioning-domain-sep ||
//       b58(signing_pubkey || old_era || new_era || {old_keyshares} || {new_keyshares} || matrix_proof_challenge ||
//           matrix_proof_response || crypto_sig[signing_privkey](matrix_proof_challenge || matrix_proof_response))
///
class multisig_account_era_conversion_msg final
{
//constructors
public:
  // default constructor
  multisig_account_era_conversion_msg() = default;

  // construct from info
  multisig_account_era_conversion_msg(const crypto::secret_key &signing_privkey,
    const cryptonote::account_generator_era old_account_era,
    const cryptonote::account_generator_era new_account_era,
    const std::vector<crypto::secret_key> &keyshare_privkeys);

  // construct from string
  multisig_account_era_conversion_msg(std::string msg);

  // copy constructor: default

//destructor: default
  ~multisig_account_era_conversion_msg() = default;

//overloaded operators: none

//member functions
  // get msg string
  const std::string& get_msg() const { return m_msg; }
  // get generator era of old account
  cryptonote::account_generator_era get_old_era() const { return m_old_era; }
  // get generator era of new account
  cryptonote::account_generator_era get_new_era() const { return m_new_era; }
  // get the msg signer's old keyshares
  const std::vector<crypto::public_key>& get_old_keyshares() const { return m_old_keyshares; }
  // get the msg signer's new keyshares
  const std::vector<crypto::public_key>& get_new_keyshares() const { return m_new_keyshares; }
  // get msg signing pubkey
  const crypto::public_key& get_signing_pubkey() const { return m_signing_pubkey; }

private:
  // set: msg string based on msg contents, with signing pubkey defined from input privkey
  void construct_msg(const crypto::secret_key &signing_privkey, const sp::MatrixProof &matrix_proof);
  // parse msg string into parts, validate contents and signature
  void parse_and_validate_msg();

//member variables
private:
  // message as string
  std::string m_msg;

  // generator era of old account
  cryptonote::account_generator_era m_old_era;
  // generator era of new account (being converted to)
  cryptonote::account_generator_era m_new_era;
  // the msg signer's old keyshares
  std::vector<crypto::public_key> m_old_keyshares;
  // the msg signer's new keyshares (1:1 with old keyshares)
  std::vector<crypto::public_key> m_new_keyshares;

  // pubkey used to sign this msg
  crypto::public_key m_signing_pubkey;
};

} //namespace multisig
