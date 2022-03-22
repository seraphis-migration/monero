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

#include "multisig_account_era_conversion_msg.h"
#include "multisig_msg_serialization.h"

#include "common/base58.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "dual_base_vector_proof.h"
#include "include_base_utils.h"
#include "ringct/rctOps.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"

#include <boost/utility/string_ref.hpp> 

#include <sstream>
#include <string>
#include <utility>
#include <vector>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

const boost::string_ref MULTISIG_CONVERSION_MSG_MAGIC_V1{"MultisigConversionV1"};

namespace multisig
{
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void pkv_to_rctv(const std::vector<crypto::public_key> &pkv, rct::keyV &rctv_out)
  {
    rctv_out.clear();
    rctv_out.reserve(pkv.size());
    for (const crypto::public_key &pk : pkv)
      rctv_out.emplace_back(rct::pk2rct(pk));
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void rctv_to_pkv(const rct::keyV &rctv, std::vector<crypto::public_key> &pkv_out)
  {
    pkv_out.clear();
    pkv_out.reserve(rctv.size());
    for (const rct::key &rct_k : rctv)
      pkv_out.emplace_back(rct::rct2pk(rct_k));
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void set_msg_magic(std::string &msg_out)
  {
    msg_out.clear();

    msg_out.append(MULTISIG_CONVERSION_MSG_MAGIC_V1.data(), MULTISIG_CONVERSION_MSG_MAGIC_V1.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static bool try_get_message_no_magic(const std::string &original_msg,
    const boost::string_ref &magic,
    std::string &msg_no_magic_out)
  {
    // abort if magic doesn't match the message
    if (original_msg.substr(0, magic.size()) != magic)
      return false;

    // decode message
    CHECK_AND_ASSERT_THROW_MES(tools::base58::decode(original_msg.substr(magic.size()), msg_no_magic_out),
      "Multisig kex msg decoding error.");

    return true;
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static void get_proof_msg(const boost::string_ref &magic,
    const crypto::public_key &signing_pubkey,
    const cryptonote::account_generator_era old_era,
    const cryptonote::account_generator_era new_era,
    rct::key &proof_msg_out)
  {
    // proof_msg = versioning-domain-sep || signing_pubkey || old_era || new_era
    std::string data;
    data.reserve(magic.size() + sizeof(crypto::public_key) + 2);

    // magic
    data.append(magic.data(), magic.size());

    // signing pubkey
    data.append(reinterpret_cast<const char *>(&signing_pubkey), sizeof(crypto::public_key));

    // new era and old era
    data += static_cast<char>(old_era);
    data += static_cast<char>(new_era);

    rct::cn_fast_hash(proof_msg_out, data.data(), data.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  static crypto::hash get_signature_msg(const crypto::DualBaseVectorProof &dualbase_proof)
  {
    // signature_msg = dualbase_proof_challenge || dualbase_proof_response
    std::string data;
    data.reserve(2*sizeof(crypto::public_key));
    data.append(reinterpret_cast<const char *>(&dualbase_proof.c), sizeof(crypto::public_key));
    data.append(reinterpret_cast<const char *>(&dualbase_proof.r), sizeof(crypto::public_key));

    return crypto::cn_fast_hash(data.data(), data.size());
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account_era_conversion_msg: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_account_era_conversion_msg::multisig_account_era_conversion_msg(const crypto::secret_key &signing_privkey,
      const cryptonote::account_generator_era old_account_era,
      const cryptonote::account_generator_era new_account_era,
      const std::vector<crypto::secret_key> &keyshare_privkeys) :
    m_old_era{old_account_era},
    m_new_era{new_account_era}
  {
    CHECK_AND_ASSERT_THROW_MES(sc_check((const unsigned char*)&signing_privkey) == 0 &&
      signing_privkey != crypto::null_skey, "Invalid msg signing key.");
    rct::key G_1{get_primary_generator(m_old_era)};
    rct::key G_2{get_primary_generator(m_new_era)};
    CHECK_AND_ASSERT_THROW_MES(!(G_1 == rct::Z), "Unknown conversion msg old era.");
    CHECK_AND_ASSERT_THROW_MES(!(G_2 == rct::Z), "Unknown conversion msg new era.");
    CHECK_AND_ASSERT_THROW_MES(keyshare_privkeys.size() > 0, "Can't make conversion message with no keys to convert.");

    // save signing pubkey
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signing_privkey, m_signing_pubkey),
      "Failed to derive public key");

    // make dual base vector proof
    rct::key proof_msg;
    get_proof_msg(MULTISIG_CONVERSION_MSG_MAGIC_V1, m_signing_pubkey, m_old_era, m_new_era, proof_msg);
    crypto::DualBaseVectorProof proof{crypto::dual_base_vector_prove(G_1, G_2, keyshare_privkeys, proof_msg)};

    // set keyshares
    rctv_to_pkv(proof.V_1, m_old_keyshares);
    rctv_to_pkv(proof.V_2, m_new_keyshares);

    // sets message and signing pub key
    construct_msg(signing_privkey, proof);
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account_era_conversion_msg: EXTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  multisig_account_era_conversion_msg::multisig_account_era_conversion_msg(std::string msg) : m_msg{std::move(msg)}
  {
    parse_and_validate_msg();
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account_era_conversion_msg: INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account_era_conversion_msg::construct_msg(const crypto::secret_key &signing_privkey,
    const crypto::DualBaseVectorProof &dualbase_proof)
  {
    ////
    // msg_to_sign = dualbase_proof_challenge || dualbase_proof_response
    //
    // msg = versioning-domain-sep ||
    //          b58(signing_pubkey || old_era || new_era || {old_keyshares} || {new_keyshares} || dualbase_proof_challenge ||
    //              dualbase_proof_response || crypto_sig[signing_privkey](dualbase_proof_challenge || dualbase_proof_response))
    ///

    // sign the message
    crypto::signature msg_signature;
    crypto::generate_signature(get_signature_msg(dualbase_proof), m_signing_pubkey, signing_privkey, msg_signature);

    // mangle the dualbase proof into a crypto::signature
    crypto::signature mangled_dualbase_proof{rct::rct2sk(dualbase_proof.c), rct::rct2sk(dualbase_proof.r)};

    // prepare the message
    std::stringstream serialized_msg_ss;
    binary_archive<true> b_archive(serialized_msg_ss);

    multisig_conversion_msg_serializable msg_serializable;
    msg_serializable.old_era        = m_old_era;
    msg_serializable.new_era        = m_new_era;
    msg_serializable.old_keyshares  = m_old_keyshares;
    msg_serializable.new_keyshares  = m_new_keyshares;
    msg_serializable.signing_pubkey = m_signing_pubkey;
    msg_serializable.dual_base_vector_proof_partial = mangled_dualbase_proof;
    msg_serializable.signature      = msg_signature;

    CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(b_archive, msg_serializable),
      "Failed to serialize multisig conversion msg.");

    // make the message
    set_msg_magic(m_msg);
    m_msg.append(tools::base58::encode(serialized_msg_ss.str()));
  }
  //----------------------------------------------------------------------------------------------------------------------
  // multisig_account_era_conversion_msg: INTERNAL
  //----------------------------------------------------------------------------------------------------------------------
  void multisig_account_era_conversion_msg::parse_and_validate_msg()
  {
    // early return on empty messages
    if (m_msg == "")
      return;

    // deserialize the message
    std::string msg_no_magic;
    CHECK_AND_ASSERT_THROW_MES(try_get_message_no_magic(m_msg, MULTISIG_CONVERSION_MSG_MAGIC_V1, msg_no_magic),
      "Could not remove magic from conversion message.");

    binary_archive<false> archived_msg{epee::strspan<std::uint8_t>(msg_no_magic)};

    // extract data from the message
    crypto::DualBaseVectorProof dualbase_proof;
    crypto::signature msg_signature;

    multisig_conversion_msg_serializable deserialized_msg;
    if (::serialization::serialize(archived_msg, deserialized_msg))
    {
      m_old_era        = deserialized_msg.old_era;
      m_new_era        = deserialized_msg.new_era;
      m_old_keyshares  = std::move(deserialized_msg.old_keyshares);
      m_new_keyshares  = std::move(deserialized_msg.new_keyshares);
      m_signing_pubkey = deserialized_msg.signing_pubkey;
      memcpy(&(dualbase_proof.c), &(deserialized_msg.dual_base_vector_proof_partial.c), sizeof(crypto::ec_scalar));
      memcpy(&(dualbase_proof.r), &(deserialized_msg.dual_base_vector_proof_partial.r), sizeof(crypto::ec_scalar));
      msg_signature    = deserialized_msg.signature;
    }
    else CHECK_AND_ASSERT_THROW_MES(false, "Deserializing conversion msg failed.");

    // checks
    rct::key G_1{get_primary_generator(m_old_era)};
    rct::key G_2{get_primary_generator(m_new_era)};
    CHECK_AND_ASSERT_THROW_MES(!(G_1 == rct::Z), "Unknown conversion msg old era.");
    CHECK_AND_ASSERT_THROW_MES(!(G_2 == rct::Z), "Unknown conversion msg new era.");
    CHECK_AND_ASSERT_THROW_MES(dualbase_proof.V_1.size() > 0, "Conversion message has no conversion keys.");
    CHECK_AND_ASSERT_THROW_MES(m_signing_pubkey != crypto::null_pkey && m_signing_pubkey != rct::rct2pk(rct::identity()),
      "Message signing key was invalid.");
    CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(rct::pk2rct(m_signing_pubkey)),
      "Message signing key was not in prime subgroup.");

    // validate dualbase proof
    pkv_to_rctv(m_old_keyshares, dualbase_proof.V_1);
    pkv_to_rctv(m_new_keyshares, dualbase_proof.V_2);
    get_proof_msg(MULTISIG_CONVERSION_MSG_MAGIC_V1, m_signing_pubkey, m_old_era, m_new_era, dualbase_proof.m);
    CHECK_AND_ASSERT_THROW_MES(crypto::dual_base_vector_verify(dualbase_proof, G_1, G_2),
      "Conversion message dualbase proof invalid.");

    // validate signature
    CHECK_AND_ASSERT_THROW_MES(crypto::check_signature(get_signature_msg(dualbase_proof), m_signing_pubkey, msg_signature),
      "Multisig kex msg signature invalid.");
  }
  //----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
