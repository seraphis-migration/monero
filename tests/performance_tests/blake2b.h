// Copyright (c) 2014-2022, The Monero Project
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

#include "crypto/blake2b.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

#include <array>

template<size_t message_length, bool use_derivation_key>
class test_blake2b
{
public:
  static const size_t num_elements = (message_length < 256) ? 1000 : ((message_length < 2048) ? 100 : 10);
  static const size_t loop_count = 256000 / num_elements + 20;
  static const bool derivation_key_mode = use_derivation_key;
  static const size_t hash_length = sizeof(crypto::hash);

  bool init()
  {
    crypto::rand(message_length, m_data.data());
    crypto::rand(32, reinterpret_cast<unsigned char*>(m_derivation_key.data));

    return true;
  }

  bool test()
  {
    const void *key_data = derivation_key_mode ? m_derivation_key.data : nullptr;
    const std::size_t key_length = derivation_key_mode ? 32 : 0;

    for (std::size_t i{0}; i < num_elements; ++i)
    {
      crypto::hash hash;
      if (blake2b(hash.data, hash_length, &m_data, message_length, key_data, key_length) != 0)
        return false;
    }

    return true;
  }

private:
  std::array<uint8_t, message_length> m_data;
  crypto::public_key m_derivation_key;
};

template<size_t message_length, bool use_derivation_key>
class test_blake2b_streaming
{
public:
  static const size_t num_elements = (message_length < 256) ? 1000 : ((message_length < 2048) ? 100 : 10);
  static const size_t loop_count = 256000 / num_elements + 20;
  static const bool derivation_key_mode = use_derivation_key;
  static const size_t hash_length = sizeof(crypto::hash);

  bool init()
  {
    // prepare message
    crypto::rand(message_length, m_data.data());

    // prepare blake2b internal state
    if (derivation_key_mode)
    {
      crypto::public_key derivation_key;
      crypto::rand(32, reinterpret_cast<unsigned char*>(derivation_key.data));

      if (blake2b_init_key(&m_hash_state, hash_length, derivation_key.data, 32) < 0)
        return false;

      // prepend 0 to force the hash state to be updated (probably don't want to do this in practice)
      char c = 0;
      if (blake2b_update(&m_hash_state, &c, sizeof(c)) < 0)
        return false;
    }
    else
    {
      if (blake2b_init(&m_hash_state, hash_length) < 0)
        return false;
    }

    return true;
  }

  bool test()
  {
    for (std::size_t i{0}; i < num_elements; ++i)
    {
      crypto::hash hash;
      blake2b_state hash_state_copy = m_hash_state;

      // hash while reusing the hash state
      if (blake2b_update(&hash_state_copy, &m_data, message_length) < 0)
        return false;
      if (blake2b_final(&hash_state_copy, hash.data, hash_length) != 0)
        return false;
    }

    return true;
  }

private:
  blake2b_state m_hash_state;
  std::array<uint8_t, message_length> m_data;
};
