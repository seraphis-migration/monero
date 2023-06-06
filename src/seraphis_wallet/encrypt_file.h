// Copyright (c) 2023, The Monero Project
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

#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"
#include "serialization/crypto.h"
#include "serialization/string.h"
#include "seraphis_mocks/jamtis_mock_keys.h"

#include "file_io_utils.h"

#include <vector>
#include <string>


using namespace sp::jamtis::mocks;

struct encrypted_file 
{
  std::string encrypted_data;
  crypto::chacha_iv iv;

  BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(encrypted_data)
    FIELD(iv)
  END_SERIALIZE()
};

template <class T>
bool read_encrypted_file(std::string path, const epee::wipeable_string &password, T &ti)
{

  // 1. Load encrypted file to string
  std::string buf;
  if (!epee::file_io_utils::load_file_to_string(path, buf))
    return false;

  encrypted_file file;

  // 2. Serialize to encrypted_file format
  binary_archive<false> file_ar{epee::strspan<std::uint8_t>(buf)};
  if (!::serialization::serialize(file_ar, file))
    return false;

  // 3. Generate chacha key using cryptonote slow_hash
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, 1);

  // 4. Get string with decrypted data
  std::string decrypted_data;
  decrypted_data.resize(file.encrypted_data.size());
  crypto::chacha20(file.encrypted_data.data(), file.encrypted_data.size(), key,
                   file.iv, &decrypted_data[0]);

  // 5. Deserialize into the structure
  binary_archive<false> ar{epee::strspan<std::uint8_t>(decrypted_data)};
  if (!::serialization::serialize(ar, ti))
    return false;

  return true;
}

template <class T>
bool write_encrypted_file(std::string path, const epee::wipeable_string &password, T &ti) {

  // 1. Generate chacha key using cryptonote slow_hash
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, 1);

  // 2. Serialize structure
  std::stringstream data_oss;
  binary_archive<true> data_ar(data_oss);
  if (!::serialization::serialize(data_ar, ti))
    return false;
  std::string buf = data_oss.str();

  // 3. Generate random iv for the encrypted file
  encrypted_file tf = {};
  tf.iv = crypto::rand<crypto::chacha_iv>();

  // 4. Resize encrypted_data to the size of serialized string
  std::string encrypted_data;
  encrypted_data.resize(buf.size());

  // 5. Encrypt data with iv
  crypto::chacha20(buf.data(), buf.size(), key, tf.iv, &encrypted_data[0]);
  tf.encrypted_data = encrypted_data;

  // 6. Serialize encrypted data
  std::stringstream file_oss;
  binary_archive<true> file_ar(file_oss);
  if (!::serialization::serialize(file_ar, tf))
    return false;

  // 7. Save encrypted string to file
  if (!epee::file_io_utils::save_string_to_file(path, file_oss.str()))
    return false;

  return true;
}


// TO BE REPLACED BY KEY_CONTAINER
bool generate_master_wallet(std::string path, const epee::wipeable_string &password);
bool read_master_wallet(std::string path, const epee::wipeable_string &password, jamtis_mock_keys &keys_out);

