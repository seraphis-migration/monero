#pragma once

#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "file_io_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "serialization/string.h"
#include "storages/portable_storage_template_helper.h"
#include "string_coding.h"

#include <type_traits>

struct EncryptedFile
{
    std::string encrypted_data;
    crypto::chacha_iv iv;

    BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(encrypted_data)
    FIELD(iv)
    END_SERIALIZE()
};

template <class T> bool read_encrypted_file(std::string path, const crypto::chacha_key &key, T &struct_out)
{
    std::string buf;
    if (!epee::file_io_utils::load_file_to_string(path, buf))
        return false;

    EncryptedFile file;

    binary_archive<false> file_ar{epee::strspan<std::uint8_t>(buf)};
    if (!::serialization::serialize(file_ar, file))
        return false;

    std::string decrypted_data;
    decrypted_data.resize(file.encrypted_data.size());
    crypto::chacha20(file.encrypted_data.data(), file.encrypted_data.size(), key, file.iv, &decrypted_data[0]);

    binary_archive<false> ar{epee::strspan<std::uint8_t>(decrypted_data)};

    if (!::serialization::serialize(ar, struct_out))
        return false;

    return true;
}

// NOTE: if this were c++20, Concepts and `require` could be used to make this one function
template <class T> bool read_encrypted_file_json(std::string path, const crypto::chacha_key &key, T &struct_out)
{
    std::string buf;
    if (!epee::file_io_utils::load_file_to_string(path, buf))
        return false;

    EncryptedFile file;

    binary_archive<false> file_ar{epee::strspan<std::uint8_t>(buf)};
    if (!::serialization::serialize(file_ar, file))
        return false;

    std::string decrypted_data;
    decrypted_data.resize(file.encrypted_data.size());
    crypto::chacha20(file.encrypted_data.data(), file.encrypted_data.size(), key, file.iv, &decrypted_data[0]);

    return epee::serialization::load_t_from_json(struct_out, decrypted_data);
}

template <class T> bool write_encrypted_file(std::string path, const crypto::chacha_key &key, T &struct_in)
{
    std::stringstream data_oss;
    binary_archive<true> data_ar(data_oss);
    if (!::serialization::serialize(data_ar, struct_in))
        return false;

    std::string buf = data_oss.str();

    EncryptedFile file = {};
    file.iv = crypto::rand<crypto::chacha_iv>();

    std::string encrypted_data;
    encrypted_data.resize(buf.size());

    crypto::chacha20(std::move(buf.data()), buf.size(), key, file.iv, &encrypted_data[0]);

    file.encrypted_data = encrypted_data;

    std::stringstream file_oss;
    binary_archive<true> file_ar(file_oss);
    if (!::serialization::serialize(file_ar, file))
        return false;

    return epee::file_io_utils::save_string_to_file(path, file_oss.str());
}

template <class T> bool write_encrypted_file_json(std::string path, const crypto::chacha_key &key, T &struct_in)
{
    std::string struct_json = epee::serialization::store_t_to_json(struct_in);

    EncryptedFile file = {};
    file.iv = crypto::rand<crypto::chacha_iv>();

    std::string encrypted_data;
    encrypted_data.resize(struct_json.size());

    crypto::chacha20(std::move(struct_json.data()), struct_json.size(), key, file.iv, &encrypted_data[0]);

    file.encrypted_data = encrypted_data;

    std::stringstream file_oss;
    binary_archive<true> file_ar(file_oss);
    if (!::serialization::serialize(file_ar, file))
        return false;

    return epee::file_io_utils::save_string_to_file(path, file_oss.str());
}
