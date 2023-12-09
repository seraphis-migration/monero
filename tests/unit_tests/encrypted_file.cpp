#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <gtest/gtest.h>

#include "crypto/chacha.h"
#include "seraphis_wallet/encrypted_file.h"
#include "serialization/serialization.h"
#include "serialization/keyvalue_serialization.h"

struct test_s
{
    std::string data;

    BEGIN_SERIALIZE()
    FIELD(data)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(data)
    END_KV_SERIALIZE_MAP()
};

TEST(EncryptedFile, ReadWriteBlob)
{
    boost::filesystem::path temp_file = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    const std::string tmp_path = temp_file.native();

    test_s test{.data = "monero is awesome"};

    crypto::chacha_key key;
    crypto::generate_chacha_key("monero is double awesome", key, 1);

    ASSERT_TRUE(write_encrypted_file(tmp_path, key, test));

    ASSERT_TRUE(read_encrypted_file(tmp_path, key, test));

    ASSERT_TRUE(test.data == "monero is awesome");
}

TEST(EncryptedFile, ReadWriteJson)
{
    boost::filesystem::path temp_file = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    const std::string tmp_path = temp_file.native();

    test_s test{.data = "monero is awesome!"};

    crypto::chacha_key key;
    crypto::generate_chacha_key("monero is double awesome", key, 1);

    ASSERT_TRUE(write_encrypted_file_json(tmp_path, key, test));

    ASSERT_TRUE(read_encrypted_file_json(tmp_path, key, test));

    ASSERT_TRUE(test.data == "monero is awesome!");
}
