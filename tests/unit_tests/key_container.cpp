#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <gtest/gtest.h>

#include "crypto/chacha.h"
#include "seraphis_wallet/key_container.h"
#include "unit_tests_utils.h"

using namespace seraphis_wallet;

TEST(seraphis_wallet, key_container) {
    KeyContainer container;
    crypto::chacha_key key;
}

TEST(seraphis_wallet, store_and_load_key_container)
{
    // 1. create variables, set password and path
    KeyContainer kc_all{},kc_all_recovered{},kc_vo{},kc_vb{};
    crypto::chacha_key chacha_key;
    const uint64_t kdf_rounds = 1;
    const epee::wipeable_string password = "password";
    const boost::filesystem::path wallet_file_all = unit_test::data_dir / "wallet3.spkeys";
    const boost::filesystem::path wallet_file_vo = unit_test::data_dir / "wallet3_vo.spkeys";
    
    // 2. generate chacha_key and keys of container
    crypto::generate_chacha_key(password.data(),password.length(),chacha_key,kdf_rounds);
    kc_all.generate_keys(chacha_key);

    // 3. save keys to file
    ASSERT_TRUE(kc_all.write_all(wallet_file_all.string(), chacha_key));
    ASSERT_TRUE(kc_all.write_view_only(wallet_file_vo.string(), chacha_key));
    
    // 4. load keys from file
    ASSERT_TRUE(kc_all_recovered.load_from_keys_file(wallet_file_all.string(), chacha_key));
    ASSERT_TRUE(kc_vo.load_from_keys_file(wallet_file_vo.string(), chacha_key));

    // 5. verify if stored and loaded keys are the same
    ASSERT_TRUE(kc_all.compare_keys(kc_all_recovered, chacha_key));
    ASSERT_FALSE(kc_all.compare_keys(kc_vo, chacha_key));
}
