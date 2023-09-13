// Copyright (c) 2022, The Monero Project
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

#include "gtest/gtest.h"

#include "common/base32.h"
#include "crypto/crypto.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "unit_tests_utils.h"

#include <fstream>
#include <stdexcept>
#include <string>

using namespace tools;
using namespace std;

TEST(base32, simple_encode_decode) 
{
    // a
    std::string test{"a"};
    std::string encoded_test;

    encoded_test = base32::encode(test);

    ASSERT_EQ(encoded_test, "ga");

    std::string recovered_test;
    recovered_test = base32::decode(encoded_test);

    ASSERT_EQ(recovered_test, test);

    // aaaaaa....
    test = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    encoded_test = base32::encode(test);

    ASSERT_EQ(encoded_test, "gskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr02");

    recovered_test = base32::decode(encoded_test);

    ASSERT_EQ(recovered_test, test);

}

TEST(base32, invalid_character)
{
    // z
    std::string wrong_encoded_test{"z"};
    std::string recovered_test;

    ASSERT_THROW(base32::decode(wrong_encoded_test), std::invalid_argument);
}

TEST(base32, future_modification_protection)
{
    const boost::filesystem::path test_file_path = unit_test::data_dir / "base32" / "future_modification_protection.txt";

    // pairs of (hex encoding of random bytes, base32_monero encoding of random bytes)
    std::vector<std::pair<std::string, std::string>> test_cases;

    // read test cases from data file
    std::ifstream ifs(test_file_path.string());
    ASSERT_TRUE(ifs);
    while (ifs)
    {
        std::string hex_enc;
        ifs >> hex_enc;

        if (hex_enc.empty())
            break;

        std::string base32_enc;
        ifs >> base32_enc;

        ASSERT_FALSE(base32_enc.empty()); // we shouldn't run out of data on this part

        test_cases.push_back({hex_enc, base32_enc});
    }

    ASSERT_EQ(249, test_cases.size()); // there should be 249 test cases in the file

    for (const auto& test_case : test_cases)
    {
        // test that base32_encode(hex_decode(test_case.first)) == test_case.second

        std::string raw_buf;
        ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(test_case.first, raw_buf));

        const std::string encoded_buf = base32::encode(raw_buf);

        EXPECT_EQ(test_case.second, encoded_buf);
    }
}
