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

#include "gtest/gtest.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

#include "common/base32.h"
#include "crypto/crypto.h"
#include "string_tools.h"
#include "unit_tests_utils.h"

#ifndef SSIZE_MAX
#define SSIZE_MAX (SIZE_MAX / 2)
#endif

static size_t num_prefix_similar(const char* a, const char* b, size_t n)
{
    // find the number of leading characters that are equal in both strings
    size_t i;
    for (i = 0; i < n && a[i] == b[i]; ++i) {}
    return i;
}

static std::string hex_decode(const std::string& s)
{
    std::string res;
    if (!epee::string_tools::parse_hexstr_to_binbuff(s, res))
        throw std::runtime_error("hex decode");
    return res;
}

static ssize_t encoded_size_mp(const size_t binary_len, const base32::Mode mode)
{
    boost::multiprecision::cpp_int res = binary_len;
    res = res * 8 / 5 + (res % 5 && mode == base32::Mode::encoded_lossy);
    boost::multiprecision::cpp_int max_res = std::numeric_limits<ssize_t>::max();
    if (res > max_res)
        return static_cast<ssize_t>(base32::Error::not_enough_space);
    return static_cast<ssize_t>(res);
}

static ssize_t decoded_size_max_mp(const size_t encoded_len, const base32::Mode mode)
{
    if (encoded_len > static_cast<size_t>(std::numeric_limits<ssize_t>::max()))
        return static_cast<ssize_t>(base32::Error::not_enough_space);
    boost::multiprecision::cpp_int res = encoded_len;
    res = res * 5 / 8 + (res % 8 && mode == base32::Mode::binary_lossy);
    boost::multiprecision::cpp_int max_res = std::numeric_limits<ssize_t>::max();
    if (res > max_res)
        return static_cast<ssize_t>(base32::Error::not_enough_space);
    return static_cast<ssize_t>(res);
}

TEST(base32, encode_decode)
{
    for (size_t raw_len = 0; raw_len < 250; ++raw_len)
    {
        for (size_t i = 0; i < 10; ++i)
        {
            std::string raw_buf;
            raw_buf.resize(raw_len);
            crypto::generate_random_bytes_not_thread_safe(raw_buf.size(), &raw_buf[0]);

            const std::string encoded_buf = base32::encode(raw_buf);
            const std::string decoded_buf = base32::decode(encoded_buf);

            ASSERT_EQ(raw_buf, decoded_buf);
        }
    }
}

TEST(base32, jamtis_address_prefix_compat)
{
    static constexpr const char NETTYPE_CHARS[3] = { 't', 's', 'm' };

    //      use 'v' chars here     VV    since it's invalid and we're forced to overwrite
    std::string addr_prefix = "xmravv00";

    // for version 1..9
    for (int ver = 1; ver <= 9; ++ver)
    {
        addr_prefix[4] = static_cast<char>(ver) + '0'; // xmra1v00, xmra2v00, ..., xmra9v00

        // for nettype in { t, s, m }
        for (const char netype_char : NETTYPE_CHARS)
        {
            addr_prefix[5] = netype_char; // xmravt00, xmravs00, xmravm00

            std::string raw_addr_bytes;
            EXPECT_NO_THROW(raw_addr_bytes = base32::decode(addr_prefix));
            EXPECT_EQ(5, raw_addr_bytes.size());

            // re-encode and check equality
            EXPECT_EQ(addr_prefix, base32::encode(raw_addr_bytes));
        }
    }
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
        std::string raw_buf;
        ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(test_case.first, raw_buf));

        // test that base32_encode(hex_decode(test_case.first)) == test_case.second
        const std::string encoded_buf = base32::encode(raw_buf);
        EXPECT_EQ(test_case.second, encoded_buf);

        // test that base32_decode(test_case.second) == hex_decode(test_cast.first)
        const std::string decoded_buf = base32::decode(test_case.second);
        EXPECT_EQ(raw_buf, decoded_buf);
    }
}

TEST(base32, right_append_affects_right_enc)
{
    // test that we can append randomness on the right side of the unencoded message and keep
    // the same prefix. this property makes Jamtis address headers less annoying

    for (size_t left_len = 0; left_len < 250; ++left_len)
    {
        const size_t expected_prefix_untouched = left_len / 8 * 5;

        std::string left_buf;
        left_buf.resize(left_len);
        crypto::generate_random_bytes_not_thread_safe(left_buf.size(), &left_buf[0]);

        const std::string left_encoded = base32::encode(left_buf);

        for (size_t right_len = 1; right_len <= 16; ++right_len)
        {
            std::string combined_buf = left_buf;
            combined_buf.resize(left_len + right_len);
            crypto::generate_random_bytes_not_thread_safe(right_len, &combined_buf[left_len]);

            const std::string combined_encoded = base32::encode(combined_buf);

            const size_t prefix_sim = num_prefix_similar(left_encoded.data(), combined_encoded.data(), left_len);

            EXPECT_GE(prefix_sim, expected_prefix_untouched);
        }
    }
}

TEST(base32, right_modify_affects_right_enc)
{
    // test that we can randomly modify on the right side of the unencoded message and keep
    // the same prefix. this property makes Jamtis address headers less annoying

    for (size_t total_len = 0; total_len < 250; ++total_len)
    {
        std::string unmodded_buf;
        unmodded_buf.resize(total_len);
        crypto::generate_random_bytes_not_thread_safe(unmodded_buf.size(), &unmodded_buf[0]);

        const std::string unmodded_encoded = base32::encode(unmodded_buf);

        for (size_t right_len = 0; right_len <= total_len; ++right_len)
        {
            const size_t left_len = total_len - right_len;

            std::string modded_buf = unmodded_buf;
            crypto::generate_random_bytes_not_thread_safe(right_len, &modded_buf[left_len]);

            const std::string modded_encoded = base32::encode(modded_buf);

            const size_t prefix_sim = num_prefix_similar(unmodded_encoded.data(), modded_encoded.data(), total_len);
            const size_t expected_prefix_untouched = left_len / 8 * 5;

            EXPECT_GE(prefix_sim, expected_prefix_untouched);
        }
    }
}

TEST(base32, jamtis_address_size)
{
    constexpr size_t HEADER_SIZE = 4 + 1 + 1;
    constexpr size_t CHECKSUM_SIZE = 8;

    constexpr size_t PUBKEY_SIZE = 32;
    constexpr size_t ADDR_TAG_HINT_SIZE = 2;
    constexpr size_t ADDR_INDEX_SIZE = 16;

    constexpr size_t JAMTIS_FR_BODY_SIZE_RAW = 3 * PUBKEY_SIZE + ADDR_INDEX_SIZE + ADDR_TAG_HINT_SIZE;
    constexpr size_t JAMTIS_DENSE_SPARSE_BODY_SIZE_RAW = 4 * PUBKEY_SIZE + ADDR_INDEX_SIZE;

    const size_t JAMTIS_FR_BODY_SIZE = base32::encoded_size(JAMTIS_FR_BODY_SIZE_RAW, base32::Mode::binary_lossy);
    const size_t JAMTIS_DENSE_SPARSE_BODY_SIZE = base32::encoded_size(JAMTIS_DENSE_SPARSE_BODY_SIZE_RAW, base32::Mode::binary_lossy);

    EXPECT_EQ(182, JAMTIS_FR_BODY_SIZE);
    EXPECT_EQ(230, JAMTIS_DENSE_SPARSE_BODY_SIZE);

    const size_t JAMTIS_FR_TOTAL_SIZE = HEADER_SIZE + JAMTIS_FR_BODY_SIZE + CHECKSUM_SIZE;
    const size_t JAMTIS_DENSE_SPARSE_TOTAL_SIZE = HEADER_SIZE + JAMTIS_DENSE_SPARSE_BODY_SIZE + CHECKSUM_SIZE;

    EXPECT_EQ(196, JAMTIS_FR_TOTAL_SIZE);
    EXPECT_EQ(244, JAMTIS_DENSE_SPARSE_TOTAL_SIZE);
}

TEST(base32, binary_lossy)
{
    auto subtest = [](const char *raw_hex, const char *encoded, bool raw_zeroed)
    {
        const std::string raw = hex_decode(raw_hex);

        const std::string enc_actual = base32::encode(raw, base32::Mode::binary_lossy);
        EXPECT_EQ(encoded, enc_actual);

        if (raw_zeroed)
        {
            const std::string dec_actual = base32::decode(encoded, base32::Mode::binary_lossy);
            EXPECT_EQ(raw, dec_actual);
        }
    };

    subtest("", "", true);
    subtest("ff", "9", false);
    subtest("f8", "9", true);
    subtest("ffff", "999", false);
    subtest("fffe", "999", true);
    subtest("ffffff", "9999", false);
    subtest("fffff0", "9999", true);
    subtest("ffffffff", "999999", false);
    subtest("fffffffc", "999999", true);
    subtest("ffffffffff", "99999999", true);
}

TEST(base32, normalization)
{
    EXPECT_EQ(base32::decode("00ii111--uuuu222-"), base32::decode("o0iI1lL--uUvV2zZ-"));
}

TEST(base32, sizes)
{
    static constexpr const ssize_t SPACE_ERR = static_cast<ssize_t>(base32::Error::not_enough_space);
    static_assert(SPACE_ERR < 0, "error value sanity");

    const auto encode_subtest = [](size_t in, ssize_t exp_default_out)
    {
        ssize_t exp_binary_lossy_output = exp_default_out - (exp_default_out > 0 && (in % 5));
        ASSERT_EQ(exp_default_out, encoded_size_mp(in, base32::Mode::encoded_lossy));
        ASSERT_EQ(exp_binary_lossy_output, encoded_size_mp(in, base32::Mode::binary_lossy));
        ASSERT_EQ(exp_default_out, base32::encoded_size(in, base32::Mode::encoded_lossy));
        ASSERT_EQ(exp_binary_lossy_output, base32::encoded_size(in, base32::Mode::binary_lossy));
    };

    const auto decode_subtest = [](size_t in, ssize_t exp_default_out)
    {
        ssize_t exp_binary_lossy_output = exp_default_out + (exp_default_out >= 0 && (in % 8));
        ASSERT_EQ(exp_default_out, decoded_size_max_mp(in, base32::Mode::encoded_lossy));
        ASSERT_EQ(exp_binary_lossy_output, decoded_size_max_mp(in, base32::Mode::binary_lossy));
        ASSERT_EQ(exp_default_out, base32::decoded_size_max(in, base32::Mode::encoded_lossy));
        ASSERT_EQ(exp_binary_lossy_output, base32::decoded_size_max(in, base32::Mode::binary_lossy));
    };

    encode_subtest(0, 0);
    encode_subtest(1, 2);
    encode_subtest(2, 4);
    encode_subtest(3, 5);
    encode_subtest(4, 7);
    encode_subtest(5, 8);

    decode_subtest(0, 0);
    decode_subtest(1, 0);
    decode_subtest(2, 1);
    decode_subtest(3, 1);
    decode_subtest(4, 2);
    decode_subtest(5, 3);
    decode_subtest(6, 3);
    decode_subtest(7, 4);
    decode_subtest(8, 5);

    encode_subtest(SIZE_MAX, SPACE_ERR);
    decode_subtest(SIZE_MAX, SPACE_ERR);

    boost::multiprecision::cpp_int enc_max = SSIZE_MAX;
    enc_max = enc_max * 5 / 8;

    encode_subtest(static_cast<size_t>(enc_max), SSIZE_MAX);
    encode_subtest(static_cast<size_t>(enc_max) + 1, SPACE_ERR);
    
    decode_subtest(static_cast<size_t>(SSIZE_MAX), static_cast<ssize_t>(enc_max));
    decode_subtest(static_cast<size_t>(SSIZE_MAX) + 1, SPACE_ERR);

    // huge encode/decode test
#if 0
    static constexpr const uint32_t SSIZE_MAX_32 = 0x7fffffff;
    static constexpr const uint32_t RAW_MAX_32 = static_cast<uint64_t>(SSIZE_MAX_32) * 5 / 8;
    char *huge_in = (char*) malloc(SSIZE_MAX_32);
    ASSERT_NE(nullptr, huge_in);
    char *huge_out = (char*) malloc(SSIZE_MAX_32);
    ASSERT_NE(nullptr, huge_out);

    ASSERT_EQ(SSIZE_MAX_32, base32::encode({huge_in, RAW_MAX_32}, {huge_out, SSIZE_MAX_32}));
    for (size_t i = 0; i < SSIZE_MAX_32; ++i)
    {
        // check that entire output is filled with valid base32 symbols
        ASSERT_LT(base32::JAMTIS_INVERTED_ALPHABET[(uint8_t) huge_out[i]], 32);
    }

    memset(huge_in, 'q', SSIZE_MAX_32);
    ASSERT_EQ(RAW_MAX_32, base32::decode({huge_in, SSIZE_MAX_32}, {huge_out, RAW_MAX_32}));
#endif
}

TEST(base32, bad_chars)
{
    static constexpr const char BASE32_UNALLOWED[] = "~`!@#$%^&*()_=+[{]}\\|;:'\",<.>/? "; // hyphen not included

    for (const char c : BASE32_UNALLOWED)
        EXPECT_EQ(base32::BADC, base32::JAMTIS_INVERTED_ALPHABET[(unsigned) c]);
    
    EXPECT_EQ(base32::IGNC, base32::JAMTIS_INVERTED_ALPHABET[(unsigned) '-']);
}
