// Copyright (c) 2014-2025, The Monero Project
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

//test header
#include "gtest/gtest.h"

//local headers
#include "common/power.cpp"
#include "common/power.h"
#include "hex.h"
#include "string_tools.h"

//third party headers
#include <equix.h>

//standard headers
#include <cstdint>
#include <limits>
#include <string_view>

// Test difficulty, real difficulty value is too high for debug builds.
constexpr uint32_t DIFF = 15;

struct test_data_equix {
  std::string_view challenge;
  std::string_view expected_solution;
  int expected_solution_count;
  uint32_t expected_scalar;
};

struct test_data_rpc {
  std::string_view tx_prefix_hash;
  std::string_view recent_block_hash;
  uint32_t expected_nonce;
  /// Final challenge bytes, not the initial bytes.
  std::string_view expected_challenge;
  std::string_view expected_solution;
  uint32_t expected_scalar;
};

struct test_data_p2p {
  uint64_t seed;
  uint64_t seed_top64;
  uint32_t expected_nonce;
  /// Final challenge bytes, not the initial bytes.
  std::string_view expected_challenge;
  std::string_view expected_solution;
  uint32_t expected_scalar;
};

constexpr std::array<test_data_equix, 5> TEST_DATA_EQUIX {{
  // test UTF8
  {
    "よ、ひさしぶりだね。",
    "546658a95f6466ecc41b24dca5a5e8f5",
    3,
    609012647
  },
  {
    "👋,🕒👉🕘.",
    "7854ba6c1c9bf7cc9354aed876ce64f4",
    3,
    1651207227
  },
  {
    "Privacy is necessary for an open society in the electronic age.",
    "7d1467364825e586ae44b9e95ff388f3",
    4,
    2074493700
  },
  {
    "We must defend our own privacy if we expect to have any.",
    "a330e6561142a57be57513c1095d46ff",
    3,
    1892198895
  },
  {
    "We must come together and create systems which allow anonymous transactions to take place.",
    "ca1e0362d9252bbb85c62fcdf4ac68f6",
    2,
    283799637
  },
}};

constexpr std::array<test_data_rpc, 3> TEST_DATA_RPC {{
  test_data_rpc {
    "c01d4920b75c0cad3a75aa71d6aa73e3d90d0be3ac8da5f562b3fc101e74b57c",
    "77ff034133bdd86914c6e177563ee8b08af896dd2603b882e280762deab609c0",
    5,
    "4d6f6e65726f20506f574552c01d4920b75c0cad3a75aa71d6aa73e3d90d0be3ac8da5f562b3fc101e74b57c77ff034133bdd86914c6e177563ee8b08af896dd2603b882e280762deab609c005000000",
    "6c81ba867f822ea88b14fe2ed027e1ee",
    259977672,
  },
  {
    "17bac54d909964de0ed46eda755904b33fb42eead7ce015fbdde17fa6f0ec95f",
    "6d4c090582ed8cecfc8f8d90ddd8e6b7c8b39dd86c7e882078b670a7ba29b03f",
    24,
    "4d6f6e65726f20506f57455217bac54d909964de0ed46eda755904b33fb42eead7ce015fbdde17fa6f0ec95f6d4c090582ed8cecfc8f8d90ddd8e6b7c8b39dd86c7e882078b670a7ba29b03f18000000",
    "6992d7cb29ae95dbc92f6b8d50e820ef",
    252939049,
  },
  {
    "6dd6a8df16e052f53d51f5f76372ab0c14c60d748908c4589a90327bdc6498a1",
    "bc322459b35f5c58082d4193c8d6bf4f057aedd0823121f2ecbcb117276d13a2",
    1,
    "4d6f6e65726f20506f5745526dd6a8df16e052f53d51f5f76372ab0c14c60d748908c4589a90327bdc6498a1bc322459b35f5c58082d4193c8d6bf4f057aedd0823121f2ecbcb117276d13a201000000",
    "19018e8d20beaeda149816cd74f33bfd",
    187745649,
  },
}};

constexpr std::array<test_data_p2p, 3> TEST_DATA_P2P {{
  {
    0, 0, 10,
    "4d6f6e65726f20506f574552000000000000000000000000000000000f0000000a000000",
    "ad025bac4c7bb2dfcb4bb666cf2643e8",
    252557470,
  },
  {
    1589356, 6700, 0,
    "4d6f6e65726f20506f5745526c401800000000002c1a0000000000000f00000000000000",
    "0d25ad67fb065baae91a0d29a31db9d8",
    50548387,
  },
  {
    std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), 4,
    "4d6f6e65726f20506f574552ffffffffffffffffffffffffffffffff0f00000004000000",
    "3357a279712c70e3e26442d864282ef8",
    170469575,
  },
}};

namespace tools
{
  namespace power
  {

    // Sanity test Equi-X functions.
    TEST(power, equix_functions)
    {
      equix_ctx* ctx = equix_alloc(EQUIX_CTX_SOLVE);

      for (const auto& t : TEST_DATA_EQUIX)
      {
        const void* challenge = t.challenge.data();
        const size_t size = t.challenge.size();

        equix_solution solutions[EQUIX_MAX_SOLS];
        const int count = equix_solve(ctx, challenge, size, solutions);
        ASSERT_EQ(count, t.expected_solution_count);
        const equix_solution s = solutions[0];

        const std::string h = epee::string_tools::pod_to_hex(s);
        ASSERT_EQ(h, t.expected_solution);

        tools::power::solution_array s2;
        memcpy(s2.data(), s.idx, sizeof(s2));

        const uint32_t d = create_difficulty_scalar(challenge, size, s2);
        ASSERT_EQ(d, t.expected_scalar);

        const uint32_t last_difficulty_that_passes =
          std::numeric_limits<std::uint32_t>::max() / d;

        ASSERT_EQ(true, check_difficulty(d, last_difficulty_that_passes));
        ASSERT_EQ(false, check_difficulty(d, last_difficulty_that_passes + 1));
      }
    }

    TEST(power, rpc)
    {
      for (const auto& t : TEST_DATA_RPC)
      {
        crypto::hash tx_prefix_hash {};
        crypto::hash recent_block_hash {};
        epee::string_tools::hex_to_pod(t.tx_prefix_hash.data(), tx_prefix_hash);
        epee::string_tools::hex_to_pod(t.recent_block_hash.data(), recent_block_hash);

        const solution_data s = solve_rpc(tx_prefix_hash, recent_block_hash, DIFF);

        ASSERT_EQ(s.nonce, t.expected_nonce);

        const std::array<std::uint8_t, CHALLENGE_SIZE_RPC> c =
          create_challenge_rpc(tx_prefix_hash, recent_block_hash, t.expected_nonce);

        const std::string c_hex = epee::string_tools::pod_to_hex(c);
        ASSERT_EQ(c_hex, t.expected_challenge);

        const std::string c2_hex = epee::to_hex::string({s.challenge.data(), s.challenge.size()});
        ASSERT_EQ(c2_hex, t.expected_challenge);

        const uint32_t d = create_difficulty_scalar(s.challenge.data(), s.challenge.size(), s.solution);
        ASSERT_EQ(d, t.expected_scalar);

        const uint32_t last_difficulty_that_passes =
          std::numeric_limits<std::uint32_t>::max() / d;

        ASSERT_EQ(true, check_difficulty(d, last_difficulty_that_passes));
        ASSERT_EQ(false, check_difficulty(d, last_difficulty_that_passes + 1));

        ASSERT_EQ(true, verify_rpc(
          tx_prefix_hash,
          recent_block_hash,
          t.expected_nonce,
          DIFF,
          s.solution
        ));
      }
    }

    TEST(power, p2p)
    {
      for (const auto& t : TEST_DATA_P2P)
      {
        const solution_data s = solve_p2p(t.seed, t.seed_top64, DIFF);

        ASSERT_EQ(s.nonce, t.expected_nonce);

        const std::array<std::uint8_t, CHALLENGE_SIZE_P2P> c =
          create_challenge_p2p(t.seed, t.seed_top64, DIFF, t.expected_nonce);

        const std::string c_hex = epee::string_tools::pod_to_hex(c);
        ASSERT_EQ(c_hex, t.expected_challenge);

        const std::string c2_hex = epee::to_hex::string({s.challenge.data(), s.challenge.size()});
        ASSERT_EQ(c2_hex, t.expected_challenge);

        const uint32_t d = create_difficulty_scalar(s.challenge.data(), s.challenge.size(), s.solution);
        ASSERT_EQ(d, t.expected_scalar);

        const uint32_t last_difficulty_that_passes =
          std::numeric_limits<std::uint32_t>::max() / d;

        ASSERT_EQ(true, check_difficulty(d, last_difficulty_that_passes));
        ASSERT_EQ(false, check_difficulty(d, last_difficulty_that_passes + 1));

        ASSERT_EQ(true, verify_p2p(
          t.seed,
          t.seed_top64,
          t.expected_nonce,
          DIFF,
          s.solution
        ));
      }
    }

  } //namespace power
} // namespace tools
