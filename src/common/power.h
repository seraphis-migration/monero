// PoWER uses Equi-X:
// <https://github.com/tevador/equix/>.
//
// Equi-X is:
// Copyright (c) 2020 tevador <tevador@gmail.com>
//
// and licensed under the terms of the LGPL version 3.0:
// <https://www.gnu.org/licenses/lgpl-3.0.html>

// Copyright (c) 2019-2025, The Monero Project
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

//local headers
#include "crypto/hash.h"

//third party headers
#include <equix.h>

//standard headers
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

//forward declarations

namespace tools
{
  // RPC related code apply to both the RPC and ZMQ-RPC interfaces.
  namespace power
  {
    // Ban score for peers that either:
    // - attempt to send high-input transactions without PoWER.
    // - send an invalid or malformed PoWER solution.
    inline constexpr size_t BAN_SCORE = 5;

    // Input counts greater than this require PoWER.
    inline constexpr size_t INPUT_THRESHOLD = 8;

    // Number of recent block hashes viable for RPC.
    inline constexpr size_t HEIGHT_WINDOW = 2;

    // Fixed difficulty for the difficulty formula.
    //
    // Target time = ~1s of single-threaded computation.
    // The difficulty value and computation time have a quadratic relationship.
    // Reference values; value of machines are measured in seconds:
    //
    // | Difficulty | Raspberry Pi 5 | Ryzen 5950x | Mac mini M4 |
    // |------------|----------------|-------------|-------------|
    // | 0          | 0.024          | 0.006       | 0.005       |
    // | 25         | 0.307          | 0.076       | 0.067       |
    // | 50         | 0.832          | 0.207       | 0.187       |
    // | 75         | 1.654          | 0.395       | 0.373       |
    // | 100        | 2.811          | 0.657       | 0.611       |
    // | 125        | 4.135          | 0.995       | 0.918       |
    // | 150        | 5.740          | 1.397       | 1.288       |
    // | 175        | 7.740          | 1.868       | 1.682       |
    // | 200        | 9.935          | 2.365       | 2.140       |
    // | 225        | 12.279         | 2.892       | 2.645       |
    // | 250        | 14.855         | 3.573       | 3.226       |
    // | 275        | 17.736         | 4.378       | 3.768       |
    // | 300        | 20.650         | 5.116       | 4.422       |
    inline constexpr uint32_t DIFFICULTY = 100;

    // Max difficulty value.
    //
    // Technically, nodes can be modified to send lower/higher difficulties in P2P.
    // A vanilla node will adjust accordingly; it can and will solve a lower/higher difficulty challenge.
    // This is the max valid difficulty requested from a peer before the connection is dropped.
    inline constexpr uint32_t MAX_DIFFICULTY = DIFFICULTY * 2;

    // Personalization string used in PoWER hashes.
    inline constexpr std::string_view PERSONALIZATION_STRING = "Monero PoWER";

    // (PERSONALIZATION_STRING || tx_prefix_hash || recent_block_hash || nonce)
    inline constexpr size_t CHALLENGE_SIZE_RPC =
      PERSONALIZATION_STRING.size() +
      sizeof(crypto::hash) +
      sizeof(crypto::hash) +
      sizeof(uint32_t);

    // (PERSONALIZATION_STRING || seed || seed_top64 || difficulty || nonce)
    inline constexpr size_t CHALLENGE_SIZE_P2P =
      PERSONALIZATION_STRING.size() +
      sizeof(uint64_t) +
      sizeof(uint64_t) +
      sizeof(uint32_t) +
      sizeof(uint32_t);

    // Challenge byte array for RPC.
    typedef std::array<uint8_t, CHALLENGE_SIZE_RPC> challenge_rpc;

    // Challenge byte array for P2P.
    typedef std::array<uint8_t, CHALLENGE_SIZE_P2P> challenge_p2p;

    // Equi-X solution in byte array form.
    typedef std::array<uint16_t, 8> solution_array;

    static_assert(PERSONALIZATION_STRING.size() == 12, "Implementation assumes 12 bytes");
    static_assert(sizeof(challenge_rpc) == 80, "Implementation assumes 80 bytes");
    static_assert(sizeof(challenge_p2p) == 36, "Implementation assumes 36 bytes");
    static_assert(sizeof(solution_array) == sizeof(equix_solution), "Implementation assumes 16 bytes");
    static_assert(sizeof(crypto::hash) == 32, "Implementation assumes 32 bytes");

    // PoWER solution with context data.
    struct solution_data
    {
      // Challenge bytes.
      std::vector<uint8_t> challenge;
      // Equi-X solution bytes.
      solution_array solution;
      // Correct nonce required for the solution.
      uint32_t nonce;
    };

    /**
    * @brief Create the difficulty scalar used for `check_difficulty`.
    *
    * @param challenge       Pointer to the challenge data.
    * @param challenge_size  Size of the challenge.
    * @param solution        An Equi-X solution.
    */
    uint32_t create_difficulty_scalar(
      const void* challenge,
      const size_t challenge_size,
      const solution_array solution
    ) noexcept ;

    /**
    * @brief Check if a PoWER solution satisfies a difficulty.
    *
    * @param scalar      The PoWER solution as a scalar using `create_difficulty_scalar`.
    * @param difficulty  The difficulty parameter.
    *
    * @return - true if the difficulty check passes, false otherwise.
    */
    constexpr bool check_difficulty(const uint32_t scalar, uint32_t difficulty) noexcept;

    /**
    * @brief Create a PoWER challenge for RPC.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param nonce              The nonce parameter.
    *
    * @return PoWER RPC challenge as bytes.
    */
    std::array<uint8_t, CHALLENGE_SIZE_RPC> create_challenge_rpc(
      const crypto::hash tx_prefix_hash,
      const crypto::hash recent_block_hash,
      const uint32_t nonce
    ) noexcept;

    /**
    * @brief Create a PoWER challenge for P2P.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param difficulty  The difficulty parameter.
    * @param nonce       The nonce parameter.
    *
    * @return PoWER P2P challenge as bytes.
    */
    std::array<uint8_t, CHALLENGE_SIZE_P2P> create_challenge_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce
    ) noexcept;

    /**
    * @brief Generate and solve a PoWER challenge for RPC for a given difficulty.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param difficulty         The difficulty parameter.
    */
    solution_data solve_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t difficulty
    );

    /**
    * @brief Generate and solve a PoWER challenge for P2P for a given difficulty.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param difficulty  The difficulty parameter.
    */
    solution_data solve_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty
    );

    /**
    * @brief Verify a PoWER solution for RPC.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param nonce              A valid nonce.
    * @param difficulty         The difficulty parameter.
    * @param solution           The Equi-X solution.
    *
    * @return true  – if verification succeeded
    * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    */
    bool verify_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t nonce,
      const uint32_t difficulty,
      const solution_array solution
    );

    /**
    * @brief Verify a PoWER solution for P2P.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param nonce       A valid nonce.
    * @param difficulty  The difficulty parameter.
    * @param solution    The Equi-X solution.
    *
    * @return true  – if verification succeeded
    * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    */
    bool verify_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce,
      const solution_array solution
    );

  } // namespace power
} // namespace tools