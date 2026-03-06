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

//paired header
#include "power.h"

//local headers
#include "crypto/blake2b.h"
#include "int-util.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_int/import_export.hpp>
#include <boost/multiprecision/integer.hpp>
#include <cstdlib>
#include <equix.h>

//standard headers
#include <array>
#include <cstdint>
#include <cstring>

//forward declarations

namespace tools
{
  namespace power
  {
    using boost::multiprecision::uint128_t;

    namespace {
      template<std::size_t T>
      bool verify_equix_solution(
        const std::array<uint8_t, T>& challenge,
        const solution_array solution
      ) {
        equix_ctx* ctx = equix_alloc(EQUIX_CTX_VERIFY);

        if (ctx == nullptr)
        {
          return false;
        }

        equix_result result = equix_verify(
          ctx,
          challenge.data(),
          challenge.size(),
          reinterpret_cast<const equix_solution*>(solution.data())
        );

        equix_free(ctx);

        return result == EQUIX_OK;
      }

      // Generic Equi-X + difficulty solving function.
      template<std::size_t T>
      solution_data solve(
        std::array<uint8_t, T> challenge,
        const uint32_t difficulty,
        const size_t nonce_index
      ) {
        equix_ctx* ctx = equix_alloc(EQUIX_CTX_SOLVE);

        if (ctx == nullptr)
        {
          throw std::runtime_error("equix_alloc returned nullptr");
        }

        equix_solution solutions[EQUIX_MAX_SOLS];
        solution_array solution;

        for (uint32_t nonce = 0;; ++nonce) {
          const uint32_t n = swap32le(nonce);
          memcpy(challenge.data() + nonce_index, &n, sizeof(n));

          const int solution_count = equix_solve(ctx, challenge.data(), challenge.size(), solutions);

          if (solution_count <= 0)
          {
            continue;
          }

          for (int i = 0; i < solution_count; ++i) {
            memcpy(solution.data(), solutions[i].idx, sizeof(solution));
            uint32_t scalar = create_difficulty_scalar(challenge.data(), challenge.size(), solution);

            if (check_difficulty(scalar, difficulty))
            {
              equix_free(ctx);
              solution_data s;
              s.challenge = std::vector(challenge.begin(), challenge.end());
              s.solution = solution;
              s.nonce = nonce;
              return s;
            }
          }
        }

        equix_free(ctx);
        throw std::runtime_error("practically unreachable for realistic difficulties");
      }

      // Generic Equi-X + difficulty verifying function.
      template<std::size_t T>
      bool verify(
        const std::array<uint8_t, T> challenge,
        const uint32_t difficulty,
        const solution_array solution
      ) {
        if (!verify_equix_solution(challenge, solution))
        {
          return false;
        }

        const uint32_t scalar = create_difficulty_scalar(challenge.data(), challenge.size(), solution);
        return (check_difficulty(scalar, difficulty));
      }
    }

    uint32_t create_difficulty_scalar(
      const void* challenge,
      const size_t challenge_size,
      const solution_array solution
    ) noexcept {
      assert(challenge != nullptr);
      assert(challenge_size != 0);

      blake2b_state state;
      blake2b_init(&state, 4);
      blake2b_update(&state, PERSONALIZATION_STRING.data(), PERSONALIZATION_STRING.size());
      blake2b_update(&state, challenge, challenge_size);
      blake2b_update(&state, reinterpret_cast<const uint8_t*>(solution.data()), sizeof(solution));

      uint8_t out[4];
      blake2b_final(&state, out, 4);

      uint32_t scalar;
      memcpy_swap32le(&scalar, out, sizeof(scalar));

      return scalar;
    }

    constexpr bool check_difficulty(uint32_t scalar, uint32_t difficulty) noexcept
    {
      const uint64_t product = uint64_t(scalar) * uint64_t(difficulty);
      return product <= std::numeric_limits<uint32_t>::max();
    }

    challenge_rpc create_challenge_rpc(
      const crypto::hash tx_prefix_hash,
      const crypto::hash recent_block_hash,
      const uint32_t nonce
    ) noexcept {
      challenge_rpc out {};

      memcpy(out.data(), PERSONALIZATION_STRING.data(), PERSONALIZATION_STRING.size());
      memcpy(out.data() + 12, reinterpret_cast<const void*>(&tx_prefix_hash), 32);
      memcpy(out.data() + 44, reinterpret_cast<const void*>(&recent_block_hash), 32);

      const uint32_t n = swap32le(nonce);
      memcpy(out.data() + 76, &n, sizeof(n));

      return out;
    }

    challenge_p2p create_challenge_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce
    ) noexcept {
      challenge_p2p out {};

      memcpy(out.data(), PERSONALIZATION_STRING.data(), PERSONALIZATION_STRING.size());

      const uint64_t low = swap64le(seed);
      const uint64_t high = swap64le(seed_top64);
      const uint128_t nonce_128 = (uint128_t(high) << 64) | low;
      memcpy(out.data() + 12, &nonce_128, sizeof(nonce_128));

      const uint32_t d = swap32le(difficulty);
      memcpy(out.data() + 28, &d, sizeof(d));

      const uint32_t n = swap32le(nonce);
      memcpy(out.data() + 32, &n, sizeof(n));

      return out;
    }

    solution_data solve_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t difficulty
    ) {
      challenge_rpc challenge =
        create_challenge_rpc(tx_prefix_hash, recent_block_hash, 0);

      return solve(challenge, difficulty, 76);
    }

    solution_data solve_p2p(
      uint64_t seed,
      uint64_t seed_top64,
      uint32_t difficulty
    ) {
      challenge_p2p challenge =
        create_challenge_p2p(seed, seed_top64, difficulty, 0);

      return solve(challenge, difficulty, 28);
    }

    bool verify_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t nonce,
      const uint32_t difficulty,
      const solution_array solution
    ) {
      challenge_rpc challenge = create_challenge_rpc(
        tx_prefix_hash,
        recent_block_hash,
        nonce
      );

      return verify(challenge, difficulty, solution);
    }

    bool verify_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce,
      const solution_array solution
    ) {
      challenge_p2p challenge = create_challenge_p2p(
        seed,
        seed_top64,
        difficulty,
        nonce
      );

      return verify(challenge, difficulty, solution);
    }

  } // namespace power
} // namespace tools
