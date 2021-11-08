// Copyright (c) 2021, The Monero Project
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


#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "string_tools.h"


//standard headers
#include <vector>


using namespace rct;

class test_pippinger_failure
{
public:
  static const size_t loop_count = 1000;

  bool init()
  {
    return true;
  }

  bool test()
  {
    std::vector<rct::MultiexpData> data;
    rct::key k{rct::pkGen()};
    data.push_back({rct::identity(), k});
    data.push_back({sp::MINUS_ONE, k});

    ge_p3 result{rct::pippenger_p3(data, cache, 2, rct::get_pippenger_c(data.size()))};

    return ge_p3_is_point_at_infinity(&result) != 0;
  }

private:
  std::shared_ptr<rct::pippenger_cached_data> cache;
};

class test_ge_p3_identity_failure
{
public:
  static const size_t loop_count = 1000;

  bool init()
  {
    return true;
  }

  bool test()
  {
    rct::key k{rct::pkGen()};
    rct::key k2;
    rct::addKeys(k2, k, k);

    ge_p3 result;
    sp::multi_exp_p3({rct::identity(), sp::MINUS_ONE, sp::MINUS_ONE}, {k2, k, k}, result);

    // ge_p3_is_point_at_infinity
    // X = 0 and Y == Z
    for (int n{0}; n < 10; ++n)
    {
        if (result.X[n] | result.T[n])
        {
            std::cerr << "FAILED ge_p3_identity: n=" << n << " X[n]=" << result.X[n] << " T[n]=" << result.T[n] <<
                " k=" << epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)k.bytes, 32}) << '\n';
            return false;
        }
        if (result.Y[n] != result.Z[n])
        {
            std::cerr << "FAILED ge_p3_identity: n=" << n << " Y[n]=" << result.Y[n] << " Z[n]=" << result.Z[n] <<
                " k=" << epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)k.bytes, 32}) << '\n';
            return false;
        }
    }

    return true;
  }
};

class test_ge_p3_identity_fix
{
public:
  static const size_t loop_count = 1000;

  bool init()
  {
    return true;
  }

  bool test()
  {
    rct::key k{rct::pkGen()};
    rct::key k2;
    rct::addKeys(k2, k, k);

    ge_p3 result;
    sp::multi_exp_p3({rct::identity(), sp::MINUS_ONE, sp::MINUS_ONE}, {k2, k, k}, result);

    // ge_p3_is_point_at_infinity FIXED
    // X = 0 and Y == Z
    int zero_Y_count;
    zero_Y_count = 0;

    for (int n{0}; n < 10; ++n)
    {
        if (result.X[n] | result.T[n])
        {
            std::cerr << "FAILED ge_p3_identity fix: n=" << n << " X[n]=" << result.X[n] << " T[n]=" << result.T[n] <<
                " k=" << epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)k.bytes, 32}) << '\n';
            return false;
        }
        if (((uint32_t)(result.Y[n]) != (uint32_t)(result.Z[n])))
        {
            std::cerr << "FAILED ge_p3_identity fix: n=" << n << " Y[n]=" << result.Y[n] << " (Y[n])=" <<
                (std::uint32_t)(result.Y[n]) << " Z[n]=" << result.Z[n] << " (Z[n])=" << (std::uint32_t)(result.Z[n]) <<
                " k=" << epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)k.bytes, 32}) << '\n';
            return false;
        }
        if (result.Y[n] == 0)
            ++zero_Y_count;
    }

    if (zero_Y_count == 10)  // Y == Z == 0
        return false;

    return true;
  }
};

class test_pippinger_failure_serialized
{
public:
  static const size_t loop_count = 1000;

  bool init()
  {
    return true;
  }

  bool test()
  {
    std::vector<rct::MultiexpData> data;
    rct::key k{rct::pkGen()};
    data.push_back({rct::identity(), k});
    data.push_back({sp::MINUS_ONE, k});

    rct::key result{rct::pippenger(data, cache, 2, rct::get_pippenger_c(data.size()))};

    return result == rct::identity();
  }

private:
  std::shared_ptr<rct::pippenger_cached_data> cache;
};
