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
#include "mock_tx/mock_tx_utils.h"
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "string_tools.h"
#include "../io.h"


//standard headers
#include <vector>


using namespace rct;

void get_ge_p3_for_identity_test(const crypto::public_key &point, ge_p3 &result_out_p3)
{
  // compute (K + K) - K - K to get a specific ge_p3 point representation of identity
  ge_cached temp_cache;
  ge_p1p1 temp_p1p1;

  ge_frombytes_vartime(&result_out_p3, (const unsigned char*)&point);  // K
  ge_p3_to_cached(&temp_cache, &result_out_p3);
  ge_add(&temp_p1p1, &result_out_p3, &temp_cache);  // K + K
  ge_p1p1_to_p3(&result_out_p3, &temp_p1p1);
  ge_sub(&temp_p1p1, &result_out_p3, &temp_cache);  // (K + K) - K
  ge_p1p1_to_p3(&result_out_p3, &temp_p1p1);
  ge_sub(&temp_p1p1, &result_out_p3, &temp_cache);  // ((K + K) - K) - K
  ge_p1p1_to_p3(&result_out_p3, &temp_p1p1);
}

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
    crypto::public_key k{rct::rct2pk(rct::pkGen())};
    std::string k_string{epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)&k, 32})};
    ge_p3 result;
    get_ge_p3_for_identity_test(k, result);

    // ge_p3_is_point_at_infinity
    // X = 0 and Y == Z
    for (int n{0}; n < 10; ++n)
    {
        if (result.X[n] | result.T[n])
        {
            std::cerr << "FAILED ge_p3_identity: n=" << n << " X[n]=" << result.X[n] << " T[n]=" << result.T[n] <<
                " k=" << k_string << '\n';
            return false;
        }
        if (result.Y[n] != result.Z[n])
        {
            // try to reproduce failure
            std::istringstream is_k_string{k_string};
            crypto::public_key k_repro;
            get(is_k_string, k_repro);  //from tests/io.h
            ge_p3 result_repro;
            get_ge_p3_for_identity_test(k_repro, result_repro);
            bool reproduced_failure{true};

            for (std::size_t n{0}; n < 10; ++n)
            {
                if (result_repro.X[n] != result.X[n] ||
                    result_repro.Y[n] != result.Y[n] ||
                    result_repro.Z[n] != result.Z[n] ||
                    result_repro.T[n] != result.T[n])
                {
                    reproduced_failure = false;
                    break;
                }
            }

            std::cerr << "FAILED ge_p3_identity: n=" << n << " Y[n]=" << result.Y[n] << " Z[n]=" << result.Z[n] <<
                " k=" << k_string <<  " next-up-1-off=" <<
                ((result.Y[n+1]-1 == result.Z[n+1] || result.Y[n+1] == result.Z[n+1]-1) ? "TRUE" : "FALSE") <<
                " reproduced-failure=" << (reproduced_failure ? "TRUE" : "FALSE") << '\n';

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
    crypto::public_key k{rct::rct2pk(rct::pkGen())};
    std::string k_string{epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)&k, 32})};
    ge_p3 result;
    get_ge_p3_for_identity_test(k, result);

    // ge_p3_is_point_at_infinity FIXED
    // X = 0 and Y == Z
    rct::key result_Y_bytes;
    rct::key result_Z_bytes;
    fe_tobytes(result_Y_bytes.bytes, result.Y);
    fe_tobytes(result_Z_bytes.bytes, result.Z);

    for (int n{0}; n < 10; ++n)
    {
        if (result.X[n] | result.T[n])
        {
            std::cerr << "FAILED ge_p3_identity fix: n=" << n << " X[n]=" << result.X[n] << " T[n]=" << result.T[n] <<
                " k=" << k_string << '\n';
            return false;
        }
    }

    if (!(result_Y_bytes == result_Z_bytes))
    {
        std::string Y_string{epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)(result_Y_bytes.bytes), 32})};
        std::string Z_string{epee::string_tools::buff_to_hex_nodelimer(std::string{(const char *)(result_Z_bytes.bytes), 32})};
        std::cerr << "FAILED ge_p3_identity fix: Y-bytes=" << Y_string << " Z-bytes=" << Z_string <<
            " k=" << k_string << '\n';
        return false;
    }

    if (result_Y_bytes == rct::zero())  // Y == Z == 0
        return false;

    return true;
  }
};


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
