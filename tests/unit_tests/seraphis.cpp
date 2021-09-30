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

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include "gtest/gtest.h"


TEST(seraphis, multi_exp_p3)
{
    ge_p3 test;
    rct::key test_key;
    rct::key check;
    rct::key temp;

    // works normally
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp_p3(pubkeys, privkeys, test);
        ge_p3_tobytes(test_key.bytes, &test);

        EXPECT_TRUE(test_key == check);
    }

    // privkey == 1 optimization works
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            if (j < i/2)
                privkeys.push_back(rct::identity());
            else
                privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp_p3(pubkeys, privkeys, test);
        ge_p3_tobytes(test_key.bytes, &test);

        EXPECT_TRUE(test_key == check);
    }

    // pubkey = G optimization works
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            privkeys.push_back(rct::skGen());

            if (j < i/2)
            {
                pubkeys.push_back(rct::pkGen());
                rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            }
            // for j >= i/2 it will be privkey*G
            else
            {
                rct::scalarmultBase(temp, privkeys.back());
            }

            rct::addKeys(check, check, temp);
        }

        sp::multi_exp_p3(pubkeys, privkeys, test);
        ge_p3_tobytes(test_key.bytes, &test);

        EXPECT_TRUE(test_key == check);
    }
}
