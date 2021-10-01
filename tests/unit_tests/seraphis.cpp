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
#include "mock_tx/seraphis_composition_proof.h"
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include "gtest/gtest.h"


static void make_fake_sp_masked_address(rct::key &mask, rct::key &view_stuff, rct::key &spendkey, rct::key &masked_address)
{
    mask = rct::zero();
    view_stuff = rct::zero();
    spendkey = rct::zero();

    while (mask == rct::zero())
        mask = rct::skGen();

    while (view_stuff == rct::zero())
        view_stuff = rct::skGen();

    while (spendkey == rct::zero())
        spendkey = rct::skGen();

    rct::keyV privkeys;
    rct::keyV pubkeys;
    privkeys.reserve(3);
    pubkeys.reserve(2);

    privkeys.push_back(view_stuff);
    pubkeys.push_back(sp::get_X_gen());
    privkeys.push_back(spendkey);
    pubkeys.push_back(sp::get_U_gen());
    privkeys.push_back(mask);
    //G implicit

    // K' = x G + kv_stuff X + ks U
    sp::multi_exp(pubkeys, privkeys, masked_address);
}


TEST(seraphis, multi_exp)
{
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

        sp::multi_exp(pubkeys, privkeys, test_key);

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

        sp::multi_exp(pubkeys, privkeys, test_key);

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

        sp::multi_exp(pubkeys, privkeys, test_key);

        EXPECT_TRUE(test_key == check);
    }
}

TEST(seraphis, composition_proof)
{
    rct::keyV K, KI, x, y, z;
    rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    // degenerate case works (1 key)
    // normal cases work (>1 key)
    for (std::size_t num_keys{1}; num_keys < 5; ++num_keys)
    {
        K.resize(num_keys);
        KI.resize(num_keys);
        x.resize(num_keys);
        y.resize(num_keys);
        z.resize(num_keys);

        for (std::size_t i{0}; i < num_keys; ++i)
        {
            make_fake_sp_masked_address(x[i], y[i], z[i], K[i]);
            sp::seraphis_key_image_from_privkeys(z[i], y[i], KI[i]);
        }

        proof = sp::sp_composition_prove(K, x, y, z, message);

        EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));
    }

    // works even if x = 0
    {
        K.resize(1);
        KI.resize(1);
        x.resize(1);
        y.resize(1);
        z.resize(1);

        make_fake_sp_masked_address(x[0], y[0], z[0], K[0]);

        rct::key xG;
        rct::scalarmultBase(xG, x[0]);
        rct::subKeys(K[0], K[0], xG);   // kludge: remove x part manually
        x[0] = rct::zero();

        sp::seraphis_key_image_from_privkeys(z[0], y[0], KI[0]);

        proof = sp::sp_composition_prove(K, x, y, z, message);

        EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));
    }
}
