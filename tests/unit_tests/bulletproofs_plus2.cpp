// Copyright (c) 2017-2022, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "string_tools.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "seraphis_crypto/bulletproofs_plus2.h"

TEST(bulletproofs_plus2, valid_zero)
{
  sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(0, rct::skGen());
  ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proof));
}

TEST(bulletproofs_plus2, valid_max)
{
  sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(0xffffffffffffffff, rct::skGen());
  ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proof));
}

TEST(bulletproofs_plus2, valid_random)
{
  for (int n = 0; n < 8; ++n)
  {
    sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(crypto::rand<uint64_t>(), rct::skGen());
    ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proof));
  }
}

TEST(bulletproofs_plus2, valid_multi_random)
{
  for (int n = 0; n < 8; ++n)
  {
    size_t outputs = 2 + n;
    std::vector<uint64_t> amounts;
    rct::keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(crypto::rand<uint64_t>());
      gamma.push_back(rct::skGen());
    }
    sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(amounts, gamma);
    ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proof));
  }
}

TEST(bulletproofs_plus2, valid_aggregated)
{
  static const size_t N_PROOFS = 8;
  std::vector<sp::BulletproofPlus2> proofs(N_PROOFS);
  for (size_t n = 0; n < N_PROOFS; ++n)
  {
    size_t outputs = 2 + n;
    std::vector<uint64_t> amounts;
    rct::keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(crypto::rand<uint64_t>());
      gamma.push_back(rct::skGen());
    }
    proofs[n] = sp::bulletproof_plus2_PROVE(amounts, gamma);
  }
  ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proofs));
}

TEST(bulletproofs_plus2, invalid_8)
{
  rct::key invalid_amount = rct::zero();
  invalid_amount[8] = 1;
  sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(invalid_amount, rct::skGen());
  ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
}

TEST(bulletproofs_plus2, invalid_31)
{
  rct::key invalid_amount = rct::zero();
  invalid_amount[31] = 1;
  sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(invalid_amount, rct::skGen());
  ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
}

static const char * const torsion_elements[] =
{
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
};

TEST(bulletproofs_plus2, invalid_torsion)
{
  sp::BulletproofPlus2 proof = sp::bulletproof_plus2_PROVE(7329838943733, rct::skGen());
  ASSERT_TRUE(sp::bulletproof_plus2_VERIFY(proof));
  for (const auto &xs: torsion_elements)
  {
    rct::key x;
    ASSERT_TRUE(epee::string_tools::hex_to_pod(xs, x));
    ASSERT_FALSE(rct::isInMainSubgroup(x));
    for (auto &k: proof.V)
    {
      const rct::key org_k = k;
      rct::addKeys(k, org_k, x);
      ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
      k = org_k;
    }
    for (auto &k: proof.L)
    {
      const rct::key org_k = k;
      rct::addKeys(k, org_k, x);
      ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
      k = org_k;
    }
    for (auto &k: proof.R)
    {
      const rct::key org_k = k;
      rct::addKeys(k, org_k, x);
      ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
      k = org_k;
    }
    const rct::key org_A = proof.A;
    rct::addKeys(proof.A, org_A, x);
    ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
    proof.A = org_A;
    const rct::key org_A1 = proof.A1;
    rct::addKeys(proof.A1, org_A1, x);
    ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
    proof.A1 = org_A1;
    const rct::key org_B = proof.B;
    rct::addKeys(proof.B, org_B, x);
    ASSERT_FALSE(sp::bulletproof_plus2_VERIFY(proof));
    proof.B = org_B;
  }
}
