// Copyright (c) 2014-2022, The Monero Project
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

#pragma once

#include "ringct/rctSigs.h"
#include "ringct/bulletproofs_plus.h"

#include <utility>


template<bool a_verify, size_t n_amounts>
class test_bulletproof_plus
{
public:
  static const size_t approx_loop_count = 100 / n_amounts;
  static const size_t loop_count = (approx_loop_count >= 10 ? approx_loop_count : 10) / (a_verify ? 1 : 5);
  static const bool verify = a_verify;

  bool init()
  {
    proof = rct::bulletproof_plus_PROVE(std::vector<uint64_t>(n_amounts, 749327532984), rct::skvGen(n_amounts));
    return true;
  }

  bool test()
  {
    bool ret = true;
    if (verify)
      ret = rct::bulletproof_plus_VERIFY(proof);
    else
      rct::bulletproof_plus_PROVE(std::vector<uint64_t>(n_amounts, 749327532984), rct::skvGen(n_amounts));
    return ret;
  }

private:
  rct::BulletproofPlus proof;
};

struct ParamsShuttleBPPAgg final : public ParamsShuttle
{
  ParamsShuttleBPPAgg() = default;

  ParamsShuttleBPPAgg(Params &core_params, bool batch, std::vector<size_t> aggregation_groups,
    std::vector<size_t> aggregation_group_repetitions) :
    ParamsShuttle{core_params},
    batch{batch},
    aggregation_groups{std::move(aggregation_groups)},
    aggregation_group_repetitions{std::move(aggregation_group_repetitions)}
  {}

  // batch if true
  bool batch{true};
  // set of group sizes for aggregation, e.g. {3 proofs, 5 proofs}
  std::vector<size_t> aggregation_groups{};
  // number of times to make each aggregation group, e.g. {2x {3 proofs}, 4x {5 proofs}}
  std::vector<size_t> aggregation_group_repetitions{};
};

class test_aggregated_bulletproof_plus
{
public:
  static const size_t loop_count = 25;

  bool init(const ParamsShuttleBPPAgg &params)
  {
    m_params = params;

    if (m_params.aggregation_groups.size() != m_params.aggregation_group_repetitions.size())
      return false;

    for (size_t n = 0; n < m_params.aggregation_groups.size(); ++n)
    {
      for (size_t i = 0; i < m_params.aggregation_group_repetitions[n]; ++i)
        proofs.push_back(rct::bulletproof_plus_PROVE(std::vector<uint64_t>(m_params.aggregation_groups[n], 749327532984),
          rct::skvGen(m_params.aggregation_groups[n])));
    }
    return true;
  }

  bool test()
  {
    if (m_params.batch)
    {
        return rct::bulletproof_plus_VERIFY(proofs);
    }
    else
    {
      for (const rct::BulletproofPlus &proof: proofs)
        if (!rct::bulletproof_plus_VERIFY(proof))
          return false;
      return true;
    }
  }

private:
  std::vector<rct::BulletproofPlus> proofs;

  ParamsShuttleBPPAgg m_params;
};
