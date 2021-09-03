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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <vector>


enum class BalanceCheckType
{
    MultiexpSub,
    MultiexpComp,
    Rctops
};

template<BalanceCheckType CheckType, std::size_t set1_size, std::size_t set2_size>
class test_balance_check
{
    public:
        static const size_t loop_count = 1000;

        bool init()
        {
            if (set1_size == 0 || set2_size == 0)
                return false;

            commitment_set1.clear();
            commitment_set2.clear();
            commitment_set1.reserve(set1_size);
            commitment_set2.reserve(set2_size);

            rct::key sum_output_blinding_factors = rct::zero();

            // set 1 blinding factors
            for (std::size_t set1_index{0}; set1_index < set1_size; ++set1_index)
            {
                // random blinding factor
                rct::key set1_blinding_factor{rct::skGen()};

                // add all set 1 blinding factors together
                sc_add((unsigned char *)&sum_output_blinding_factors, (unsigned char *)&sum_output_blinding_factors,
                    (unsigned char *)&set1_blinding_factor);

                // commitment = x G + 0 H
                commitment_set1.emplace_back(rct::commit(0, set1_blinding_factor));
            }

            // set 2 blinding factors (all but last)
            for (std::size_t set2_index{0}; set2_index + 1 < set2_size; ++set2_index)
            {
                // random blinding factor
                rct::key set2_blinding_factor{rct::skGen()};

                // subtract all set 2 blinding factors from sum
                sc_sub((unsigned char *)&sum_output_blinding_factors, (unsigned char *)&sum_output_blinding_factors,
                    (unsigned char *)&set2_blinding_factor);

                // commitment = x G + 0 H
                commitment_set2.emplace_back(rct::commit(0, set2_blinding_factor));
            }

            // last set 2 blinding factor is the remainder
            // sum(output blinding factors) - sum(input image blinding factors)_except_last
            commitment_set2.emplace_back(rct::commit(0, sum_output_blinding_factors));

            return true;
        }

        bool test()
        {
            switch(CheckType)
            {
                case BalanceCheckType::MultiexpSub:
                {
                    std::vector<rct::MultiexpData> multiexp_balance;
                    multiexp_balance.reserve(commitment_set1.size() + commitment_set2.size());

                    rct::key ZERO = rct::zero();
                    rct::key ONE = rct::identity();
                    rct::key MINUS_ONE;
                    sc_sub(MINUS_ONE.bytes, ZERO.bytes, ONE.bytes);

                    for (std::size_t i = 0; i < commitment_set1.size(); ++i)
                    {
                        multiexp_balance.push_back({ONE, commitment_set1[i]});
                    }

                    for (std::size_t j = 0; j < commitment_set2.size(); ++j)
                    {
                        multiexp_balance.push_back({MINUS_ONE, commitment_set2[j]});
                    }

                    // check the balance using multiexponentiation magic
                    // sum(commitment set 1) - sum(commitment set 2) ?= group identity
                    if (!(rct::straus(multiexp_balance) == ONE))
                        return false;
                    else
                        return true;
                }
                case BalanceCheckType::MultiexpComp:
                {
                    std::vector<rct::MultiexpData> multiexp_sumset1;
                    std::vector<rct::MultiexpData> multiexp_sumset2;
                    multiexp_sumset1.reserve(commitment_set1.size());
                    multiexp_sumset2.reserve(commitment_set2.size());

                    rct::key ONE = rct::identity();

                    for (std::size_t i = 0; i < commitment_set1.size(); ++i)
                    {
                        multiexp_sumset1.push_back({ONE, commitment_set1[i]});
                    }

                    for (std::size_t j = 0; j < commitment_set2.size(); ++j)
                    {
                        multiexp_sumset2.push_back({ONE, commitment_set2[j]});
                    }

                    // check the balance using multiexponentiation magic
                    // sum(commitment set 1) ?= sum(commitment set 2)
                    if (!(rct::straus(multiexp_sumset1) == rct::straus(multiexp_sumset2)))
                        return false;
                    else
                        return true;
                }
                case BalanceCheckType::Rctops:
                {
                    // check the balance using basic curve ops
                    // sum(commitment set 1) ?= sum(commitment set 2)
                    if (!(rct::equalKeys(rct::addKeys(commitment_set1), rct::addKeys(commitment_set2))))
                        return false;
                    else
                        return true;
                }
                default:
                    return false;
            };

            return false;
        }

    private:
        rct::keyV commitment_set1;
        rct::keyV commitment_set2;
};
