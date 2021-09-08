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

// NOT FOR PRODUCTION

//paired header
#include "mock_tx_interface.h"

//local headers
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers


namespace mock_tx
{
std::size_t ref_set_size_from_decomp(const std::size_t ref_set_decomp_n, const std::size_t ref_set_decomp_m)
{
    // ref set size = n^m
    std::size_t ref_set_size{ref_set_decomp_n};

    if (ref_set_decomp_n == 0 || ref_set_decomp_m == 0)
        ref_set_size = 1;
    else
    {
        for (std::size_t mul{1}; mul < ref_set_decomp_m; ++mul)
            ref_set_size *= ref_set_decomp_n;
    }

    return ref_set_size;
}
//-----------------------------------------------------------------
std::size_t compute_rangeproof_grouping_size(const std::size_t num_amounts, const std::size_t max_num_splits)
{
    // if there are 'n' amounts, split them into power-of-2 groups up to 'max num splits' times
    // n = 7, split = 1: [4, 3]
    // n = 7, split = 2: [2, 2, 2, 1]
    // n = 11, split = 1: [8, 3]
    // n = 11, split = 2: [4, 4, 3]

    std::size_t split_size{num_amounts};
    std::size_t rangeproof_splits{max_num_splits};

    while (rangeproof_splits > 0)
    {
        // if split size isn't a power of 2, then the split is [power of 2, remainder]
        // - this can only occur the first passthrough
        std::size_t last_bit_pos{0};
        std::size_t temp_size{split_size};

        while (temp_size)
        {
            temp_size = temp_size >> 1;
            ++last_bit_pos;
        }

        if ((1 << (last_bit_pos - 1)) == split_size)
            split_size = split_size >> 1;
        else
            split_size = (1 << (last_bit_pos - 1));

        // min split size is 1
        if (split_size <= 1)
        {
            split_size = 1;
            break;
        }

        --rangeproof_splits;
    }

    return split_size;
}
//-----------------------------------------------------------------
bool balance_check_equality(const rct::keyV &commitment_set1, const rct::keyV &commitment_set2)
{
    // balance check method chosen from perf test: tests/performance_tests/balance_check.h
    return rct::equalKeys(rct::addKeys(commitment_set1), rct::addKeys(commitment_set2));
}
//-----------------------------------------------------------------
} //namespace mock_tx
