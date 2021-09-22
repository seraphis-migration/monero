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

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "grootle.h"
#include "rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace rct
{
struct pippenger_cached_data;
struct MultiexpData;
}


namespace sp
{

////
// Invert a nonzero scalar
// return: (1/x) mod l
///
rct::key invert(const rct::key &x);

/// Make generators, but only once
void init_sp_gens();

ge_p3 get_grootle_Hi_p3_gen(const std::size_t i);
ge_p3 get_G_p3_gen();
ge_p3 get_H_p3_gen();
ge_p3 get_U_p3_gen();
ge_p3 get_X_p3_gen();
rct::key get_U_gen();
rct::key get_X_gen();

std::shared_ptr<rct::pippenger_cached_data> get_grootle_Hi_pippinger_cache_init();

////
// Decompose an integer with a fixed base and size
// val -> [_, _, ... ,_]
// - num slots = 'size'
// - numeric base = 'base'
// e.g. if base = 2 then convert val to binary, if base = 10 then put its decimal digits into the return vector
// r = decomposed val (little endian)
///
void decompose(std::vector<std::size_t> &r, const std::size_t val, const std::size_t base, const std::size_t size);

////
// Commit to a scalar matrix
// vector commitment for values a_{1,1}, ..., a_{1,n} ..., a_{m,n} and blinding factor x
// C = x H + a_{1,1} H_{1,1} + a_{1,2} H_{1,2} + ... + a_{m,n} H_{m,n}
///
void com_matrix(std::vector<rct::MultiexpData> &data, const rct::keyM &M, const rct::key &x);

/// Kronecker delta
rct::key delta(const std::size_t x, const std::size_t y);

////
// Compute a convolution with a degree-one polynomial
// x: x_1, x_2, ..., x_m
// y: a, b
// return: a*x_1, b*x_1 + a*x_2, ..., b*x_{m - 2} + a*x_{m - 1}, b*x_m
///
rct::keyV convolve(const rct::keyV &x, const rct::keyV &y, const std::size_t m);

} //namespace sp
