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

// Miscellaneous crypto utils for Seraphis


#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "grootle.h"
#include "ringct/rctTypes.h"

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

/**
* brief: invert - Invert a nonzero scalar
* param: x - scalar to invert
* return: (1/x) mod l
*/
rct::key invert(const rct::key &x);
/**
* brief: Get generators
*/
ge_p3 get_grootle_Hi_p3_gen(const std::size_t i);  // get i'th Hi generator
ge_p3 get_G_p3_gen();
ge_p3 get_H_p3_gen();
ge_p3 get_U_p3_gen();
ge_p3 get_X_p3_gen();
rct::key get_U_gen();
rct::key get_X_gen();
/**
* brief: get_grootle_Hi_pippinger_cache_init - get initial cache for pippinger multiexp in Grootle proofs
* return: initialized pippinger cache
*/
std::shared_ptr<rct::pippenger_cached_data> get_grootle_Hi_pippinger_cache_init();
/**
* brief: invert - Decompose an integer with a fixed base and size
*   val -> [_, _, ... ,_]
*   - num slots = 'size'
*   - numeric base = 'base'
*   e.g. if base = 2 then convert val to binary, if base = 10 then put its decimal digits into the return vector
* param: val - value to decompose
* param: base - numeric base for decomposing the value
* param: size - number of digits to record the value in
* outparam: r_out - decomposed val (little endian)
*/
void decompose(const std::size_t val, const std::size_t base, const std::size_t size, std::vector<std::size_t> &r_out);
/**
* brief: com_matrix - Commit to a scalar matrix
*   vector commitment for values a_{1,1}, ..., a_{1,n} ..., a_{m,n} and blinding factor x
*   C = x G + a_{1,1} H_{1,1} + a_{1,2} H_{1,2} + ... + a_{m,n} H_{m,n}
* param: M_priv - matrix of private keys to commit to
* param: x - commitment blinding factor
* outparam: data_out - multiexp data for computing the matrix commitment in one step
*/
void com_matrix(const rct::keyM &M_priv, const rct::key &x, std::vector<rct::MultiexpData> &data_out);
/**
* brief: delta - Kronecker delta
* param: x - first integer
* param: y - second integer
* return: 1 if x == y, else 0
*/
rct::key delta(const std::size_t x, const std::size_t y);
/**
* brief: convolve - Compute a convolution with a degree-one polynomial
* param: x - x_1, x_2, ..., x_m
* param: y - a, b
* param: m - number of elements to look at from x (only access up to x[m-1] in case x.size() > m)
* return: [a*x_1], [b*x_1 + a*x_2], ..., [b*x_{m - 2} + a*x_{m - 1}], [b*x_m]
*/
rct::keyV convolve(const rct::keyV &x, const rct::keyV &y, const std::size_t m);
/**
* brief: powers_of_scalar - powers of a scalar
* param: scalar - scalar to take powers of
* param: num_pows - number of powers to take (0-indexed)
* param: negate_all - bool flag for negating all returned values
* return: (negate ? -1 : 1)*([scalar^0], [scalar^1], ..., [scalar^{num_pows - 1}])
*/
rct::keyV powers_of_scalar(const rct::key &scalar, const std::size_t num_pows, const bool negate_all = false);
/**
* brief: small_scalar_gen - Generate a curve scalar of arbitrary size (in bytes).
*   WARNING: NOT FOR USE WITH CRYPTOGRAPHIC SECRETS
* param: size_bytes - size of the scalar to generate
* return: generated scalar
*/
rct::key small_scalar_gen(const std::size_t size_bytes);
/**
* brief: multi_exp_p3 - EC multiexp operation with arbitrary element count
*   optimization: if a privkey == 1, skips the scalar mul operation
* param: pubkeys - A, B, ..., N
* param: privkeys - a, b, ..., n
* outparam: result_out - aA + bB + ... + nN
*/
void multi_exp_p3(const rct::keyV &pubkeys, const rct::keyV &privkeys, ge_p3 &result_out);

} //namespace sp
