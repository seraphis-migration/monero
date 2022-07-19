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

// Miscellaneous crypto utils for Seraphis.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/// scalar: -1 mod q
static const rct::key MINUS_ONE = { {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
    0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10} };

/// sortable key (e.g. for hash maps)
struct sortable_key
{
    unsigned char bytes[32];

    sortable_key() = default;
    sortable_key(const rct::key &rct_key)
    {
        memcpy(bytes, rct_key.bytes, 32);
    }

    bool operator<(const sortable_key &other) const
    {
        return memcmp(bytes, other.bytes, 32) < 0;
    }
};
static inline const rct::key& sortable2rct(const sortable_key &sortable)
{
    return reinterpret_cast<const rct::key&>(sortable);
}

/**
* brief: invert - invert a nonzero scalar
* param: x - scalar to invert
* return: (1/x) mod l
*/
rct::key invert(const rct::key &x);
/**
* brief: decompose - decompose an integer with a fixed base and size
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
* brief: kronecker_delta - Kronecker delta
* param: x - first integer
* param: y - second integer
* return: 1 if x == y, else 0
*/
rct::key kronecker_delta(const std::size_t x, const std::size_t y);
/**
* brief: convolve - compute a convolution with a degree-one polynomial
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
* brief: generate_proof_nonce - generate a random scalar and corresponding pubkey for use in a Schnorr-like signature opening
* param: base - base EC pubkey for the nonce term
* outparam: nonce_out - private key 'nonce'
* outparam: nonce_pub_out - public key 'nonce * base'
*/
void generate_proof_nonce(const rct::key &base, crypto::secret_key &nonce_out, rct::key &nonce_pub_out);
void generate_proof_nonce(const rct::key &base, rct::key &nonce_out, rct::key &nonce_pub_out);
/**
* brief: subtract_secret_key_vectors - subtract one vector of secret keys from another
*   sum(A) - sum(B)
* param: keys_A - first vector (addors)
* param: keys_B - second vector (subtractors)
* outparam: result_out - 'sum(A) - sum(B)'
*/
void subtract_secret_key_vectors(const std::vector<crypto::secret_key> &keys_A,
    const std::vector<crypto::secret_key> &keys_B,
    crypto::secret_key &result_out);
/**
* brief: mask_key - commit to an EC key
*   K" = mask G + K
* param: mask - commitment mask/blinding factor
* param: key - EC key to commit to
* outparam: masked_key_out - K", the masked key
*/
void mask_key(const crypto::secret_key &mask, const rct::key &key, rct::key &masked_key_out);
/**
* brief: key_domain_is_prime_subgroup - check that input key is in prime order EC subgroup
*   l*K ?= identity
* param: check_key - key to check
* result: true if input key is in prime order EC subgroup
*/
bool key_domain_is_prime_subgroup(const rct::key &check_key);

} //namespace sp
