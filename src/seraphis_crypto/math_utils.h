// Copyright (c) 2022, The Monero Project
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

// Miscellaneous math utils.

#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>

//forward declarations


namespace sp
{
namespace math
{

/**
* brief: uint_pow - compute n^m
* param: n - base
* param: m - uint_pow
* return: n^m
* 
* note: use this instead of std::pow() for better control over error states
*/
constexpr std::uint64_t uint_pow(std::uint64_t n, unsigned char m) noexcept
{
    // 1. special case: 0^m = 0
    if (n == 0) return 0;

    // 2. special case: n^0 = 1
    if (m == 0) return 1;

    // 3. normal case: n^m
    // - use square and multiply
    std::uint64_t result{1};
    std::uint64_t temp{};

    while (m != 0)
    {
        // multiply
        if (m & 1) result *= n;

        // test end condition
        if (m == 1) break;

        // square with overflow check
        temp = n*n;
        if (temp < n) return -1;
        n = temp;

        // next level
        m >>= 1;
    }

    return result;
}
/**
* brief: n_choose_k - n choose k math function
* param: n -
* param: k -
* return: n choose k
*/
std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k);
/**
* clamp 'a' to range [min, max]
*/
std::uint64_t clamp(const std::uint64_t a, const std::uint64_t min, const std::uint64_t max);
/**
* a + b, saturate to 'max'
*/
std::uint64_t saturating_add(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max);
/**
* a - b, saturate to 'min'
*/
std::uint64_t saturating_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t min);
/**
* a * b, saturate to 'max'
*/
std::uint64_t saturating_mul(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max);
/**
* a mod n
* special case: n = 0 means n = std::uint64_t::max + 1
*/
std::uint64_t mod(const std::uint64_t a, const std::uint64_t n);
/**
* -a mod n
*/
std::uint64_t mod_negate(const std::uint64_t a, const std::uint64_t n);
/**
* a + b mod n
*/
std::uint64_t mod_add(std::uint64_t a, std::uint64_t b, const std::uint64_t n);
/**
* a - b mod n
*/
std::uint64_t mod_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t n);
/**
* a * b mod n
*/
std::uint64_t mod_mul(std::uint64_t a, std::uint64_t b, const std::uint64_t n);

} //namespace math
} //namespace sp
