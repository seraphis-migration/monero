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

//paired header
#include "math_utils.h"

//local headers

//third party headers
#include <boost/math/special_functions/binomial.hpp>
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <cmath>
#include <limits>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace math
{
//-------------------------------------------------------------------------------------------------------------------
std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
{
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
        "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
        return 0;

    const double fp_result{boost::math::binomial_coefficient<double>(n, k)};

    if (fp_result < 0)
        return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
        return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t clamp(const std::uint64_t a, const std::uint64_t min, const std::uint64_t max)
{
    // clamp 'a' to range [min, max]
    if (a < min)
        return min;
    else if (a > max)
        return max;
    else
        return a;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t saturating_add(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max)
{
    if (a > max ||
        b > max - a)
        return max;
    return a + b;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t saturating_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t min)
{
    if (a < min ||
        b > a - min)
        return min;
    return a - b;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t saturating_mul(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max)
{
    boost::multiprecision::uint128_t a_big{a};
    boost::multiprecision::uint128_t b_big{b};
    boost::multiprecision::uint128_t r_big{a * b};

    if (r_big > max)
        return max;

    return static_cast<std::uint64_t>(r_big);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t mod(const std::uint64_t a, const std::uint64_t n)
{
    // a mod n
    // - special case: n = 0 means n = std::uint64_t::max + 1
    return n > 0 ? a % n : a;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t mod_negate(const std::uint64_t a, const std::uint64_t n)
{
    // -a mod n = n - (a mod n)
    return n - mod(a, n);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t mod_add(std::uint64_t a, std::uint64_t b, const std::uint64_t n)
{
    // a + b mod n
    a = mod(a, n);
    b = mod(b, n);

    // if adding doesn't overflow the modulus, then add directly, otherwise overflow the modulus
    return (n - a > b) ? a + b : b - (n - a);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t mod_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t n)
{
    // a - b mod n
    return mod_add(a, mod_negate(b, n), n);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t mod_mul(std::uint64_t a, std::uint64_t b, const std::uint64_t n)
{
    // a * b mod n
    boost::multiprecision::uint128_t a_big{mod(a, n)};
    boost::multiprecision::uint128_t b_big{mod(b, n)};
    boost::multiprecision::uint128_t r_big{a * b};

    return static_cast<std::uint64_t>(n > 0 ? r_big % n : r_big);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace math
} //namespace sp
